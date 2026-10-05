//! hash.rs - 流键的稳定哈希（分片与采样共用一份）。
//!
//! **为什么单独成模块**：分片（`pipeline::shard_of`）与采样（`sampling::Sampler`）
//! 都要"把流键稳定地映射成一个 64 位数"，而这两处的稳定性要求是一样的：
//!
//! 1. **跨进程/跨版本稳定**：用 `DefaultHasher` 会随 Rust 版本漂移。一旦漂移，
//!    "上次这条流落在哪个 worker / 有没有被采到"就对不上号，排查时无从复现。
//! 2. **低位必须被搅匀**：FNV-1a 的低位只由最后几个字节决定，而真实流量的流键尾部
//!    （目的端口 443、协议号 6）往往完全相同 —— 直接取低位会得到恒定值。
//!
//! 本仓已经因为这个坑付过一次学费（见 HANDOFF §2.10：20000 条流在 8 个 worker 上
//! 只用到 0/4 号，输出正确、单测全绿、并行度为零）。把构造抽到这里，是为了让
//! 采样不要**再犯一次同样的错**，也避免两处各写一份 FNV/splitmix 后各自漂移。

use crate::flow::FlowKey;

/// FNV-1a 的一步。
#[inline]
pub fn fnv1a_step(h: u64, b: u8) -> u64 {
    (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
}

/// FNV-1a 的初始值。
pub const FNV1A_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;

/// splitmix64 的收尾混合：把 FNV 的低位偏置搅匀，然后用低位取模才有意义。
///
/// 为什么"必须有这一步"而不是"更保险一点"：**FNV-1a 的低位只取决于最后几个字节**
/// —— 乘法不会把高位信息带进低位。而真实流量的流键尾部（目的端口、协议号）在同一批
/// 流量里往往完全相同，于是 `h % workers` 取到的低位恒定，全部流挤到一个 worker 上。
/// 实测：20000 条流、8 个 worker 时只用到了 0 号和 4 号（`h % 4` 恒为 0），
/// 2/4 个 worker 时**全部**落在 0 号 —— 并行度是零，而输出仍然"正确"、单测全绿。
/// 这个 bug 是吞吐测量（每个 worker 承担多少条流）暴露的。
#[inline]
pub fn mix64(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// 流键 → 未混合的 FNV-1a 哈希。
///
/// 喂入顺序固定为 `src_ip, src_port, dst_ip, dst_port, proto`，地址族用一个字节
/// 打头（4/6），于是 `10.0.0.1` 与某个 v6 地址不会因为前 4 字节巧合而撞到一起。
pub fn key_hash(key: &FlowKey) -> u64 {
    let mut h = FNV1A_OFFSET;
    let mut feed = |bytes: &[u8]| {
        for b in bytes {
            h = fnv1a_step(h, *b);
        }
    };
    match key.src_ip {
        std::net::IpAddr::V4(a) => {
            feed(&[4]);
            feed(&a.octets());
        }
        std::net::IpAddr::V6(a) => {
            feed(&[6]);
            feed(&a.octets());
        }
    }
    feed(&key.src_port.to_be_bytes());
    match key.dst_ip {
        std::net::IpAddr::V4(a) => {
            feed(&[4]);
            feed(&a.octets());
        }
        std::net::IpAddr::V6(a) => {
            feed(&[6]);
            feed(&a.octets());
        }
    }
    feed(&key.dst_port.to_be_bytes());
    feed(&[key.proto.number()]);
    h
}

/// 流键 → 稳定且分布均匀的 64 位数（已混合）。**必须传 `canonical()` 过的键**。
pub fn key_hash_mixed(key: &FlowKey) -> u64 {
    mix64(key_hash(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn k(a: u8, b: u8) -> FlowKey {
        FlowKey {
            src_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, a)),
            src_port: 1024 + u16::from(a),
            dst_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 128, 0, b)),
            dst_port: 443,
            proto: crate::channel::Proto::Tcp,
        }
    }

    #[test]
    fn hash_is_stable_and_key_sensitive() {
        assert_eq!(key_hash(&k(1, 1)), key_hash(&k(1, 1)), "同一个键必须稳定");
        assert_ne!(key_hash(&k(1, 1)), key_hash(&k(1, 2)), "不同的键必须不同");
    }

    #[test]
    fn mixed_hash_low_bits_are_balanced() {
        // 回归那个真实缺陷：只改**前部**字节（真实流量变化在源地址/端口，
        // 尾部固定为目的端口 443 + 协议 6）时，低位不能被"钉住"。
        let mut buckets = [0usize; 8];
        for i in 0..2048u32 {
            let key = FlowKey {
                src_ip: IpAddr::V4(std::net::Ipv4Addr::from(0x0a00_0000u32 + i)),
                src_port: 1024 + (i as u16 % 40000),
                dst_ip: IpAddr::V4(std::net::Ipv4Addr::new(10, 128, 0, 1)),
                dst_port: 443,
                proto: crate::channel::Proto::Tcp,
            };
            buckets[(key_hash_mixed(&key) % 8) as usize] += 1;
        }
        // 手算期望：2048 条 / 8 桶 = 256 条；允许 ±40%（分桶是均匀采样，不会更差）。
        for (i, c) in buckets.iter().enumerate() {
            assert!(
                (154..=358).contains(c),
                "第 {i} 桶 {c} 条，超出 256±40% —— 低位又被钉住了？分布：{buckets:?}"
            );
        }
    }
}
