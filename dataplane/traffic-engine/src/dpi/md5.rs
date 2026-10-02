// dpi/md5.rs —— 最小 MD5（RFC 1321），供 JA3 指纹使用。
//
// 为什么自己实现而不引 crate：**本工程刻意保持零第三方依赖**（见 Cargo.toml），
// 这让它在离线环境、容器、以及"必须能静态审计每一字节在做什么"的安全场景里可构建。
//
// 更重要的是 MD5 在这里不只是工具，还是**互证渠道**：JA3 指纹 = MD5(握手特征串)，
// 而特征串本身的正确性由 tshark 独立复核（见 scripts/verify/check-dpi-vectors.sh）。
// 于是形成三层：
//     生成器算特征串 → 自实现 MD5 出哈希 → tshark 用**它的**实现出哈希 → 三方比对。
// 若 MD5 写错（轮常量抄错一列、移位表错位一格），RFC 1321 的测试向量会立刻炸，
// 不会悄悄让所有 JA3 都偏成一个"看起来正常"的值 —— 那才是 JA3 最危险的失败模式。

/// 每轮 16 步的循环左移位数：`7,12,17,22` 循环四次（第 1 轮）…`6,10,15,21`（第 4 轮）。
/// 写成字面量而非"用循环生成"：这张表错一位与写错一个值一样致命，
/// 让读者一眼能跟 RFC 1321 的表格对照，而不是去信任一段看起来在算但其实算错了的代码。
const SHIFT: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, // 第 1 轮
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, // 第 2 轮
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, // 第 3 轮
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, // 第 4 轮
];

/// 第 i 步读取的 16 个消息字下标（按 RFC 1321 的四条公式展开）。
const G: [usize; 64] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, // i, i, …
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, // (5i+1) mod 16
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2, // (3i+5) mod 16
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9, // (7i) mod 16
];

/// 轮常量 K[i] = floor(|sin(i+1)| · 2^32) 的低 32 位（RFC 1321 附录）。
///
/// 必须写成表：它**不是**任何整数运算能推出来的（|sin| 的截断结果），
/// 试图用 `2^32 + (i+1)` 之类"看起来像"的公式近似，只会得到一个
/// 能跑、格式正确、但每个值都错的哈希 —— 这类错误在 JA3 上尤其致命。
const K: [u32; 64] = [
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE, 0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C, 0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1, 0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
];

/// 第 i 步的非线性函数 F(b,c,d,i)，对四轮分别取其一。
#[inline]
fn f(b: u32, c: u32, d: u32, i: usize) -> u32 {
    match i / 16 {
        0 => (b & c) | ((!b) & d),
        1 => (d & b) | ((!d) & c),
        2 => b ^ c ^ d,
        _ => c ^ (b | !d),
    }
}

/// 对给定字节串求 MD5，返回小写十六进制（32 字符）。
pub fn md5_hex(data: &[u8]) -> String {
    // 初始链接变量（RFC 1321 3.3 节）。这四个数看着像"随便写的魔数"，其实是把
    // `01234567 89abcdef fedcba98 76543210` 这四个字节串按**小端**解释出来的 u32。
    // 因此 B 是 0xEFCDAB89 而不是 0xEFCD89AB —— 中间两位写反的话，
    // 哈希照样是 32 位十六进制、照样稳定，只是每一个值都错（JA3 最怕的失败模式）。
    let mut a0: u32 = 0x6745_2301;
    let mut b0: u32 = 0xEFCD_AB89;
    let mut c0: u32 = 0x98BA_DCFE;
    let mut d0: u32 = 0x1032_5476;

    // 预处理：附加 0x80，补 0 直到长度 ≡ 56 (mod 64)，再附 64 位 little-endian 比特长度。
    // 长度用 wrapping 加法：超过 2^64 比特的输入不属于本实现的适用范围。
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let mut m = [0u32; 16];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            let o = i * 4;
            m[i] = u32::from_le_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]);
        }
        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
        for i in 0..64 {
            let k = K[i];
            // F 必须作用在**重命名之前**的 (b,c,d) 上：这一步的顺序写反，
            // 得到的是一个"能跑、输出 32 位十六进制、但值全错"的哈希 ——
            // JA3 最危险的失败模式正是这种，它不报错，只是让所有指纹都悄悄不同。
            let tmp = d;
            let ff = f(b, c, d, i);
            d = c;
            c = b;
            // 循环左移只作用在被括号括住的那一项 (a+f+k+w[g])，**再**加上 b。
            // 把 rotate 套在包含 b 的整体上，是这类手写摘要最常见的错法：
            // 结果仍然是 32 位、仍然稳定，只是每个值都错。
            b = b.wrapping_add(
                ff.wrapping_add(a)
                    .wrapping_add(k)
                    .wrapping_add(m[G[i]])
                    .rotate_left(SHIFT[i]),
            );
            a = tmp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    // 摘要字节序：每个链接变量按**小端**输出 4 个字节。这一步若写成"从最低半字节开始拼"，
    // 得到的是同样是 32 个十六进制字符、同样是合法外观的字符串，但每两个字符都反了 ——
    // 与 JA3 参考实现对不上时最难察觉的就是这种"看起来对"的错。
    let mut out = String::with_capacity(32);
    for v in [a0, b0, c0, d0] {
        for i in 0..4 {
            let byte = ((v >> (8 * i)) & 0xFF) as u8;
            out.push_str(&format!("{:02x}", byte));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1321 第 3.5 节官方测试向量：这些都是**公开已知答案**，
    // 任何一轮函数抄错、移位表错一格、小端大端弄反，都会在这里暴露。
    #[test]
    fn rfc1321_vectors() {
        assert_eq!(md5_hex(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            md5_hex(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            md5_hex(b"abcdefghijklmnopqrstuvwxyz"),
            "c3fcd3d76192e4007dfb496cca67e13b"
        );
        let long = b"abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(md5_hex(long), "36eea18da65a8e4606c529635c3d5b15");
        assert_eq!(
            md5_hex(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            "d174ab98d277d9f5a5611c2c9f419d9f"
        );
    }

    // 补位边界：55/56/57/64 字节分别落在"需要补 8 字节""正好 56”“补 1 字节”“补满一整块"
    // 四种补位分支上，写错任一条分支的表现是**只在特定长度输入上错**，日常用例测不出来。
    #[test]
    fn length_padding_boundaries() {
        assert_eq!(md5_hex(&[b'a'; 55]), "ef1772b6dff9a122358552954ad0df65");
        assert_eq!(md5_hex(&[b'a'; 56]), "3b0c8ac703f828b04c6c197006d17218");
        assert_eq!(md5_hex(&[b'a'; 57]), "652b906d60af96844ebd21b674f35e93");
        assert_eq!(md5_hex(&[b'a'; 64]), "014842d480b571495a4a0363793f7367");
        // 相邻长度哈希必须不同 —— 若实现漏了附加长度字段，某些长度会返回相同结果
        assert_ne!(md5_hex(&[b'a'; 55]), md5_hex(&[b'a'; 56]));
        assert_ne!(md5_hex(&[b'a'; 63]), md5_hex(&[b'a'; 64]));
    }
}
