// bin/ring_consume.rs - cythsec-ring-consume：从共享环消费报文并解成 Flow。
//
// 与 C++ 侧 `cythsec-ring-feed` 配对：C++ 写真数据进环，本程序读出来解成五元组，
// 按流聚合后输出。两者合起来就是 CYS-TRF-034 要求的「跨语言端到端」垂直切片。
//
// 用法:
//   cythsec-ring-consume --ring <路径> [选项]
//
// 选项:
//       --ring <路径>        共享区域文件路径
//       --slot-count <N>     期望槽位数（默认 1024）
//       --slot-size <N>      期望槽容量（默认 2048）
//       --from-head          丢弃既有积压，从当前 head 开始（默认：从区域记录的 tail 续读）
//       --expect-packets <N> 断言消费到的报文数（不符则退出码 6）
//       --expect-flows <N>   断言解出的流条数（不符则退出码 6）
//   -q, --quiet              只输出机器可读汇总行
//
// 退出码: 0 成功 / 2 用法错误 / 3 attach 失败 / 4 消费出错 / 6 断言不符
//
// 机器可读输出（供 scripts/verify/e2e-shared-ring.sh 抓取，格式稳定不要改）。
// 每类记录有**唯一的二级标签**（summary / counts / region / flow / decode_fail）—— 这一点是必须的：
// 逐流行里也有 `packets=`，若汇总行只写 `ring-consume packets=`，抓取端「取最后一次匹配」
// 会拿到某条流的 packets 数（实测拿到了 1），而那个数字看起来完全合理，不会引起怀疑。
//   ring-consume path=<路径> slot_count=<n> slot_size=<n> producer_pid=<n>
//   ring-consume summary packets=<n> decoded=<n> decode_fail=<n> flows=<n> bytes=<n>
//   ring-consume counts truncated=<n> vlan_tagged=<n> ipv6=<n> overrun_skipped=<n>
//   ring-consume region head=<n> tail=<n> published=<n> consumed=<n> dropped=<n> full_events=<n>
//   ring-consume decode_fail code=<错误码> count=<n>        （每个错误码一行）
//   ring-consume flow src=<ip>:<port> dst=<ip>:<port> proto=<n> packets=<n> bytes=<n>
//
// `summary` 是本进程的记账，`region` 是消费完成后共享区域里的计数。两者分开报，
// 才能核出「消费端把 tail 推进了但区域计数没跟上」这类分歧 —— 那种情况下本进程
// 的输出完全正常，只有把两个来源放在一起比才看得出来。
//
// 刻意不在本程序里做「帧解码失败就跳过」之外的任何容错：解码失败按码计数上报，
// 让 e2e 脚本能对「失败了几条、为什么」给出可核对的事实，而不是一个笼统的成功。

use std::collections::BTreeMap;
use std::process::ExitCode;

use traffic_engine::channel::{decode_frame, Channel, Consumer, PacketMeta, RegionPerm};
use traffic_engine::flow::{Flow, FlowKey};

const DEFAULT_SLOT_COUNT: u32 = 1024;
const DEFAULT_SLOT_SIZE: u32 = 2048;

fn usage() {
    eprintln!(
        "用法:\n  \
     cythsec-ring-consume --ring <路径> [选项]\n\n\
     选项:\n  \
     \x20     --ring <路径>        共享区域文件路径\n  \
     \x20     --slot-count <N>     期望槽位数（默认 {DEFAULT_SLOT_COUNT}）\n  \
     \x20     --slot-size <N>      期望槽容量（默认 {DEFAULT_SLOT_SIZE}）\n  \
     \x20     --from-head          丢弃既有积压，从当前 head 开始\n  \
     \x20     --expect-packets <N> 断言消费到的报文数\n  \
     \x20     --expect-flows <N>   断言解出的流条数\n  \
     \x20 -q, --quiet              只输出机器可读汇总行"
    );
}

struct Options {
    ring: Option<String>,
    slot_count: u32,
    slot_size: u32,
    from_head: bool,
    expect_packets: Option<u64>,
    expect_flows: Option<usize>,
    quiet: bool,
}

/// 解析参数。返回 `Err(code)` 表示应以此退出码结束 ——
/// `--help` 单独用 `None` 表达，因为它不是错误。
fn parse_args() -> Result<Options, u8> {
    let mut o = Options {
        ring: None,
        slot_count: DEFAULT_SLOT_COUNT,
        slot_size: DEFAULT_SLOT_SIZE,
        from_head: false,
        expect_packets: None,
        expect_flows: None,
        quiet: false,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        // 取值型选项统一在此取下一个参数，避免每个分支各自越界判断。
        let mut take = |name: &str| -> Result<String, u8> {
            if i + 1 >= argv.len() {
                eprintln!("错误: {name} 需要一个取值");
                return Err(2);
            }
            i += 1;
            Ok(argv[i].clone())
        };
        match a {
            "--ring" => o.ring = Some(take(a)?),
            "--slot-count" => {
                let v = take(a)?;
                o.slot_count = match v.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("错误: --slot-count 取值非法: {v}");
                        return Err(2);
                    }
                };
            }
            "--slot-size" => {
                let v = take(a)?;
                o.slot_size = match v.parse::<u32>() {
                    Ok(n) => n,
                    Err(_) => {
                        eprintln!("错误: --slot-size 取值非法: {v}");
                        return Err(2);
                    }
                };
            }
            "--from-head" => o.from_head = true,
            "--expect-packets" => {
                let v = take(a)?;
                o.expect_packets = match v.parse::<u64>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        eprintln!("错误: --expect-packets 取值非法: {v}");
                        return Err(2);
                    }
                };
            }
            "--expect-flows" => {
                let v = take(a)?;
                o.expect_flows = match v.parse::<usize>() {
                    Ok(n) => Some(n),
                    Err(_) => {
                        eprintln!("错误: --expect-flows 取值非法: {v}");
                        return Err(2);
                    }
                };
            }
            "-q" | "--quiet" => o.quiet = true,
            "-h" | "--help" => {
                usage();
                return Err(0);
            }
            other => {
                eprintln!("错误: 未知参数 {other}");
                return Err(2);
            }
        }
        i += 1;
    }
    if o.ring.is_none() {
        eprintln!("错误: --ring 为必填");
        return Err(2);
    }
    Ok(o)
}

fn main() -> ExitCode {
    let opt = match parse_args() {
        Ok(o) => o,
        Err(0) => return ExitCode::SUCCESS, // --help 已打印用法
        Err(code) => return ExitCode::from(code),
    };
    let ring = opt.ring.as_deref().unwrap_or_default();

    // attach 走 expect 语义：部署配置写着「1024 × 2048」，而磁盘上可能是上一版配置留下的
    // 区域 —— 它自身完全自洽，只是槽位配置不是本端要的那个。此时两端布局不同，
    // 读到的每一条描述符都无意义，而区域自检不会有任何异常。
    let mut chan = match Channel::attach_expect(
        std::path::Path::new(ring),
        opt.slot_count,
        opt.slot_size,
        RegionPerm::ReadWrite,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("attach 共享环失败 [{}] {}", e.code(), e);
            return ExitCode::from(3);
        }
    };

    // 结构性自检：tail 越过 head 时消费端会永远报告「无数据」且不报错，
    // 而生产端在背后持续丢包 —— 必须显式拦下。
    if let Err(e) = chan.revalidate() {
        eprintln!("通道自检失败 [{}] {}", e.code(), e);
        return ExitCode::from(3);
    }

    let info = chan.stats();
    println!(
        "ring-consume path={} slot_count={} slot_size={} producer_pid={}",
        ring,
        chan.slot_count(),
        chan.slot_size(),
        info.producer_pid
    );

    if !opt.quiet {
        println!("共享环       : {ring}");
        println!(
            "槽位配置     : {} 槽 × {} 字节",
            chan.slot_count(),
            chan.slot_size()
        );
        println!("生产者 pid   : {}", info.producer_pid);
        println!("其中 head/tail: {} / {}", info.head, info.tail);
    }

    // 默认从区域记录的 tail 续读，即「把环里已有的报文读出来」——这是本工具名的直白含义。
    //
    // 刻意**不**默认从 head 开始：那样在一个已灌满数据的环上运行会「成功消费 0 条」并返回 0，
    // 失败现象与「环本来就是空的」完全一致。这类假绿灯正是本仓库反复吃亏的地方，
    // 因此跳过积压改成必须显式要求的 --from-head。
    let mut consumer = if opt.from_head {
        Consumer::from_head(&mut chan)
    } else {
        Consumer::resume(&mut chan)
    };

    // 流表以 FlowKey 为键。BTreeMap 而非 HashMap：输出需要确定性顺序（e2e 逐行 diff），
    // 哈希序遍历会让同一批数据每次输出不同，使 diff 失去意义。
    let mut flows: BTreeMap<FlowKey, Flow> = BTreeMap::new();
    let mut packets = 0u64;
    let mut decoded = 0u64;
    let mut bytes = 0u64;
    let mut truncated = 0u64;
    let mut vlan_tagged = 0u64;
    let mut ipv6 = 0u64;
    let mut decode_fail: BTreeMap<&'static str, u64> = BTreeMap::new();

    let drain_result = consumer.drain(|meta: PacketMeta, data: &[u8]| {
        packets += 1;
        bytes += u64::from(meta.wirelen);
        if meta.is_truncated() {
            truncated += 1;
        }
        if meta.is_vlan_tagged() {
            vlan_tagged += 1;
        }
        if meta.is_ipv6() {
            ipv6 += 1;
        }

        match decode_frame(data) {
            Ok(f) => {
                decoded += 1;
                // 负载长度用 ip_payload_len（从 IP 头长度字段算出），而不是 wirelen：
                // 后者含链路层与网络层头，且截断捕获下偏小。两者混用会让流的字节统计
                // 在两份输出间不可比。
                let pkt = traffic_engine::flow::Packet {
                    key: f.key,
                    payload_len: f.ip_payload_len,
                    timestamp_us: meta.timestamp_us(),
                };
                flows
                    .entry(f.key)
                    .or_insert_with(|| Flow::new(f.key))
                    .observe(&pkt);
            }
            Err(e) => {
                // 计数而非中断：非 IP 帧（ARP/STP/LLDP）在真实抓包里必然出现，
                // 它们不构成五元组，是预期现象而不是错误。按错误码分类上报，
                // 让脚本能对「失败了几条、为什么」给出可核对的事实。
                *decode_fail.entry(e.code()).or_insert(0) += 1;
            }
        }
    });

    if let Err(e) = drain_result {
        eprintln!("消费出错: {e}");
        return ExitCode::from(4);
    }

    let overrun = consumer.stats().overrun_skipped;
    let chan_stats = consumer.channel_stats();

    println!(
        "ring-consume summary packets={} decoded={} decode_fail={} flows={} bytes={}",
        packets,
        decoded,
        packets - decoded,
        flows.len(),
        bytes
    );
    println!(
        "ring-consume counts truncated={} vlan_tagged={} ipv6={} overrun_skipped={}",
        truncated, vlan_tagged, ipv6, overrun
    ); // 区域共享计数（消费完成后读取）。与上面的 summary 分开报，供抓取端核对
       // 两端对同一块内存的记账是否一致 —— 只比各自本地计数时，记账分歧本身看不见。
    println!(
        "ring-consume region head={} tail={} published={} consumed={} dropped={} full_events={}",
        chan_stats.head,
        chan_stats.tail,
        chan_stats.published,
        chan_stats.consumed,
        chan_stats.dropped,
        chan_stats.full_events
    );
    for (code, count) in &decode_fail {
        println!("ring-consume decode_fail code={code} count={count}");
    }

    // 逐流输出。IP:port 的写法对 IPv6 用方括号括起地址，使 `host:port` 的分隔无歧义。
    for flow in flows.values() {
        let (src_ip, dst_ip) = (flow.key.src_ip, flow.key.dst_ip);
        let (src, dst) = match (src_ip.is_ipv6(), dst_ip.is_ipv6()) {
            (false, false) => (format!("{src_ip}"), format!("{dst_ip}")),
            _ => (format!("[{src_ip}]"), format!("[{dst_ip}]")),
        };
        println!(
            "ring-consume flow src={src}:{} dst={dst}:{} proto={} packets={} bytes={}",
            flow.key.src_port,
            flow.key.dst_port,
            flow.key.proto,
            flow.packet_count,
            flow.total_bytes
        );
    }

    if !opt.quiet {
        println!("\n===== 消费摘要 =====");
        println!("消费报文      : {packets}");
        println!("解码成功      : {decoded}");
        println!("解码失败      : {}", packets - decoded);
        for (code, count) in &decode_fail {
            println!("    {code:<34} {count}");
        }
        println!("流条数        : {}", flows.len());
        println!("线上字节      : {bytes}");
        println!("截断捕获      : {truncated}");
        println!("VLAN 标记     : {vlan_tagged}");
        println!("IPv6 报文     : {ipv6}");
        println!("落后丢包      : {overrun}");
        println!("通道 head/tail: {} / {}", chan_stats.head, chan_stats.tail);
        println!("通道 consumed : {}", chan_stats.consumed);
    }

    // 断言放在最后：无论断言是否通过，完整事实都已打印，调用方无需为了拿到数字
    // 而先让断言通过 —— 否则「断言失败时看不到实际值」这种事会发生。
    let mut mismatch = false;
    if let Some(exp) = opt.expect_packets {
        if packets != exp {
            eprintln!("断言不符: 期望消费 {exp} 个报文，实际 {packets}");
            mismatch = true;
        }
    }
    if let Some(exp) = opt.expect_flows {
        if flows.len() != exp {
            eprintln!("断言不符: 期望 {} 条流，实际 {}", exp, flows.len());
            mismatch = true;
        }
    }
    if mismatch {
        return ExitCode::from(6);
    }
    ExitCode::SUCCESS
}
