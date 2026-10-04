// main.rs - traffic-engine 演示入口
//
// 走一遍当前的数据链：Packet -> FlowTable（方向级）-> SessionManager（双向会话 + TCP 状态机），
// 用于验证 cargo build + cargo test 在目标平台（Linux ELF / openEuler）正常，
// 同时也是一份**可读的用法示例**：真实调用方（`cythsec-analyze`）走的是同一条路径。
use traffic_engine::flow::{FlowKey, Packet, IPPROTO_TCP};
use traffic_engine::reassembly::tcp::TcpFlags;
use traffic_engine::session::{SessionConfig, SessionManager};
use traffic_engine::tcp::{Side, TcpState};
use traffic_engine::{build_info, crate_version};

fn flags(syn: bool, ack: bool, fin: bool, rst: bool) -> TcpFlags {
    TcpFlags {
        syn,
        ack,
        fin,
        rst,
        ..TcpFlags::default()
    }
}

fn main() {
    // --version / -V：只打印版本三元组，便于脚本与门禁抓取（与 Go 侧
    // `-version` 的用途对齐）。在此之前先判断参数，避免演示逻辑先跑一遍。
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        let info = build_info();
        println!("traffic-engine version={}", info.version);
        println!("traffic-engine commit={}", info.commit);
        println!("traffic-engine build_time={}", info.build_time);
        return;
    }

    let info = build_info();
    println!(
        "traffic-engine v{} (commit {}, built {})",
        crate_version(),
        info.commit,
        info.build_time
    );
    println!("demo: Packet -> FlowTable -> SessionManager\n");

    // 一条 TCP 会话：10.0.0.1:40000 -> example 服务器 93.184.216.34:443
    let forward_key = FlowKey::new_ipv4([10, 0, 0, 1], 40000, [93, 184, 216, 34], 443, IPPROTO_TCP);
    let backward_key = forward_key.reverse();

    let mut mgr = SessionManager::new(SessionConfig::default());

    // 完整握手 + 一次双向传输 + 主动关闭。
    let script: [(FlowKey, TcpFlags, u32, u64); 8] = [
        (forward_key, flags(true, false, false, false), 0, 1_000),
        (backward_key, flags(true, true, false, false), 0, 2_000),
        (forward_key, flags(false, true, false, false), 0, 3_000),
        (forward_key, flags(false, true, false, false), 1200, 4_000),
        (backward_key, flags(false, true, false, false), 4096, 5_000),
        (forward_key, flags(false, true, true, false), 0, 6_000),
        (backward_key, flags(false, true, true, false), 0, 7_000),
        (forward_key, flags(false, true, false, false), 0, 8_000),
    ];
    for (key, f, len, ts) in script {
        mgr.observe(
            &Packet {
                key,
                payload_len: len,
                timestamp_us: ts,
            },
            Some(&f),
        );
    }

    let (id, state, initiator, adopted, packets, bytes, switches, class) = {
        let session = mgr.session(&forward_key).expect("会话应存在");
        println!("session id       : {}", session.id);
        println!("canonical key    : {:?}", session.key);
        println!("tcp state        : {}", session.tcp_state().as_str());
        println!("initiator        : {:?}", session.initiator());
        println!("adopted midstream: {}", session.adopted_midstream());
        println!("packets          : {}", session.packets);
        println!("bytes            : {}", session.bytes);
        println!("direction switch : {}", session.direction_switches);
        println!("timeout class    : {}", session.timeout_class().as_str());
        (
            session.id,
            session.tcp_state(),
            session.initiator(),
            session.adopted_midstream(),
            session.packets,
            session.bytes,
            session.direction_switches,
            session.timeout_class(),
        )
    };

    println!("\n方向级流表（上下行分开记账）：");
    for entry in mgr.flows().entries_sorted() {
        let dir = if entry.key == forward_key { "->" } else { "<-" };
        println!(
            "  {} {:>5} pkts {:>6} bytes  class={}",
            dir,
            entry.flow.packet_count,
            entry.flow.total_bytes,
            entry.class.as_str()
        );
    }

    // 冒烟断言：
    //   * 完整握手 + 双向数据 + 双向 FIN 之后应停在 TIME_WAIT（RFC 9293：
    //     TIME_WAIT 由 2MSL 计时结束，**不是**由最后那个 ACK 结束 —— 把它判成
    //     Closed 会让"仍在 TIME_WAIT 的端口不可复用"这一事实消失）；
    //   * 发起方必须是 A 侧；上下行字节必须分开记账。
    assert_eq!(id, 1);
    assert_eq!(
        state,
        TcpState::TimeWait,
        "双方 FIN 之后应停 TIME_WAIT，由超时终结"
    );
    assert_eq!(initiator, Some(Side::A));
    assert!(!adopted, "握手完整，不应标为中途接入");
    assert_eq!(packets, 8, "共 8 个包");
    assert_eq!(bytes, 1200 + 4096);
    assert_eq!(switches, 6, "A→B→A→A→B→A→B→A 共 6 次方向切换");
    assert_eq!(class.as_str(), "tcp_transient", "TIME_WAIT 走短超时档");
    assert_eq!(mgr.flow_count(), 2, "上下行是两条流");
    assert_eq!(mgr.session_count(), 1, "双向包属于同一条会话");

    // 超时是 TIME_WAIT 的终结方式（本配置下 transient 档 30 秒）。
    let (expired_sessions, expired_flows) = mgr.expire(1_000 + 60_000_000);
    assert_eq!(expired_sessions, 1, "TIME_WAIT 会话应在超时后回收");
    assert_eq!(expired_flows, 2, "两个方向的流一并回收");
    assert_eq!(mgr.session_count(), 0);
    assert_eq!(mgr.flow_count(), 0);
    assert_eq!(mgr.live_ids(), 0, "回收后会话 id 必须归还");

    println!("\n[traffic-engine] demo OK (rc=0)");
}
