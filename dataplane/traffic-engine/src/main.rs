// main.rs - traffic-engine 演示入口
// 走一遍最小数据链：Packet -> Flow -> Session，输出会话聚合统计，
// 用于验证 cargo build + cargo test 在目标平台(Linux ELF / openEuler)正常。
use traffic_engine::crate_version;
use traffic_engine::flow::{FlowKey, Packet};
use traffic_engine::session::{Session, SessionState};

fn main() {
    println!("traffic-engine v{}", crate_version());
    println!("demo: Packet -> Flow -> Session\n");

    // 构造一条 TCP 会话：10.0.0.1:40000 -> example 服务器 93.184.216.34:443
    let forward_key = FlowKey::new_ipv4([10, 0, 0, 1], 40000, [93, 184, 216, 34], 443, 6);
    let mut sess = Session::new(1, forward_key);

    // 模拟几次 TCP 握手与数据传输
    let syn = Packet::new(forward_key, 0); // SYN（无负载）
    sess.ingest(&syn);

    let syn_ack = Packet::new(sess.backward.key, 0); // SYN-ACK
    sess.ingest(&syn_ack);

    let ack = Packet::new(forward_key, 0); // ACK
    sess.ingest(&ack);

    // 真实数据
    for (key, len) in [
        (forward_key, 1200),
        (forward_key, 800),
        (sess.backward.key, 4096),
        (forward_key, 200),
    ] {
        sess.ingest(&Packet::new(key, len));
    }

    // 输出会话聚合
    println!("session id       : {}", sess.id);
    println!("state            : {:?}", sess.state);
    println!("forward flow     : {:?}", sess.forward.key);
    println!("  packets        : {}", sess.forward.packet_count);
    println!("  bytes          : {}", sess.forward.total_bytes);
    println!("backward flow    : {:?}", sess.backward.key);
    println!("  packets        : {}", sess.backward.packet_count);
    println!("  bytes          : {}", sess.backward.total_bytes);
    println!("total packets    : {}", sess.total_packets());
    println!("total bytes      : {}", sess.total_bytes());

    // 单向 SYN 会话不应 Established
    let mut half = Session::new(2, forward_key);
    half.ingest(&syn);
    let only_syn = half.state == SessionState::SynSent;

    // 冒烟断言：双向有数据应 Established，纯 SYN 应停留在 SynSent
    assert_eq!(sess.state, SessionState::Established, "双向会话应已建立");
    assert!(only_syn, "纯 SYN 会话不应进入 Established");
    assert_eq!(
        sess.total_packets(),
        7,
        "共 7 个包：SYN, SYN-ACK, ACK + 4 个数据包"
    );

    println!("\n[traffic-engine] demo OK (rc=0)");
}
