// dump_abi.rs —— 通道 ABI 的跨语言 parity 输出入口（CYS-PKT-024 第 3 层）。
//
// 打印 abi_gen::abi_dump() 的逐行 `key=value`，由
// scripts/verify/check-channel-parity.sh 与 C++ 侧 cythsec-dump-abi 的输出逐行 diff。
//
// 内容全部取自本端**编译产物**（常量 / offset_of / size_of / 生成的布局函数 / 诊断样本），
// 而不是照抄真源 —— 照抄只能证明「生成器把真源抄了两遍」，diff 永远相等，等于没验证。
//
// 用法：
//   cargo run --offline --quiet --bin dump-abi
fn main() {
    for line in traffic_engine::channel::abi_gen::abi_dump() {
        println!("{}", line);
    }
}
