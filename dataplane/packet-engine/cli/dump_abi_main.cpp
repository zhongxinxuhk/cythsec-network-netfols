// dump_abi_main.cpp —— 通道 ABI 的跨语言 parity 输出入口（CYS-PKT-024 第 3 层）。
//
// 本文件存在的第一个理由不是打印，而是**让 abi_gen.h 被真正编译**。
//
// abi_gen.h 是 header-only：里面的 35 条 static_assert 只在有人 include 它时才被求值。
// 在此之前没有任何翻译单元引用它，于是「改错字段顺序会在编译期失败」这句话描述的
// 是一个从未运行过的检查 —— 形态完整、读起来像防线，实际是注释。Rust 侧不存在这个
// 陷阱（`pub mod abi_gen;` 即触发编译），C++ 侧必须显式存在消费者。
//
// 第二个理由才是 parity：打印本端**编译产物**的取值（常量 / offsetof / sizeof /
// 生成的布局函数 / 诊断样本），由 scripts/verify/check-channel-parity.sh 与 Rust 侧
// dump-abi 的输出逐行 diff。静态断言只看自己那一侧，跨语言一致性只能这样验。
#include <cstdio>
#include <string>
#include <vector>

#include "packet_engine/channel/abi_gen.h"

int main() {
  for (const std::string& line : packet_engine::channel::abi::dump::AbiDump()) {
    std::printf("%s\n", line.c_str());
  }
  return 0;
}
