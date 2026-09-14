// backends/link_type.h - 链路层类型的可读名（平台中立入口）。
//
// 为什么需要一个头文件而不是各自实现：macOS 的 BPF 用 **DLT_*** 编号，Linux 的
// AF_PACKET 用 **ARPHRD_*** 编号，两者是**不同的编号空间**，只是以太网恰好都为 1
// （DLT_EN10MB=1、ARPHRD_ETHER=1），回环则完全不同（DLT_NULL=0 / ARPHRD_LOOPBACK=772）。
// 若不抽这一层，上层工具就得写 `#if defined(__APPLE__)` 来决定该调哪个函数 ——
// 那正是本项目在「跨发行版通用」上要避免的那类平台分支扩散。
//
// 实现按平台各写一份（bpf_capture.cpp / af_packet.cpp），同平台只会有一个被编译，
// 因此**调用方无需任何条件编译**：`link_type_name(be->link_type())` 在两端都成立。
#pragma once

#include <cstdint>
#include <string>

namespace packet_engine {

// 把本平台后端的链路层类型编号转成可读名。未知编号返回形如 "未知链路类型(0x1234)"
// 的字符串（含原始值）—— 排障时「看到没见过的编号」比「看到一句笼统的未知」有用得多。
std::string link_type_name(uint32_t value);

} // namespace packet_engine
