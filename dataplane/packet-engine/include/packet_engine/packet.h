// packet.h - 最小 Packet 类型与 hello 演示接口
// packet-engine 最小工程的目标是验证「CMake -> 编译 -> Linux ELF -> 运行」链路，
// 因此本头只暴露极简类型与函数，不涉及 XDP/AF_XDP/DPDK 等后端（后续迭代引入）。
#pragma once

#include <cstdint>
#include <string>

namespace packet_engine {

// 最小数据包表示：仅记录字节数与一段携带的负载（用于后续特征/分析模块的输入雏形）。
struct Packet {
  uint32_t length = 0;   // 包长度（字节）
  uint8_t data[16] = {}; // 最小负载缓冲，真实高速收包阶段将由零拷贝缓冲取代
};

// hello packet：打印欢迎语并回显包的元信息，用于冒烟验证整条工具链。
// 返回 0 表示成功（可被 CLI 与单元测试共同校验）。
int hello_packet(const char* message = "hello packet");

// 返回 hello 文案（便于单元测试断言，不依赖终端输出）。
std::string hello_message();

// 工程版本号（自 version.h 读取）。
std::string version();

}  // namespace packet_engine
