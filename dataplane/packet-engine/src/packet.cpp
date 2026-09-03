// packet.cpp - packet-engine 最小库实现
#include "packet_engine/packet.h"
#include "packet_engine/version.h"

#include <cstdio>

namespace packet_engine {

std::string hello_message() {
  return "hello packet";
}

int hello_packet(const char* message) {
  // 构造一个占位包用于演示元信息打印（长度 6：即 "packet"）。
  Packet p;
  p.length = 6;

  std::printf("[packet-engine] %s\n", (message && *message) ? message : "hello packet");
  std::printf("[packet-engine]   version : %s\n", version().c_str());
  std::printf("[packet-engine]   packet  : length=%u bytes\n", p.length);
  return 0;
}

std::string version() {
  return PACKET_ENGINE_VERSION_STR;
}

}  // namespace packet_engine
