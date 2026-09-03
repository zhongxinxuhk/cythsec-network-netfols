// main.cpp - packet-engine CLI 入口：打印 hello packet
// 用途：验证「编译 -> Linux ELF -> openEuler 运行」链路的最小可执行程序。
#include "packet_engine/packet.h"

#include <cstdio>

int main(int argc, char** argv) {
  // 允许自定义文案：hello_packet [message]
  const char* msg = (argc > 1) ? argv[1] : nullptr;
  const int rc = packet_engine::hello_packet(msg);

  std::printf("[packet-engine] ELF smoke test OK (rc=%d)\n", rc);
  return rc;
}
