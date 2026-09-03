// test_packet.cpp - packet-engine 最小单元测试（CTest）
// 不依赖第三方测试框架（gtest 等），保持最小工程零外部依赖、可离线构建。
#include "packet_engine/packet.h"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

int failures = 0;

void check(bool cond, const char* what) {
  if (cond) {
    std::printf("[PASS] %s\n", what);
  } else {
    std::printf("[FAIL] %s\n", what);
    ++failures;
  }
}

}  // namespace

int main() {
  // 1) hello_message 返回预期文案
  check(packet_engine::hello_message() == "hello packet", "hello_message() == \"hello packet\"");

  // 2) version() 非空且为三段式数字（x.y.z）
  const std::string ver = packet_engine::version();
  bool ver_ok = !ver.empty();
  if (ver_ok) {
    // 简单校验：以数字开头且含两个点
    ver_ok = (ver[0] >= '0' && ver[0] <= '9');
    int dots = 0;
    for (char c : ver) dots += (c == '.');
    ver_ok = ver_ok && (dots == 2);
  }
  check(ver_ok, ("version() = \"" + ver + "\" 符合 x.y.z").c_str());

  // 3) Packet 基本字段默认值与赋值
  packet_engine::Packet p;
  check(p.length == 0, "Packet().length == 0");
  p.length = 6;
  check(p.length == 6, "Packet().length = 6 赋值生效");

  // 4) hello_packet 返回 0（成功冒烟）
  check(packet_engine::hello_packet("unit test") == 0, "hello_packet() returns 0");

  std::printf("\n--- %s: %d failure(s) ---\n", failures == 0 ? "ALL PASS" : "FAILED",
              failures);
  return failures == 0 ? 0 : 1;
}
