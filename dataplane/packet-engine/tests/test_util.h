// test_util.h - 零依赖单元测试工具（check + 统计）。
// 供 test_packet / test_parser 共用，避免重复实现（CYS-PKT-025）。
// 不依赖 gtest/Catch2，保持可离线构建。
#pragma once

#include <cstdio>
#include <cstring>

namespace packet_engine {
namespace test {

// 失败计数为函数内静态变量，跨同一翻译单元内的所有 check() 共享。
inline int& failures() {
  static int f = 0;
  return f;
}

inline void check(bool cond, const char* what) {
  if (cond) {
    std::printf("[PASS] %s\n", what);
  } else {
    std::printf("[FAIL] %s\n", what);
    ++failures();
  }
}

// 打印汇总并以退出码返回（0=全过，1=有失败）。
inline int summary(const char* name) {
  std::printf("\n--- %s: %s (%d failure(s)) ---\n", name, failures() == 0 ? "ALL PASS" : "FAILED",
              failures());
  return failures() == 0 ? 0 : 1;
}

} // namespace test
} // namespace packet_engine
