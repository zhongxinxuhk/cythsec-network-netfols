cmake_minimum_required(VERSION 3.20)

# ============================================================================
# packet-engine —— 高速数据包处理引擎
#
# 目标：构建「零拷贝协议解析 + 后端抽象」的数据平面基座，可：
#     - 独立构建（在 dataplane/packet-engine 下直接 cmake）
#     - 被上层根 CMakeLists 以 add_subdirectory 引入
#
# 当前已实现：
#     静态库(packet_engine) —— 解析器(L2/L3/L4) + 后端抽象接口 + 零拷贝缓冲视图
#     CLI(hello_packet 冒烟 / cythsec-parse 解析演示)
#     CTest 单元测试（packet_engine_unit / packet_engine_parser，零第三方依赖）
#
# 后端（XDP / AF_XDP / DPDK / pcap）以 option 开关预留；目录尚未实现时给出
# INTERFACE 占位目标，保证上层链接点稳定（见下方 backend 段）。
# ============================================================================
project(packet-engine VERSION 0.1.0 LANGUAGES C CXX)

# ---- 语言标准 -------------------------------------------------------------
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- 构建类型默认 Debug（便于 CLion / 调试）-------------------------------
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# ---- 可选后端开关（默认关闭，后续迭代按需开启）---------------------------
option(ENABLE_XDP "Enable XDP/eBPF backend" OFF)
option(ENABLE_AF_XDP "Enable AF_XDP backend" OFF)
option(ENABLE_DPDK "Enable DPDK backend" OFF)

# 测试开关统一遵循 CMake 标准 BUILD_TESTING 约定：
#   - 从根仓库 configure（根 include(CTest) 定义 BUILD_TESTING，默认 ON）-> 测试开
#   - 作为独立工程 configure -> 本目录自行 include(CTest) 定义 BUILD_TESTING
include(CTest)

# ---- 版本号头文件生成 -----------------------------------------------------
set(PACKET_ENGINE_VERSION "${PROJECT_VERSION}")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/packet_engine/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/packet_engine/version.h"
  @ONLY
)

# ---- 静态库 ---------------------------------------------------------------
# 源文件分组：基础(packet/backend) + 解析器(parser/*)。
add_library(packet_engine STATIC
  src/packet.cpp
  src/backend.cpp
  src/parser/ethernet.cpp
  src/parser/ipv4.cpp
  src/parser/ipv6.cpp
  src/parser/tcp.cpp
  src/parser/udp.cpp
  src/parser/icmp.cpp
  src/parser/parser.cpp
  src/backends/pcap_file.cpp
)
target_include_directories(packet_engine PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(packet_engine PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}/include"
)

# ---- 可选后端：仅在目录真实存在且有 CMakeLists 时才接入 -------------------
# 否则给出 INTERFACE 占位目标（packet_engine_<backend>），使上层链接点保持稳定，
# 并以 WARNING 明确告知「后端未实现」。无论 ON/OFF 均保证 configure 成功
# （CYS-PKT-015）。
function(packet_engine_backend_stub name)
  add_library(${name} INTERFACE)
  target_link_libraries(${name} INTERFACE packet_engine)
endfunction()

foreach(BACKEND XDP AF_XDP DPDK)
  string(TOLOWER ${BACKEND} backend_lc)
  if(ENABLE_${BACKEND})
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${backend_lc}/CMakeLists.txt")
      add_subdirectory(${backend_lc})
    else()
      message(WARNING
        "packet-engine: 后端 ${BACKEND} 已请求(ENABLE_${BACKEND}=ON)但尚未实现；"
        "提供 INTERFACE 占位目标 packet_engine_${backend_lc}。")
      packet_engine_backend_stub(packet_engine_${backend_lc})
    endif()
  endif()
endforeach()

# ---- CLI 可执行 ------------------------------------------------------------
# 保留 hello_packet 作为最小冒烟测试，新增 cythsec-parse 用于手动验证解析器。
add_executable(hello_packet cli/main.cpp)
target_link_libraries(hello_packet PRIVATE packet_engine)

add_executable(cythsec-parse cli/parse_main.cpp)
target_link_libraries(cythsec-parse PRIVATE packet_engine)

# ---- 单元测试（CTest，零第三方依赖）---------------------------------------
if(BUILD_TESTING)
  add_executable(test_packet tests/test_packet.cpp)
  target_link_libraries(test_packet PRIVATE packet_engine)
  add_test(NAME packet_engine_unit COMMAND test_packet)

  add_executable(test_parser tests/test_parser.cpp)
  target_link_libraries(test_parser PRIVATE packet_engine)
  add_test(NAME packet_engine_parser COMMAND test_parser)

  add_executable(test_pcap tests/test_pcap.cpp)
  target_link_libraries(test_pcap PRIVATE packet_engine)
  add_test(NAME packet_engine_pcap COMMAND test_pcap)
endif()
