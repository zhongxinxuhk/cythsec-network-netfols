cmake_minimum_required(VERSION 3.20)

# ============================================================================
# packet-engine —— 高速数据包处理引擎（最小工程）
#
# 目标：先用最小 C++ 工程验证整条工具链：
#     CLion -> CMake -> 编译 -> Linux ELF -> openEuler -> 运行
# 本阶段不引入 XDP / AF_XDP / DPDK 等后端，仅建立：
#     静态库(packet_engine) + CLI(hello_packet) + CTest 单元测试
# 后续再按组件方式接入 xdp/ af_xdp/ dpdk/ buffer/ dispatcher/ rss/ ebpf。
#
# 既可独立构建（在 dataplane/packet-engine 下直接 cmake），
# 也可被上层根 CMakeLists 以 add_subdirectory 引入。
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

# ---- 可选后端开关（本阶段默认关闭，后续迭代按需开启）---------------------
option(ENABLE_XDP "Enable XDP/eBPF backend" OFF)
option(ENABLE_AF_XDP "Enable AF_XDP backend" OFF)
option(ENABLE_DPDK "Enable DPDK backend" OFF)
# 仅当被作为独立工程（未处于上层 add_subdirectory 语境）时，允许跑 CTest
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  option(PACKET_ENGINE_BUILD_TESTS "Build packet-engine unit tests" ON)
else()
  option(PACKET_ENGINE_BUILD_TESTS "Build packet-engine unit tests" OFF)
endif()

# ---- 版本号头文件生成 -----------------------------------------------------
set(PACKET_ENGINE_VERSION "${PROJECT_VERSION}")
configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/include/packet_engine/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/include/packet_engine/version.h"
  @ONLY
)

# ---- 静态库 ---------------------------------------------------------------
add_library(packet_engine STATIC
  src/packet.cpp
)
target_include_directories(packet_engine PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
target_include_directories(packet_engine PRIVATE
  "${CMAKE_CURRENT_BINARY_DIR}/include"
)
# 可选后端库，预留链接点（当前为空实现）
if(ENABLE_XDP)
  add_subdirectory(xdp)
endif()
if(ENABLE_AF_XDP)
  add_subdirectory(af_xdp)
endif()
if(ENABLE_DPDK)
  add_subdirectory(dpdk)
endif()

# ---- CLI 可执行 ------------------------------------------------------------
add_executable(hello_packet cli/main.cpp)
target_link_libraries(hello_packet PRIVATE packet_engine)

# ---- 单元测试（CTest）-----------------------------------------------------
if(PACKET_ENGINE_BUILD_TESTS)
  enable_testing()
  add_executable(test_packet tests/test_packet.cpp)
  target_link_libraries(test_packet PRIVATE packet_engine)
  add_test(NAME packet_engine_unit COMMAND test_packet)
endif()
