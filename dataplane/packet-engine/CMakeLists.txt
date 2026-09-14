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
#                                + 共享通道（区域映射/校验 + SPSC 生产端）
#     通道 ABI 契约（include/packet_engine/channel/abi_gen.h，由真源生成）
#     CLI(hello_packet 冒烟 / cythsec-parse 解析演示 / cythsec-dump-abi 契约输出
#         / cythsec-ring-feed pcap -> 共享环)
#     CTest 单元测试（unit / parser / pcap / channel_abi / channel_producer，零第三方依赖）
#
# 后端（XDP / AF_XDP / DPDK / pcap）以 option 开关预留；目录尚未实现时给出
# INTERFACE 占位目标，保证上层链接点稳定（见下方 backend 段）。
# ============================================================================
# ---- 版本号：以仓库根 VERSION 为唯一真源 --------------------------------
# 两种用法都要落到同一个值：
#   - 由根 CMakeLists 以 add_subdirectory 引入 -> 根已 READ VERSION 并定义 CYTHSEC_VERSION
#   - 在本目录下独立 configure            -> 此处自行读取
# 此处**刻意不写版本字面量**：写过一次就多出一份需手工同步的副本。
if(NOT DEFINED CYTHSEC_VERSION)
  set(_cythsec_version_file "${CMAKE_CURRENT_SOURCE_DIR}/../../VERSION")
  if(NOT EXISTS "${_cythsec_version_file}")
    message(FATAL_ERROR "未找到版本真源文件: ${_cythsec_version_file}")
  endif()
  file(READ "${_cythsec_version_file}" _cythsec_version_raw)
  string(STRIP "${_cythsec_version_raw}" CYTHSEC_VERSION)
endif()

project(packet-engine VERSION ${CYTHSEC_VERSION} LANGUAGES C CXX)

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
# 源文件分组：基础(packet/backend) + 解析器(parser/*) + 共享通道(channel/*)
#             + 采集后端(backends/*，含平台专属实现)。
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
  src/backends/iface_list.cpp
  src/pcap_writer.cpp
  src/channel/region.cpp
  src/channel/producer.cpp
)

# ---- 平台专属的实时抓包后端 -----------------------------------------------
# 与 src/backend.cpp 里的 CYTHSEC_HAVE_* 判定必须**保持一致**：工厂只会在对应
# 宏为真时引用这些类，若此处漏加源文件就会出现「工厂引用了未定义符号」的链接
# 错误，而错误信息指向 backend.cpp，与真正的缺口不在同一处。
#
# 为什么不做成「跨平台的单一实现」：Linux 的 AF_PACKET 与 BSD 的 /dev/bpf 在
# 缓冲区模型、权限模型、返回值语义上都不同（前者是 socket + 可 mmap 环，后者是
# 字符设备 + read 聚合多包）。强行合并只会得到一个到处是平台分支的实现，
# 而把差异关在各自文件里、由统一接口收口，才是可维护的形态。
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_sources(packet_engine PRIVATE src/backends/af_packet.cpp)
  message(STATUS "packet-engine: 已启用 Linux AF_PACKET 实时采集后端")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin" OR CMAKE_SYSTEM_NAME MATCHES "BSD")
  target_sources(packet_engine PRIVATE src/backends/bpf_capture.cpp)
  message(STATUS "packet-engine: 已启用 ${CMAKE_SYSTEM_NAME} BPF 实时采集后端")
else()
  message(WARNING
    "packet-engine: 平台 ${CMAKE_SYSTEM_NAME} 无实时采集后端实现；"
    "live 后端会以明确诊断失败（而非静默退化为空实现）。")
endif()

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

# ---- 通道 ABI 的 parity 输出入口（CYS-PKT-024 第 3 层）--------------------
# 与 Rust 侧 `dump-abi` 的输出逐行 diff（scripts/verify/check-channel-parity.sh）。
# 它同时是 channel/abi_gen.h 的编译触发器：该头是 header-only，其中的 static_assert
# 只在有人 include 时才会被求值。去掉这个目标（以及 tests/test_channel_abi.cpp），
# 那些断言就会退回成注释。
add_executable(cythsec-dump-abi cli/dump_abi_main.cpp)
target_link_libraries(cythsec-dump-abi PRIVATE packet_engine)

# ---- 共享环生产侧驱动：真实 pcap -> 共享环（CYS-PKT-024 / CYS-TRF-034）----
# C++ 写、Rust 读的跨语言端到端链路的生产侧入口，由 scripts/verify/e2e-shared-ring.sh
# 与 Rust 侧 consumer 配对驱动。
add_executable(cythsec-ring-feed cli/ring_feed_main.cpp)
target_link_libraries(cythsec-ring-feed PRIVATE packet_engine)

# ---- 跨平台实时抓包 CLI：macOS(en0/BPF) 与 Linux(eth0|ens33|ens192/AF_PACKET) 同一份命令 ----
# 本工具不含任何平台条件编译 —— 后端由 `-b live` 按平台自动路由（见 cli/capture_main.cpp）。
add_executable(cythsec-capture cli/capture_main.cpp)
target_link_libraries(cythsec-capture PRIVATE packet_engine)

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

  # 跨语言通道契约的单测（CYS-PKT-024）：本目标也是 abi_gen.h 的实际消费者，
  # 见文件头注释 —— 没有消费者时那些 static_assert 不会被编译。
  add_executable(test_channel_abi tests/test_channel_abi.cpp)
  target_link_libraries(test_channel_abi PRIVATE packet_engine)
  add_test(NAME packet_engine_channel_abi COMMAND test_channel_abi)

  # 共享环生产端的行为契约（CYS-PKT-024 的 C++ 生产端，CYS-TRF-034 的上游）。
  # 与 Rust 侧 channel/tests.rs 断言同一组语义，两端各验一侧。
  add_executable(test_channel_producer tests/test_channel_producer.cpp)
  target_link_libraries(test_channel_producer PRIVATE packet_engine)
  add_test(NAME packet_engine_channel_producer COMMAND test_channel_producer)

  # 实时采集后端（CYS-PKT-007/008）：接口枚举 + 无特权下的错误诊断正确性。
  # 这些断言在无 root 环境下同样有意义 —— 它们验的是「失败时的行为是否正确」，
  # 而不仅是「成功时是否能跑通」。
  add_executable(test_live_capture tests/test_live_capture.cpp)
  target_link_libraries(test_live_capture PRIVATE packet_engine)
  add_test(NAME packet_engine_live_capture COMMAND test_live_capture)
endif()
