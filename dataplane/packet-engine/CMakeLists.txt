cmake_minimum_required(VERSION 3.20)
project(packet-engine C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# 高速数据包处理引擎：XDP/eBPF、AF_XDP、DPDK、Buffer、Dispatcher、RSS。
# 各后端（xdp/ af_xdp/ dpdk/）以可选组件形式接入，避免强制依赖。
option(ENABLE_XDP "Enable XDP/eBPF backend" ON)
option(ENABLE_AF_XDP "Enable AF_XDP backend" ON)
option(ENABLE_DPDK "Enable DPDK backend" OFF)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(packet-engine STATIC ${SRC})
target_include_directories(packet-engine PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

# 子目录与后端后端在后续迭代中按需 add_subdirectory。
