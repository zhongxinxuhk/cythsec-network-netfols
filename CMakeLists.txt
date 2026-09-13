cmake_minimum_required(VERSION 3.20)

# 版本号单一来源：从仓库根 VERSION 文件读取，作为 C++ 侧（仓库级）唯一真源。
# 子工程（packet-engine 等，位于 dataplane/，由对应负责人维护）若需注入版本，
# 应改用本变量 ${CYTHSEC_VERSION} 而非硬编码，以确保与根 VERSION 一致。
file(READ "${CMAKE_SOURCE_DIR}/VERSION" CYTHSEC_VERSION_RAW)
string(STRIP "${CYTHSEC_VERSION_RAW}" CYTHSEC_VERSION)
project(cythsec VERSION ${CYTHSEC_VERSION} LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 仓库级统一 CTest：include(CTest) 会定义标准 BUILD_TESTING 选项(默认 ON)，
# 并 enable_testing()。子工程(packet-engine 等)据此决定是否构建/注册单测。
include(CTest)

# 数据平面 C/C++ 子工程（packet-engine, inference）各自持有独立 CMakeLists.txt。
# 此处作为仓库级入口，可统一配置工具链与编译选项。
option(CYTHSEC_BUILD_PACKET_ENGINE "Build packet-engine" ON)
option(CYTHSEC_BUILD_INFERENCE "Build inference" ON)

if(CYTHSEC_BUILD_PACKET_ENGINE)
  add_subdirectory(dataplane/packet-engine)
endif()

if(CYTHSEC_BUILD_INFERENCE)
  add_subdirectory(ml/inference)
endif()
