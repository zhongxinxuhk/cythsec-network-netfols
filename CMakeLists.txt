cmake_minimum_required(VERSION 3.20)
project(cythsec C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

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
