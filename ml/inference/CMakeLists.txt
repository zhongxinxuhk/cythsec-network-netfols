cmake_minimum_required(VERSION 3.20)
project(inference C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# 生产推理引擎：ONNX Runtime 接入与低延迟推理运行时。
option(ENABLE_ONNXRUNTIME "Enable ONNX Runtime backend" ON)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

add_library(inference STATIC ${SRC})
target_include_directories(inference PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
