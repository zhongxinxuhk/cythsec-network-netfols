cmake_minimum_required(VERSION 3.20)
project(inference C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

# 生产推理引擎：ONNX Runtime 接入与低延迟推理运行时。
option(ENABLE_ONNXRUNTIME "Enable ONNX Runtime backend" OFF)

# 占位骨架：src/ 尚无 .c/.cpp 源文件时，避免 add_library 因「无源文件」导致
# 整棵 CMake 树 Generate 失败。待推理运行时落地后，源文件一出现即自动成库。
file(GLOB_RECURSE SRC CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp"
)

if(SRC)
  add_library(inference STATIC ${SRC})
  target_include_directories(inference PUBLIC
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )
  # ONNX Runtime 依赖与链接点，待 onnx/ runtime/ 落地后接入
  message(STATUS "inference: building with ${SRC}")
else()
  # 无源码：定义一个空 interface 库占位，保证上层 add_subdirectory 不中断，
  # 也便于后续直接把源文件加进 src/ 无需改动此处。
  add_library(inference INTERFACE)
  target_include_directories(inference INTERFACE
      "${CMAKE_CURRENT_SOURCE_DIR}/include"
  )
  message(STATUS "inference: no sources yet, creating placeholder INTERFACE target")
endif()
