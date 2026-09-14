// packet_buffer.h - 零拷贝报文缓冲视图。
//
// 解析器与后端共享这一「视图」概念：所有字段指向底层内存，不持有数据副本。
// 后端（XDP/AF_XDP/DPDK/pcap，后续实现）负责分配与管理真实内存（环形缓冲、UMEM 等），
// 本结构仅记录视图元信息，使上层可零拷贝地读取报文各层。
#pragma once

#include <cstdint>
#include <cstddef>

namespace packet_engine {

// 报文缓冲视图（零拷贝）。
struct PacketBuffer {
  uint8_t* data = nullptr;  // 报文数据起点（含链路层头部）
  uint32_t caplen = 0;      // 实际捕获长度（可能因 snaplen/截断而小于 wirelen）
  uint32_t wirelen = 0;     // 线上原始长度（未截断时等于 caplen）
  uint32_t headroom = 0;    // data 之前的预留空间（封装/隧道/添加头用，当前占位）
  uint32_t ifindex = 0;     // 接收/发送接口索引（Linux if_index）
  int64_t timestamp_ns = 0; // 时间戳，单位：纳秒（由后端约定 epoch 或相对值）
  uint32_t refcount = 0;    // 引用计数（零拷贝共享时 +1，释放时 -1）

  // VLAN 标签。网卡做硬件 VLAN 剥离时，标签会从帧里被摘掉、改由元数据携带
  // （Linux 经 tp_status 的 TP_STATUS_VLAN_VALID + tp_vlan_tci）。此时**帧内已无
  // 4 字节标签**，而以太网类型字段的位置整体前移 4 字节 —— 若按「帧内必有标签」
  // 去解析，解出的五元组是错的，且不会报错。
  //
  // 故标签必须在元数据里携带，而不是让上层在帧内搜索 0x8100：后者在
  // 「帧内恰好出现 8100 这个值」时会误判（如某些 IP 载荷），也无法处理
  // QinQ 双标签的第一层。解析边界仍以 caplen 为准。
  uint16_t vlan_tci = 0;    // 标签控制信息（PCP+DEI+VID，主机字节序）
  bool vlan_tagged = false; // 是否有有效标签（true 时 vlan_tci 才有意义）

  // 解析边界应以 caplen 为准，而非 wirelen（wirelen 可能超出已捕获范围）。
  size_t available() const { return static_cast<size_t>(caplen); }

  void retain() {
    if (refcount < UINT32_MAX)
      ++refcount;
  }
  void release() {
    if (refcount > 0)
      --refcount;
  }
};

} // namespace packet_engine
