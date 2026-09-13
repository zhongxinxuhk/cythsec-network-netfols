// backend.cpp - 后端工厂。
//
// 按名称创建后端。当前已实现的真实后端：pcap-file（经典 pcap 文件，零第三方依赖）。
// 未知名称返回 nullptr，并通过 create_backend_error() 给出原因，供后续 af_packet/
// XDP/AF_XDP/DPDK 等真后端接入时扩展。
#include "packet_engine/backend.h"
#include "packet_engine/backends/pcap_file.h"

#include <cstring>

namespace packet_engine {

static const char* g_backend_error = "packet-engine: 暂无可用后端实现";

PacketBackend* create_backend(const char* name) {
  if (name && std::strcmp(name, "pcap-file") == 0) {
    return new PcapFileBackend();
  }
  g_backend_error = "packet-engine: 未知后端名（已知: pcap-file）";
  return nullptr;
}

const char* create_backend_error() {
  return g_backend_error;
}

} // namespace packet_engine
