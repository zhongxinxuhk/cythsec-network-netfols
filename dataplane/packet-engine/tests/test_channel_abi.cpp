// test_channel_abi.cpp —— 通道 ABI 的 C++ 侧单测（CYS-PKT-024）。
//
// 本文件是 abi_gen.h 的**第一个 C++ 消费者**，这一点比测试内容本身更重要：
// abi_gen.h 是 header-only，其中的 35 条 static_assert 只在有人 include 它时才会被
// 编译。此前没有任何 .cpp 引用它，于是「改错字段顺序会在编译期失败」这条防线在
// C++ 侧从未生效过（Rust 侧因 `pub mod abi_gen;` 正常生效）。只要求「双端各自单测
// 通过」而 C++ 侧零消费者，等于这一半验收标准是空的。
//
// 断言只写**不变量**，不复制真源的字面量：把 4096 / 1024 这类常量抄进测试，等于为
// 真源增加第二份需手工同步的副本，而「忘了同步」的表现只是测试仍然通过 —— 这样的
// 测试是反向有害的。凡是要验「真源写对了」，那是 check-channel-abi.sh 的职责。
#include <cstddef>
#include <cstdint>
#include <string>

#include "packet_engine/channel/abi_gen.h"
#include "test_util.h"

using packet_engine::channel::abi::ChannelHeader;
using packet_engine::channel::abi::ChannelLayout;
using packet_engine::channel::abi::LayoutError;
using packet_engine::channel::abi::PacketDescriptor;
using packet_engine::test::check;
using packet_engine::test::summary;

namespace abi = packet_engine::channel::abi;

namespace {

// 布局失败时必须保持 out 不变。调用方拿到部分结果就会拿去 mmap —— 一个「看起来
// 合理」的错误尺寸比直接报错危险得多。
void check_layout_failure_leaves_out_untouched() {
  ChannelLayout out{};
  out.desc_off = 0xDEADBEEFu;
  out.data_off = 0xBEEFu;
  out.required = 0x0123456789ABCDEFULL;
  const ChannelLayout before = out;

  const LayoutError e = abi::channel_layout(0u, 4096u, &out);
  check(e == LayoutError::kSlotCountOutOfRange, "槽位数 0 应报 kSlotCountOutOfRange");
  check(out.desc_off == before.desc_off && out.data_off == before.data_off &&
            out.required == before.required,
        "布局失败时不得留下部分结果（调用方会拿它去 mmap）");
}

} // namespace

int main() {
  // ---- 魔数自洽：文本、字节序列、BE 解读值三者必须一致 ----
  // 三者不一致时，一端按字节比较、另一端按 BE 值打印日志，会得出互相矛盾的排障结论。
  check(sizeof(abi::kMagicText) - 1 == abi::kMagicLen, "魔数长度常量与魔数字面量一致");
  std::uint64_t be = 0;
  bool bytes_match_text = true;
  for (std::size_t i = 0; i < abi::kMagicLen; ++i) {
    be = (be << 8) | abi::kMagicBytes[i];
    if (abi::kMagicBytes[i] != static_cast<std::uint8_t>(abi::kMagicText[i])) {
      bytes_match_text = false;
    }
  }
  check(bytes_match_text, "魔数字节序列与魔数文本逐字节一致");
  check(be == abi::kMagicBE, "魔数 BE 常量与字节序列一致");

  // ---- 结构性不变量 ----
  check(abi::kDescriptorStep == sizeof(PacketDescriptor),
        "描述符步进必须等于描述符结构体尺寸（差 1 字节就永久错位）");
  check(offsetof(ChannelHeader, reserved3) + sizeof(std::uint64_t) == sizeof(ChannelHeader),
        "通道头最后一个字段的末尾即结构体尺寸（不得有尾部填充）");
  check(offsetof(PacketDescriptor, reserved3) + sizeof(std::uint64_t) == sizeof(PacketDescriptor),
        "描述符最后一个字段的末尾即结构体尺寸（不得有尾部填充）");
  check(abi::kHeaderRegionSize >= sizeof(ChannelHeader), "头部区必须容得下通道头");
  check(abi::kRegionAlignment != 0 && (abi::kRegionAlignment & (abi::kRegionAlignment - 1)) == 0,
        "对齐值必须是 2 的幂（否则 align_up 的整数写法会算错）");
  check(abi::kAbiVersion != 0, "ABI 版本号不得为 0（0 与「未初始化区域」无法区分）");

  // ---- 布局算术 ----
  ChannelLayout l{};
  check(abi::channel_layout(abi::kDefaultSlotCount, abi::kDefaultSlotSize, &l) ==
            LayoutError::kNone,
        "默认槽位配置必须可用");

  const std::uint64_t expect_desc_off =
      ((static_cast<std::uint64_t>(abi::kHeaderRegionSize) + abi::kRegionAlignment - 1) /
       abi::kRegionAlignment) *
      abi::kRegionAlignment;
  check(l.desc_off == expect_desc_off, "desc_off = align_up(header_region_size, region_alignment)");
  check(static_cast<std::uint64_t>(l.data_off) ==
            static_cast<std::uint64_t>(l.desc_off) +
                static_cast<std::uint64_t>(abi::kDefaultSlotCount) * abi::kDescriptorStep,
        "data_off = desc_off + slot_count * descriptor_step");
  check(l.required ==
            static_cast<std::uint64_t>(l.data_off) +
                static_cast<std::uint64_t>(abi::kDefaultSlotCount) * abi::kDefaultSlotSize,
        "required = data_off + slot_count * slot_size");

  // ---- 边界：下界必须被接受 ----
  // 把 `< min` 写成 `<= min` 是范围检查最常见的差一错，而它只在恰好取最小值时才暴露 ——
  // 默认配置永远测不到。
  check(abi::channel_layout(abi::kMinSlotCount, abi::kMinSlotSize, &l) == LayoutError::kNone,
        "下界配置（min_slot_count × min_slot_size）必须被接受");
  check(abi::channel_layout(abi::kMinSlotCount - 1, abi::kDefaultSlotSize, &l) ==
            LayoutError::kSlotCountOutOfRange,
        "低于 min_slot_count 必须被拒绝");
  check(abi::channel_layout(abi::kMaxSlotCount + 1, abi::kDefaultSlotSize, &l) ==
            LayoutError::kSlotCountOutOfRange,
        "高于 max_slot_count 必须被拒绝");
  check(abi::channel_layout(abi::kDefaultSlotCount, abi::kMinSlotSize - 1, &l) ==
            LayoutError::kSlotSizeOutOfRange,
        "低于 min_slot_size 必须被拒绝");
  check(abi::channel_layout(abi::kDefaultSlotCount, abi::kMaxSlotSize + 1, &l) ==
            LayoutError::kSlotSizeOutOfRange,
        "高于 max_slot_size 必须被拒绝");

  // ---- 溢出：上界组合超出 32 位可表达范围 ----
  // 先溢出再比较会得到一个「看起来合理」的小数字，是最难查的一类错。
  check(abi::channel_layout(abi::kMaxSlotCount, abi::kMaxSlotSize, &l) ==
            LayoutError::kSizeOverflow,
        "上界组合超出 32 位可表达范围，必须报 kSizeOverflow 而非回绕成小数字");

  check_layout_failure_leaves_out_untouched();

  // ---- parity dump 的形状 ----
  // 用 dump 枚举诊断而非在测试里再列一遍清单：清单一旦复制，就会在新增诊断时漏更新，
  // 而漏更新的表现是「测试仍然通过」。
  std::size_t dump_lines = 0;
  std::size_t diag_samples = 0;
  bool shape_ok = true;
  bool samples_ok = true;
  for (const std::string& line : abi::dump::AbiDump()) {
    ++dump_lines;
    const std::size_t eq = line.find('=');
    if (eq == std::string::npos || eq == 0) {
      shape_ok = false;
      continue;
    }
    const std::string key = line.substr(0, eq);
    const std::string value = line.substr(eq + 1);
    // 值里出现换行会破坏「一行一条」这个 diff 前提。
    if (value.find('\n') != std::string::npos) {
      shape_ok = false;
    }
    const std::string kSampleSuffix = ".sample";
    if (key.compare(0, 5, "diag.") == 0 && key.size() > kSampleSuffix.size() &&
        key.compare(key.size() - kSampleSuffix.size(), kSampleSuffix.size(), kSampleSuffix) == 0) {
      ++diag_samples;
      // 空文案等于两端「一致地什么都没说」，diff 照样通过 —— 必须单独拦。
      if (value.empty()) {
        samples_ok = false;
      }
    }
  }
  check(dump_lines > 0, "parity dump 不得为空");
  check(shape_ok, "parity dump 每行必须是单行 key=value");
  check(diag_samples > 0, "parity dump 必须包含诊断样本");
  check(samples_ok, "每条诊断样本都要渲染出非空文案");

  return summary("channel_abi");
}
