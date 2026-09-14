#!/usr/bin/env python3
# gen-channel-abi.py —— 由通道 ABI 单一真源生成 C++ 与 Rust 双端契约代码。
#
# 背景（CYS-PKT-024）：packet-engine（C++，生产端）与 traffic-engine（Rust，消费端）
# 通过共享内存环传递报文。跨语言共享内存的失败模式与单语言不同——**写错不会崩，只会
# 静默错读**：步进差 8 字节就永久错位，槽位数不一致就读到隔壁槽的报文，ABI 版本不同则
# 整块区域的每个字段都无意义。因此本契约的设计目标不是「能跑」，而是**不一致时必须显式
# 失败**：
#
#   configs/registry/channel-abi.json          （唯一真源，人工维护）
#           │
#           ├── dataplane/packet-engine/include/packet_engine/channel/abi_gen.h  （C++）
#           └── dataplane/traffic-engine/src/channel/abi_gen.rs                  （Rust）
#
# 三处一致性由三层机制分别守住，缺一不可：
#   1. **编译期**：生成的结构体带 static_assert（字段偏移 + 结构体尺寸），
#      人类改错字段顺序会在编译时失败，而不是在运行时读到垃圾。
#   2. **生成物新鲜度**：`--check` 比对生成物与真源（scripts/verify/check-channel-abi.sh），
#      改真源忘记重新生成会被拦下。
#   3. **跨语言 parity**：两端各自的 `--dump-abi` 输出逐行 `key=value`，脚本直接 diff。
#      这是唯一能发现「一侧改了、另一侧没改」的手段——静态断言只看自己那一侧。
#
# 诊断文案同样由真源生成（而非两侧各写一遍）：ABI 报错的读者是排障的人，两端报错措辞
# 不同会让人误以为遇到了两个不同的问题。
#
# 用法：
#   python3 tools/codegen/gen-channel-abi.py            # 生成（幂等覆盖）
#   python3 tools/codegen/gen-channel-abi.py --check    # 只校验生成物是否与真源一致

import argparse
import difflib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "configs" / "registry" / "channel-abi.json"

TARGETS = {
    "cpp": "dataplane/packet-engine/include/packet_engine/channel/abi_gen.h",
    "rust": "dataplane/traffic-engine/src/channel/abi_gen.rs",
}

# 字段类型 -> 各语言 C 等价类型与格式化占位。type 决定三件事：结构体成员类型、
# static_assert 的期望尺寸、诊断文案里该值的打印方式。
# 加新类型时必须三处齐备，否则生成器报错退出（宁可不生成，也不生成本钱不对的代码）。
FIELDS = {
    # size 是**单元素**字节数，count 是元素个数；结构体成员尺寸 = size × count。
    # bytes8 因此是 size=1 / count=8（而非 size=8），否则 8×8=64 会把后续字段判成重叠。
    "bytes8": {"cpp": "uint8_t", "rust": "u8", "size": 1, "count": 8, "fmt": None},
    "u32": {"cpp": "uint32_t", "rust": "u32", "size": 4, "count": 1, "fmt": "u32"},
    "u64": {"cpp": "uint64_t", "rust": "u64", "size": 8, "count": 1, "fmt": "u64"},
    "i64": {"cpp": "int64_t", "rust": "i64", "size": 8, "count": 1, "fmt": "i64"},
}

# 诊断字段类型 -> 各语言形参类型与格式化方式。
DIAG_TYPES = {
    "u32": {"cpp_type": "uint32_t", "rust_type": "u32", "cpp_fmt": "%u", "rust_fmt": "{}",
            "cpp_expr": "static_cast<unsigned>(v)", "rust_expr": "v", "sample_kind": "int"},
    "u64": {"cpp_type": "uint64_t", "rust_type": "u64", "cpp_fmt": "%llu", "rust_fmt": "{}",
            "cpp_expr": "static_cast<unsigned long long>(v)", "rust_expr": "v", "sample_kind": "int"},
    "i64": {"cpp_type": "int64_t", "rust_type": "i64", "cpp_fmt": "%lld", "rust_fmt": "{}",
            "cpp_expr": "static_cast<long long>(v)", "rust_expr": "v", "sample_kind": "int"},
    "hex64": {"cpp_type": "uint64_t", "rust_type": "u64", "cpp_fmt": "0x%016llx",
              "rust_fmt": "0x{:016x}", "cpp_expr": "static_cast<unsigned long long>(v)",
              "rust_expr": "v", "sample_kind": "int"},
    "str": {"cpp_type": "const char*", "rust_type": "&str", "cpp_fmt": "%s", "rust_fmt": "{}",
            "cpp_expr": "(v != nullptr ? v : \"(null)\")", "rust_expr": "v", "sample_kind": "str"},
}

# 严重度 -> 各语言标识。
SEVERITIES = {
    "error": {"cpp": "Severity::kError", "rust": "Severity::Error"},
    "warning": {"cpp": "Severity::kWarning", "rust": "Severity::Warning"},
}

# 字段名会成为生成源码里的成员名，因此必须同时在 C++ 与 Rust 里可用。两类坑：
#
# 1. **C++ 预处理器宏**。成员名会先被预处理一遍，与系统头文件宏同名时会被就地展开，
#    报错指向宏定义本身（如 `__error()`），与真源毫无关联，极难定位。真事：字段名
#    `errno` 在 macOS/Linux 上展开成 `(*__error())`，任何包含本头的编译单元都炸。
# 2. **语言关键字**。作为成员名直接语法错误。
#
# 这类冲突的代价与「改个名字」完全不成比例，因此在生成前直接拦下。
CPP_RESERVED = {
    "errno": "<errno.h> 的宏 errno",
    "index": "<strings.h> 的 index()",
    "major": "<sys/sysmacros.h> 的宏 major",
    "minor": "<sys/sysmacros.h> 的宏 minor",
    "timezone": "<time.h> 的 timezone",
    "unix": "部分工具链预定义的 unix",
    "linux": "部分工具链预定义的 linux",
    "min": "Windows 头文件的 min 宏",
    "max": "Windows 头文件的 max 宏",
    "small": "Windows 头文件的 small 宏",
    "near": "Windows 头文件的 near 宏",
    "far": "Windows 头文件的 far 宏",
    "interface": "Windows 头文件的 interface 宏",
    "NULL": "<stddef.h> 的 NULL",
    "EOF": "<stdio.h> 的 EOF",
    "stdin": "<stdio.h> 的 stdin",
    "stdout": "<stdio.h> 的 stdout",
    "stderr": "<stdio.h> 的 stderr",
    "class": "C++ 关键字",
    "struct": "C++ 关键字",
    "namespace": "C++ 关键字",
    "template": "C++ 关键字",
    "typename": "C++ 关键字",
    "operator": "C++ 关键字",
    "new": "C++ 关键字",
    "delete": "C++ 关键字",
    "this": "C++ 关键字",
    "virtual": "C++ 关键字",
    "friend": "C++ 关键字",
    "explicit": "C++ 关键字",
    "mutable": "C++ 关键字",
    "constexpr": "C++ 关键字",
    "private": "C++ 关键字",
    "protected": "C++ 关键字",
    "public": "C++ 关键字",
    "auto": "C++ 关键字",
    "register": "C++ 关键字",
}

RUST_RESERVED = {
    "type": "Rust 关键字",
    "match": "Rust 关键字",
    "move": "Rust 关键字",
    "loop": "Rust 关键字",
    "ref": "Rust 关键字",
    "box": "Rust 关键字",
    "where": "Rust 关键字",
    "fn": "Rust 关键字",
    "let": "Rust 关键字",
    "mut": "Rust 关键字",
    "pub": "Rust 关键字",
    "impl": "Rust 关键字",
    "trait": "Rust 关键字",
    "use": "Rust 关键字",
    "mod": "Rust 关键字",
    "enum": "Rust 关键字",
    "const": "Rust 关键字",
    "static": "Rust 关键字",
    "async": "Rust 关键字",
    "await": "Rust 关键字",
    "dyn": "Rust 关键字",
    "unsafe": "Rust 关键字",
    "extern": "Rust 关键字",
    "as": "Rust 关键字",
    "in": "Rust 关键字",
    "if": "Rust 关键字",
    "else": "Rust 关键字",
    "while": "Rust 关键字",
    "for": "Rust 关键字",
    "break": "Rust 关键字",
    "continue": "Rust 关键字",
    "return": "Rust 关键字",
    "self": "Rust 关键字",
    "super": "Rust 关键字",
    "crate": "Rust 关键字",
    "true": "Rust 关键字",
    "false": "Rust 关键字",
}


def die(msg):
    print("gen-channel-abi: " + msg, file=sys.stderr)
    sys.exit(1)


def load_registry():
    if not REGISTRY.exists():
        die("未找到真源文件: %s" % REGISTRY)
    with REGISTRY.open(encoding="utf-8") as fh:
        doc = json.load(fh)
    validate(doc)
    return doc


def validate(doc):
    """校验真源自洽性。真源写错时必须在生成前拦下——生成物一旦落盘就有人会去读它。"""
    ch = doc.get("channel")
    if not ch:
        die("真源缺少 channel 段")

    magic = ch.get("magic_bytes", "")
    if len(magic.encode("ascii", "ignore")) != 8 or len(magic) != 8:
        die("magic_bytes 必须恰好 8 个 ASCII 字节，实际 %r" % magic)

    for key in ("abi_version", "header_region_size", "descriptor_step", "region_alignment",
                "default_slot_count", "default_slot_size", "min_slot_count", "max_slot_count",
                "min_slot_size", "max_slot_size"):
        if not isinstance(ch.get(key), int):
            die("channel.%s 缺失或不是整数" % key)
    if ch["min_slot_count"] > ch["default_slot_count"] or ch["default_slot_count"] > ch["max_slot_count"]:
        die("slot_count 默认值不在 [min, max] 内")
    if ch["min_slot_size"] > ch["default_slot_size"] or ch["default_slot_size"] > ch["max_slot_size"]:
        die("slot_size 默认值不在 [min, max] 内")

    # 字段偏移必须严格递增且不重叠 —— 这是整套契约的根基。
    for group in ("header_fields", "descriptor_fields"):
        fields = doc.get(group)
        if not fields:
            die("真源缺少 %s" % group)
        end = 0
        for f in fields:
            info = FIELDS.get(f.get("type"))
            if info is None:
                die("%s.%s 的类型 %r 未在 FIELDS 中登记" % (group, f.get("name"), f.get("type")))
            if f["offset"] < end:
                die("%s.%s 偏移 %d 与前一个字段重叠（上一字段结束于 %d）"
                    % (group, f.get("name"), f["offset"], end))
            end = f["offset"] + info["size"] * info["count"]
        if group == "header_fields":
            if end > ch["header_region_size"]:
                die("header 结构体（%d 字节）超出头部区预留（%d 字节）"
                    % (end, ch["header_region_size"]))
        if group == "descriptor_fields" and end != ch["descriptor_step"]:
            die("descriptor 字段合计 %d 字节 != descriptor_step %d" % (end, ch["descriptor_step"]))

    if not doc.get("flags"):
        die("真源缺少 flags 段")
    seen_bits = set()
    for fl in doc["flags"]:
        if fl["bit"] in seen_bits:
            die("flag 位 %d 重复" % fl["bit"])
        seen_bits.add(fl["bit"])
        if fl["bit"] >= 32:
            die("flag 位 %d 超出 u32" % fl["bit"])

    # 诊断：占位符、字段表、样本值三者必须严格对应，否则生成的格式串会错位。
    diags = doc.get("diagnostics") or []
    if not diags:
        die("真源缺少 diagnostics 段")
    seen_codes = set()
    for d in diags:
        code = d["code"]
        if code in seen_codes:
            die("诊断码重复: %s" % code)
        seen_codes.add(code)
        if d["severity"] not in SEVERITIES:
            die("%s 的 severity %r 未登记" % (code, d["severity"]))
        names = [f["name"] for f in d["fields"]]
        for f in d["fields"]:
            if f["type"] not in DIAG_TYPES:
                die("%s.%s 的字段类型 %r 未登记" % (code, f["name"], f["type"]))
        placeholders = re.findall(r"\{(\w+)\}", d["template"])
        if placeholders != names:
            die("%s 的模板占位符 %s 与字段表 %s 顺序/名称不一致"
                % (code, placeholders, names))
        if sorted(d["sample"]) != sorted(names):
            die("%s 的 sample 键 %s 与字段表 %s 不一致" % (code, sorted(d["sample"]), names))
        # 模板里若混入裸大括号会让 C++/Rust 的格式串解析出错
        if re.search(r"[{}]", re.sub(r"\{\w+\}", "", d["template"])):
            die("%s 的模板含未被占位符覆盖的大括号" % code)

    # 字段名必须同时可用于 C++ 与 Rust（见 CPP_RESERVED / RUST_RESERVED 的说明）。
    # 只查会以原名出现在生成源码里的名字：flag 常量带 k 前缀 / 全大写，不在此列。
    targets = [("header_fields", f["name"]) for f in doc["header_fields"]]
    targets += [("descriptor_fields", f["name"]) for f in doc["descriptor_fields"]]
    targets += [("diagnostics." + d["code"], f["name"]) for d in diags for f in d["fields"]]
    for where, name in targets:
        if name in CPP_RESERVED:
            die("%s 的字段名 %r 与 %s 冲突；该名字会出现在 C++ 生成源码里，请改用无冲突的名字"
                % (where, name, CPP_RESERVED[name]))
        if name in RUST_RESERVED:
            die("%s 的字段名 %r 与 %s 冲突；该名字会出现在 Rust 生成源码里，请改用无冲突的名字"
                % (where, name, RUST_RESERVED[name]))


def cpp_str(s):
    """C++ 字符串字面量转义：仅处理本真源可能出现的字符（无控制字符）。"""
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def rust_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def cpp_doc_comment(desc, indent):
    return "%s// %s\n" % (indent, desc) if desc else ""


def render_cpp(doc):
    ch = doc["channel"]
    magic = ch["magic_bytes"]
    out = []
    w = out.append
    w("// 由 tools/codegen/gen-channel-abi.py 生成，请勿手工修改。\n")
    w("// 真源：configs/registry/channel-abi.json（registry_version=%s）\n"
      % doc["registry_version"])
    w("//\n")
    w("// 本文件是 C++ 生产端与 Rust 消费端共享的**冻结 ABI**。改动本文件而不动真源，\n")
    w("// 会被 scripts/verify/check-channel-abi.sh 拦下。\n")
    w("#pragma once\n\n")
    w("#include <cstddef>\n")
    w("#include <cstdint>\n")
    w("#include <cstdio>\n")
    w("#include <string>\n")
    w("#include <vector>\n\n")

    w("namespace packet_engine {\nnamespace channel {\nnamespace abi {\n\n")

    w("// ---- 真源标识 ----\n")
    w("inline constexpr char kRegistryVersion[] = %s;\n" % cpp_str(doc["registry_version"]))
    w("inline constexpr char kMagicText[] = %s;\n" % cpp_str(magic))
    w("inline constexpr std::size_t kMagicLen = 8;\n")
    w("inline constexpr uint8_t kMagicBytes[kMagicLen] = {%s};\n"
      % ", ".join("0x%02x" % b for b in magic.encode("ascii")))
    w("// 魔数的 BE 解读值，仅用于日志与诊断打印（比较一律走字节，避免字节序歧义）。\n")
    w("inline constexpr uint64_t kMagicBE = 0x%sULL;\n" % magic.encode("ascii").hex())

    w("\n// ---- 通道常量 ----\n")
    w("inline constexpr uint32_t kAbiVersion = %du;\n" % ch["abi_version"])
    w("inline constexpr uint32_t kHeaderRegionSize = %du;\n" % ch["header_region_size"])
    w("inline constexpr uint32_t kDescriptorStep = %du;\n" % ch["descriptor_step"])
    w("inline constexpr uint32_t kRegionAlignment = %du;\n" % ch["region_alignment"])
    w("inline constexpr uint32_t kDefaultSlotCount = %du;\n" % ch["default_slot_count"])
    w("inline constexpr uint32_t kDefaultSlotSize = %du;\n" % ch["default_slot_size"])
    w("inline constexpr uint32_t kMinSlotCount = %du;\n" % ch["min_slot_count"])
    w("inline constexpr uint32_t kMaxSlotCount = %du;\n" % ch["max_slot_count"])
    w("inline constexpr uint32_t kMinSlotSize = %du;\n" % ch["min_slot_size"])
    w("inline constexpr uint32_t kMaxSlotSize = %du;\n" % ch["max_slot_size"])

    for group, cpp_name, rust_name in (("header_fields", "ChannelHeader", "ChannelHeader"),
                                       ("descriptor_fields", "PacketDescriptor", "PacketDescriptor")):
        w("\n// ---- %s 字段偏移 ----\n" % cpp_name)
        w("namespace %s_off {\n" % ("header" if group == "header_fields" else "desc"))
        for f in doc[group]:
            w("inline constexpr uint32_t k%s = %du;\n"
              % (f["name"][0].upper() + f["name"][1:], f["offset"]))
        w("}  // namespace %s_off\n" % ("header" if group == "header_fields" else "desc"))

    w("\n// ---- 描述符 flags 位 ----\nnamespace flag {\n")
    for fl in doc["flags"]:
        w("inline constexpr uint32_t k%s = 1u << %d;  // %s\n"
          % (fl["name"][0].upper() + fl["name"][1:], fl["bit"], fl["desc"]))
    w("}  // namespace flag\n")

    # 结构体：与真源字段表同源生成，字段顺序由偏移决定。
    w("\n// ---- 冻结结构体 ----\n")
    w("// 注意：这两个结构体是 POD，不含成员函数与虚表 —— 偏移即 ABI。\n")
    w("// 所有偏移由真源生成 static_assert 固定；改字段顺序会编译失败而非静默错读。\n\n")
    for group, name in (("header_fields", "ChannelHeader"), ("descriptor_fields", "PacketDescriptor")):
        w("struct %s {\n" % name)
        for f in doc[group]:
            info = FIELDS[f["type"]]
            decl = "%s %s" % (info["cpp"], f["name"])
            if info["count"] > 1:
                decl += "[%d]" % info["count"]
            decl += ";"
            if f.get("desc"):
                decl = "%-38s // +%-4d %s" % (decl, f["offset"], f["desc"])
            else:
                decl = "%-38s // +%d" % (decl, f["offset"])
            w("  %s\n" % decl)
        w("};\n\n")
        for f in doc[group]:
            w("static_assert(offsetof(%s, %s) == %du, \"%s.%s 偏移与通道 ABI 不符\");\n"
              % (name, f["name"], f["offset"], name, f["name"]))
        last = doc[group][-1]
        end = last["offset"] + FIELDS[last["type"]]["size"] * FIELDS[last["type"]]["count"]
        w("static_assert(sizeof(%s) == %du, \"%s 尺寸与通道 ABI 不符\");\n\n" % (name, end, name))

    # 诊断
    w(_layout_cpp(ch))
    w("// ---- 诊断严重度 ----\n")
    w("enum class Severity : uint8_t { kWarning = 0, kError = 1 };\n\n")
    w("// 严重度字符串：与 Rust 端 as_str() 一致，是 parity 校验的一部分。\n")
    w("inline const char* to_string(Severity s) {\n")
    w("  return s == Severity::kError ? \"error\" : \"warning\";\n")
    w("}\n\n")

    w("// ---- 诊断（码 + 文案均由真源生成，保证两端逐字一致）----\n")
    w("namespace diag {\n\n")
    for d in doc["diagnostics"]:
        w("// %s（%s）\n" % (d["code"], d["severity"]))
        w("inline constexpr char k%sCode[] = %s;\n"
          % (diag_ident(d["code"]), cpp_str(d["code"])))
    w("\n")
    for d in doc["diagnostics"]:
        ident = diag_ident(d["code"])
        w("// %s\n" % d["code"])
        w("struct %s {\n" % ident)
        w("  static const char* code() { return k%sCode; }\n" % ident)
        w("  static Severity severity() { return %s; }\n" % SEVERITIES[d["severity"]]["cpp"])
        for f in d["fields"]:
            info = DIAG_TYPES[f["type"]]
            if info["cpp_type"] == "const char*":
                w("  const char* %s = nullptr;\n" % f["name"])
            else:
                w("  %s %s = 0;\n" % (info["cpp_type"], f["name"]))
        w("\n  // 用两遍 snprintf 取得精确长度：诊断里含路径这类变长字段，\n")
        w("  // 定长缓冲会在最需要看到完整路径时把尾部截掉。\n")
        w("  std::string format() const {\n")
        w("    const char* kFmt = %s;\n" % cpp_str(cpp_format(d)))
        w("    const int need = std::snprintf(nullptr, 0, kFmt, %s);\n" % cpp_args(d))
        w("    if (need <= 0) return std::string();\n")
        w("    std::vector<char> buf(static_cast<std::size_t>(need) + 1);\n")
        w("    std::snprintf(buf.data(), buf.size(), kFmt, %s);\n" % cpp_args(d))
        w("    return std::string(buf.data(), static_cast<std::size_t>(need));\n")
        w("  }\n\n")
        w("  // parity 校验用的确定性样本（取值亦来自真源）。\n")
        w("  static std::string sample() {\n")
        w("    %s v{};\n" % ident)
        for f in d["fields"]:
            w("    v.%s = %s;\n" % (f["name"], cpp_sample(f, d["sample"][f["name"]])))
        w("    return v.format();\n")
        w("  }\n")
        w("};\n\n")
    w("}  // namespace diag\n")
    w("}  // namespace abi\n}  // namespace channel\n}  // namespace packet_engine\n")
    return "".join(out)


def render_rust(doc):
    ch = doc["channel"]
    magic = ch["magic_bytes"]
    out = []
    w = out.append
    w("// 由 tools/codegen/gen-channel-abi.py 生成，请勿手工修改。\n")
    w("// 真源：configs/registry/channel-abi.json（registry_version=%s）\n"
      % doc["registry_version"])
    w("//\n")
    w("// 本文件是 C++ 生产端与 Rust 消费端共享的**冻结 ABI**。改动本文件而不动真源，\n")
    w("// 会被 scripts/verify/check-channel-abi.sh 拦下。\n")
    w("#![allow(dead_code)]\n\n")

    w("// ---- 真源标识 ----\n")
    w("pub const REGISTRY_VERSION: &str = %s;\n" % rust_str(doc["registry_version"]))
    w("pub const MAGIC_TEXT: &str = %s;\n" % rust_str(magic))
    w("pub const MAGIC_LEN: usize = 8;\n")
    w("pub const MAGIC: [u8; MAGIC_LEN] = [%s];\n"
      % ", ".join("0x%02x" % b for b in magic.encode("ascii")))
    w("/// 魔数的 BE 解读值，仅用于日志与诊断打印（比较一律走字节，避免字节序歧义）。\n")
    w("pub const MAGIC_BE: u64 = 0x%s;\n" % magic.encode("ascii").hex())

    w("\n// ---- 通道常量 ----\n")
    w("pub const ABI_VERSION: u32 = %d;\n" % ch["abi_version"])
    w("pub const HEADER_REGION_SIZE: u32 = %d;\n" % ch["header_region_size"])
    w("pub const DESCRIPTOR_STEP: u32 = %d;\n" % ch["descriptor_step"])
    w("pub const REGION_ALIGNMENT: u32 = %d;\n" % ch["region_alignment"])
    w("pub const DEFAULT_SLOT_COUNT: u32 = %d;\n" % ch["default_slot_count"])
    w("pub const DEFAULT_SLOT_SIZE: u32 = %d;\n" % ch["default_slot_size"])
    w("pub const MIN_SLOT_COUNT: u32 = %d;\n" % ch["min_slot_count"])
    w("pub const MAX_SLOT_COUNT: u32 = %d;\n" % ch["max_slot_count"])
    w("pub const MIN_SLOT_SIZE: u32 = %d;\n" % ch["min_slot_size"])
    w("pub const MAX_SLOT_SIZE: u32 = %d;\n" % ch["max_slot_size"])

    w("\n// ---- 字段偏移 ----\n")
    for group, mod in (("header_fields", "header_off"), ("descriptor_fields", "desc_off")):
        w("pub mod %s {\n" % mod)
        for f in doc[group]:
            w("    pub const %s: usize = %d;\n"
              % (f["name"].upper(), f["offset"]))
        w("}\n")

    w("\n// ---- 描述符 flags 位 ----\n")
    w("pub mod flag {\n")
    for fl in doc["flags"]:
        w("    /// %s\n" % fl["desc"])
        w("    pub const %s: u32 = 1 << %d;\n" % (fl["name"].upper(), fl["bit"]))
    w("}\n")

    w("\n// ---- 冻结结构体 ----\n")
    w("// 注意：`#[repr(C)]` 是硬要求 —— 默认 repr 的字段顺序由编译器决定，\n")
    w("// 与 C++ 端不保证一致。尺寸与偏移由 const 断言在编译期固定。\n\n")
    for group, name in (("header_fields", "ChannelHeader"), ("descriptor_fields", "PacketDescriptor")):
        w("#[repr(C)]\n")
        w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n")
        w("pub struct %s {\n" % name)
        for f in doc[group]:
            info = FIELDS[f["type"]]
            decl = "pub %s: %s" % (f["name"], info["rust"])
            if info["count"] > 1:
                decl += " * [%d]" % info["count"]
                # 数组字段用 [u8; N]
                decl = "pub %s: [%s; %d]" % (f["name"], info["rust"], info["count"])
            decl += ","
            if f.get("desc"):
                decl = "%-40s // +%-4d %s" % (decl, f["offset"], f["desc"])
            else:
                decl = "%-40s // +%d" % (decl, f["offset"])
            w("    %s\n" % decl)
        w("}\n\n")
        w("// 编译期断言：字段偏移与结构体尺寸必须与真源一致。\n")
        for f in doc[group]:
            w("const _: () = assert!(std::mem::offset_of!(%s, %s) == %d, \"%s.%s 偏移与通道 ABI 不符\");\n"
              % (name, f["name"], f["offset"], name, f["name"]))
        last = doc[group][-1]
        end = last["offset"] + FIELDS[last["type"]]["size"] * FIELDS[last["type"]]["count"]
        w("const _: () = assert!(std::mem::size_of::<%s>() == %d, \"%s 尺寸与通道 ABI 不符\");\n\n"
          % (name, end, name))

    w(_layout_rust(ch))
    w("// ---- 诊断严重度 ----\n")
    w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n")
    w("pub enum Severity {\n    Warning,\n    Error,\n}\n\n")
    w("impl Severity {\n")
    w("    /// 严重度字符串：与 C++ 端 to_string() 一致，是 parity 校验的一部分。\n")
    w("    pub fn as_str(self) -> &'static str {\n")
    w("        match self {\n            Severity::Error => \"error\",\n            Severity::Warning => \"warning\",\n        }\n")
    w("    }\n}\n\n")

    w("// ---- 诊断（码 + 文案均由真源生成，保证两端逐字一致）----\n")
    w("pub mod diag {\n")
    w("    use super::Severity;\n    use std::fmt;\n\n")
    for d in doc["diagnostics"]:
        w("    pub const %s_CODE: &str = %s;\n"
          % (diag_ident(d["code"]).upper(), rust_str(d["code"])))
    w("\n")
    for d in doc["diagnostics"]:
        ident = diag_ident(d["code"])
        w("    /// %s\n" % d["code"])
        w("    %s\n" % rust_derives(d))
        w("    pub struct %s {\n" % ident)
        for f in d["fields"]:
            info = DIAG_TYPES[f["type"]]
            # 字符串字段用 owned String：跨语言需一致的是「码」与「渲染文案」，不是内存表示。
            ty = "String" if info["rust_type"] == "&str" else info["rust_type"]
            w("        pub %s: %s,\n" % (f["name"], ty))
        w("    }\n\n")
        w("    impl %s {\n" % ident)
        w("        pub const CODE: &'static str = %s_CODE;\n" % ident.upper())
        w("        pub const SEVERITY: Severity = %s;\n" % SEVERITIES[d["severity"]]["rust"])
        w("    }\n\n")
        w("    impl fmt::Display for %s {\n" % ident)
        w("        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n")
        w("            write!(\n                f,\n                %s,\n" % rust_str(rust_format(d)))
        for f in d["fields"]:
            # 参数必须带尾逗号：rustfmt 不会替缺失的逗号兜底，只会报语法错误。
            w("                %s,\n"
              % DIAG_TYPES[f["type"]]["rust_expr"].replace("v", "self." + f["name"]))
        w("            )\n        }\n    }\n\n")
        w("    /// parity 校验用的确定性样本（取值亦来自真源）。\n")
        w("    pub fn %s_sample() -> String {\n" % ident.lower())
        w("        %s {\n" % ident)
        for f in d["fields"]:
            w("            %s: %s,\n" % (f["name"], rust_sample(f, d["sample"][f["name"]])))
        w("        }\n        .to_string()\n    }\n\n")
    w("}  // pub mod diag\n")
    return "".join(out)


def rust_derives(d):
    """带字符串字段的诊断需要 owned String，因而不能 derive Copy。

    这类结构体只在本端出错时构造（每次装载至多一次），分配开销可以忽略；
    而借用 &str 会把「值来自运行时格式化」的调用方逼进生命周期体操。故取 owned。
    """
    base = "Debug, Clone, PartialEq, Eq"
    if any(f["type"] == "str" for f in d["fields"]):
        return "#[derive(%s)]" % base
    return "#[derive(Debug, Clone, Copy, PartialEq, Eq)]"


def diag_ident(code):
    """chan.abi_version_mismatch -> ChanAbiVersionMismatch"""
    parts = re.split(r"[._]", code)
    return "".join(p[0].upper() + p[1:] for p in parts if p)


def _layout_cpp(ch):
    """生成 C++ 侧布局计算。

    布局公式本身是契约的一部分，因此也由真源生成而非两端各写一遍：两侧手写同一段
    算术，早晚会在某次「只改了一边」时静默错位——读到的每个字段都无意义，却不会崩。
    """
    lines = []
    w = lines.append
    w("// ---- 布局计算（由真源生成，两端必须用同一套算术）----\n")
    w("// desc_off = align_up(header_region_size, region_alignment)\n")
    w("// data_off = desc_off + slot_count * descriptor_step\n")
    w("// required = data_off + slot_count * slot_size\n")
    w("//\n")
    w("// 中间量一律用 64 位：slot_count 与 slot_size 相乘在极端配置下会溢出 32 位，\n")
    w("// 先溢出再比较得到的「看起来合理」的小数字，是最难查的一类错。\n")
    w("struct ChannelLayout {\n")
    w("  uint32_t desc_off = 0;\n")
    w("  uint32_t data_off = 0;\n")
    w("  uint64_t required = 0;\n")
    w("};\n\n")
    w("enum class LayoutError {\n  kNone = 0,\n  kSlotCountOutOfRange,\n"
      "  kSlotSizeOutOfRange,\n  kSizeOverflow,\n};\n\n")
    w("inline constexpr uint64_t kOverflowLimit = 0xFFFFFFFFULL;\n\n")
    w("// 计算通道布局。成功返回 kNone 并填充 out；失败时 out 不被修改。\n")
    w("inline LayoutError channel_layout(uint32_t slot_count, uint32_t slot_size,\n"
      "                                  ChannelLayout* out) {\n")
    w("  if (slot_count < kMinSlotCount || slot_count > kMaxSlotCount) {\n")
    w("    return LayoutError::kSlotCountOutOfRange;\n  }\n")
    w("  if (slot_size < kMinSlotSize || slot_size > kMaxSlotSize) {\n")
    w("    return LayoutError::kSlotSizeOutOfRange;\n  }\n")
    w("  const uint64_t desc_off = ((static_cast<uint64_t>(kHeaderRegionSize) +\n")
    w("                              kRegionAlignment - 1) /\n")
    w("                             kRegionAlignment) *\n")
    w("                            kRegionAlignment;\n")
    w("  const uint64_t data_off =\n")
    w("      desc_off + static_cast<uint64_t>(slot_count) * kDescriptorStep;\n")
    w("  const uint64_t required =\n")
    w("      data_off + static_cast<uint64_t>(slot_count) * slot_size;\n")
    w("  if (data_off > kOverflowLimit || required > kOverflowLimit) {\n")
    w("    return LayoutError::kSizeOverflow;\n  }\n")
    w("  ChannelLayout v;\n")
    w("  v.desc_off = static_cast<uint32_t>(desc_off);\n")
    w("  v.data_off = static_cast<uint32_t>(data_off);\n")
    w("  v.required = required;\n")
    w("  if (out != nullptr) *out = v;\n")
    w("  return LayoutError::kNone;\n}\n\n")
    return "".join(lines)


def _layout_rust(ch):
    """生成 Rust 侧布局计算（与 C++ 侧同一套算术，见 _layout_cpp 说明）。"""
    lines = []
    w = lines.append
    w("// ---- 布局计算（由真源生成，两端必须用同一套算术）----\n")
    w("// desc_off = align_up(header_region_size, region_alignment)\n")
    w("// data_off = desc_off + slot_count * descriptor_step\n")
    w("// required = data_off + slot_count * slot_size\n")
    w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n")
    w("pub struct ChannelLayout {\n")
    w("    pub desc_off: u32,\n")
    w("    pub data_off: u32,\n")
    w("    pub required: u64,\n")
    w("}\n\n")
    w("/// 布局计算失败的原因。变体自带诊断所需字段，可直接喂给 `diag` 模块。\n")
    w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n")
    w("pub enum LayoutError {\n")
    w("    SlotCountOutOfRange {\n        value: u32,\n        min_value: u32,\n"
      "        max_value: u32,\n    },\n")
    w("    SlotSizeOutOfRange {\n        value: u32,\n        min_value: u32,\n"
      "        max_value: u32,\n    },\n")
    w("    SizeOverflow {\n        slot_count: u32,\n        slot_size: u32,\n    },\n")
    w("}\n\n")
    w("/// 32 位可表示范围上限：区域各偏移都是 u32，超出的布局无法用现有头部表达。\n")
    w("pub const OVERFLOW_LIMIT: u64 = 0xFFFF_FFFF;\n\n")
    w("/// 计算通道布局。失败时不返回部分结果。\n")
    w("pub fn channel_layout(slot_count: u32, slot_size: u32) -> Result<ChannelLayout, LayoutError> {\n")
    w("    if slot_count < MIN_SLOT_COUNT || slot_count > MAX_SLOT_COUNT {\n")
    w("        return Err(LayoutError::SlotCountOutOfRange {\n")
    w("            value: slot_count,\n            min_value: MIN_SLOT_COUNT,\n"
      "            max_value: MAX_SLOT_COUNT,\n        });\n    }\n")
    w("    if slot_size < MIN_SLOT_SIZE || slot_size > MAX_SLOT_SIZE {\n")
    w("        return Err(LayoutError::SlotSizeOutOfRange {\n")
    w("            value: slot_size,\n            min_value: MIN_SLOT_SIZE,\n"
      "            max_value: MAX_SLOT_SIZE,\n        });\n    }\n")
    w("    let desc_off =\n")
    w("        ((HEADER_REGION_SIZE as u64 + REGION_ALIGNMENT as u64 - 1) / REGION_ALIGNMENT as u64)\n")
    w("            * REGION_ALIGNMENT as u64;\n")
    w("    let data_off = desc_off + slot_count as u64 * DESCRIPTOR_STEP as u64;\n")
    w("    let required = data_off + slot_count as u64 * slot_size as u64;\n")
    w("    if data_off > OVERFLOW_LIMIT || required > OVERFLOW_LIMIT {\n")
    w("        return Err(LayoutError::SizeOverflow {\n            slot_count,\n"
      "            slot_size,\n        });\n    }\n")
    w("    Ok(ChannelLayout {\n")
    w("        desc_off: desc_off as u32,\n        data_off: data_off as u32,\n"
      "        required,\n    })\n}\n\n")
    return "".join(lines)


def cpp_format(d):
    """把 {name} 占位符按字段顺序替换为 C printf 占位符。"""
    out = d["template"]
    for f in d["fields"]:
        out = out.replace("{%s}" % f["name"], DIAG_TYPES[f["type"]]["cpp_fmt"], 1)
    return out


def cpp_args(d):
    return ", ".join(DIAG_TYPES[f["type"]]["cpp_expr"].replace("v", f["name"])
                     for f in d["fields"])


def rust_format(d):
    out = d["template"]
    for f in d["fields"]:
        out = out.replace("{%s}" % f["name"], DIAG_TYPES[f["type"]]["rust_fmt"], 1)
    return out


def cpp_sample(f, value):
    """样本值的 C++ 字面量。整数一律带 ULL/LL 后缀，避免常量被推断成 int 后溢出。"""
    if DIAG_TYPES[f["type"]]["sample_kind"] == "str":
        return cpp_str(value)
    return "%dULL" % value if value >= 0 else "%dLL" % value


def rust_sample(f, value):
    """样本值的 Rust 字面量。字符串字段是 owned String，故显式 to_string()。"""
    if DIAG_TYPES[f["type"]]["sample_kind"] == "str":
        return "%s.to_string()" % rust_str(value)
    return str(value)


# clang-format 常随 Xcode CommandLineTools 一同安装，但**不在 PATH 上**。
# 只用 shutil.which() 会把它误判为「未安装」并静默跳过格式化 —— 于是生成物在本地
# 看起来没问题，到了 CI（clang-format 在 PATH 上）才因格式不符被拦。候选列表与
# scripts/lint/lint-all.sh 保持同一套，避免两处判断不一致。
CPP_FORMATTER_CANDIDATES = (
    "clang-format",
    "/Library/Developer/CommandLineTools/usr/bin/clang-format",
    "/opt/homebrew/bin/clang-format",
    "/opt/homebrew/opt/llvm/bin/clang-format",
    "/usr/local/bin/clang-format",
    "/usr/local/opt/llvm/bin/clang-format",
    "/usr/bin/clang-format",
)


def find_formatter(kind):
    """返回可用的格式化器路径；找不到返回 None。"""
    if kind == "rust":
        return shutil.which("rustfmt")
    for cand in CPP_FORMATTER_CANDIDATES:
        if os.sep in cand:
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
            continue
        found = shutil.which(cand)
        if found:
            return found
    return None


def run_formatter(text, kind):
    """用该语言的格式化器后处理，使生成物天然通过既有的格式关口。"""
    tool = find_formatter(kind)
    if tool is None:
        return text, "未找到 %s，跳过格式化" % ("clang-format" if kind == "cpp" else "rustfmt")
    if kind == "cpp":
        # --style=file 依赖 cwd 下可发现的 .clang-format，故下面以 ROOT 为 cwd 调用。
        cmd = [tool, "--style=file", "-"]
    else:
        cmd = [tool, "--edition", "2021", "--emit", "stdout"]
    try:
        # C++ 用管道读 stdin，Rust 传文件路径更稳，但 stdin 亦受支持。
        proc = subprocess.run(cmd, input=text.encode("utf-8"), capture_output=True,
                              cwd=str(ROOT), check=False)
    except OSError as exc:
        return text, "格式化器调用失败: %s" % exc
    if proc.returncode != 0 or not proc.stdout.strip():
        return text, "格式化失败（保持未格式化输出）: %s" % proc.stderr.decode("utf-8", "replace")[:200]
    return proc.stdout.decode("utf-8"), None


def build_all(doc):
    out = {}
    cpp_text, cpp_warn = run_formatter(render_cpp(doc), "cpp")
    out[TARGETS["cpp"]] = cpp_text
    rust_text, rust_warn = run_formatter(render_rust(doc), "rust")
    out[TARGETS["rust"]] = rust_text
    return out, [w for w in (cpp_warn, rust_warn) if w]


def diff_report(rel, want, got):
    print("✗ %s 与真源不一致" % rel, file=sys.stderr)
    for line in list(difflib.unified_diff(
            want.splitlines(keepends=True), got.splitlines(keepends=True),
            fromfile="真源生成（期望）", tofile="磁盘现状", n=2))[:40]:
        sys.stderr.write(line.rstrip("\n") + "\n")


# 实现树的根，用于诊断可达性检查。生成物本身绝不参与 —— 它逐条包含全部诊断，
# 纳入检查等于让检查恒真。
REACH_ROOTS = (
    "dataplane/packet-engine/include",
    "dataplane/packet-engine/src",
    "dataplane/packet-engine/cli",
    "dataplane/packet-engine/tests",
    "dataplane/traffic-engine/src",
)

REACH_SUFFIXES = (".h", ".hpp", ".cpp", ".cc", ".rs")


def collect_impl_text():
    """把实现树（排除生成物）拼成一段文本，供可达性检查。"""
    chunks = []
    for rel in REACH_ROOTS:
        base = ROOT / rel
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.suffix not in REACH_SUFFIXES:
                continue
            if "_gen" in path.name:
                continue
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def _is_constructed(text, ident):
    """ident 是否出现在某个**非映射分支**的行上（即疑似构造点）。

    判据：该行不含 `=>`。两端映射诊断的写法都是「分支 => 构造」同行（Rust 的 match、
    C++ 的 switch 同理不含 `=>`），因此「不含 `=>` 的出现」≈「构造点」。

    这是启发式，且刻意偏向漏报：漏报只是放过一条潜在死诊断，误报却会让正确代码通不过
    检查 —— 后者代价大得多。局限：C++ 若用 `case ...: return diag::X::code;` 这类写法，
    映射行不含 `=>`，会被误当构造点而漏报。
    """
    for line in text.splitlines():
        if ident in line and "=>" not in line:
            return True
    return False


def check_reachability(doc):
    """诊断必须真的能被触发；返回 [(code, ident, 原因)]。

    存在理由：**登记了却永远不会触发的诊断是纯负债**。它在真源里看起来是一份能力，两端
    都会为它生成结构体与渲染代码，但没有代码路径构造它；而读到它的人会以为这条校验存在。
    本批次已因此删掉三条（descriptor_size_mismatch、slot_count_mismatch、
    slot_size_mismatch）—— 同一个成因：先写了诊断，后来设计改了却没回来删。

    分两级判定，因为两类死的表现与代价不同：
      - 完全未被引用：连映射都没有，任何一侧都不会渲染它；
      - 仅出现在映射分支里：**最隐蔽的一类** —— 码、文案、渲染函数一应俱全，读起来毫无
        破绽，只是永远没人构造它。
    """
    text = collect_impl_text()
    if not text:
        print("  提示: 未找到实现树，跳过诊断可达性检查")
        return []
    problems = []
    for d in doc["diagnostics"]:
        ident = diag_ident(d["code"])
        if ident not in text:
            problems.append((d["code"], ident, "在实现树中完全未被引用"))
        elif not _is_constructed(text, ident):
            problems.append((d["code"], ident, "只出现在映射分支里，没有任何构造点"))
    return problems


def main():
    ap = argparse.ArgumentParser(description="由通道 ABI 真源生成 C++ / Rust 双端契约代码")
    ap.add_argument("--check", action="store_true", help="只校验生成物与真源是否一致，不写盘")
    args = ap.parse_args()

    doc = load_registry()
    generated, warns = build_all(doc)
    for wn in warns:
        print("  提示: %s" % wn)

    if args.check:
        stale = []
        for rel, text in generated.items():
            path = ROOT / rel
            current = path.read_text(encoding="utf-8") if path.exists() else ""
            if current != text:
                stale.append(rel)
                diff_report(rel, text, current)
        if stale:
            print("通道 ABI 生成物过期 %d 个：%s" % (len(stale), ", ".join(stale)), file=sys.stderr)
            return 1
        print("通道 ABI 生成物与真源一致（%d 个目标文件）" % len(generated))

        problems = check_reachability(doc)
        if problems:
            for code, ident, why in problems:
                print("✗ 诊断 %s（%s）%s：登记了却不可达的诊断会被读成「存在这条校验」；"
                      "请实现它，或从真源删除" % (code, ident, why), file=sys.stderr)
            return 1
        print("通道 ABI 诊断可达性通过（%d 条全部被实现引用）" % len(doc["diagnostics"]))
        return 0

    for rel, text in generated.items():
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print("  生成 %s" % rel)
    return 0


if __name__ == "__main__":
    sys.exit(main())
