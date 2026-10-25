#!/usr/bin/env python3
# gen-attributes.py —— 由属性字典单一真源生成四语言绑定。
#
# 背景（借鉴自 TSG/Maat）：规则引擎能表达什么，由「可扫描属性集合」决定。TSG 把属性
# 集合当成一等公民枚举，但其定义散落在各插件源码中，导致跨组件对齐只能靠人工。本项目
# 改为单一真源 + 代码生成：
#
#   configs/registry/attributes.json   （唯一真源，人工维护）
#           │
#           ├── services/pkg/attributes/gen.go                 （Go：policyd / 控制面）
#           ├── dataplane/traffic-engine/src/attributes_gen.rs （Rust：数据面）
#           ├── web/console/src/constants/attributes.gen.ts    （TS：控制台）
#           └── ml/training/features/attributes_gen.py         （Python：训练侧）
#
# 规范标识统一为 `ATTR_*` 大写串；各语言常量名按该语言习惯生成为派生名，
# 但**字符串值恒等于规范标识**，跨语言对齐与日志检索都以字符串为准。
#
# 用法：
#   python3 tools/codegen/gen-attributes.py            # 生成（幂等覆盖）
#   python3 tools/codegen/gen-attributes.py --check    # 只校验生成物是否与真源一致
#
# 校验（--check）用于 CI 关口（见 scripts/verify/check-attributes.sh）：手工改了生成物
# 或改了真源却忘了重新生成，都会以非 0 退出并在报告中给出文件级差异。
#
# 生成后会用该语言的格式化器（gofmt / rustfmt）后处理，保证生成物天然通过
# `gofmt -l` 与 `cargo fmt --check` 两个既有关口；格式化器缺失时跳过并提示，
# 此时生成物仍确定，但可能不满足格式关口。

import argparse
import difflib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
REGISTRY = ROOT / "configs" / "registry" / "attributes.json"

# 目标文件：语言 -> 仓库相对路径。
TARGETS = {
    "go": "services/pkg/attributes/gen.go",
    "rust": "dataplane/traffic-engine/src/attributes_gen.rs",
    "ts": "web/console/src/constants/attributes.gen.ts",
    "py": "ml/training/features/attributes_gen.py",
}

# 驼峰化时保持大写的技术缩写。缺项会退化为普通首字母大写（如 DNS 写成 Dns），
# 因此新增属性若含缩写，先补这里。
ACRONYMS = {
    "IP": "IP", "IPV6": "IPv6", "IPV4": "IPv4", "MAC": "MAC", "TCP": "TCP",
    "UDP": "UDP", "ICMP": "ICMP", "DNS": "DNS", "TLS": "TLS", "HTTP": "HTTP",
    "QUIC": "QUIC", "SSH": "SSH", "SMTP": "SMTP", "SIP": "SIP", "ASN": "ASN",
    "IOC": "IOC", "VLAN": "VLAN", "VXLAN": "VXLAN", "GRE": "GRE", "TTL": "TTL",
    "DF": "DF", "VNI": "VNI", "JA3": "JA3", "JA4": "JA4", "ML": "ML",
    "C2S": "C2S", "S2C": "S2C", "PKT": "PKT", "IAT": "IAT", "SNI": "SNI",
    "PTR": "PTR", "SAN": "SAN", "CN": "CN", "ORG": "ORG",
    "FQDN": "FQDN", "ID": "ID", "URI": "URI", "QNAME": "QName",
    "QTYPE": "QType", "QCLASS": "QClass", "RCODE": "RCode",
}

# 类型标识 -> 各语言枚举名。
TYPE_ENUM = {
    "string": "String", "bytes": "Bytes", "ip": "IP", "ip_prefix": "IPPrefix",
    "port": "Port", "u8": "U8", "u16": "U16", "u32": "U32", "u64": "U64",
    "i64": "I64", "bool": "Bool", "enum": "Enum", "string_set": "StringSet",
    "time_ms": "TimeMs",
}

# 作用域标识 -> 各语言枚举名。
SCOPE_ENUM = {
    "l2": "L2", "l3": "L3", "l4": "L4", "l5plus": "L5Plus", "tunnel": "Tunnel",
    "identity": "Identity", "flow": "Flow", "derived": "Derived",
}

# 计算阶段标识 -> 各语言枚举名。
STAGE_ENUM = {
    "packet": "Packet", "flow": "Flow", "l7": "L7", "window": "Window", "ml": "ML",
}

# Rust 枚举变体名与上面三张表一致（L5Plus / ML 等均为合法标识符）。

ID_RE = re.compile(r"^ATTR_[A-Z0-9_]+$")


# ---------------------------------------------------------------- 真源读取与校验

def load_registry():
    with open(REGISTRY, "r", encoding="utf-8") as fp:
        doc = json.load(fp)
    return doc


def validate(doc):
    """返回错误字符串列表；空列表表示真源合法。"""
    errs = []
    for key in ("version", "types", "scopes", "stages", "costs", "attributes"):
        if key not in doc:
            errs.append("真源缺少顶层字段 %r" % key)
    if errs:
        return errs

    attrs = doc["attributes"]
    if not isinstance(attrs, list) or not attrs:
        return ["attributes 必须是非空数组"]

    seen_ids = {}
    seen_go = {}
    for i, a in enumerate(attrs):
        where = "attributes[%d]" % i
        for key in ("id", "type", "scope", "stage", "cost", "source", "desc"):
            if key not in a:
                errs.append("%s 缺少字段 %r" % (where, key))
        if errs:
            continue

        aid = a["id"]
        if not ID_RE.match(aid):
            errs.append("%s 的 id %r 不符合 ATTR_[A-Z0-9_]+ 规范" % (where, aid))
        if aid in seen_ids:
            errs.append("属性 id 重复：%s（第 %d 条与第 %d 条）" % (aid, seen_ids[aid], i))
        seen_ids[aid] = i

        if a["type"] not in doc["types"]:
            errs.append("%s 的 type %r 未在 types 中登记" % (where, a["type"]))
        if a["scope"] not in doc["scopes"]:
            errs.append("%s 的 scope %r 未在 scopes 中登记" % (where, a["scope"]))
        if a["stage"] not in doc["stages"]:
            errs.append("%s 的 stage %r 未在 stages 中登记" % (where, a["stage"]))
        if a["cost"] not in (1, 2, 3):
            errs.append("%s 的 cost %r 必须是 1/2/3" % (where, a["cost"]))
        if not isinstance(a["source"], str) or not a["source"]:
            errs.append("%s 的 source 必须是非空字符串" % where)
        if not isinstance(a["desc"], str) or not a["desc"]:
            errs.append("%s 的 desc 必须是非空字符串" % where)

        gid = go_ident(aid)
        if not gid:
            errs.append("%s 的 id %r 无法转换为 Go 标识符" % (where, aid))
        elif gid in seen_go:
            errs.append("Go 标识符冲突：%s 由 %s 与 %s 同时生成"
                        % (gid, seen_go[gid], aid))
        else:
            seen_go[gid] = aid

    if not TYPE_ENUM.get("string"):
        errs.append("TYPE_ENUM 表缺失")
    for t in doc["types"]:
        if t not in TYPE_ENUM:
            errs.append("types 中的 %r 未在生成器的 TYPE_ENUM 表中映射" % t)
    for s in doc["scopes"]:
        if s not in SCOPE_ENUM:
            errs.append("scopes 中的 %r 未在生成器的 SCOPE_ENUM 表中映射" % s)
    for st in doc["stages"]:
        if st not in STAGE_ENUM:
            errs.append("stages 中的 %r 未在生成器的 STAGE_ENUM 表中映射" % st)
    return errs


# ---------------------------------------------------------------- 命名转换

def go_ident(attr_id):
    """ATTR_SRC_IP -> SrcIP；ATTR_IPV6_EXT_HEADERS -> IPv6ExtHeaders。"""
    if not attr_id.startswith("ATTR_"):
        return ""
    parts = attr_id[len("ATTR_"):].split("_")
    out = []
    for p in parts:
        if not p:
            continue
        out.append(ACRONYMS.get(p, p[:1].upper() + p[1:].lower()))
    return "".join(out)


# ---------------------------------------------------------------- 字符串转义

def go_str(s):
    out = []
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\t":
            out.append("\\t")
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


def rust_str(s):
    return go_str(s)


def json_str(s):
    # JSON 字符串字面量在 TS / Python 中同样合法（本真源不含控制字符）。
    return json.dumps(s, ensure_ascii=False)


_TS_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def ts_key(s):
    """TS 对象字面量的键。

    规范标识（string / l2 / l5_plus…）都是合法标识符，可直接裸写；但真源由人工维护，
    未来可能加入含 `-` 或 `.` 的取值 —— 那时裸写会产出语法非法的 TS。故按标识符规则
    判定，不满足就退回带引号（带引号的键在 TS 中同样合法，不影响取值）。
    """
    return s if _TS_IDENT_RE.match(s) else json_str(s)


# ---------------------------------------------------------------- 生成：Go

GO_HEADER = """// Code generated by tools/codegen/gen-attributes.py from configs/registry/attributes.json. DO NOT EDIT.
//
// 属性字典是规则引擎的「表达上限」：新增可匹配维度必须先登记到真源，再重新生成四语言绑定。
// 生成物与真源的一致性由 scripts/verify/check-attributes.sh 把关（CI 关口）。
//
// 规范标识统一为 ATTR_* 字符串；本文件的常量名是 Go 风格的派生名，值恒等于规范标识。

package attributes
"""


def render_go(doc):
    attrs = doc["attributes"]
    L = []
    L.append(GO_HEADER)

    L.append("// ValueType 是属性值类型，决定表达式字面量的解析方式与可用匹配算子。")
    L.append("type ValueType string")
    L.append("")
    L.append("// 属性值类型取值。")
    L.append("const (")
    for t in doc["types"]:
        L.append("\tValueType%s ValueType = %s" % (TYPE_ENUM[t], go_str(t)))
    L.append(")")
    L.append("")
    L.append("// typeDescs 是值类型的说明，供控制台与文档生成使用。")
    L.append("var typeDescs = map[ValueType]string{")
    for t in doc["types"]:
        L.append("\tValueType%s: %s," % (TYPE_ENUM[t], go_str(doc["types"][t])))
    L.append("}")
    L.append("")
    L.append("// Valid 判断值类型是否为已登记取值。")
    L.append("func (t ValueType) Valid() bool {")
    L.append("\t_, ok := typeDescs[t]")
    L.append("\treturn ok")
    L.append("}")
    L.append("")
    L.append("// Description 返回值类型说明；未登记时返回空串。")
    L.append("func (t ValueType) Description() string { return typeDescs[t] }")
    L.append("")

    L.append("// Scope 是属性所属的协议层/语义域。")
    L.append("type Scope string")
    L.append("")
    L.append("// 作用域取值。")
    L.append("const (")
    for s in doc["scopes"]:
        L.append("\tScope%s Scope = %s" % (SCOPE_ENUM[s], go_str(s)))
    L.append(")")
    L.append("")
    L.append("var scopeDescs = map[Scope]string{")
    for s in doc["scopes"]:
        L.append("\tScope%s: %s," % (SCOPE_ENUM[s], go_str(doc["scopes"][s])))
    L.append("}")
    L.append("")
    L.append("// Valid 判断作用域是否为已登记取值。")
    L.append("func (s Scope) Valid() bool {")
    L.append("\t_, ok := scopeDescs[s]")
    L.append("\treturn ok")
    L.append("}")
    L.append("")
    L.append("// Description 返回作用域说明；未登记时返回空串。")
    L.append("func (s Scope) Description() string { return scopeDescs[s] }")
    L.append("")

    L.append("// Stage 是属性的计算阶段，用于按需计算（lazy evaluation）：")
    L.append("// 规则只引用 packet 阶段属性时，无需付出 l7/ml 阶段的开销。")
    L.append("type Stage string")
    L.append("")
    L.append("// 计算阶段取值。")
    L.append("const (")
    for st in doc["stages"]:
        L.append("\tStage%s Stage = %s" % (STAGE_ENUM[st], go_str(st)))
    L.append(")")
    L.append("")
    L.append("var stageDescs = map[Stage]string{")
    for st in doc["stages"]:
        L.append("\tStage%s: %s," % (STAGE_ENUM[st], go_str(doc["stages"][st])))
    L.append("}")
    L.append("")
    L.append("// Valid 判断计算阶段是否为已登记取值。")
    L.append("func (s Stage) Valid() bool {")
    L.append("\t_, ok := stageDescs[s]")
    L.append("\treturn ok")
    L.append("}")
    L.append("")
    L.append("// Description 返回计算阶段说明；未登记时返回空串。")
    L.append("func (s Stage) Description() string { return stageDescs[s] }")
    L.append("")

    L.append("// Def 定义单个属性的元数据。Cost 为相对计算代价：1 低（查表/头部字段）、")
    L.append("// 2 中（流状态）、3 高（重组/解密/模型推理）。")
    L.append("type Def struct {")
    L.append("\tID     string")
    L.append("\tType   ValueType")
    L.append("\tScope  Scope")
    L.append("\tStage  Stage")
    L.append("\tCost   int")
    L.append("\tSource string")
    L.append("\tDesc   string")
    L.append("}")
    L.append("")
    L.append("// 属性规范标识常量。字符串值即跨语言对齐依据。")
    L.append("const (")
    for a in attrs:
        L.append("\t%s = %s" % (go_ident(a["id"]), go_str(a["id"])))
    L.append(")")
    L.append("")
    L.append("// defs 是全部属性的定义表，顺序与真源一致（控制台与文档按此顺序展示）。")
    L.append("var defs = []Def{")
    for a in attrs:
        L.append("\t{ID: %s, Type: ValueType%s, Scope: Scope%s, Stage: Stage%s, Cost: %d, Source: %s, Desc: %s}," % (
            go_ident(a["id"]), TYPE_ENUM[a["type"]], SCOPE_ENUM[a["scope"]],
            STAGE_ENUM[a["stage"]], a["cost"], go_str(a["source"]), go_str(a["desc"])))
    L.append("}")
    L.append("")
    L.append("// byID 是规范标识到定义下标的索引，避免每次查找线性扫描。")
    L.append("var byID = func() map[string]int {")
    L.append("\tm := make(map[string]int, len(defs))")
    L.append("\tfor i, d := range defs {")
    L.append("\t\tm[d.ID] = i")
    L.append("\t}")
    L.append("\treturn m")
    L.append("}()")
    L.append("")
    L.append("// All 返回全部属性定义的副本，调用方可安全修改返回值。")
    L.append("func All() []Def {")
    L.append("\tout := make([]Def, len(defs))")
    L.append("\tcopy(out, defs)")
    L.append("\treturn out")
    L.append("}")
    L.append("")
    L.append("// Lookup 按规范标识查找属性定义。")
    L.append("func Lookup(id string) (Def, bool) {")
    L.append("\ti, ok := byID[id]")
    L.append("\tif !ok {")
    L.append("\t\treturn Def{}, false")
    L.append("\t}")
    L.append("\treturn defs[i], true")
    L.append("}")
    L.append("")
    L.append("// MustLookup 与 Lookup 相同，但未命中时 panic —— 仅用于「属性名在编译期即确定」的")
    L.append("// 内部调用点；任何来自配置或网络的属性名都必须走 Lookup 并处理缺失分支。")
    L.append("func MustLookup(id string) Def {")
    L.append("\td, ok := Lookup(id)")
    L.append("\tif !ok {")
    L.append("\t\tpanic(\"未登记的属性标识: \" + id)")
    L.append("\t}")
    L.append("\treturn d")
    L.append("}")
    L.append("")
    L.append("// IDs 按真源顺序返回全部属性标识。")
    L.append("func IDs() []string {")
    L.append("\tout := make([]string, 0, len(defs))")
    L.append("\tfor _, d := range defs {")
    L.append("\t\tout = append(out, d.ID)")
    L.append("\t}")
    L.append("\treturn out")
    L.append("}")
    L.append("")
    L.append("// Count 返回已登记属性数量。")
    L.append("func Count() int { return len(defs) }")
    L.append("")
    L.append("// RegistryVersion 是真源版本号，供运行期上报与控制台提示。")
    L.append("const RegistryVersion = %d" % doc["version"])
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- 生成：Rust

RUST_HEADER = """// Code generated by tools/codegen/gen-attributes.py from configs/registry/attributes.json. DO NOT EDIT.
//
// 属性字典是规则引擎的「表达上限」：新增可匹配维度必须先登记到真源，再重新生成四语言绑定。
// 生成物与真源的一致性由 scripts/verify/check-attributes.sh 把关（CI 关口）。
//
// 规范标识统一为 ATTR_* 字符串；本文件的常量名是 Rust 风格的派生名，值恒等于规范标识。

/// 属性值类型，决定表达式字面量的解析方式与可用匹配算子。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttrType {
"""


def render_rust(doc):
    attrs = doc["attributes"]
    L = [RUST_HEADER]
    for t in doc["types"]:
        L.append("    %s," % TYPE_ENUM[t])
    L.append("}")
    L.append("")
    L.append("impl AttrType {")
    L.append("    /// 规范字符串（与真源 `types` 键一致）。")
    L.append("    pub const fn as_str(self) -> &'static str {")
    L.append("        match self {")
    for t in doc["types"]:
        L.append("            AttrType::%s => %s," % (TYPE_ENUM[t], rust_str(t)))
    L.append("        }")
    L.append("    }")
    L.append("")
    L.append("    /// 类型说明，供控制台与文档使用。")
    L.append("    pub const fn description(self) -> &'static str {")
    L.append("        match self {")
    for t in doc["types"]:
        L.append("            AttrType::%s => %s," % (TYPE_ENUM[t], rust_str(doc["types"][t])))
    L.append("        }")
    L.append("    }")
    L.append("}")
    L.append("")

    L.append("/// 属性所属的协议层/语义域。")
    L.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    L.append("pub enum Scope {")
    for s in doc["scopes"]:
        L.append("    %s," % SCOPE_ENUM[s])
    L.append("}")
    L.append("")
    L.append("impl Scope {")
    L.append("    /// 规范字符串（与真源 `scopes` 键一致）。")
    L.append("    pub const fn as_str(self) -> &'static str {")
    L.append("        match self {")
    for s in doc["scopes"]:
        L.append("            Scope::%s => %s," % (SCOPE_ENUM[s], rust_str(s)))
    L.append("        }")
    L.append("    }")
    L.append("")
    L.append("    /// 作用域说明。")
    L.append("    pub const fn description(self) -> &'static str {")
    L.append("        match self {")
    for s in doc["scopes"]:
        L.append("            Scope::%s => %s," % (SCOPE_ENUM[s], rust_str(doc["scopes"][s])))
    L.append("        }")
    L.append("    }")
    L.append("}")
    L.append("")

    L.append("/// 属性的计算阶段，用于按需计算：只引用 `Packet` 阶段属性的规则无需付出 `L7`/`Ml` 开销。")
    L.append("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
    L.append("pub enum Stage {")
    for st in doc["stages"]:
        L.append("    %s," % STAGE_ENUM[st])
    L.append("}")
    L.append("")
    L.append("impl Stage {")
    L.append("    /// 规范字符串（与真源 `stages` 键一致）。")
    L.append("    pub const fn as_str(self) -> &'static str {")
    L.append("        match self {")
    for st in doc["stages"]:
        L.append("            Stage::%s => %s," % (STAGE_ENUM[st], rust_str(st)))
    L.append("        }")
    L.append("    }")
    L.append("")
    L.append("    /// 计算阶段说明。")
    L.append("    pub const fn description(self) -> &'static str {")
    L.append("        match self {")
    for st in doc["stages"]:
        L.append("            Stage::%s => %s," % (STAGE_ENUM[st], rust_str(doc["stages"][st])))
    L.append("        }")
    L.append("    }")
    L.append("}")
    L.append("")

    L.append("/// 单个属性的元数据。`cost` 为相对计算代价：1 低、2 中、3 高。")
    L.append("#[derive(Debug, Clone, Copy)]")
    L.append("pub struct AttrDef {")
    L.append("    pub id: &'static str,")
    L.append("    pub ty: AttrType,")
    L.append("    pub scope: Scope,")
    L.append("    pub stage: Stage,")
    L.append("    pub cost: u8,")
    L.append("    pub source: &'static str,")
    L.append("    pub desc: &'static str,")
    L.append("}")
    L.append("")
    L.append("// 属性规范标识常量。字符串值即跨语言对齐依据。")
    for a in attrs:
        L.append("pub const %s: &str = %s;" % (a["id"], rust_str(a["id"])))
    L.append("")
    L.append("/// 全部属性的定义表，顺序与真源一致。")
    L.append("pub static ATTRIBUTES: &[AttrDef] = &[")
    for a in attrs:
        L.append("    AttrDef {")
        L.append("        id: %s," % a["id"])
        L.append("        ty: AttrType::%s," % TYPE_ENUM[a["type"]])
        L.append("        scope: Scope::%s," % SCOPE_ENUM[a["scope"]])
        L.append("        stage: Stage::%s," % STAGE_ENUM[a["stage"]])
        L.append("        cost: %d," % a["cost"])
        L.append("        source: %s," % rust_str(a["source"]))
        L.append("        desc: %s," % rust_str(a["desc"]))
        L.append("    },")
    L.append("];")
    L.append("")
    L.append("/// 按规范标识查找属性定义。")
    L.append("pub fn lookup(id: &str) -> Option<&'static AttrDef> {")
    L.append("    ATTRIBUTES.iter().find(|d| d.id == id)")
    L.append("}")
    L.append("")
    L.append("/// 已登记属性数量。")
    L.append("pub fn count() -> usize {")
    L.append("    ATTRIBUTES.len()")
    L.append("}")
    L.append("")
    L.append("/// 真源版本号，供运行期上报与诊断。")
    L.append("pub const REGISTRY_VERSION: u32 = %d;" % doc["version"])
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- 生成：TypeScript

TS_HEADER = """// Code generated by tools/codegen/gen-attributes.py from configs/registry/attributes.json. DO NOT EDIT.
//
// 属性字典是规则引擎的「表达上限」：新增可匹配维度必须先登记到真源，再重新生成四语言绑定。
// 生成物与真源的一致性由 scripts/verify/check-attributes.sh 把关（CI 关口）。
//
// 规范标识统一为 ATTR_* 字符串。本文件有两类对象的键，取法刻意不同：
//   - 枚举映射（ATTR_VALUE_TYPE / ATTR_SCOPE / ATTR_STAGE）：键是 TS 派生名（String / L2 / …），
//     值是规范标识，供 ATTR_SCOPE.L2 这种可读写法访问。
//   - 说明表（*_DESC）：键是规范标识（string / l2 / …）。因为其类型 Record<AttrScope, string>
//     里的 AttrScope 取自枚举映射的**值**联合，按值查说明才成立：ATTR_SCOPE_DESC[scope]。
"""


def render_ts(doc):
    attrs = doc["attributes"]
    L = [TS_HEADER]
    L.append("/** 属性值类型，决定表达式字面量的解析方式与可用匹配算子。 */")
    L.append("export const ATTR_VALUE_TYPE = {")
    for t in doc["types"]:
        L.append("  %s: %s," % (TYPE_ENUM[t], json_str(t)))
    L.append("} as const;")
    L.append("")
    L.append("export type AttrValueType = (typeof ATTR_VALUE_TYPE)[keyof typeof ATTR_VALUE_TYPE];")
    L.append("")
    L.append("/** 值类型说明。 */")
    L.append("export const ATTR_VALUE_TYPE_DESC: Readonly<Record<AttrValueType, string>> = {")
    # 键用**值**（规范标识）而非派生名：Record<AttrValueType, string> 的 AttrValueType 取自
    # 上面枚举映射的值联合，故按值查说明才成立。历史上误用派生名，TS 报 TS2561。
    for t in doc["types"]:
        L.append("  %s: %s," % (ts_key(t), json_str(doc["types"][t])))
    L.append("};")
    L.append("")
    L.append("/** 属性所属的协议层/语义域。 */")
    L.append("export const ATTR_SCOPE = {")
    for s in doc["scopes"]:
        L.append("  %s: %s," % (SCOPE_ENUM[s], json_str(s)))
    L.append("} as const;")
    L.append("")
    L.append("export type AttrScope = (typeof ATTR_SCOPE)[keyof typeof ATTR_SCOPE];")
    L.append("")
    L.append("/** 作用域说明。 */")
    L.append("export const ATTR_SCOPE_DESC: Readonly<Record<AttrScope, string>> = {")
    for s in doc["scopes"]:
        L.append("  %s: %s," % (ts_key(s), json_str(doc["scopes"][s])))
    L.append("};")
    L.append("")
    L.append("/** 属性的计算阶段，用于按需计算。 */")
    L.append("export const ATTR_STAGE = {")
    for st in doc["stages"]:
        L.append("  %s: %s," % (STAGE_ENUM[st], json_str(st)))
    L.append("} as const;")
    L.append("")
    L.append("export type AttrStage = (typeof ATTR_STAGE)[keyof typeof ATTR_STAGE];")
    L.append("")
    L.append("/** 计算阶段说明。 */")
    L.append("export const ATTR_STAGE_DESC: Readonly<Record<AttrStage, string>> = {")
    for st in doc["stages"]:
        L.append("  %s: %s," % (ts_key(st), json_str(doc["stages"][st])))
    L.append("};")
    L.append("")
    L.append("/** 属性规范标识常量。字符串值即跨语言对齐依据。 */")
    L.append("export const ATTR = {")
    for a in attrs:
        L.append("  %s: %s," % (a["id"][len("ATTR_"):], json_str(a["id"])))
    L.append("} as const;")
    L.append("")
    L.append("export type AttributeID = (typeof ATTR)[keyof typeof ATTR];")
    L.append("")
    L.append("/** 单个属性的元数据。cost 为相对计算代价：1 低、2 中、3 高。 */")
    L.append("export interface AttributeDef {")
    L.append("  readonly id: AttributeID;")
    L.append("  readonly type: AttrValueType;")
    L.append("  readonly scope: AttrScope;")
    L.append("  readonly stage: AttrStage;")
    L.append("  readonly cost: 1 | 2 | 3;")
    L.append("  readonly source: string;")
    L.append("  readonly desc: string;")
    L.append("}")
    L.append("")
    L.append("/** 全部属性定义，顺序与真源一致。 */")
    L.append("export const ATTRIBUTES: readonly AttributeDef[] = [")
    for a in attrs:
        L.append("  { id: ATTR.%s, type: ATTR_VALUE_TYPE.%s, scope: ATTR_SCOPE.%s, stage: ATTR_STAGE.%s, cost: %d, source: %s, desc: %s }," % (
            a["id"][len("ATTR_"):], TYPE_ENUM[a["type"]], SCOPE_ENUM[a["scope"]],
            STAGE_ENUM[a["stage"]], a["cost"], json_str(a["source"]), json_str(a["desc"])))
    L.append("];")
    L.append("")
    L.append("const BY_ID: ReadonlyMap<string, AttributeDef> = new Map(ATTRIBUTES.map((d) => [d.id, d]));")
    L.append("")
    L.append("/** 按规范标识查找属性定义。 */")
    L.append("export function lookupAttribute(id: string): AttributeDef | undefined {")
    L.append("  return BY_ID.get(id);")
    L.append("}")
    L.append("")
    L.append("/** 已登记属性数量。 */")
    L.append("export function attributeCount(): number {")
    L.append("  return ATTRIBUTES.length;")
    L.append("}")
    L.append("")
    L.append("/** 真源版本号，供控制台提示与诊断。 */")
    L.append("export const REGISTRY_VERSION = %d;" % doc["version"])
    L.append("")
    return "\n".join(L)


# ---------------------------------------------------------------- 生成：Python

PY_HEADER = '''# Code generated by tools/codegen/gen-attributes.py from configs/registry/attributes.json. DO NOT EDIT.
#
# 属性字典是规则引擎的「表达上限」：新增可匹配维度必须先登记到真源，再重新生成四语言绑定。
# 生成物与真源的一致性由 scripts/verify/check-attributes.sh 把关（CI 关口）。
#
# 规范标识统一为 ATTR_* 字符串。训练侧使用属性标识时，必须从本模块导入常量，
# 不得写字面量 —— 否则真源改名后训练与推理两侧会静默错位。
'''


def render_py(doc):
    attrs = doc["attributes"]
    L = [PY_HEADER]
    L.extend(["from __future__ import annotations", "", "from typing import TypedDict", "", "",
              "class Attribute(TypedDict):", "    id: str", "    type: str", "    scope: str",
              "    stage: str", "    cost: int", "    source: str", "    desc: str", "", ""])
    L.append("REGISTRY_VERSION = %d" % doc["version"])
    L.append("")
    L.append("# 属性值类型说明。")
    L.append("VALUE_TYPES = {")
    for t in doc["types"]:
        L.append("    %s: %s," % (json_str(t), json_str(doc["types"][t])))
    L.append("}")
    L.append("")
    L.append("# 作用域说明。")
    L.append("SCOPES = {")
    for s in doc["scopes"]:
        L.append("    %s: %s," % (json_str(s), json_str(doc["scopes"][s])))
    L.append("}")
    L.append("")
    L.append("# 计算阶段说明。")
    L.append("STAGES = {")
    for st in doc["stages"]:
        L.append("    %s: %s," % (json_str(st), json_str(doc["stages"][st])))
    L.append("}")
    L.append("")
    L.append("# 属性规范标识常量。")
    for a in attrs:
        L.append("%s = %s" % (a["id"], json_str(a["id"])))
    L.append("")
    L.append("# 全部属性定义，顺序与真源一致。")
    L.append("ATTRIBUTES: list[Attribute] = [")
    for a in attrs:
        L.append("    {")
        L.append("        \"id\": %s," % json_str(a["id"]))
        L.append("        \"type\": %s," % json_str(a["type"]))
        L.append("        \"scope\": %s," % json_str(a["scope"]))
        L.append("        \"stage\": %s," % json_str(a["stage"]))
        L.append("        \"cost\": %d," % a["cost"])
        L.append("        \"source\": %s," % json_str(a["source"]))
        L.append("        \"desc\": %s," % json_str(a["desc"]))
        L.append("    },")
    L.append("]")
    L.append("")
    L.append("ATTRIBUTE_INDEX = {a[\"id\"]: a for a in ATTRIBUTES}")
    L.append("")
    L.append("")
    L.append("def lookup(attr_id: str) -> Attribute | None:")
    L.append("    \"\"\"按规范标识返回属性定义；未登记时返回 None。\"\"\"")
    L.append("    return ATTRIBUTE_INDEX.get(attr_id)")
    L.append("")
    L.append("")
    L.append("def ids() -> list[str]:")
    L.append("    \"\"\"按真源顺序返回全部属性标识。\"\"\"")
    L.append("    return [a[\"id\"] for a in ATTRIBUTES]")
    L.append("")
    L.append("")
    L.append("def by_stage(stage: str) -> list[Attribute]:")
    L.append("    \"\"\"返回指定计算阶段的属性列表（用于按需计算的分级）。\"\"\"")
    L.append("    return [a for a in ATTRIBUTES if a[\"stage\"] == stage]")
    L.append("")
    return "\n".join(L)


RENDERERS = {"go": render_go, "rust": render_rust, "ts": render_ts, "py": render_py}


# ---------------------------------------------------------------- 格式化后处理

def run_formatter(text, kind):
    """用语言自带格式化器后处理生成文本；格式化器缺失时原样返回。

    这样生成物天然满足既有格式关口（gofmt -l 为空 / cargo fmt --check 零差异），
    无需在生成器里手工模仿 rustfmt 的换行策略。
    """
    if kind == "go":
        tool = shutil.which("gofmt")
        # gofmt 默认把格式化结果写到 stdout，必须给 -w 才会原地改写临时文件。
        args = ["-w"]
    elif kind == "rust":
        tool = shutil.which("rustfmt")
        args = ["--edition", "2021"]
    else:
        return text, True
    if not tool:
        return text, False

    suffix = {"go": ".go", "rust": ".rs"}[kind]
    fd, tmp = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    try:
        with open(tmp, "w", encoding="utf-8") as fp:
            fp.write(text)
        proc = subprocess.run([tool] + args + [tmp], capture_output=True, text=True)
        if proc.returncode != 0:
            raise SystemExit("%s 格式化失败：%s" % (tool, proc.stderr.strip()))
        with open(tmp, "r", encoding="utf-8") as fp:
            return fp.read(), True
    finally:
        os.unlink(tmp)


# ---------------------------------------------------------------- 主流程

def build_all(doc):
    """生成全部目标文本，返回 (kind -> text, kind -> 格式化器是否可用)。"""
    rendered = {}
    formatted = {}
    for kind, renderer in RENDERERS.items():
        text = renderer(doc)
        text, ok = run_formatter(text, kind)
        rendered[kind] = text
        formatted[kind] = ok
    return rendered, formatted


def diff_report(rel, want, got):
    lines = list(difflib.unified_diff(
        want.splitlines(True), got.splitlines(True),
        fromfile="真源生成结果", tofile=rel, n=2))
    if len(lines) > 60:
        lines = lines[:60] + ["... （差异过长，已截断；直接重新生成即可）\n"]
    return "".join(lines)


def main():
    ap = argparse.ArgumentParser(description="由属性字典真源生成四语言绑定")
    ap.add_argument("--check", action="store_true",
                    help="只校验生成物是否与真源一致，不写文件")
    args = ap.parse_args()

    doc = load_registry()
    errs = validate(doc)
    if errs:
        sys.stderr.write("属性字典真源校验失败（%s）：\n" % REGISTRY.relative_to(ROOT))
        for e in errs:
            sys.stderr.write("  - %s\n" % e)
        return 2

    rendered, formatted = build_all(doc)
    for kind, ok in sorted(formatted.items()):
        if not ok:
            sys.stderr.write("提示：未找到 %s 格式化器，%s 跳过格式化后处理\n"
                             % ({"go": "gofmt", "rust": "rustfmt"}[kind], TARGETS[kind]))

    if args.check:
        stale = []
        for kind, rel in sorted(TARGETS.items()):
            path = ROOT / rel
            want = rendered[kind]
            if not path.exists():
                stale.append((rel, "文件缺失", ""))
                continue
            with open(path, "r", encoding="utf-8") as fp:
                got = fp.read()
            if got != want:
                stale.append((rel, "内容与真源不一致", diff_report(rel, want, got)))
        if stale:
            sys.stderr.write("属性字典生成物已过期（%d 个）：\n" % len(stale))
            for rel, why, d in stale:
                sys.stderr.write("  - %s：%s\n" % (rel, why))
                if d:
                    sys.stderr.write(d)
            sys.stderr.write("\n修复：python3 tools/codegen/gen-attributes.py\n")
            return 1
        print("属性字典生成物与真源一致（%d 个属性 / %d 个目标文件）"
              % (len(doc["attributes"]), len(TARGETS)))
        return 0

    for kind, rel in sorted(TARGETS.items()):
        path = ROOT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(rendered[kind])
        print("生成 %s" % rel)
    print("完成：%d 个属性 -> %d 个语言绑定" % (len(doc["attributes"]), len(TARGETS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
