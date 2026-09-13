#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-prometheus-format.py —— Prometheus 文本暴露格式（version 0.0.4）严格校验器。

用途：独立校验各服务 `GET /metrics` 的响应是否合法。刻意用 Python 重新实现一套
解析逻辑（而非复用 Go 侧代码），以便在「实现有系统性误解」时能真正发现问题。

用法：
    check-prometheus-format.py <文件路径>
    curl -s http://127.0.0.1:8080/metrics | check-prometheus-format.py -

校验项：
  1. 不得存在空行（文本格式不允许）
  2. `# HELP <name> <text>` / `# TYPE <name> <type>` 语法合法，name 字符集合规
  3. 每个指标族至多一条 HELP / TYPE，且 TYPE 出现在该族样本之前
  4. 样本行：`<name>[{labels}] <value> [<timestamp>]` 语法合法
  5. 标签：名称合规、双引号闭合、转义序列合法（仅 \\\\ \\" \\n）
  6. 数值：合法浮点，支持 NaN / +Inf / -Inf；可选时间戳为整数
  7. counter 族名必须以 _total 结尾
  8. 每条样本所属族必须有 TYPE 声明（本仓库自定契约，比规范更严）
  9. histogram 必须提供 _bucket（含 le 标签）/ _sum / _count 三件套
 10. histogram 的 le 值按「标签集（不含 le）」分组后必须严格递增且最后为 +Inf
 11. histogram 同一标签集内 +Inf 桶计数必须等于 _count
 12. 同一族内不得出现重复序列（名称 + 标签集合完全相同）

退出码：0 = 全部通过；1 = 存在违规；2 = 用法错误。
"""
from __future__ import annotations

import re
import sys

METRIC_NAME_RE = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
LABEL_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")
TYPE_LINE_RE = re.compile(r"^#\s+TYPE\s+(\S+)\s+(\S+)\s*$")
HELP_LINE_RE = re.compile(r"^#\s+HELP\s+(\S+)\s+(.*)$")
VALID_TYPES = {"counter", "gauge", "histogram", "summary", "untyped"}

# 数值：合法浮点 / 特殊值。时间戳为可选整数。
VALUE_RE = re.compile(
    r"^(?P<name>[a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?P<labels>\{.*\})?"
    r"\s+(?P<value>[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|NaN|[+-]?Inf)"
    r"(?:\s+(?P<ts>[0-9]+))?\s*$"
)

# 标签对：name="value"，value 中 \" \\ \n 为合法转义。
LABEL_PAIR_RE = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"$')
VALID_ESCAPES = {"\\\\", '\\"', "\\n"}


class Problem(Exception):
    """表示一处格式违规。"""


def parse_labels(raw: str, lineno: int) -> list[tuple[str, str]]:
    """解析 `{k="v",...}`；返回按序的 (name, value) 列表。"""
    if not (raw.startswith("{") and raw.endswith("}")):
        raise Problem(f"第 {lineno} 行：标签块未正确闭合: {raw!r}")
    inner = raw[1:-1]
    if inner == "":
        return []
    pairs: list[tuple[str, str]] = []
    for chunk in split_label_pairs(inner, lineno):
        m = LABEL_PAIR_RE.match(chunk)
        if not m:
            raise Problem(f"第 {lineno} 行：标签对语法非法: {chunk!r}")
        name, value = m.group(1), m.group(2)
        if not LABEL_NAME_RE.match(name):
            raise Problem(f"第 {lineno} 行：标签名非法: {name!r}")
        check_escapes(value, lineno)
        pairs.append((name, value))
    return pairs


def split_label_pairs(inner: str, lineno: int) -> list[str]:
    """按逗号切分标签对，但忽略处于引号内的逗号。"""
    out: list[str] = []
    buf: list[str] = []
    in_quotes = False
    escaped = False
    for ch in inner:
        if escaped:
            buf.append(ch)
            escaped = False
            continue
        if ch == "\\":
            buf.append(ch)
            escaped = True
            continue
        if ch == '"':
            in_quotes = not in_quotes
            buf.append(ch)
            continue
        if ch == "," and not in_quotes:
            out.append("".join(buf))
            buf = []
            continue
        buf.append(ch)
    if in_quotes:
        raise Problem(f"第 {lineno} 行：标签值引号未闭合")
    out.append("".join(buf))
    return out


def check_escapes(value: str, lineno: int) -> None:
    """校验转义序列仅使用规范允许的三种。"""
    i = 0
    while i < len(value):
        if value[i] == "\\":
            if i + 1 >= len(value):
                raise Problem(f"第 {lineno} 行：标签值以孤立反斜杠结尾")
            seq = value[i : i + 2]
            if seq not in VALID_ESCAPES:
                raise Problem(f"第 {lineno} 行：非法转义序列 {seq!r}")
            i += 2
            continue
        i += 1


def format_label_set(label_set: tuple) -> str:
    """把标签集格式化为 `{k="v",...}`，用于错误信息中指明具体序列；空集返回空串。"""
    if not label_set:
        return ""
    inner = ",".join(f'{k}="{v}"' for k, v in label_set)
    return "{" + inner + "}"


def validate(text: str) -> list[str]:
    """执行全部校验，返回违规描述列表（空列表表示通过）。"""
    errors: list[str] = []

    # family -> {"type": str, "help": bool}
    families: dict[str, dict] = {}
    # family -> {标签集(不含 le) -> [(le_value, count), ...]} 用于校验直方图分桶。
    # 必须按标签集分组：不同 method/route 的桶各自构成独立序列，串接会误报
    # 「+Inf -> 0.001 未严格递增」这类假阳性。
    hist_buckets: dict[str, dict[tuple, list[tuple[float, int]]]] = {}
    # family -> {标签集(不含 le) -> _count 值} 用于校验 +Inf 桶与 _count 一致
    hist_counts: dict[str, dict[tuple, int]] = {}
    hist_parts: dict[str, set[str]] = {}
    # (name, labels_tuple) -> lineno，用于重复序列检测
    seen_series: dict[tuple[str, tuple], int] = {}

    lines = text.split("\n")
    # 去掉尾部单个换行造成的空串
    if lines and lines[-1] == "":
        lines.pop()

    for idx, line in enumerate(lines, start=1):
        if line.strip() == "":
            errors.append(f"第 {idx} 行：存在空行（文本格式不允许空行）")
            continue

        if line.startswith("#"):
            m = TYPE_LINE_RE.match(line) or HELP_LINE_RE.match(line)
            if not m:
                errors.append(f"第 {idx} 行：注释行语法非法: {line!r}")
                continue
            kind = "TYPE" if line.lstrip().startswith("# TYPE") else "HELP"
            name = m.group(1)
            if not METRIC_NAME_RE.match(name):
                errors.append(f"第 {idx} 行：注释中的指标名非法: {name!r}")
                continue
            fam = families.setdefault(name, {"type": None, "help": False})
            if kind == "TYPE":
                typ = m.group(2)
                if typ not in VALID_TYPES:
                    errors.append(f"第 {idx} 行：非法类型 {typ!r}")
                    continue
                if fam["type"] is not None:
                    errors.append(f"第 {idx} 行：指标族 {name} 重复声明 TYPE")
                    continue
                if fam["help"] is False and seen_family_samples(name, seen_series):
                    errors.append(f"第 {idx} 行：TYPE 声明出现在样本之后（族 {name}）")
                fam["type"] = typ
            else:
                if fam["help"]:
                    errors.append(f"第 {idx} 行：指标族 {name} 重复声明 HELP")
                    continue
                fam["help"] = True
            continue

        # ---- 样本行 ----
        m = VALUE_RE.match(line)
        if not m:
            errors.append(f"第 {idx} 行：样本行语法非法: {line!r}")
            continue

        name = m.group("name")
        label_pairs = parse_labels(m.group("labels"), idx) if m.group("labels") else []
        raw_value = m.group("value")

        # 所属族必须已声明 TYPE（本仓库契约）
        base = family_of(name, families)
        if base is None:
            errors.append(f"第 {idx} 行：样本 {name} 所属指标族未声明 TYPE")
        else:
            typ = families[base]["type"]
            if typ == "counter" and not base.endswith("_total"):
                errors.append(f"第 {idx} 行：counter 族名 {base} 未以 _total 结尾")
            if typ == "histogram":
                hist_parts.setdefault(base, set())

        # 数值合法性
        if raw_value not in ("NaN", "+Inf", "-Inf", "Inf"):
            try:
                float(raw_value)
            except ValueError:
                errors.append(f"第 {idx} 行：数值非法 {raw_value!r}")

        # 重复序列检测
        key = (name, tuple(sorted(label_pairs)))
        if key in seen_series:
            errors.append(
                f"第 {idx} 行：与第 {seen_series[key]} 行重复的序列 {name}{m.group('labels') or ''}"
            )
        else:
            seen_series[key] = idx

        # 直方图分桶
        if base and families.get(base, {}).get("type") == "histogram":
            if name == base + "_bucket":
                les = [v for (k, v) in label_pairs if k == "le"]
                if not les:
                    errors.append(f"第 {idx} 行：histogram bucket 缺少 le 标签")
                else:
                    le = les[0]
                    if le == "+Inf":
                        val = float("inf")
                    else:
                        try:
                            val = float(le)
                        except ValueError:
                            errors.append(f"第 {idx} 行：le 值非法 {le!r}")
                            continue
                    try:
                        count = int(float(raw_value))
                    except ValueError:
                        count = 0
                    label_set = tuple(sorted((k, v) for (k, v) in label_pairs if k != "le"))
                    hist_buckets.setdefault(base, {}).setdefault(label_set, []).append((val, count))
                hist_parts[base].add("_bucket")
            elif name == base + "_sum":
                hist_parts[base].add("_sum")
            elif name == base + "_count":
                hist_parts[base].add("_count")
                label_set = tuple(sorted((k, v) for (k, v) in label_pairs if k != "le"))
                try:
                    hist_counts.setdefault(base, {})[label_set] = int(float(raw_value))
                except ValueError:
                    pass
            elif name == base:
                errors.append(f"第 {idx} 行：histogram 族不应直接暴露裸样本 {name}")

    # ---- 直方图完整性 ----
    for base, parts in hist_parts.items():
        for suffix in ("_bucket", "_sum", "_count"):
            if suffix not in parts:
                errors.append(f"histogram 族 {base} 缺少 {suffix}")

    for base, by_labels in hist_buckets.items():
        for label_set, buckets in by_labels.items():
            where = f"{base}{format_label_set(label_set)}"
            # 同一标签集内按出现顺序校验 le 严格递增
            for i in range(1, len(buckets)):
                if buckets[i][0] <= buckets[i - 1][0]:
                    errors.append(
                        f"histogram 序列 {where} 的 le 未严格递增："
                        f"{buckets[i-1][0]} -> {buckets[i][0]}"
                    )
            if buckets and buckets[-1][0] != float("inf"):
                errors.append(f"histogram 序列 {where} 的 le 未以 +Inf 收尾")
            # 累积计数单调不减
            for i in range(1, len(buckets)):
                if buckets[i][1] < buckets[i - 1][1]:
                    errors.append(
                        f"histogram 序列 {where} 的 bucket 计数非累积递减："
                        f"{buckets[i-1][1]} -> {buckets[i][1]}"
                    )
            # +Inf 桶计数必须等于 _count（Prometheus 服务端据此判定 histogram 合法性）
            cnt = hist_counts.get(base, {}).get(label_set)
            if (
                cnt is not None
                and buckets
                and buckets[-1][0] == float("inf")
                and buckets[-1][1] != cnt
            ):
                errors.append(
                    f"histogram 序列 {where} 的 +Inf 桶计数 {buckets[-1][1]} "
                    f"与 _count {cnt} 不一致"
                )

    # ---- 每个 sample 族的 TYPE 必须存在 ----
    for base, info in families.items():
        if info["type"] is None:
            errors.append(f"指标族 {base} 声明了 HELP 但缺少 TYPE")

    return errors


def seen_family_samples(name: str, seen: dict) -> bool:
    """判断是否已有该族（或其后缀子样本）的样本被解析过。"""
    prefix = name
    for (sname, _labels) in seen:
        if sname == prefix or sname.startswith(prefix + "_"):
            return True
    return False


def family_of(sample_name: str, families: dict[str, dict]) -> str | None:
    """由样本名反查所属指标族（处理 _bucket/_sum/_count 后缀）。"""
    if sample_name in families:
        return sample_name
    for suffix in ("_bucket", "_sum", "_count"):
        if sample_name.endswith(suffix):
            base = sample_name[: -len(suffix)]
            if base in families:
                return base
    # 兜底：找最长前缀匹配
    best = None
    for fam in families:
        if sample_name.startswith(fam + "_"):
            if best is None or len(fam) > len(best):
                best = fam
    return best


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] in ("-h", "--help"):
        print(__doc__.strip(), file=sys.stderr)
        return 2

    path = argv[1]
    if path == "-":
        text = sys.stdin.read()
        source = "<stdin>"
    else:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            print(f"无法读取 {path}: {exc}", file=sys.stderr)
            return 2
        source = path

    if text.strip() == "":
        print(f"✗ {source}: 输出为空，无任何指标内容")
        return 1

    errors = validate(text)

    fam_count = len(
        {ln.split()[2] for ln in text.split("\n") if ln.startswith("# TYPE")}
    )
    sample_count = len(
        [
            ln
            for ln in text.split("\n")
            if ln.strip() and not ln.startswith("#")
        ]
    )

    if errors:
        print(f"✗ {source}: 发现 {len(errors)} 处格式违规（{fam_count} 族 / {sample_count} 条样本）")
        for e in errors[:40]:
            print("   -", e)
        if len(errors) > 40:
            print(f"   ... 另有 {len(errors) - 40} 处")
        return 1

    print(f"✓ {source}: Prometheus 文本格式合法（{fam_count} 个指标族 / {sample_count} 条样本）")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
