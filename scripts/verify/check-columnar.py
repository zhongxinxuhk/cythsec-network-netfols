#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-columnar.py —— 列式落盘（ClickHouse `Native`）门禁的独立解码器与比对器。

## 为什么单独写一份解码器（而不是用 Rust 的）

Rust 侧的编码器与解码器**同源自证**：一起写错时两边照样互相通过。这个风险
2026-10-19 真实发生过 —— 编码器把「全部列头写完再写数据」，解码器照同一种
错误布局写，401 项测试全绿，而参考实现根本读不进去。

本文件按 `docs`/模块头里**写下的规范**独立实现（不 import 仓库里任何 Rust 常量、
不读 Rust 源码取宽度），只依赖 ClickHouse Native 的公开字节规则：

    块    := varint(列数) varint(行数) (列名 列类型 [掩码] 数据)*
    列名/列类型 := varint(字节数) 字节
    UIntN := N/8 字节小端        Float64 := 8 字节 IEEE754 小端
    IPv6  := 16 字节（大端序，与 IPv6NumToString 同序）
    String:= varint(长度) 字节
    Nullable(T) := 每行 1 字节掩码(1=NULL) **后接全部行的嵌套值**

## 子命令

  compare       --native N --jsonl J --columns-tsv T
      解出每一格，与 JSONL 逐格比对。期望值规则来自 TSV 第 5 列（由
      `cythsec-dump-ddl` 生成，**不在此手抄**）；出现不认识的规则 ⇒ 判红。
  compare-ch    --clickhouse-tsv C --jsonl J --columns-tsv T
      与上一样的比对，但取值来自**真实 ClickHouse 读回我们产物**后的输出。
      这一条才回答"第三方能不能把我们的文件读对"。
  inject        --name 名字 --in N --out N2
      产出一个被改坏的副本（7 种，见 INJECTIONS），要求比对器每次报错。
  self-test     --native N --jsonl J --columns-tsv T
      ① 不改动时必须通过；② 每种注入都必须被判红；③ 另附一组**手算**的
      varint/Nullable 单元校验（不依赖任何仓库产物）。

退出码：0 通过；1 比对不一致 / 注入未被检出 / 规则不认识；2 用法错误；3 前置缺失。
"""

import argparse
import ipaddress
import json
import os
import struct
import sys

NULL = object()


def fail(msg):
    print("    ✗ " + msg, file=sys.stderr)
    return 1


def ok(msg):
    print("    ✓ " + msg)


# ---------------------------------------------------------------------------
# Native 解码（按规范独立实现）
# ---------------------------------------------------------------------------
FIXED = {"UInt8": 1, "UInt16": 2, "UInt32": 4, "UInt64": 8, "Float64": 8, "IPv6": 16}


class DecodeError(Exception):
    pass


def read_varint(buf, pos):
    """无符号 LEB128。返回 (值, 新位置)。超过 10 字节即报错。"""
    val = 0
    shift = 0
    n = 0
    while True:
        if pos >= len(buf):
            raise DecodeError(f"第 {pos} 字节处读 varint 时数据提前结束")
        b = buf[pos]
        pos += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, pos
        shift += 7
        n += 1
        if n > 10:
            raise DecodeError(f"第 {pos} 字节处 varint 超过 10 字节")


def read_text(buf, pos):
    at = pos
    n, pos = read_varint(buf, pos)
    if pos + n > len(buf):
        raise DecodeError(f"第 {at} 字节处读标识符（需 {n} 字节）时数据提前结束")
    raw = buf[pos:pos + n]
    try:
        return raw.decode("utf-8"), pos + n
    except UnicodeDecodeError as e:
        raise DecodeError(f"第 {at} 字节处标识符不是合法 UTF-8：{e}")


def split_nullable(ty):
    if ty.startswith("Nullable(") and ty.endswith(")"):
        return ty[len("Nullable("):-1], True
    return ty, False


def decode_blocks(buf):
    """返回 [{"rows": n, "columns": [(name, ty)], "cells": [[cell,...] 每列一行]}]。

    cell 是 (kind, value)：kind ∈ U8/U16/U32/U64/F64/STR/IP6/NULL。
    """
    pos = 0
    blocks = []
    while pos < len(buf):
        ncols, pos = read_varint(buf, pos)
        nrows, pos = read_varint(buf, pos)
        heads = []
        cells = []
        for _ in range(ncols):
            name, pos = read_text(buf, pos)
            ty, pos = read_text(buf, pos)
            inner, nullable = split_nullable(ty)
            col = []
            masks = None
            if nullable:
                if pos + nrows > len(buf):
                    raise DecodeError(f"列 {name}：第 {pos} 字节处读 null 掩码时数据提前结束")
                masks = buf[pos:pos + nrows]
                pos += nrows
            for ri in range(nrows):
                is_null = bool(nullable and masks[ri] != 0)
                if inner == "String":
                    ln, pos = read_varint(buf, pos)
                    if pos + ln > len(buf):
                        raise DecodeError(
                            f"列 {name} 第 {ri} 行：第 {pos} 字节处读 {ln} 字节字符串时结束")
                    raw = buf[pos:pos + ln]
                    pos += ln
                    if is_null:
                        if raw:
                            raise DecodeError(
                                f"列 {name} 第 {ri} 行标为 NULL 却带非空哑值（{len(raw)} 字节）")
                        col.append(("NULL", None))
                    else:
                        col.append(("STR", raw.decode("utf-8", "replace")))
                else:
                    w = FIXED.get(inner)
                    if w is None:
                        raise DecodeError(
                            f"列 {name} 的类型 `{ty}` 是本解码器不认识的格式："
                            "拒绝按猜的宽度跳过（猜错会让之后每一列都错位）")
                    if pos + w > len(buf):
                        raise DecodeError(f"列 {name} 第 {ri} 行：第 {pos} 字节处数据提前结束")
                    raw = buf[pos:pos + w]
                    pos += w
                    if is_null:
                        col.append(("NULL", None))
                    elif inner == "UInt8":
                        col.append(("U8", raw[0]))
                    elif inner == "UInt16":
                        col.append(("U16", struct.unpack("<H", raw)[0]))
                    elif inner == "UInt32":
                        col.append(("U32", struct.unpack("<I", raw)[0]))
                    elif inner == "UInt64":
                        col.append(("U64", struct.unpack("<Q", raw)[0]))
                    elif inner == "Float64":
                        col.append(("F64", struct.unpack("<d", raw)[0]))
                    else:
                        col.append(("IP6", bytes(raw)))
            heads.append((name, ty))
            cells.append(col)
        blocks.append({"rows": nrows, "columns": heads, "cells": cells})
    if not blocks:
        raise DecodeError("空的 Native 块流")
    # 块间列集合必须一致（同一文件内列名/类型不一致 ⇒ 按名取数会拿到别的意思）
    base = blocks[0]["columns"]
    for i, b in enumerate(blocks[1:], start=1):
        if b["columns"] != base:
            for j, (h0, h1) in enumerate(zip(base, b["columns"])):
                if h0 != h1:
                    raise DecodeError(
                        f"第 {i} 块第 {j} 列与第 0 块不一致：{h0} vs {h1}"
                        f"（列数 {len(base)} vs {len(b['columns'])}）")
            raise DecodeError(
                f"第 {i} 块列数与第 0 块不同：{len(b['columns'])} vs {len(base)}")
    return blocks


def flat_cells(blocks):
    out = []
    for b in blocks:
        rows = [[] for _ in range(b["rows"])]
        for ci, _ in enumerate(b["columns"]):
            for ri in range(b["rows"]):
                rows[ri].append(b["cells"][ci][ri])
        for r in rows:
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# 列清单与期望值
# ---------------------------------------------------------------------------
def load_columns(path):
    cols = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) < 6:
                raise SystemExit(
                    f"列映射表 {path} 第 {len(cols)+1} 行只有 {len(parts)} 个字段（需 6）："
                    "期望值规则来自这张表，缺列会让整类比对悄悄不跑")
            cols.append({"name": parts[0], "type": parts[1], "group": parts[2],
                         "jsonl": parts[3], "expect": parts[4], "comment": parts[5]})
    return cols


def json_get(rec, path):
    cur = rec
    for key in path.split("."):
        if not isinstance(cur, dict) or key not in cur:
            raise KeyError(path)
        cur = cur[key]
    return cur


def expected_cell(c, rec):
    """返回 (kind, value) 或 ("NULL", None)。规则不认识时抛 ValueError。"""
    rule = c["expect"]
    if rule == "derived:family":
        return ("U8", 6 if ":" in str(json_get(rec, "flow.src_ip")) else 4)
    if rule == "derived:duration_us":
        first = int(json_get(rec, "time.first_seen_us"))
        last = int(json_get(rec, "time.last_seen_us"))
        return ("U64", max(0, last - first))
    if rule.startswith("derived:ip_text:"):
        text = str(json_get(rec, rule.split(":", 2)[2]))
        ip = ipaddress.ip_address(text)
        if ip.version == 4:
            return ("IP6", ip.packed[:0] + b"\x00" * 10 + b"\xff\xff" + ip.packed)
        return ("IP6", ip.packed)
    if rule.startswith("const:"):
        return ("U32", int(rule.split(":", 1)[1]))
    if rule.startswith("json:"):
        v = json_get(rec, rule.split(":", 1)[1])
        if v is None:
            return ("NULL", None)
        ty = c["type"]
        if isinstance(v, bool):
            return ("U8", 1 if v else 0)
        if ty == "String" or ty.endswith("(String)"):
            return ("STR", str(v))
        if ty.startswith("Float64") or ty == "Nullable(Float64)":
            return ("F64", float(v))
        if ty.startswith("IPv6"):
            ip = ipaddress.ip_address(str(v))
            return ("IP6", ip.packed if ip.version == 6 else b"\x00" * 10 + b"\xff\xff" + ip.packed)
        return ("INT", int(v))
    raise ValueError(rule)


def cell_matches(kind, want, got_kind, got):
    # NULL 必须与 NULL 对上：把"缺值"读成 0/空串是本格式最危险的静默篡改，
    # 因此这一支单独存在，而不是靠"got == want"里 None 恰好相等。
    if kind == "NULL":
        return got_kind == "NULL"
    if got_kind == "NULL":
        return False
    if kind == "F64":
        return got == want
    if kind == "INT":
        return got_kind in ("U8", "U16", "U32", "U64") and got == want
    return got == want


# ---------------------------------------------------------------------------
# 比对
# ---------------------------------------------------------------------------
def do_compare(args):
    buf = open(args.native, "rb").read()
    try:
        blocks = decode_blocks(buf)
    except DecodeError as e:
        print(f"    ✗ 解码失败：{e}", file=sys.stderr)
        return 1
    recs = [json.loads(l) for l in open(args.jsonl, encoding="utf-8") if l.strip()]
    cols = load_columns(args.columns_tsv)
    names = [h[0] for b in blocks[:1] for h in b["columns"]]
    if names != [c["name"] for c in cols]:
        return fail(
            f"产物列序与列契约不一致（产物 {len(names)} 列 / 契约 {len(cols)} 列）："
            f"{names[:3]} vs {[c['name'] for c in cols][:3]}")
    rows = flat_cells(blocks)
    if len(rows) != len(recs):
        return fail(f"产物 {len(rows)} 行，JSONL {len(recs)} 行 —— 两个出口必须同序同数")
    compared = bad = 0
    first_errs = []
    for ri, (row, rec) in enumerate(zip(rows, recs)):
        for ci, c in enumerate(cols):
            try:
                kind, want = expected_cell(c, rec)
            except ValueError:
                return fail(f"列 {c['name']} 的期望规则 `{c['expect']}` 本比对器不认识")
            except KeyError:
                return fail(f"列 {c['name']} 要 JSONL 路径 `{c['expect']}`，但该记录里没有它")
            got_kind, got = row[ci]
            compared += 1
            if not cell_matches(kind, want, got_kind, got):
                bad += 1
                if len(first_errs) < 10:
                    first_errs.append(
                        f"      第 {ri} 行 列 {c['name']}（{c['type']}）：期望 {kind}={want!r}，"
                        f"得到 {got_kind}={got!r}")
    if bad:
        print(f"    ✗ {bad}/{compared} 格不一致（rows={len(rows)} cols={len(cols)}）",
              file=sys.stderr)
        print("\n".join(first_errs), file=sys.stderr)
        return 1
    print(f"    ✓ 逐格比对通过：compared={compared} rows={len(rows)} "
          f"columns={len(cols)} blocks={len(blocks)} bytes={len(buf)}")
    return 0


def do_compare_clickhouse(args):
    """ClickHouse 读回我们产物后的输出 vs JSONL。这才是"第三方读得对"的证据。"""
    cols = load_columns(args.columns_tsv)
    recs = [json.loads(l) for l in open(args.jsonl, encoding="utf-8") if l.strip()]
    lines = [l.rstrip("\n") for l in open(args.clickhouse_tsv, encoding="utf-8") if l.strip("\n") != ""]
    if len(lines) != len(recs):
        return fail(f"ClickHouse 返回 {len(lines)} 行，JSONL {len(recs)} 行")
    bad = compared = 0
    errs = []
    for ri, (line, rec) in enumerate(zip(lines, recs)):
        vals = line.split("\t")
        if len(vals) != len(cols):
            return fail(f"第 {ri} 行有 {len(vals)} 字段，应为 {len(cols)}（列数变了）")
        for ci, c in enumerate(cols):
            raw = vals[ci]
            got = None if raw == "\\N" else raw
            try:
                kind, want = expected_cell(c, rec)
            except ValueError:
                return fail(f"列 {c['name']} 的期望规则 `{c['expect']}` 不认识")
            compared += 1
            if got is None:
                if kind == "NULL":
                    continue
                bad += 1
                errs.append(f"      第 {ri} 行 列 {c['name']}：期望 {want!r}，ClickHouse 给 NULL")
                continue
            if kind == "NULL":
                bad += 1
                errs.append(f"      第 {ri} 行 列 {c['name']}：期望 NULL，得到 {got!r}")
                continue
            if kind == "F64":
                try:
                    same = abs(float(got) - float(want)) <= 1e-9 * max(1.0, abs(float(want)))
                except ValueError:
                    same = False
            elif kind in ("U8", "U16", "U32", "U64", "INT"):
                # 整数一律按整数比：UInt64 可以超过 2^53，走 float() 会在"两边都掉到
                # 同一个近似值"时**假装相等**。
                try:
                    same = int(want) == int(got)
                except ValueError:
                    same = False
            elif kind == "IP6":
                # 比对走文本列（DDL 的 ALIAS），所以这里比的是"反解出来的地址文本"。
                # 期望值规则：`::ffff:` 映射地址必须反解成点分十进制，其余按 IPv6 文本。
                # 这正是 DDL 里 `if(ip_family = 4, substring(...,8), ...)` 的语义，
                # 但这里用 Python 的 ipaddress 独立算一遍，不跟着 SQL 的写法自证。
                ip = ipaddress.ip_address(bytes(want))
                if ip.version == 6 and ip.ipv4_mapped is not None:
                    want_txt = str(ip.ipv4_mapped)
                else:
                    want_txt = str(ip)
                same = want_txt == got
            else:
                same = str(want) == got_n if False else str(want) == got
            if not same:
                bad += 1
                if len(errs) < 12:
                    errs.append(f"      第 {ri} 行 列 {c['name']}：期望 {want!r} 得到 {got!r}")
    if bad:
        print(f"    ✗ ClickHouse 读回值与 JSONL 有 {bad}/{compared} 处不一致", file=sys.stderr)
        print("\n".join(errs), file=sys.stderr)
        return 1
    print(f"    ✓ ClickHouse 独立读回逐格相符：compared={compared} rows={len(recs)}")
    return 0


# ---------------------------------------------------------------------------
# 反向故障注入
# ---------------------------------------------------------------------------
def walk_columns(buf):
    """按规范走一遍产物，返回每个 (块, 列) 的**字节区间**。

    注入器必须靠这个定位，而不是写死偏移：列一多、块一碎，写死的偏移就会
    "落在无关字节上"，于是注入看似跑了其实什么都没测（这类空注入比没注入更坏）。
    返回 [(block_index, name, type, mask_range, payload_ranges)]
    """
    pos = 0
    out = []
    bi = 0
    while pos < len(buf):
        ncols, pos = read_varint(buf, pos)
        nrows, pos = read_varint(buf, pos)
        for _ in range(ncols):
            name, pos = read_text(buf, pos)
            ty, pos = read_text(buf, pos)
            inner, nullable = split_nullable(ty)
            mask_rng = None
            if nullable:
                mask_rng = (pos, pos + nrows)
                pos += nrows
            payloads = []
            for ri in range(nrows):
                start = pos
                if inner == "String":
                    ln, pos = read_varint(buf, pos)
                    pos += ln
                else:
                    w = FIXED.get(inner)
                    if w is None:
                        raise DecodeError(f"列 {name} 的类型 `{ty}` 不认识，无法定位注入点")
                    pos += w
                payloads.append((start, pos))
            out.append((bi, name, ty, mask_rng, payloads))
        bi += 1
    return out


def find_column(buf, column, occurrence=-1):
    """取某列在**最后一个**含它的块里的位置信息。"""
    hits = [h for h in walk_columns(buf) if h[1] == column]
    if not hits:
        raise ValueError(f"产物里没有列 {column}")
    return hits[0] if occurrence < 0 else hits[occurrence]


INJECTIONS = {
    # 掩码翻转：帧结构完好、解码不报错，**只有比对能抓到**（NULL ↔ 0.0 互换）。
    # 位置由 walk_columns() 结构化定位：risk_score 是最后一列，取它第 0 行的掩码字节。
    "null-mask": lambda b: _flip_mask(b, "risk_score"),
    # 定宽列改一个字节：值变，帧不变（同样结构化定位到 session_id 第 0 行的最高字节）
    "value-byte": lambda b: _flip_payload(b, "session_id", -1),
    # 类型名换成不认识的形式：解码必须拒绝（不许靠猜宽度跳过）。
    # IPv6 的类型名字面量是 varint(4) + "IPv6" —— 长度前缀一起换，
    # 否则会退化成"改了个不存在的字节"的空注入（这个错在 2026-10-19 真踩过）。
    "type-name": lambda b: _replace_once(b, b"\x04IPv6", b"\x0cFixedString?"),
    # 行数 +1：帧长与内容矛盾，必须报错
    "row-count": lambda b: _put(b, 1, bytes([b[1] + 1])),
    # 截断尾部
    "truncate": lambda b: b[:-16],
    # 交换两列的列名（等长，帧不变，只有比对能抓）
    # 两条名字都从产物结构里取（等长才行），换名之后帧不变、只有比对能抓
    "swap-names": lambda b: _swap_names(b, "src_port", "dst_port"),
    # 变长列长度 +1：从这一列起整体错位
    "string-len": lambda b: _bump_first_str_len(b),
}


def _flip_mask(buf, column):
    _bi, name, _ty, mask_rng, _pl = find_column(buf, column)
    if mask_rng is None:
        raise ValueError(f"列 {column} 不是 Nullable，无法注入掩码")
    at = mask_rng[0]
    return buf[:at] + bytes([buf[at] ^ 0x01]) + buf[at + 1:]


def _flip_payload(buf, column, byte_index):
    _bi, name, _ty, _mr, payloads = find_column(buf, column)
    start, end = payloads[0]
    at = max(start, min(end - 1, start + (byte_index % (end - start))))
    return buf[:at] + bytes([buf[at] ^ 0x01]) + buf[at + 1:]


def _replace_once(b, x, y):
    if b.find(x) < 0:
        raise ValueError(f"注入目标 `{x}` 不在产物里（说明注入已与线路格式脱节）")
    return b.replace(x, y, 1)


def _put(buf, at, new):
    assert len(new) == 1, "单字节注入"
    return buf[:at] + new + buf[at + 1:]


def _swap_names(b, x, y):
    """交换两列的**列名**。

    选的是 `src_port`/`dst_port`：等长（8 字节）、同类型（UInt16），所以换名之后
    帧结构与每个字段的宽度都不变 —— 只有"按名取值比对"能发现源端口被读成了目的端口。
    等长与同类型都在函数里断言，改列名后这条注入不会退化成空注入。
    """
    hx, hy = find_column(b, x), find_column(b, y)
    if len(x) != len(y):
        raise ValueError(f"注入要求两列名等长，实际 {len(x)} vs {len(y)}")
    if hx[2] != hy[2]:
        raise ValueError(f"注入要求两列同类型，实际 {hx[2]} vs {hy[2]}")
    return _swap(b, x.encode(), y.encode())


def _swap(b, x, y):
    """把第一次出现的 x 换成 y、第一次出现的 y 换成 x（两者等长时才可用）。"""
    i, j = b.find(x), b.find(y)
    if i < 0 or j < 0:
        raise ValueError("注入目标不存在")
    assert len(x) == len(y)
    out = bytearray(b)
    out[i:i + len(x)] = y
    out[j:j + len(y)] = x
    return bytes(out)


def _bump_first_str_len(b):
    """找到第一个 String 列的数据长度 varint 并 +1。

    定位方式：块头之后按规范走到 proto_name（第一个 String 列）的数据段。
    这里**刻意不硬编码偏移**：列一多偏移就会变，写死的注入会退化成"注入落在无关字节上"。
    """
    pos = 0
    ncols, pos = read_varint(b, pos)
    nrows, pos = read_varint(b, pos)
    for _ in range(ncols):
        name, pos = read_text(b, pos)
        ty, pos = read_text(b, pos)
        inner, nullable = split_nullable(ty)
        if inner == "String" and not nullable:
            ln, at = read_varint(b, pos)
            data_at = pos
            return b[:data_at] + bytes([ln + 1]) + b[data_at + 1:]
        if nullable:
            pos += nrows
        w = FIXED.get(inner)
        pos += nrows * (w if w else 1)
    raise ValueError("没找到非空的 String 列")


def do_inject(args):
    fn = INJECTIONS.get(args.name)
    if fn is None:
        return fail(f"没有注入 `{args.name}`，可用：{' '.join(sorted(INJECTIONS))}")
    buf = open(args.src, "rb").read()
    try:
        out = fn(buf)
    except (ValueError, AssertionError) as e:
        return fail(f"注入 `{args.name}` 无法施加：{e}")
    with open(args.out, "wb") as fh:
        fh.write(out)
    print(f"    注入 {args.name}：{len(buf)} → {len(out)} 字节")
    return 0


# ---------------------------------------------------------------------------
# 自证
# ---------------------------------------------------------------------------
def hand_checks():
    """不依赖任何仓库产物的手算单元校验（规范本身也要能被单独钉住）。"""
    # varint：与参考实现产物里观察到的取值一致（200000 = c0 9a 0c）
    for val, enc in [(0, b"\x00"), (1, b"\x01"), (127, b"\x7f"), (128, b"\x80\x01"),
                     (200000, b"\xc0\x9a\x0c")]:
        got, pos = read_varint(enc, 0)
        assert got == val and pos == len(enc), f"varint({val}) 解成 {got}"
    # 手工搭一个 Nullable(UInt8) 的块：1 列 / 2 行 / 第 2 行是 NULL（仍带哑值 0）
    buf = bytearray()
    buf += b"\x01\x02"
    name = b"x"
    ty = b"Nullable(UInt8)"
    buf += bytes([len(name)]) + name + bytes([len(ty)]) + ty
    buf += b"\x00\x01"          # 掩码：第一行有值、第二行 NULL
    buf += b"\x07\x00"          # 嵌套值：两行都写（第二行是哑值）
    blocks = decode_blocks(bytes(buf))
    assert blocks[0]["cells"][0] == [("U8", 7), ("NULL", None)], blocks[0]["cells"]
    # 少写哑值时必须报错，而不是"看起来解出来了"
    try:
        decode_blocks(bytes(buf[:-1]))
        raise AssertionError("少一字节却仍解码成功 ⇒ 长度校验没生效")
    except DecodeError:
        pass
    # 未知类型必须拒绝
    try:
        decode_blocks(b"\x01\x01\x01a\x14LowCardinality(String)\x01b")
        raise AssertionError("不认识的类型被跳过了")
    except DecodeError:
        pass
    ok(f"手算校验通过（varint {5} 例 / Nullable 掩码与哑值 / 未知类型拒绝）")
    return 0


def do_self_test(args):
    rc = hand_checks()
    if rc:
        return rc
    buf = open(args.native, "rb").read()
    if not buf:
        print("    ✗ 没有产物可比对", file=sys.stderr)
        return 3
    base = argparse.Namespace(native=args.native, jsonl=args.jsonl, columns_tsv=args.columns_tsv)
    if do_compare(base) != 0:
        return fail("未注入时比对就失败了：基线不成立，后面的注入判红没有意义")
    caught = 0
    tmp = args.native + ".inj"
    for name in sorted(INJECTIONS):
        fn = INJECTIONS[name]
        try:
            mutated = fn(buf)
        except (ValueError, AssertionError) as e:
            print(f"    ✗ 注入 {name} 无法施加：{e}", file=sys.stderr)
            return 1
        if mutated == buf:
            print(f"    ✗ 注入 {name} 没有改变任何字节 ⇒ 该注入是空的", file=sys.stderr)
            return 1
        with open(tmp, "wb") as fh:
            fh.write(mutated)
        rc = do_compare(argparse.Namespace(native=tmp, jsonl=args.jsonl,
                                           columns_tsv=args.columns_tsv))
        if rc == 0:
            print(f"    ✗ 注入 `{name}` **未被检出**（比对仍通过）", file=sys.stderr)
            return 1
        print(f"    ✓ 注入 {name} 被判红")
        caught += 1
    os.unlink(tmp)
    print(f"    ✓ 反向故障注入 {caught}/{len(INJECTIONS)} 全部被检出")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("compare", "self-test"):
        p = sub.add_parser(name)
        p.add_argument("--native", required=True)
        p.add_argument("--jsonl", required=True)
        p.add_argument("--columns-tsv", required=True)
    p = sub.add_parser("compare-ch")
    p.add_argument("--clickhouse-tsv", required=True)
    p.add_argument("--jsonl", required=True)
    p.add_argument("--columns-tsv", required=True)
    p = sub.add_parser("inject")
    p.add_argument("--name", required=True, choices=sorted(INJECTIONS))
    p.add_argument("--src", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("decode-info")
    p.add_argument("--native", required=True)
    p = sub.add_parser("list-injections")
    args = ap.parse_args(argv)

    if args.cmd == "compare":
        return do_compare(args)
    if args.cmd == "compare-ch":
        return do_compare_clickhouse(args)
    if args.cmd == "self-test":
        return do_self_test(args)
    if args.cmd == "inject":
        return do_inject(args)
    if args.cmd == "decode-info":
        blocks = decode_blocks(open(args.native, "rb").read())
        print(f"blocks={len(blocks)} rows={sum(b['rows'] for b in blocks)} "
              f"columns={len(blocks[0]['columns'])}")
        return 0
    if args.cmd == "list-injections":
        for k in sorted(INJECTIONS):
            print(k)
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
