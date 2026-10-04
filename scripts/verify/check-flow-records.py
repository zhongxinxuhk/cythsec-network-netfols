#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-flow-records.py —— FlowRecord 与 tshark 的逐条交叉核验（内置反向自检）。

为什么需要它：
    `cythsec-analyze` 产出的 FlowRecord 是**我们自己**算出来的。Rust 单测里的期望值
    是手写的，但它们验证的是"实现符合我的理解"；只要理解本身错了，期望值会和实现
    一起错，测试照样全绿。tshark 是**独立实现**：它按自己的解析器给出逐帧事实
    （IP 头长度、TCP 标志位、载荷长度、协议识别）。把这些事实聚合成会话级结果并与
    我们的记录逐项比对，是这条数据链目前唯一的外部证据。

核验项（每项单独计数，最后打印"比对 N 项"）：
    1. 会话集合：记录里的流与 tshark 看到的会话**一一对应**（多一条/少一条都失败）。
    2. 包数 / 字节数 / 双向包数与字节数。字节口径 = IP 载荷长度（含四层头），
       tshark 侧由 `ip.len - ip.hdr_len` 或 `ipv6.plen` 独立算出。
    3. 方向切换次数、首末时间戳、时长。
    4. TCP 末态 / 发起方 / 是否中途接入：判定规则由**独立重写的第二实现**给出
       （输入是 tshark 的标志位序列），不是抄 Rust 的迁移表。规则覆盖不到的组合
       打印 `SKIP`，绝不静默算作通过。
    5. 应用识别列：tshark 的协议栈含 tls/dns/http 而我们报了别的 → 失败（假阳性）；
       tshark 没有这三种协议而我们却"识别"出了其中一个 → 失败（凭空断言）；
       我们有 `need_more`/`unknown` 而 tshark 靠重组看全了 → 显式 SKIP（未核验）。
    6. 解码失败计数：tshark 认出的非首片分片数必须等于统计里的
       `decode.non_initial_fragment` 计数（读不了的包必须显式计数）。
    7. 统计自证：`packets_read` == tshark 帧数、`records` == 会话数。

反向故障注入（--self-test）：
    把每一项都改坏一次（包数 +1、字节 −1、状态改写、发起方翻转、应用改写、
    删一条会话、重复一条会话、改 tshark 事实、改统计摘要……），**要求核验程序
    对每一次都报错**。不这么做的后果是：核验器写错了（比如恒返回 0 个失败）
    也能一路绿灯 —— 而"绿色的通过"和"绿色的没跑"长得一模一样。

用法：
    check-flow-records.py --pair LABEL:MODE:RECORDS.jsonl:FACTS.tsv:STATS.txt [...]
    check-flow-records.py --self-test --pair ...
    check-flow-records.py --check-facts FACTS.tsv        # 只打印事实摘要（排查用）

MODE 为 tolerant 或 strict，对应分析器跑的是默认模式还是 --strict。

退出码：0 全部一致；1 存在不一致或"什么都没比对"；2 输入/参数错误。
"""

import argparse
import copy
import ipaddress
import json
import sys

# tsv 的列顺序，必须与 check-flow-records.sh 里 tshark 的 -e 顺序完全一致。
# 顺序错了不会报错，只会把相邻两列的值对调 —— 所以这里连列名一起写下来核对。
TSV_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "ip.proto",
    "ipv6.nxt",
    "ip.len",
    "ip.hdr_len",
    "ipv6.plen",
    "ip.frag_offset",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.flags",
    "tcp.len",
    "frame.protocols",
]

APP_HINTS = ("tls", "dns", "http")

# 统计摘要里必须出现的键：缺了说明 stderr 格式变了，而格式变了就没法交叉核验。
STATS_REQUIRED = (
    "packets_read",
    "packets_decoded",
    "decode_errors",
    "sessions",
    "emitted",
    "non_finite_feature_vectors",
    "counter_mismatches",
    "sorted_by_key",
)


class Failure(Exception):
    """参数/输入层面的错误（与"核验不一致"区分开）。"""


def _i(v):
    """tshark 的 `tcp.flags` 是 `0x0012` 这种十六进制串，端口/长度是十进制。"""
    if v in ("", None):
        return None
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def new_fact():
    return {
        "frames": 0,
        "bytes": 0,
        "fwd_frames": 0,
        "rev_frames": 0,
        "fwd_bytes": 0,
        "rev_bytes": 0,
        "first_us": None,
        "last_us": None,
        "switches": 0,
        "order": [],
        "protocols": set(),
        "tcp": {
            "syn_sides": [],
            "synack": 0,
            "fin_sides": [],
            "rst": 0,
            "data_bytes": 0,
            "ack_sides": [],
        },
    }


def parse_facts(path):
    """把 tshark 的逐帧输出聚合成会话级事实。"""
    facts = {}
    frag_skipped = 0
    frame_count = 0
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            parts = line.split("|")
            if len(parts) != len(TSV_FIELDS):
                raise Failure(
                    f"{path}:{lineno} 列数 {len(parts)} != {len(TSV_FIELDS)}："
                    "tshark 的 -e 顺序与 TSV_FIELDS 不一致"
                )
            f = dict(zip(TSV_FIELDS, parts))
            frame_count += 1
            src = f["ip.src"] or f["ipv6.src"]
            dst = f["ip.dst"] or f["ipv6.dst"]
            if not src or not dst:
                raise Failure(f"第 {f['frame.number']} 帧没有 IP 地址（非 IP 帧？）")
            proto = _i(f["ip.proto"]) if f["ip.proto"] else _i(f["ipv6.nxt"])
            if proto is None:
                raise Failure(f"第 {f['frame.number']} 帧读不到协议号")
            # 非首片分片没有四层头：我们跳过并计数，这里把它排除在会话之外。
            if _i(f["ip.frag_offset"]):
                frag_skipped += 1
                continue
            if f["ip.len"] and f["ip.hdr_len"]:
                payload = int(f["ip.len"]) - int(f["ip.hdr_len"])
            elif f["ipv6.plen"]:
                payload = int(f["ipv6.plen"])
            else:
                raise Failure(f"第 {f['frame.number']} 帧算不出 IP 载荷长度")
            sport = _i(f["tcp.srcport"]) or _i(f["udp.srcport"]) or 0
            dport = _i(f["tcp.dstport"]) or _i(f["udp.dstport"]) or 0

            a, b = (src, sport), (dst, dport)
            # 规范端点序：先比 IP 的字节序（网络序 = 数值序），再比端口 —— 与
            # FlowKey::canonical 同规则。规则若不一致，会话集合核对会立刻炸。
            if (ipaddress.ip_address(a[0]).packed, a[1]) <= (
                ipaddress.ip_address(b[0]).packed,
                b[1],
            ):
                fwd, rev, side = a, b, "fwd"
            else:
                fwd, rev, side = b, a, "rev"
            key = (fwd[0], fwd[1], rev[0], rev[1], proto)
            e = facts.setdefault(key, new_fact())
            ts_us = int(round(float(f["frame.time_epoch"]) * 1_000_000))
            e["frames"] += 1
            e["bytes"] += payload
            e[f"{side}_frames"] += 1
            e[f"{side}_bytes"] += payload
            e["first_us"] = ts_us if e["first_us"] is None else min(e["first_us"], ts_us)
            e["last_us"] = ts_us if e["last_us"] is None else max(e["last_us"], ts_us)
            if e["order"] and e["order"][-1] != side:
                e["switches"] += 1
            e["order"].append(side)
            for p in (f["frame.protocols"] or "").split(":"):
                if p:
                    e["protocols"].add(p)

            flags = _i(f["tcp.flags"]) or 0
            if proto == 6:
                syn, ack = bool(flags & 0x02), bool(flags & 0x10)
                fin, rst = bool(flags & 0x01), bool(flags & 0x04)
                t = e["tcp"]
                if rst:
                    t["rst"] += 1
                elif syn and ack:
                    t["synack"] += 1
                elif syn:
                    t["syn_sides"].append(side)
                elif fin:
                    t["fin_sides"].append(side)
                else:
                    t["data_bytes"] += _i(f["tcp.len"]) or 0
                    if ack:
                        t["ack_sides"].append(side)
    return facts, frag_skipped, frame_count


def expected_tcp_state(e, mode):
    """独立重写的第二实现：由 tshark 的标志位序列推出 TCP 末态。

    返回 (期望状态, 说明) 或 (None, 跳过原因)。规则只覆盖能被标志位序列唯一确定的
    情形；覆盖不到就明确 SKIP —— "没核验"绝不能冒充"核验通过"。
    """
    t = e["tcp"]
    init = t["syn_sides"][0] if t["syn_sides"] else None
    if t["rst"]:
        return "reset", "见到 RST"
    if init is None:
        if mode == "strict":
            return "closed", "无 SYN + 严格模式：拒绝采纳"
        return "established", "无 SYN + 容忍模式：采纳为已建立"
    if not t["synack"]:
        return "syn_sent", "只有 SYN，没有 SYN+ACK"
    fin = t["fin_sides"]
    if not fin:
        return ("established", "握手完成且未见到 FIN") if t["synack"] else (None, "握手未完成")
    first_fin = fin[0]
    both = set(fin) == {"fwd", "rev"}
    if both and first_fin == init:
        return "time_wait", "先发 FIN 的是发起方，双方 FIN 均已见到"
    if both:
        return "last_ack", "先发 FIN 的是被动方，双方 FIN 均已见到"
    if first_fin == init:
        other = "rev" if init == "fwd" else "fwd"
        if other in t["ack_sides"]:
            return "fin_wait2", "发起方先 FIN 且收到对方 ACK"
        return "fin_wait1", "发起方先 FIN，未见对方 ACK"
    if init is not None and first_fin != init:
        return "close_wait", "被动方先 FIN"
    return None, "关闭序列组合未覆盖"


def app_hint(e):
    for p in sorted(e["protocols"]):
        if p in APP_HINTS:
            return p
    return None


def parse_stats(path):
    """解析 analyze 的 stderr 摘要（`key=value` 行）。"""
    stats = {"decode_error": {}}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("[cythsec-analyze]"):
                continue
            body = line[len("[cythsec-analyze]") :].strip()
            if body.startswith("decode_error "):
                kv = dict(p.split("=", 1) for p in body.split() if "=" in p)
                stats["decode_error"][kv.get("code", "?")] = int(kv.get("count", 0))
                continue
            for part in body.split():
                if "=" in part:
                    k, v = part.split("=", 1)
                    if v in ("true", "false"):
                        # stderr 里是 true/false（Rust bool），比对方是整数口径。
                        stats[k] = 1 if v == "true" else 0
                        continue
                    try:
                        stats[k] = int(v)
                    except ValueError:
                        stats[k] = v
    missing = [k for k in STATS_REQUIRED if k not in stats]
    if missing:
        raise Failure(f"{path}: 统计摘要缺少 {missing}（stderr 格式变了？）")
    return stats


def key_of(r):
    fl = r["flow"]
    return (fl["src_ip"], fl["src_port"], fl["dst_ip"], fl["dst_port"], fl["proto"])


def compare(records, facts, stats, frag_skipped, frame_count, mode, label, verbose=True):
    """核心比对。返回 (checked, skipped, failures)。"""
    checked = [0]
    skipped = [0]
    failures = []

    def chk(name, got, want):
        checked[0] += 1
        if got != want:
            failures.append(f"[{label}] {name}: 得到 {got!r}，tshark 事实是 {want!r}")

    def skip(reason):
        skipped[0] += 1
        if verbose:
            print(f"  SKIP({reason}) {label}")

    # 会话集合必须一一对应（多一条/少一条都是失败）。
    got_keys = sorted(key_of(r) for r in records)
    want_keys = sorted(facts.keys())
    checked[0] += 1
    if got_keys != want_keys:
        only_rec = [k for k in got_keys if k not in want_keys]
        only_tshark = [k for k in want_keys if k not in got_keys]
        failures.append(
            f"[{label}] 会话集合不一致：记录多出 {only_rec}，tshark 多出 {only_tshark}"
        )

    for r in records:
        k = key_of(r)
        e = facts.get(k)
        if e is None:
            continue
        tag = f"{k[0]}:{k[1]}->{k[2]}:{k[3]}/{k[4]}"
        c, fe, t = r["counters"], r["features"], r["tcp"]
        chk(f"{tag} packets", c["packets"], e["frames"])
        chk(f"{tag} bytes", c["bytes"], e["bytes"])
        chk(f"{tag} fwd_packets", fe["fwd_packets"], e["fwd_frames"])
        chk(f"{tag} rev_packets", fe["rev_packets"], e["rev_frames"])
        chk(f"{tag} fwd_bytes", fe["fwd_bytes"], e["fwd_bytes"])
        chk(f"{tag} rev_bytes", fe["rev_bytes"], e["rev_bytes"])
        chk(f"{tag} direction_switches", c["direction_switches"], e["switches"])
        chk(f"{tag} features.direction_switches", fe["direction_switches"], e["switches"])
        chk(f"{tag} first_seen_us", r["time"]["first_seen_us"], e["first_us"])
        chk(f"{tag} last_seen_us", r["time"]["last_seen_us"], e["last_us"])
        chk(f"{tag} duration_us", r["time"]["duration_us"], e["last_us"] - e["first_us"])
        chk(f"{tag} features.duration_us", fe["duration_us"], e["last_us"] - e["first_us"])
        chk(f"{tag} packets == features.packets", c["packets"], fe["packets"])
        chk(f"{tag} bytes == features.bytes", c["bytes"], fe["bytes"])

        # ---- 发起方 / 中途接入 ----
        init = e["tcp"]["syn_sides"][0] if e["tcp"]["syn_sides"] else None
        chk(f"{tag} initiator", t["initiator"], init if k[4] == 6 else None)
        # 「中途接入」只对 TCP 有意义：UDP/ICMP 没有握手，谈不上"没看到握手"。
        chk(
            f"{tag} adopted_midstream",
            t["adopted_midstream"],
            k[4] == 6 and mode == "tolerant" and init is None,
        )
        chk(f"{tag} 非 TCP 无状态", t["state"] is None, k[4] != 6)

        # ---- TCP 末态（第二实现；规则覆盖不到就 SKIP）----
        if k[4] == 6:
            want, why = expected_tcp_state(e, mode)
            if want is None:
                skip(f"{tag} {why}")
            else:
                chk(f"{tag} tcp_state（{why}）", t["state"], want)

        # ---- 应用识别 ----
        hint = app_hint(e)
        app = r["app"]
        if hint is None:
            # tshark 没看到 tls/dns/http：我们也不许"识别"出这三个之一。
            # 这一项**是**核验（"没有凭空断言"本身就是一个可证伪的断言），
            # 不算跳过 —— 跳过只留给"确实没能比对"的情形。
            checked[0] += 1
            if app["outcome"] == "identified":
                failures.append(
                    f"[{label}] {tag} 应用假阳性：我们报 {app['app']}，"
                    f"tshark 协议栈只有 {sorted(e['protocols'])}"
                )
        elif app["outcome"] == "identified":
            chk(f"{tag} app", app["app"], hint)
        else:
            # 例如只抓到请求的一半：我们给 need_more/unknown，tshark 靠重组看全了。
            # 这是**未核验**，不是通过。
            skip(f"{tag} 应用未识别（我们 {app['outcome']}，tshark 看到 {hint}）")

    # ---- 统计自证（分析器自己说的话也要被检）----
    chk("frames_read", stats["packets_read"], frame_count)
    chk("sessions", stats["sessions"], len(records))
    chk("emitted", stats["emitted"], len(records))
    chk(
        "non_initial_fragment 计数",
        stats["decode_error"].get("decode.non_initial_fragment", 0),
        frag_skipped,
    )
    chk("decode_errors 总数", stats["decode_errors"], frag_skipped)
    chk("特征向量有限性", stats["non_finite_feature_vectors"], 0)
    chk("会话与特征计数一致性", stats["counter_mismatches"], 0)
    chk("输出有序", stats["sorted_by_key"], 1)
    return checked[0], skipped[0], failures


def load_pair(spec):
    parts = spec.split(":")
    if len(parts) != 5:
        raise Failure(f"--pair 需要 LABEL:MODE:RECORDS:TSV:STATS 五段，收到 `{spec}`")
    label, mode, records, tsv, stats = parts
    if mode not in ("tolerant", "strict"):
        raise Failure(f"MODE 只能是 tolerant 或 strict，收到 `{mode}`")
    facts, frag, frames = parse_facts(tsv)
    with open(records, encoding="utf-8") as fh:
        recs = [json.loads(line) for line in fh if line.strip()]
    return label, mode, recs, facts, parse_stats(stats), frag, frames


def self_test(label, mode, recs, facts, stats, frag, frames, checked_in, fails):
    """反向故障注入：每一项都改坏一次，要求核验程序报错。"""
    print(f"-- 反向故障注入 {label}")
    base_c, _, base_f = compare(copy.deepcopy(recs), facts, stats, frag, frames, mode, label)
    if base_f:
        fails.append(f"[{label}] 自检前提不成立：原始数据本身就没通过")
        return checked_in

    def mutate(name, fn):
        r2 = copy.deepcopy(recs)
        f2 = copy.deepcopy(facts)
        fn(r2, f2)
        _, _, out = compare(r2, f2, stats, frag, frames, mode, label, verbose=False)
        if not out:
            fails.append(f"[{label}] 注入「{name}」未被检出 —— 核验器对这一项是瞎的")
            print(f"   未检出 ← 注入「{name}」")
        else:
            print(f"   已检出 ← 注入「{name}」：{out[0][:100]}")

    def mut_stats(name, fn):
        s2 = copy.deepcopy(stats)
        fn(s2)
        _, _, out = compare(
            copy.deepcopy(recs), copy.deepcopy(facts), s2, frag, frames, mode, label,
            verbose=False,
        )
        if not out:
            fails.append(f"[{label}] 注入「{name}」未被检出")
            print(f"   未检出 ← 注入「{name}」")
        else:
            print(f"   已检出 ← 注入「{name}」：{out[0][:100]}")

    if recs:
        mutate(
            "包数 +1",
            lambda r, e: r[0]["counters"].__setitem__("packets", r[0]["counters"]["packets"] + 1),
        )
        mutate(
            "字节 −1",
            lambda r, e: r[0]["counters"].__setitem__("bytes", r[0]["counters"]["bytes"] - 1),
        )
        mutate(
            "方向切换 +1",
            lambda r, e: r[0]["counters"].__setitem__(
                "direction_switches", r[0]["counters"]["direction_switches"] + 1
            ),
        )
        mutate(
            "首见时间 +1µs",
            lambda r, e: r[0]["time"].__setitem__(
                "first_seen_us", r[0]["time"]["first_seen_us"] + 1
            ),
        )
        mutate(
            "TCP 状态改为另一个合法状态",
            lambda r, e: r[0]["tcp"].__setitem__(
                "state", "time_wait" if r[0]["tcp"]["state"] != "time_wait" else "closed"
            ),
        )
        mutate(
            "中途接入标记翻转",
            lambda r, e: r[0]["tcp"].__setitem__(
                "adopted_midstream", not r[0]["tcp"]["adopted_midstream"]
            ),
        )
        mutate(
            "发起方翻转",
            lambda r, e: r[0]["tcp"].__setitem__(
                "initiator",
                {"fwd": "rev", "rev": "fwd"}.get(r[0]["tcp"]["initiator"], "fwd"),
            ),
        )

        def app_mut(r, e):
            cur = r[0]["app"]["app"]
            hint = app_hint(e.get(key_of(r[0]), {"protocols": set()}))
            cand = [a for a in APP_HINTS if a != cur and a != hint]
            r[0]["app"].update({"outcome": "identified", "app": cand[0], "app_id": 9})

        mutate("应用改写为不可能的值", app_mut)
        mutate("删掉一条会话", lambda r, e: r.pop(0))
        mutate("重复一条会话", lambda r, e: r.append(copy.deepcopy(r[0])))
        mutate(
            "fwd_packets +1",
            lambda r, e: r[0]["features"].__setitem__(
                "fwd_packets", r[0]["features"]["fwd_packets"] + 1
            ),
        )
        # tshark 一侧被改坏（证明核验不是只单向相信自己的输出）
        mutate("tshark 事实里的包数 +1", lambda r, e: e[key_of(r[0])].__setitem__(
            "frames", e[key_of(r[0])]["frames"] + 1))
        mutate("tshark 事实里多一条会话", lambda r, e: e.__setitem__(
            ("9.9.9.9", 1, "8.8.8.8", 2, 6), new_fact()))

    mut_stats("统计 packets_read +1", lambda s: s.__setitem__("packets_read", s["packets_read"] + 1))
    mut_stats("统计 counter_mismatches 改为 1", lambda s: s.__setitem__("counter_mismatches", 1))
    mut_stats(
        "统计 non_initial_fragment 计数 +1",
        lambda s: s["decode_error"].__setitem__(
            "decode.non_initial_fragment", s["decode_error"].get("decode.non_initial_fragment", 0) + 1
        ),
    )

    # "什么都没比对"必须失败（空输入不能算通过）
    _, _, empty_out = compare([], {}, stats, 0, 0, mode, label)
    if not empty_out:
        fails.append(f"[{label}] 空输入竟被判定为通过")
        print("   未检出 ← 注入「空输入」")
    else:
        print(f"   已检出 ← 注入「空输入」：{empty_out[0][:100]}")
    return checked_in


def run(pairs, do_self_test):
    checked_total = 0
    skipped_total = 0
    failures = []
    for spec in pairs:
        label, mode, recs, facts, stats, frag, frames = load_pair(spec)
        print(
            f"== {label}（{mode}）: 记录 {len(recs)} 条，tshark 会话 {len(facts)} 条，"
            f"帧 {frames} 个，非首片分片 {frag} 个"
        )
        c, s, f = compare(copy.deepcopy(recs), facts, stats, frag, frames, mode, label)
        checked_total += c
        skipped_total += s
        failures += f
        for line in f:
            print("FAIL " + line)
        if do_self_test:
            checked_total = self_test(
                label, mode, recs, facts, stats, frag, frames, checked_total, failures
            )

    print(
        f"\ntshark 交叉核验：比对 {checked_total} 项，跳过 {skipped_total} 项"
        "（跳过 = 未核验，不计入通过）"
    )
    if checked_total == 0:
        print("FAIL 一项都没比对 —— 「没跑」绝不能算「通过」")
        return 1
    if failures:
        print(f"FAIL 共 {len(failures)} 项不一致")
        return 1
    print("FlowRecord 与 tshark 的逐帧事实一致")
    return 0


def main():
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--pair", action="append", default=[])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--check-facts")
    args = ap.parse_args()
    try:
        if args.check_facts:
            facts, frag, frames = parse_facts(args.check_facts)
            print(f"帧 {frames} 个，会话 {len(facts)} 条，非首片分片 {frag} 个")
            for k, v in sorted(facts.items()):
                print(
                    f"  {k[0]}:{k[1]}->{k[2]}:{k[3]}/{k[4]} frames={v['frames']} "
                    f"bytes={v['bytes']} switches={v['switches']} "
                    f"protocols={sorted(v['protocols'])}"
                )
            return 0
        if not args.pair:
            raise Failure("至少需要一个 --pair")
        return run(args.pair, args.self_test)
    except Failure as e:
        print(f"输入错误：{e}", file=sys.stderr)
        return 2
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"输入错误：{type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
