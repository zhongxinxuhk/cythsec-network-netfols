#!/usr/bin/env python3
"""check-ipfix-export.py —— IPFIX 导出的**第三方交叉核验** + 反向故障注入。

为什么需要这一步：
  导出的 IPFIX 是"我们编码、我们自测"的产物。Rust 单测里的金标准字节只能证明
  "实现符合我写下的规范理解"，证明不了**我的理解对**。tshark 的 IPFIX/NetFlow 解析器
  是上游独立实现，它把报文字节解成字段值这件事，是当前唯一的外部证据。

比对口径（两侧同源、路径完全不同）：
  - 左：`cythsec-analyze` 自己写的 JSONL（记录内容）
  - 右：tshark 解 `--ipfix-pcap` 产物得到的 IPFIX 字段（编码正确性 + 协议合法性）
  逐条比对九类字段（JSON 输出），时标另走 PDML 的**原始字段字节**（见下），
  并核对报文级不变量（版本/长度/序列号/模板可见性/刷新节奏）。

为什么时标不用 JSON 里渲染好的字符串：**同一份产物在不同 tshark 版本上渲染不同**
（macOS 4.6.9 给 `2023-11-14T22:13:30.016000000Z`，Rocky 4.4.2 给本地化的
`Nov 15, 2023 06:13:30`）。解析渲染串等于把第三方工具的时间显示偏好当成协议事实。
PDML 的 `value=` 是该 IE 的**线上原始字节**（IE 152/153 是 8 字节毫秒），
与显示偏好、locale、版本都无关 —— 拿它与 JSONL 的毫秒值比才是"逐字节"的核验。

反向故障注入（--self-test，全部注入在**产物字节**上，不需要重新编译）：
  ① 改掉一条数据记录的计数值      ② 把数据集 setID 改成未定义值
  ③ 改掉报文头 length              ④ 截掉最后一个 datagram
  ⑤ 改掉 IE 152 的原始 8 字节（专门守"时标比对"这条断言）
  注入未被检出 = 比对器失效（"绿色的通过"和"绿色的没跑"长得一样），判失败。

用法：check-ipfix-export.py --pair <label>:<jsonl>:<ipfix.pcap>[:<模板刷新周期>] [...]
                            [--self-test] [--refresh N]
      每条 pair 可自带刷新周期（第 4 段），缺省用 --refresh。
退出码：0 一致且注入全被检出；1 不一致/注入未检出；2 产物缺失；3 环境不满足。
"""

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree

TSHARK = os.environ.get("TSHARK", "tshark")

# (说明, tshark 侧记录字段名, 由 JSONL 记录推出期望字符串的函数)
FIELD_SPECS = [
    ("源地址", "src", lambda r: r["flow"]["src_ip"]),
    ("目的地址", "dst", lambda r: r["flow"]["dst_ip"]),
    ("源端口", "srcport", lambda r: str(r["flow"]["src_port"])),
    ("目的端口", "dstport", lambda r: str(r["flow"]["dst_port"])),
    ("协议号", "protocol", lambda r: str(r["flow"]["proto"])),
    ("字节数", "octets", lambda r: str(r["counters"]["bytes"])),
    ("包数", "packets", lambda r: str(r["counters"]["packets"])),
    ("流 id", "flowid", lambda r: str(r["session_id"])),
    ("采样间隔", "sampling", lambda r: "1"),
]


class Fail(Exception):
    pass


def collect(node, name, out):
    """递归收集某个字段名下的所有取值。

    tshark 的 JSON 形状不固定：同一个 Set 里只有一个模板时，`cflow.template_id`
    会挂在 `Template (Id = 256, Count = 11)` 子节点下；有多个模板时又是另一种排布。
    按"字段名"递归收集，而不是按固定的键路径取值——固定路径会在样本一换就炸。
    """
    if isinstance(node, dict):
        for k, v in node.items():
            if k == name:
                out.append(v)
            else:
                collect(v, name, out)
    elif isinstance(node, list):
        for item in node:
            collect(item, name, out)


def run_tshark_json(pcap):
    proc = subprocess.run([TSHARK, "-r", pcap, "-T", "json"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise Fail(f"tshark 打不开产物：{proc.stderr.strip()[:200]}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise Fail(f"tshark 输出不是合法 JSON：{e}")


def malformed_frames(pcap):
    proc = subprocess.run(
        [TSHARK, "-r", pcap, "-Y", "_ws.malformed", "-T", "fields", "-e", "frame.number"],
        capture_output=True,
        text=True,
    )
    return [l.strip() for l in proc.stdout.split("\n") if l.strip()]


def extract(tshark_json):
    """把 tshark JSON 压成报文列表（消息级字段 + 逐条数据记录）。"""
    msgs = []
    for frame in tshark_json:
        layers = frame["_source"]["layers"]
        cflow = layers.get("cflow")
        if not cflow:
            raise Fail("tshark 没有把产物识别成 IPFIX（cflow 层缺失）")
        msg = {
            "version": int(cflow["cflow.version"]),
            "len": int(cflow["cflow.len"]),
            "sequence": int(cflow["cflow.sequence"]),
            "od_id": int(cflow["cflow.od_id"]),
            "templates": [],
            "records": [],
            "frame_number": int(layers["frame"]["frame.number"]),
            "udp_len": int(layers["udp"]["udp.length"]) if "udp" in layers else None,
        }
        for key, val in cflow.items():
            if key.startswith("Set ") and "Data Template" in key:
                ids = []
                collect(val, "cflow.template_id", ids)
                if not ids:
                    raise Fail(f"模板集 `{key}` 里没有 template_id")
                msg["templates"].extend(int(i) for i in ids)
            elif key.startswith("Set ") and "flows" in key:
                set_ids = []
                collect(val, "cflow.flowset_id", set_ids)
                if not set_ids:
                    raise Fail(f"数据集 `{key}` 里没有 flowset_id")
                for fk, fv in val.items():
                    if not fk.startswith("Flow "):
                        continue
                    # 一律不用默认值：字段没解出来就是 None，让比对报"未解出"。
                    # 若给个 "0" 兜底，缺字段会被伪装成"值不一致"，把"没解出来"
                    # 和"值错了"混在一起——排查时这是两件完全不同的事。
                    starts, ends = [], []
                    collect(fv, "cflow.abstimestart", starts)
                    collect(fv, "cflow.abstimeend", ends)
                    msg["records"].append(
                        {
                            "template_id": int(set_ids[0]),
                            "src": fv.get("cflow.srcaddr") or fv.get("cflow.srcaddrv6"),
                            "dst": fv.get("cflow.dstaddr") or fv.get("cflow.dstaddrv6"),
                            "srcport": fv.get("cflow.srcport"),
                            "dstport": fv.get("cflow.dstport"),
                            "protocol": fv.get("cflow.protocol"),
                            "octets": fv.get("cflow.octets"),
                            "packets": fv.get("cflow.packets"),
                            # 注意字段名是 flow_id（不是 flowid）：IE 148 在 cflow 解析器里
                            # 叫 cflow.flow_id。名字写错会退化成"全部未解出"，而这类错误
                            # 在脚本里看起来就像"导出坏了"，为此我在这里踩过一次。
                            "flowid": fv.get("cflow.flow_id"),
                            "sampling": fv.get("cflow.sampling_interval"),
                            "start_ms": starts[0] if starts else None,
                            "end_ms": ends[0] if ends else None,
                        }
                    )
        msgs.append(msg)
    return msgs


def pdml_time_values(pcap):
    """从 PDML 里取每个数据记录的 IE 152/153 原始 8 字节（按文档顺序）。

    返回 (starts, ends)，元素是整数（该 IE 的线上字节按大端解释）。
    """
    proc = subprocess.run([TSHARK, "-r", pcap, "-T", "pdml"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise Fail(f"tshark -T pdml 打不开产物：{proc.stderr.strip()[:200]}")
    try:
        root = xml.etree.ElementTree.fromstring(proc.stdout)
    except xml.etree.ElementTree.ParseError as e:
        raise Fail(f"tshark -T pdml 输出不是合法 XML：{e}")
    starts, ends = [], []
    for field in root.iter("field"):
        name = field.get("name")
        raw = field.get("value")
        if raw is None:
            continue
        if name == "cflow.abstimestart":
            starts.append(int(raw, 16))
        elif name == "cflow.abstimeend":
            ends.append(int(raw, 16))
    return starts, ends


def check_pair(label, jsonl_path, pcap_path, expect_refresh):
    """返回 (检查项列表, 失败列表)。每项形如 ("✓"/"✗", 描述)。"""
    checks = []
    fails = []

    def ok(desc):
        checks.append(("✓", desc))

    def bad(desc):
        checks.append(("✗", desc))
        fails.append(desc)

    with open(jsonl_path, encoding="utf-8") as fh:
        expected = [json.loads(l) for l in fh if l.strip()]

    # malformed 必须为空：产物要能被第三方当作合法报文读
    bad_frames = malformed_frames(pcap_path)
    if bad_frames:
        bad(f"{label}: 产物含 malformed 帧 {bad_frames[:5]}")
    else:
        ok(f"{label}: tshark 未报 malformed")

    try:
        msgs = extract(run_tshark_json(pcap_path))
    except Fail as e:
        bad(f"{label}: {e}")
        return checks, fails

    # --- 报文级不变量 ---
    badver = [m["frame_number"] for m in msgs if m["version"] != 10]
    if badver:
        bad(f"{label}: 报文 {badver[:5]} 的 version 不是 10")
    else:
        ok(f"{label}: {len(msgs)} 个报文 version=10")

    badlen = [
        m["frame_number"]
        for m in msgs
        if m["udp_len"] is not None and m["len"] != m["udp_len"] - 8
    ]
    if badlen:
        bad(f"{label}: 报文 {badlen[:5]} 的头部 length 与 UDP 载荷不符")
    else:
        ok(f"{label}: 报文头 length 与 UDP 载荷逐一相符")

    # 序列号 = 本报文之前该 ODID 已发送的数据记录数（RFC 7011 §3.1）
    cum = 0
    seq_bad = []
    for m in msgs:
        if m["sequence"] != cum:
            seq_bad.append(f"报文 {m['frame_number']} 序列号={m['sequence']} 应为 {cum}")
        cum += len(m["records"])
    if seq_bad:
        bad(f"{label}: 序列号语义错误：{seq_bad[:3]}")
    else:
        ok(f"{label}: 序列号逐报文等于此前记录累计数（共 {cum} 条）")

    # 模板可见性 + 刷新节奏
    seen = set()
    tmpl_bad = False
    for m in msgs:
        seen.update(m["templates"])
        for r in m["records"]:
            if r["template_id"] not in seen:
                bad(f"{label}: 报文 {m['frame_number']} 使用了尚未声明的模板 {r['template_id']}")
                tmpl_bad = True
    if not tmpl_bad:
        ok(f"{label}: 所有数据记录都在模板声明之后（模板 id {sorted(seen)}）")

    tmpl_frames = [i for i, m in enumerate(msgs) if m["templates"]]
    if not tmpl_frames:
        bad(f"{label}: 产物里没有任何模板集")
    else:
        if tmpl_frames[0] != 0:
            bad(f"{label}: 首个报文未携带模板（首个带模板的是第 {tmpl_frames[0] + 1} 个）")
        gaps = [b - a for a, b in zip(tmpl_frames, tmpl_frames[1:])]
        if gaps and max(gaps) > expect_refresh:
            bad(f"{label}: 模板重发间隔 {max(gaps)} 超过配置的 {expect_refresh}")
        else:
            ok(f"{label}: 首报文携带模板，重发间隔 ≤ {expect_refresh}（共 {len(tmpl_frames)} 次）")

    # --- 逐条字段比对 ---
    got = [r for m in msgs for r in m["records"]]
    if len(got) != len(expected):
        bad(f"{label}: 记录条数不符：tshark 解出 {len(got)}，JSONL {len(expected)}")
        return checks, fails

    mism = []
    for i, (exp, rec) in enumerate(zip(expected, got)):
        for name, key, getter in FIELD_SPECS:
            want = str(getter(exp))
            have = rec[key]
            if have is None:
                mism.append(f"第 {i + 1} 条 {name}：tshark 未解出，JSONL={want}")
            elif str(have) != want:
                mism.append(f"第 {i + 1} 条 {name}：tshark={have} JSONL={want}")
    if mism:
        for mm in mism[:8]:
            bad(f"{label}: {mm}")
        if len(mism) > 8:
            bad(f"{label}: 另有 {len(mism) - 8} 处不一致未列出")
    else:
        ok(f"{label}: {len(expected)} 条 × {len(FIELD_SPECS)} 类字段逐条相符（地址/端口/协议/字节/包数/流 id/采样间隔）")

    # --- 时标：PDML 里的原始 8 字节 vs JSONL 的毫秒值 ---
    try:
        starts, ends = pdml_time_values(pcap_path)
    except Fail as e:
        bad(f"{label}: {e}")
        return checks, fails
    if len(starts) != len(expected) or len(ends) != len(expected):
        bad(
            f"{label}: PDML 里 IE 152/153 的条数与记录数不符"
            f"（{len(starts)}/{len(ends)} vs {len(expected)}）"
        )
        return checks, fails
    tmism = []
    for i, (exp, got_s, got_e) in enumerate(zip(expected, starts, ends)):
        want_s = exp["time"]["first_seen_us"] // 1000
        want_e = exp["time"]["last_seen_us"] // 1000
        if got_s != want_s:
            tmism.append(f"第 {i + 1} 条 起始时标：tshark 解出 {got_s}，JSONL {want_s} 毫秒")
        if got_e != want_e:
            tmism.append(f"第 {i + 1} 条 结束时标：tshark 解出 {got_e}，JSONL {want_e} 毫秒")
    if tmism:
        for t in tmism[:6]:
            bad(f"{label}: {t}")
    else:
        ok(
            f"{label}: {len(expected)} 条记录的 IE 152/153 线上原始 8 字节逐条相符"
            "（不经渲染串，跨 tshark 版本稳定）"
        )
    return checks, fails


# ---------------- 反向注入 ----------------


def _pcap_record_starts(data):
    pos = 24
    starts = []
    while pos + 16 <= len(data):
        incl = struct.unpack("<I", data[pos + 8 : pos + 12])[0]
        starts.append(pos)
        pos += 16 + incl
    return starts


def inject_counter(src, dst, expected, msgs):
    """① 改掉一条数据记录的计数值（取最大值，保证唯一）。"""
    data = bytearray(open(src, "rb").read())
    want = max(r["counters"]["bytes"] for r in expected)
    pat = struct.pack(">Q", want)
    idx = data.rfind(pat)  # 数据记录在报文尾部，取最后一次出现
    if idx < 0:
        return None
    data[idx : idx + 8] = struct.pack(">Q", want + 1)
    open(dst, "wb").write(data)
    return f"把一条记录的字节数 {want} 改成 {want + 1}"


def inject_set_id(src, dst, expected, msgs):
    """② 把最后一个数据集的 setID 改成未定义值。"""
    data = bytearray(open(src, "rb").read())
    idx = data.rfind(struct.pack(">H", msgs[-1]["records"][0]["template_id"]))
    if idx < 0:
        return None
    data[idx : idx + 2] = struct.pack(">H", 60000)
    open(dst, "wb").write(data)
    return "把数据集 setID 改成未定义值 60000"


def inject_msg_length(src, dst, expected, msgs):
    """③ 改掉第一个报文头的 length（IPFIX 起点 = pcap 24 + 记录头 16 + 以太/ip/udp 42）。"""
    data = bytearray(open(src, "rb").read())
    off = 24 + 16 + 42
    if len(data) < off + 4:
        return None
    data[off + 2 : off + 4] = struct.pack(">H", max(4, msgs[0]["len"] - 4))
    open(dst, "wb").write(data)
    return "把首报文头 length 改小 4 字节"


def inject_start_time(src, dst, expected, msgs):
    """⑤ 改掉一条记录的 IE 152 原始 8 字节（时标比对必须红）。

    没有这条注入，"时标逐条相符"就是一条从未被检验过的断言：
    它照样会打印 ✓（比如字段名写错时全取不到、或两边都取错时一致）。
    """
    data = bytearray(open(src, "rb").read())
    want = expected[0]["time"]["first_seen_us"] // 1000
    pat = struct.pack(">Q", want)
    idx = data.rfind(pat)
    if idx < 0:
        return None
    data[idx : idx + 8] = struct.pack(">Q", want + 1000)
    open(dst, "wb").write(data)
    return f"把一条记录的起始时标 {want} 改成 {want + 1000} 毫秒"


def inject_truncate(src, dst, expected, msgs):
    """④ 截掉最后一个 datagram。"""
    data = open(src, "rb").read()
    starts = _pcap_record_starts(data)
    if len(starts) < 2:
        return None
    open(dst, "wb").write(data[: starts[-1]])
    return "截掉最后一个 datagram"


INJECTIONS = [
    ("改计数值", inject_counter),
    ("改 setID", inject_set_id),
    ("改报文长度", inject_msg_length),
    ("截断报文", inject_truncate),
    ("改时标", inject_start_time),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--pair",
        action="append",
        default=[],
        help="label:jsonl:ipfix.pcap[:refresh]",
    )
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--refresh", type=int, default=20)
    args = ap.parse_args()

    if shutil.which(TSHARK) is None:
        print(f"环境检查失败：未找到 {TSHARK}", file=sys.stderr)
        return 3
    if not args.pair:
        print("至少需要一个 --pair", file=sys.stderr)
        return 3

    pairs = []
    for spec in args.pair:
        parts = spec.split(":")
        if len(parts) not in (3, 4):
            print(f"--pair 需要 label:jsonl:pcap[:refresh]，得到 `{spec}`", file=sys.stderr)
            return 3
        label, jsonl, pcap = parts[0], parts[1], parts[2]
        refresh = int(parts[3]) if len(parts) == 4 else args.refresh
        for p in (jsonl, pcap):
            if not os.path.exists(p):
                print(f"产物缺失：{p}", file=sys.stderr)
                return 2
        pairs.append((label, jsonl, pcap, refresh))

    total = []
    print("==> 逐字段比对：tshark 解出的字段 vs JSONL 记录")
    for label, jsonl, pcap, refresh in pairs:
        checks, fails = check_pair(label, jsonl, pcap, refresh)
        for mark, desc in checks:
            print(f"  {mark} {desc}")
        total.extend(fails)

    if args.self_test:
        print("==> 反向故障注入（注入在产物字节上，比对器必须报错）")
        with tempfile.TemporaryDirectory() as tmp:
            label, jsonl, pcap, _refresh = pairs[0]
            with open(jsonl, encoding="utf-8") as fh:
                expected = [json.loads(l) for l in fh if l.strip()]
            msgs = extract(run_tshark_json(pcap))
            for name, fn in INJECTIONS:
                dst = os.path.join(tmp, f"inj-{name}.pcap")
                desc = fn(pcap, dst, expected, msgs)
                if desc is None:
                    print(f"  ! 注入「{name}」无法构造（产物形态不匹配）")
                    total.append(f"注入 {name} 未构造成功")
                    continue
                _, fails = check_pair(f"注入:{name}", jsonl, dst, args.refresh)
                if fails:
                    print(f"  ✓ 注入「{name}」被检出（{desc}）")
                else:
                    print(f"  ✗ 注入「{name}」未被检出：比对器失效（{desc}）")
                    total.append(f"注入 {name} 未被检出")

    print()
    if total:
        print(f"✗ IPFIX 交叉核验失败：{len(total)} 项", file=sys.stderr)
        for f in total[:10]:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("✓ IPFIX 导出交叉核验通过（含反向故障注入全部被检出）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
