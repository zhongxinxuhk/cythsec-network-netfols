#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""check-ipfix-collect.py —— IPFIX 采集回路门禁的比对与注入工具（CYS-TRF-054）。

四个子命令（都被 check-ipfix-collect.sh 调用）：

  roundtrip <orig.jsonl> <col.jsonl>
      导出侧记录 vs 采集侧还原记录，逐字段比对。
      **只比 IPFIX 真的承载了的字段**：五元组 / 包数 / 字节数 / flowId(session_id) /
      起止时标（毫秒粒度）。并校验采集侧对"没采集到的字段"是**如实为空**而不是占位值。

  drop-datagram <in.pcap> <out.pcap> <index>
      删掉一个 datagram（pcap 记录）来构造"导出链路丢包"。刻意删**中间**那个：
      丢尾部没有后续报文就没有基线，丢首部连基线本身都没有 —— 两种都测不出缺口。

  assert-loss <clean.stats> <gap.stats>
      从两行统计里取出采集器自报的数字，独立手算一遍丢包率并要求与自报值一致。

  self-test
      对上面的判定做反向注入：把统计行里的数字改坏，判定必须变红。
      （一条从未被判红过的断言，与"没跑"长得一样。）

退出码：0 通过；1 断言失败；2 用法错误；3 前置条件缺失。
"""

import json
import struct
import sys

def fail(msg):
    print("    ✗ " + msg, file=sys.stderr)
    return 1


def ok(msg):
    print("    ✓ " + msg)


def parse_stats(path):
    """从采集器输出里取统计行（最后一个 `[cythsec-ipfix-collect] datagrams=` 行）。

    只认这一种来源：**不自己重算** —— 门禁要比的是"采集器自报的数"与"独立手算的数"，
    两边都由门禁算就退化成了自证。
    """
    line = None
    for raw in open(path, encoding="utf-8", errors="replace"):
        if "cythsec-ipfix-collect] datagrams=" in raw:
            line = raw.strip()
    if line is None:
        raise ValueError(f"{path} 里找不到采集器统计行（是不是没跑起来？）")
    body = line.split("datagrams=", 1)[1]
    stats = {}
    for kv in body.split():
        if "=" in kv:
            k, v = kv.split("=", 1)
            stats[k] = v
    return stats


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def five_tuple(rec):
    f = rec["flow"]
    return (f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["proto"])


def cmd_roundtrip(orig_path, col_path):
    orig = load_jsonl(orig_path)
    col = load_jsonl(col_path)
    if len(orig) != len(col):
        return fail(f"记录条数不符：导出 {len(orig)} 条，采集还原 {len(col)} 条")
    if not orig:
        return fail("两边都是 0 条记录：这种'通过'没有意义（样本没导出成功）")

    bad = 0
    for i, (a, b) in enumerate(zip(orig, col)):
        tag = f"第 {i + 1} 条"
        if five_tuple(a) != five_tuple(b):
            fail(f"{tag} 五元组不符：{five_tuple(a)} vs {five_tuple(b)}")
            bad += 1
        if a["counters"]["packets"] != b["counters"]["packets"]:
            fail(f"{tag} 包数不符：{a['counters']['packets']} vs {b['counters']['packets']}")
            bad += 1
        if a["counters"]["bytes"] != b["counters"]["bytes"]:
            fail(f"{tag} 字节数不符：{a['counters']['bytes']} vs {b['counters']['bytes']}")
            bad += 1
        if a["session_id"] != b["session_id"]:
            fail(f"{tag} flowId/session_id 不符：{a['session_id']} vs {b['session_id']}")
            bad += 1
        # IE 152/153 是**毫秒**：导出即有精度损失，故按毫秒粒度比对。
        # 写成 `== first_seen_us` 会在任何亚毫秒样本上假红（这不是采集器的错）。
        for field in ("first_seen_us", "last_seen_us"):
            want_ms = a["time"][field] // 1000
            got = b["time"][field]
            if got != want_ms * 1000:
                fail(f"{tag} {field} 不符（毫秒粒度）：期望 {want_ms * 1000}，得到 {got}")
                bad += 1
    if bad:
        return fail(f"共 {bad} 处字段不符")

    # 口径诚实性：IPFIX v1 的模板里没有 TCP 状态与 DPI 结论，
    # 采集侧必须如实写 null / not_inspected。填 0 或 "unknown" 就是把"没采集到"伪装成结论。
    for i, b in enumerate(col):
        if b["tcp"]["state"] is not None:
            return fail(f"第 {i + 1} 条 tcp.state={b['tcp']['state']!r}：IPFIX 不承载 TCP 状态，必须为 null")
        if b["app"]["outcome"] != "not_inspected":
            return fail(f"第 {i + 1} 条 app.outcome={b['app']['outcome']!r}：应为 not_inspected（没看过 ≠ 不认识）")
        if b["risk_score"] is not None:
            return fail(f"第 {i + 1} 条 risk_score={b['risk_score']!r}：IPFIX 不承载风险评分，必须为 null")
    ok(f"回路逐字段相符：{len(orig)} 条记录（五元组/包数/字节数/flowId/起止毫秒）")
    ok("未承载字段如实为空：tcp.state=null、app.outcome=not_inspected、risk_score=null")
    return 0


def read_pcap_records(blob):
    if blob[:4] not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        raise ValueError("不是小端经典 pcap（本关口只处理我们自己产的 IPFIX pcap）")
    recs = []
    off = 24
    while off + 16 <= len(blob):
        _ts_s, _ts_us, incl, _orig = struct.unpack("<IIII", blob[off : off + 16])
        if off + 16 + incl > len(blob):
            break
        recs.append(blob[off : off + 16 + incl])
        off += 16 + incl
    if off != len(blob):
        raise ValueError(f"pcap 尾部有 {len(blob) - off} 字节残留，不是一个规整的产物")
    return blob[:24], recs


def cmd_drop_datagram(in_path, out_path, index):
    blob = open(in_path, "rb").read()
    header, recs = read_pcap_records(blob)
    if not (0 <= index < len(recs)):
        return fail(f"要删的下标 {index} 越界（产物共 {len(recs)} 个 datagram）")
    if len(recs) < 3:
        return fail(f"产物只有 {len(recs)} 个 datagram，删一个就凑不出'中间'的语义")
    out = bytearray(header)
    for i, rec in enumerate(recs):
        if i == index:
            continue
        out.extend(rec)
    open(out_path, "wb").write(bytes(out))
    ok(f"已删掉第 {index + 1} 个 datagram（共 {len(recs)} 个 → {len(recs) - 1} 个）")
    return 0


def cmd_assert_loss(clean_path, gap_path):
    clean = parse_stats(clean_path)
    gap = parse_stats(gap_path)

    # 上游已经断言过 clean 行是 0；这里再独立确认一遍，避免"上游改了口径而这里不知道"。
    if clean.get("lost_records") != "0" or clean.get("gaps") != "0":
        return fail(f"无注入时不该有缺口：{clean.get('gaps')=} {clean.get('lost_records')=}")

    try:
        gaps = int(gap["gaps"])
        lost = int(gap["lost_records"])
        received = int(gap["records"])
        ppm = int(gap["loss_ppm"])
        delivered = int(gap["delivered"])
    except (KeyError, ValueError) as exc:
        return fail(f"统计行缺字段或不是整数：{exc}")
    if gaps != 1:
        return fail(f"删掉 1 个 datagram 应报 gaps=1，实际 {gaps}")
    if lost <= 0:
        return fail(f"缺口条数必须为正，实际 {lost}")

    # 独立手算：删掉的那个 datagram 携带多少条记录 = 完整回路的记录数 - 缺口回路的记录数。
    full = int(clean["records"])
    want_lost = full - received
    if want_lost != lost:
        return fail(
            f"缺口条数对不上：完整 {full} 条 - 收到 {received} 条 = {want_lost}，"
            f"但采集器自报 lost_records={lost}"
        )
    # 丢包率 = 丢失 / (实收 + 丢失)，单位 ppm；先乘后除，避免小缺口被整数除法抹成 0。
    want_ppm = lost * 1_000_000 // (received + lost) if (received + lost) else 0
    if ppm != want_ppm:
        return fail(f"loss_ppm 不符：独立手算 {want_ppm}，采集器自报 {ppm}")
    if delivered != received:
        return fail(f"缺口回路的 delivered={delivered} 与 records={received} 不符（本样本无重复记录）")
    ok(f"缺口与丢包率可复算：gaps=1 lost_records={lost}（完整 {full} - 收到 {received}）")
    ok(f"loss_ppm={ppm}（独立手算 {lost}/({received}+{lost})）")
    return 0


def cmd_self_test():
    """对判定本身做反向注入：把统计行改坏，判定必须变红。"""
    import os
    import tempfile

    clean_stats = (
        "[cythsec-ipfix-collect] datagrams=5 bytes=884 exporters=1 records=9 delivered=9 "
        "duplicates=0 gaps=0 lost_records=0 loss_ppm=0 out_of_order=0 templates=5 expired=0 "
        "no_template_sets=0 malformed=0 version_mismatch=0 unknown_ies=-\n"
    )
    gap_stats = (
        "[cythsec-ipfix-collect] datagrams=4 bytes=696 exporters=1 records=7 delivered=7 "
        "duplicates=0 gaps=1 lost_records=2 loss_ppm=222222 out_of_order=0 templates=4 expired=0 "
        "no_template_sets=0 malformed=0 version_mismatch=0 unknown_ies=-\n"
    )
    cases = [
        ("正确的一对必须过", clean_stats, gap_stats, 0),
        ("缺口条数改坏（2 → 1）", clean_stats, gap_stats.replace("lost_records=2", "lost_records=1"), 1),
        ("缺口次数改坏（1 → 0）", clean_stats, gap_stats.replace("gaps=1", "gaps=0"), 1),
        ("丢包率改坏（222222 → 0）", clean_stats, gap_stats.replace("loss_ppm=222222", "loss_ppm=0"), 1),
        ("把「没有丢包」伪造成有缺口", clean_stats.replace("lost_records=0", "lost_records=3"),
         gap_stats, 1),
        ("丢包率分母算错（ppm 按 records 而非 records+lost）", clean_stats,
         gap_stats.replace("loss_ppm=222222", "loss_ppm=285714"), 1),
    ]
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        # cmd_assert_loss 会往 stderr 打失败原因：自证阶段把噪声收起来，只看退出码。
        real_stderr = sys.stderr
        for label, c, g, want_rc in cases:
            cp = os.path.join(tmp, "clean.stats")
            gp = os.path.join(tmp, "gap.stats")
            open(cp, "w", encoding="utf-8").write(c)
            open(gp, "w", encoding="utf-8").write(g)
            sys.stderr = open(os.devnull, "w", encoding="utf-8")
            real_stdout = sys.stdout
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
            try:
                rc = cmd_assert_loss(cp, gp)
            finally:
                sys.stdout.close()
                sys.stderr.close()
                sys.stdout = real_stdout
                sys.stderr = real_stderr
            got_rc = 0 if rc == 0 else 1
            if got_rc != want_rc:
                bad += 1
                print(f"    ✗ 自证失败：{label} 期望 rc={want_rc}，实际 rc={got_rc}", file=sys.stderr)
                continue
            mark = "通过" if want_rc == 0 else "已被判红"
            print(f"    ✓ 注入「{label}」→ {mark}")
    if bad:
        return fail(f"{bad} 项自证未达预期")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    cmd = argv[1]
    if cmd == "roundtrip" and len(argv) == 4:
        return cmd_roundtrip(argv[2], argv[3])
    if cmd == "drop-datagram" and len(argv) == 5:
        return cmd_drop_datagram(argv[2], argv[3], int(argv[4]))
    if cmd == "assert-loss" and len(argv) == 4:
        return cmd_assert_loss(argv[2], argv[3])
    if cmd == "self-test" and len(argv) == 2:
        return cmd_self_test()
    print(f"用法错误：{argv[1:]}", file=sys.stderr)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except ValueError as exc:
        print(f"    ✗ {exc}", file=sys.stderr)
        sys.exit(3)
