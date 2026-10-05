#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""measure-storage.py —— **落盘字节/记录实测**（`CYS-INF-041`）。

## 为什么必须量

`CYS-INF-040` 的容量表把「每条落盘 40 B」当规划参数用，它直接决定 `TB/天`，
而这个数是**假设来的、没人量过**（脚本里也如实标了「规划（未实测）」）。
本脚本把它换成实测：吃真实的 `FlowRecord` JSONL（由 `cythsec-analyze` 从真实抓包产出），
给出**未压缩 / gzip 两档**的字节/记录，并顺便回答"这些字节花在哪"。

## 口径（三条，缺一条这个数就会被误用）

1. **样本量必须一起看**：字节/记录与流量构成强相关，本脚本每次输出都把
   `records`（样本条数）与输入文件名一起打印，禁止只引用一个孤立的平均数。
2. **gzip 档与"内容重复度"强相关**：同一个模板反复出现（压测流量）会压得极好；
   真实省网流量的字段多样性更高，压缩率**一定比同质语料差**。故本脚本把
   「同质大样本」与「真实小样本」分成两次测量分别记录，规划取**较差的那一端**，
   绝不拿压测语料那个漂亮数字当规划值。
3. **未压缩档才是上界**：JSONL 每条约 1 KB 是**实测**上界；要降到几十字节
   必须改落盘格式（列式/二进制），那时要重新测，不能沿用这里的数字。

## 用法

    measure-storage.py --jsonl a.jsonl [b.jsonl ...] [--label 名字] [--json 产物.json]
                       [--gzip-level 9] [--record-rate 5000000] [--breakdown-lines 200000]
    measure-storage.py --self-test [--inject 名字]

退出码：0 正常；1 输入/自证失败；2 参数错误；3 环境缺少 gzip（那一档按"未核验"处理）。
"""

import argparse
import json
import os
import shutil
import subprocess
import sys

DEFAULT_RECORD_RATE = 5_000_000  # 记录/秒：省网 20 Tbps × 1:1000 的上界（见 CYS-INF-040）
GZIP_LEVEL = 9
CHUNK = 1 << 20


# ---------------------------------------------------------------------------
# 实测
# ---------------------------------------------------------------------------
def count_bytes_and_records(paths):
    """未压缩：逐文件统计**文件字节数**与**行数**。

    字节数取文件大小而不是"sum(len(line))"：落盘就是这些字节（含换行），
    而 `len(line)` 需要假设换行符长度；文件大小可被 `wc -c` 独立复核。
    """
    total_bytes = 0
    records = 0
    per_file = []
    for p in paths:
        size = os.path.getsize(p)
        n = 0
        with open(p, "rb") as fh:
            for chunk in iter(lambda: fh.read(CHUNK), b""):
                n += chunk.count(b"\n")
                if not chunk.endswith(b"\n"):
                    # 最后一行没有换行符也要算一条（否则条数会被静默少算 1）
                    pass
        # 上一步只数了换行；末行无换行时补一条
        with open(p, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            if size > 0:
                fh.seek(-1, os.SEEK_END)
                if fh.read(1) != b"\n":
                    n += 1
        total_bytes += size
        records += n
        per_file.append({"path": p, "bytes": size, "records": n})
    return total_bytes, records, per_file


def gzip_size(paths, level):
    """把输入按顺序喂给 `gzip -<level> -c`，数输出字节。

    用系统 gzip 而不是 python zlib：现场部署落盘用的也是系统工具/同族实现，
    且 gzip 版本会写进产物（不同 zlib 版本的输出字节数会有微小差异，
    不写版本别人就无法复现同一个数）。
    """
    if shutil.which("gzip") is None:
        return None
    proc = subprocess.Popen(["gzip", f"-{level}", "-c"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    total = 0
    import threading
    err = []

    def feed():
        try:
            for p in paths:
                with open(p, "rb") as fh:
                    for chunk in iter(lambda: fh.read(CHUNK), b""):
                        proc.stdin.write(chunk)
        except BrokenPipeError:
            pass
        finally:
            try:
                proc.stdin.close()
            except BrokenPipeError:
                pass

    t = threading.Thread(target=feed)
    t.start()
    while True:
        chunk = proc.stdout.read(CHUNK)
        if not chunk:
            break
        total += len(chunk)
    t.join()
    err.append(proc.stderr.read())
    proc.wait()
    proc.stdout.close()
    proc.stderr.close()
    if proc.returncode != 0:
        raise RuntimeError(f"gzip 失败：{b''.join(err).decode('utf-8', 'replace')[:200]}")
    return total


def gzip_version():
    """gzip 版本要写进产物：不同实现（Apple gzip / GNU gzip）压缩输出字节数会有差异。"""
    try:
        r = subprocess.run(["gzip", "--version"], capture_output=True, text=True, timeout=10)
        out = (r.stdout + r.stderr).strip()   # Apple gzip 把版本行打到 stderr
        return out.split("\n")[0] if out else "未知"
    except Exception:
        return "未知"


def gzip_roundtrip_ok(paths, level):
    """压缩→解压→与原文**逐字节相同**。

    这是"压缩后字节数"这个数有意义的前提：一个把输入截断的实现也能给出更小的数，
    但它不是"压缩"。故这一步不通过就必须整档作废（不是警告）。
    """
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as tmp:
        gz = tmp.name
    try:
        with open(gz, "wb") as out:
            proc = subprocess.run(["gzip", f"-{level}", "-c"] +
                                  [p for p in paths], stdout=out, stderr=subprocess.PIPE)
            if proc.returncode != 0:
                raise RuntimeError(f"gzip 失败：{proc.stderr.decode('utf-8', 'replace')[:200]}")
        dec = subprocess.Popen(["gzip", "-d", "-c", gz], stdout=subprocess.PIPE)
        for p in paths:
            with open(p, "rb") as fh:
                for chunk in iter(lambda: fh.read(CHUNK), b""):
                    got = dec.stdout.read(len(chunk))
                    if got != chunk:
                        dec.kill()
                        return False
        tail = dec.stdout.read(1)
        dec.stdout.close()
        dec.wait()
        return tail == b""
    finally:
        os.unlink(gz)


def breakdown(paths, max_lines):
    """字节花在哪：按顶层键累加 `key + 值的紧凑 JSON 表示` 的字节数。

    只作为**诊断**（不是判据）：它回答"features 这个数组占了多少"这种问题，
    从而说明"为什么 JSONL 不可能压到几十字节"以及"改列式能省哪一块"。
    """
    acc = {}
    seen = 0
    for p in paths:
        with open(p, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                if seen >= max_lines:
                    break
                seen += 1
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                for k, v in obj.items():
                    size = len(k.encode("utf-8")) + len(
                        json.dumps(v, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    ) + 4  # 引号、冒号、逗号等结构字符的粗略计
                    acc[k] = acc.get(k, 0) + size
        if seen >= max_lines:
            break
    return {"lines_scanned": seen, "bytes_by_key": acc}


def measure(paths, label, level, record_rate, breakdown_lines):
    raw_bytes, records, per_file = count_bytes_and_records(paths)
    for f in per_file:
        if f["records"] == 0:
            raise ValueError(f"输入 {f['path']} 里没有记录（0 行）—— 空语料上的平均数是伪数")
    if records == 0:
        raise ValueError("全部输入合计 0 条记录")
    gz_bytes = gzip_size(paths, level) if shutil.which("gzip") else None
    if gz_bytes is not None and not gzip_roundtrip_ok(paths, level):
        raise ValueError("gzip 往返不一致（压缩产物解压后与原文不同）—— 压缩数不可用")
    out = {
        "label": label,
        "inputs": per_file,
        "records": records,
        "raw_bytes": raw_bytes,
        "raw_bytes_per_record": raw_bytes / records,
        "gzip_level": level,
        "gzip_tool": gzip_version(),
        "gzip_method": "stdin 管道（gzip -9 -c，不含 FNAME/MTIME 头）",
        "gzip_bytes": gz_bytes,
        "gzip_bytes_per_record": (gz_bytes / records) if gz_bytes is not None else None,
        "gzip_ratio": (raw_bytes / gz_bytes) if gz_bytes else None,
        "gzip_roundtrip_verified": gz_bytes is not None,
        "record_rate_per_sec": record_rate,
        "tb_per_day_raw": raw_bytes / records * record_rate * 86400 / 1e12,
        "tb_per_day_gzip": (gz_bytes / records * record_rate * 86400 / 1e12)
        if gz_bytes is not None else None,
        "breakdown": breakdown(paths, breakdown_lines),
    }
    return out


def print_report(m):
    print(f"==> 落盘字节/记录实测：{m['label']}")
    for f in m["inputs"]:
        print(f"    输入 {f['path']}：{f['records']} 条 · {f['bytes']} B")
    print(f"    样本量：{m['records']} 条（**引用这个数时必须一起给**）")
    print(f"    未压缩：{m['raw_bytes']} B ÷ {m['records']} = "
          f"**{m['raw_bytes_per_record']:.1f} B/记录**（上界口径，实测）")
    if m["gzip_bytes"] is None:
        print("    gzip   ：**未核验**（环境缺 gzip）")
    else:
        print(f"    gzip -{m['gzip_level']}：{m['gzip_bytes']} B ÷ {m['records']} = "
              f"**{m['gzip_bytes_per_record']:.1f} B/记录**"
              f"（压缩比 {m['gzip_ratio']:.1f}× · 往返校验通过 · {m['gzip_tool']}）")
        print(f"      方法：{m['gzip_method']}")
        # 现场若用 `gzip -9 file` 复现，会多出文件名与时间戳头（实测 1~20+ B 不等，
        # 取决于文件名长度），少这几个字节的差别不该让人怀疑测量本身。
        print("      注：`gzip -9 <file>`（文件参数）会多嵌文件名/时间戳，字节数略高；")
    rate = m["record_rate_per_sec"]
    print(f"    按 {rate:,} 记录/秒（省网 20 Tbps × 1:1000 上界）折算：")
    print(f"      未压缩 {m['tb_per_day_raw']:.2f} TB/天"
          + (f"；gzip {m['tb_per_day_gzip']:.2f} TB/天" if m["tb_per_day_gzip"] else ""))
    b = m["breakdown"]["bytes_by_key"]
    if b:
        total = sum(b.values())
        print(f"    字节花在哪（诊断，扫了 {m['breakdown']['lines_scanned']} 行）：")
        for k, v in sorted(b.items(), key=lambda kv: -kv[1])[:6]:
            print(f"      {k:<14} {v:>12} B  {100.0*v/total:5.1f}%")


def combine(paths, pick_best=False):
    """把多次测量合成**规划值**：两档各取**较差的一端**（字节数最大者）。

    为什么取最大而不是平均：gzip 档的字节数由"内容重复度"决定 —— 同质压测语料能压到
    20 B/记录，真实流量 80 B/记录。规划用平均或最小值，等于把乐观假设偷偷带进容量表，
    和"40 B/记录"那个老问题**一模一样**（只是数值更好看）。取最大是**故意的保守**，
    且这条规则本身可被判死（注入 `pick-best` 时必须红）。
    """
    ms = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            m = json.load(fh)
        for k in ("records", "raw_bytes_per_record", "gzip_bytes_per_record"):
            if k not in m:
                raise ValueError(f"{p} 缺少字段 {k}（不是本脚本的测量产物？）")
        if m["records"] <= 0:
            raise ValueError(f"{p} 的样本量为 0 —— 空语料上的平均数不能用")
        ms.append((p, m))
    if not ms:
        raise ValueError("没有可合并的测量产物")
    if pick_best:  # 注入：错误地"取最好看的一端"
        raw = min(m["raw_bytes_per_record"] for _p, m in ms)
        gz = min((m["gzip_bytes_per_record"] for _p, m in ms
                  if m["gzip_bytes_per_record"] is not None), default=None)
    else:
        raw = max(m["raw_bytes_per_record"] for _p, m in ms)
        gz = max((m["gzip_bytes_per_record"] for _p, m in ms
                  if m["gzip_bytes_per_record"] is not None), default=None)
    return {
        "sources": [{"path": p, "label": m["label"], "records": m["records"],
                     "raw_bytes_per_record": m["raw_bytes_per_record"],
                     "gzip_bytes_per_record": m["gzip_bytes_per_record"]} for p, m in ms],
        "rule": ("两档各取测量中的较差端（字节数最大者）："
                 + ("**注入：取最好看的一端（错误）**" if pick_best else "故意保守")),
        "raw_bytes_per_record": raw,
        "gzip_bytes_per_record": gz,
        "total_records": sum(m["records"] for _p, m in ms),
    }


def print_combine(c):
    print("==> 落盘字节/记录规划值（多次测量取较差端）")
    for s in c["sources"]:
        gz = f"{s['gzip_bytes_per_record']:.1f}" if s["gzip_bytes_per_record"] is not None else "未核验"
        print(f"    {s['label'][:48]:<48} {s['records']:>8} 条 · raw {s['raw_bytes_per_record']:7.1f} B · gzip {gz:>6} B")
    print(f"    规则：{c['rule']}")
    print(f"    ⇒ 规划值：raw **{c['raw_bytes_per_record']:.1f} B/记录**（上界）· "
          f"gzip **{c['gzip_bytes_per_record']:.1f} B/记录**（规划用这个）")


def cmd_measure(args):
    for p in args.jsonl:
        if not os.path.isfile(p):
            print(f"✗ 输入不存在：{p}", file=sys.stderr)
            return 2
    m = measure(args.jsonl, args.label or ",".join(os.path.basename(p) for p in args.jsonl),
                args.gzip_level, args.record_rate, args.breakdown_lines)
    print_report(m)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(m, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
        print(f"    产物：{args.json}")
    return 0


# ---------------------------------------------------------------------------
# 自证：期望值是**手算**的，且压缩档必须过往返校验
# ---------------------------------------------------------------------------
LINES = [
    b'{"session_id":1,"flow":{"src_ip":"10.0.0.1","dst_ip":"10.0.0.2"}}\n',
    b'{"session_id":2,"flow":{"src_ip":"10.0.0.3","dst_ip":"10.0.0.4"}}\n',
    b'{"session_id":3,"flow":{"src_ip":"10.0.0.5","dst_ip":"10.0.0.6"}}\n',
]


def _write_corpus(path, lines):
    with open(path, "wb") as fh:
        for l in lines:
            fh.write(l)


def cmd_self_test(inject):
    import tempfile
    work = tempfile.mkdtemp(prefix="measure-storage-self-")
    corpus = os.path.join(work, "tiny.jsonl")
    _write_corpus(corpus, LINES)
    fails = 0

    def check(ok, what):
        nonlocal fails
        if ok:
            print(f"  ✓ {what}")
        else:
            print(f"  ✗ {what}")
            fails += 1

    m = measure([corpus], "self", GZIP_LEVEL, 1000, 1000)

    # ---- 反向注入：把"实现有 bug 时会报出来的数"真的改写掉，再看断言会不会红 ----
    # 关键点：注入必须作用在**被测数值**上，不能只写一段"假如错了会怎样"的判断 ——
    # 否则注入模式永远返回 0（断言全过），外层就会把"注入未被检出"当成通过。
    if inject is not None:
        print(f"  （注入模式：{inject} —— 把上报值改成有 bug 时的样子）")
        if inject == "drop-newlines":       # 统计字节时漏掉每行的换行符
            m["raw_bytes"] -= m["records"]
        elif inject == "gzip-as-raw":       # 压缩档直接上报未压缩大小（没真压缩）
            m["gzip_bytes"] = m["raw_bytes"]
        elif inject == "tb-for-bits":       # 单位错：把字节当比特
            m["tb_per_day_raw"] *= 8
        elif inject == "records-plus-one":  # 条数多算 1（末行重复计数）
            m["records"] += 1
        else:
            raise SystemExit(f"未知注入：{inject}")

    hand_raw = sum(len(l) for l in LINES)          # 手算：三行字节数之和
    check(hand_raw == m["raw_bytes"],
          f"未压缩字节数 == 手算 {hand_raw}（实际 {m['raw_bytes']}）")
    check(m["records"] == 3, f"记录条数 == 3（实际 {m['records']}）")
    # 末行无换行的文件也必须算一条（计数器少算 1 会让 B/记录 偏大）
    no_nl = os.path.join(work, "no-nl.jsonl")
    with open(no_nl, "wb") as fh:
        fh.write(LINES[0] + LINES[1].rstrip(b"\n"))
    m2 = measure([no_nl], "no-nl", GZIP_LEVEL, 1000, 1000)
    check(m2["records"] == 2, f"末行无换行仍算 1 条（实际 {m2['records']}）")
    # gzip 档：必须过往返校验，且对这种同形重复语料必须真的更小
    check(m["gzip_roundtrip_verified"] is True, "gzip 往返校验（解压 == 原文）")
    check(m["gzip_bytes"] < m["raw_bytes"],
          f"同形语料压缩后必须更小（{m['gzip_bytes']} < {m['raw_bytes']}）")
    # TB/天：手算 rate × 86400 × B/记录 ÷ 1e12
    want_tb = 1000 * 86400 * hand_raw / 3 / 1e12
    check(abs(m["tb_per_day_raw"] - want_tb) < 1e-12,
          f"TB/天 == 手算 {want_tb:.6f}（实际 {m['tb_per_day_raw']:.6f}）")
    # 字节去向诊断：只应出现 session_id 与 flow
    keys = set(m["breakdown"]["bytes_by_key"])
    check(keys == {"session_id", "flow"}, f"顶层键只应有 session_id/flow（实际 {sorted(keys)}）")
    # 空语料必须报错，而不是给出一个"0 B/记录"的伪数
    empty = os.path.join(work, "empty.jsonl")
    open(empty, "wb").close()
    try:
        measure([empty], "empty", GZIP_LEVEL, 1000, 1000)
        check(False, "空语料必须抛错而不是产出 0 B/记录")
    except ValueError:
        check(True, "空语料抛错（不给伪数）")

    # 合并规则：两档各取**较差端**（这里两份假产物：一份好看、一份难看）
    good = os.path.join(work, "good.json")
    bad = os.path.join(work, "bad.json")
    with open(good, "w", encoding="utf-8") as fh:
        json.dump({"label": "同质压测语料", "records": 1000, "raw_bytes_per_record": 1000.0,
                   "gzip_bytes_per_record": 20.0}, fh)
    with open(bad, "w", encoding="utf-8") as fh:
        json.dump({"label": "真实多样语料", "records": 100, "raw_bytes_per_record": 1100.0,
                   "gzip_bytes_per_record": 80.0}, fh)
    c = combine([good, bad])
    check(abs(c["gzip_bytes_per_record"] - 80.0) < 1e-9,
          f"合并取较差端 gzip == 80（实际 {c['gzip_bytes_per_record']}）")
    check(abs(c["raw_bytes_per_record"] - 1100.0) < 1e-9,
          f"合并取较差端 raw == 1100（实际 {c['raw_bytes_per_record']}）")
    if inject == "pick-best":       # 注入：错误地取"最好看的一端"
        c = combine([good, bad], pick_best=True)
        check(abs(c["gzip_bytes_per_record"] - 20.0) < 1e-9,
              f"注入 pick-best 后变成 20（实际 {c['gzip_bytes_per_record']}）—— 上面那条断言此时应为红")
    # 缺字段/空样本的产物必须报错（否则会拿"0 条"的伪数进容量表）
    bogus = os.path.join(work, "bogus.json")
    with open(bogus, "w", encoding="utf-8") as fh:
        json.dump({"label": "缺字段", "records": 0}, fh)
    try:
        combine([bogus])
        check(False, "缺字段/0 样本的产物必须抛错")
    except (ValueError, KeyError):
        check(True, "缺字段/0 样本的产物抛错")

    if inject is None:
        # 五项注入逐一复跑：每一个都必须让这个自证**返回非零**（判死）
        for name in ("drop-newlines", "gzip-as-raw", "tb-for-bits", "records-plus-one",
                     "pick-best"):
            rc = subprocess.run([sys.executable, os.path.abspath(__file__), "--self-test",
                                 "--inject", name], capture_output=True, text=True)
            if rc.returncode == 0:
                print(f"  ✗ 注入「{name}」未被判死")
                fails += 1
            else:
                print(f"  ✓ 注入已检出：{name}")

    shutil.rmtree(work, ignore_errors=True)
    print(f"\n{'✓ measure-storage 自证通过' if fails == 0 else '✗ measure-storage 自证失败'}")
    return 0 if fails == 0 else 1


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--jsonl", nargs="+", default=[])
    ap.add_argument("--label")
    ap.add_argument("--json")
    ap.add_argument("--gzip-level", type=int, default=GZIP_LEVEL)
    ap.add_argument("--record-rate", type=int, default=DEFAULT_RECORD_RATE)
    ap.add_argument("--breakdown-lines", type=int, default=200_000)
    ap.add_argument("--combine", nargs="+", default=[],
                    help="合并多份测量产物为规划值（两档各取较差端）")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--inject", help=argparse.SUPPRESS)
    args = ap.parse_args(argv[1:])
    if args.self_test:
        return cmd_self_test(args.inject)
    if args.combine:
        c = combine(args.combine, pick_best=(args.inject == "pick-best"))
        print_combine(c)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as fh:
                json.dump(c, fh, ensure_ascii=False, indent=2, sort_keys=True)
                fh.write("\n")
            print(f"    产物：{args.json}")
        return 0
    if not args.jsonl:
        ap.error("需要 --jsonl（或 --combine / --self-test）")
    return cmd_measure(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
