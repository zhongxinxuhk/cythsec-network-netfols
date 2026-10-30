#!/usr/bin/env python3
"""FlowRecord -> MergeTree -> 新进程读回；空间与耗时均实测，零 Python 依赖。

--jsonl a.jsonl [b.jsonl ...] --clickhouse /path/to/clickhouse [--json report.json]
--self-test：纯 Python 比对器自证（进 --plan）；--integration-test：真实引擎反注入。
退出码 0=通过，1=数据/检查失败，2=参数错误，3=ClickHouse 不可用（未核验）。
"""

import argparse
from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
DDL = ROOT / "storage/clickhouse/flow_records_v2.sql"
TABLE = "flow_records_v2"
SETTINGS = """
SET input_format_skip_unknown_fields = 0;
SET input_format_json_ignore_unknown_keys_in_named_tuple = 0;
SET input_format_json_defaults_for_missing_elements_in_named_tuple = 0;
SET input_format_null_as_default = 0;
SET output_format_json_named_tuples_as_objects = 1;
SET output_format_json_quote_64bit_integers = 0;
"""


def sql_string(value):
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def run(binary, directory, query):
    p = subprocess.run([binary, "local", "--path", str(directory), "--multiquery",
                        "--query", SETTINGS + query], capture_output=True, text=True,
                       timeout=300)
    if p.returncode:
        raise ValueError(f"ClickHouse 退出 {p.returncode}: {p.stderr[-3000:]}")
    return p.stdout


def canonical(value):
    # JSONEachRow 可把 1.0 打印为 1；仅统一数值表示，保留 null/bool/字符串的差别。
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in value.items()}
    if isinstance(value, list):
        return [canonical(v) for v in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def signature(record):
    return json.dumps(canonical(record), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def verify_records(expected, actual):
    # ponytail: 测量语料在内存中逐字段比对；百万级常驻写入须换流式外排比对。
    want = Counter(signature(r) for r in expected)
    got = Counter(signature(r) for r in actual)
    if want != got:
        raise ValueError(f"逐字段读回不一致：缺少 {sum((want-got).values())} 条，"
                         f"多出/改变 {sum((got-want).values())} 条（保留重复记录计数）")


def read_records(path):
    with Path(path).open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def measure(binary, paths, label):
    expected, inputs = [], []
    with tempfile.TemporaryDirectory(prefix="cythsec-ch-") as tmp:
        directory = Path(tmp) / "db"
        corpus = Path(tmp) / "input.jsonl"
        # 固定输入快照：测量/比对读同一批字节，避免并发追加污染结果。
        with corpus.open("wb") as out:
            for path in paths:
                data = Path(path).read_bytes()
                rows = [json.loads(line) for line in data.splitlines() if line.strip()]
                if not rows:
                    raise ValueError(f"空语料：{path}")
                for row in rows:
                    if not isinstance(row, dict) or not isinstance(row.get("features"), dict):
                        raise ValueError("FlowRecord 与 features 必须是 JSON 对象")
                    if row.get("schema_version") != 2 or row["features"].get("schema_version") != 1:
                        raise ValueError("仅支持 FlowRecord v2 / FeatureVector v1")
                    # 非有限数与缺失的证据不允许在比对期间被悄悄归一化。
                    signature(row)
                expected.extend(rows)
                inputs.append({"path": str(path), "records": len(rows), "bytes": len(data),
                               "sha256": hashlib.sha256(data).hexdigest()})
                out.write(data)
                if not data.endswith(b"\n"):
                    out.write(b"\n")
        ddl = DDL.read_text(encoding="utf-8")
        version = run(binary, directory, "SELECT version() FORMAT TSV;").strip()
        run(binary, directory, ddl)
        started = time.perf_counter()
        run(binary, directory, f"INSERT INTO {TABLE} FROM INFILE {sql_string(corpus)} FORMAT JSONEachRow;")
        insert_seconds = time.perf_counter() - started
        # 独立进程重新打开目录读回，不能只验证内存里那份表。
        actual = [json.loads(line) for line in run(
            binary, directory, f"SELECT * FROM {TABLE} FORMAT JSONEachRow;").splitlines()]
        verify_records(expected, actual)
        parts = json.loads(run(binary, directory, f"""
SELECT count() AS active_parts, sum(rows) AS records,
       sum(bytes_on_disk) AS bytes_on_disk,
       sum(data_compressed_bytes) AS data_compressed_bytes,
       sum(data_uncompressed_bytes) AS data_uncompressed_bytes
FROM system.parts WHERE active AND database = 'default' AND table = '{TABLE}'
FORMAT JSONEachRow;
"""))
        if parts["records"] != len(expected) or parts["bytes_on_disk"] <= 0:
            raise ValueError("system.parts 条数/落盘字节与语料不符")
        if not 0 < parts["data_compressed_bytes"] <= parts["bytes_on_disk"]:
            raise ValueError("压缩列数据字节必须为正且不大于含索引/元数据的 part 总字节")
        return {
            "label": label, "measured_at_utc": datetime.now(timezone.utc).isoformat(),
            "platform": platform.platform(), "clickhouse_version": version,
            "clickhouse_binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
            "ddl_sha256": hashlib.sha256(ddl.encode()).hexdigest(),
            "engine": "MergeTree", "format": "JSONEachRow", "inputs": inputs,
            "records": len(expected), "roundtrip_verified": True, "parts": parts,
            "bytes_per_record": parts["bytes_on_disk"] / len(expected),
            "working_directory_file_bytes": sum(p.stat().st_size for p in directory.rglob("*") if p.is_file()),
            "insert_process_seconds": insert_seconds,
            "insert_records_per_second": len(expected) / insert_seconds,
            "caveats": [
                "单机 clickhouse local、单批写入；耗时含进程启动/打开表/解析/写入/退出，非服务持续写入吞吐。",
                "bytes_on_disk 为 active parts（含索引/marks/part 元数据），不是仅压缩列流大小。",
                "working_directory_file_bytes 为临时数据库文件逻辑长度；不含文件系统块取整、日志、复制、备份和合并峰值。",
                "样本量、字段多样性、分区、批次与版本影响空间；本结果不自动替换 gzip(JSONL) 容量默认值。",
            ],
        }


def self_test():
    row = {"id": 2**64 - 1, "risk": None, "ip": "2001:db8::1", "f": 1.0,
           "name": '例子"\n\\', "enabled": True}
    verify_records([row, row], [copy.deepcopy(row), copy.deepcopy(row)])
    verify_records([row], [dict(row, f=1)])
    verify_records([row, dict(row, id=1)], [dict(row, id=1), row])
    for bad in ([row], [dict(row, risk=0), row], [dict(row, id=float(row["id"])), row],
                [dict(row, enabled=1), row], [dict(row, ip="::1"), row],
                [dict(row, name="例子"), row], [dict(row, extra=0), row]):
        try:
            verify_records([row, row], bad)
        except ValueError:
            continue
        raise AssertionError("读回比对器未拦住丢行/改值/类型变化")
    assert sql_string("a'\\b") == "'a\\'\\\\b'"
    print("✓ ClickHouse 比对器自证：乱序/数值表示兼容，7 项损坏注入均被拒绝")


def integration_test(binary, measure_fn=measure):
    # 来自真实 Rust 产物，避免另写一份 Python FlowRecord 假装对齐。
    source = ROOT / "build/storage-measurement/check.jsonl"
    source.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([str(ROOT / "target/release/cythsec-analyze"), "-r",
                    str(ROOT / "datasets/dpi/dns-vectors.pcap"), "-o", str(source), "--quiet"], check=True)
    rows = read_records(source)
    special = copy.deepcopy(rows[0])
    special["session_id"] = 2**64 - 1
    special["flow"]["src_ip"] = "2001:db8::1"
    special["app"]["server_name"] = '例子.测试"\n\\'
    special["features"]["payload_entropy_bits"] = None
    special["risk_score"] = 0.0
    rows.extend([special, copy.deepcopy(special)])
    with tempfile.TemporaryDirectory(prefix="cythsec-ch-check-") as tmp:
        path = Path(tmp) / "edge'case.jsonl"

        def write(items):
            path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in items), encoding="utf-8")

        write(rows)
        report = measure_fn(binary, [path], "边界检查")
        assert report["records"] == len(rows) and report["roundtrip_verified"]
        print("✓ 真实引擎：Rust DNS 语料 + IPv6 / UInt64 最大值 / null / Unicode / 转义 / 重复行 / 末行无换行")
        for name in ("record-version", "feature-version", "missing-field", "missing-top-level",
                     "unknown-field", "unknown-top-level", "overflow", "null-counter"):
            bad = copy.deepcopy(rows[0])
            if name == "record-version":
                bad["schema_version"] = 3
            elif name == "feature-version":
                bad["features"]["schema_version"] = 2
            elif name == "missing-field":
                del bad["features"]["payload_entropy_bits"]
            elif name == "missing-top-level":
                del bad["risk_score"]
            elif name == "unknown-field":
                bad["features"]["surprise"] = 42
            elif name == "unknown-top-level":
                bad["surprise"] = 42
            elif name == "overflow":
                bad["flow"]["src_port"] = 65536
            else:
                bad["counters"]["bytes"] = None
            write([bad])
            try:
                measure_fn(binary, [path], name)
            except ValueError as exc:
                # 环境错误/进程崩溃不能伪装成"拒绝了坏数据"。
                markers = ("仅支持 FlowRecord", "逐字段读回不一致", "INCORRECT_DATA",
                           "UNKNOWN_FIELD", "CANNOT_INSERT_NULL_IN_ORDINARY_COLUMN",
                           "CANNOT_PARSE_INPUT_ASSERTION_FAILED", "VALUE_IS_OUT_OF_RANGE_OF_DATA_TYPE",
                           "VIOLATED_CONSTRAINT")
                if not any(marker in str(exc) for marker in markers):
                    raise
                print(f"✓ 真实引擎注入被拒绝：{name}")
                continue
            raise AssertionError(f"真实引擎注入未被检出：{name}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--jsonl", nargs="+", type=Path)
    ap.add_argument("--clickhouse", default="clickhouse")
    ap.add_argument("--label", default="FlowRecord MergeTree 落盘测量")
    ap.add_argument("--json", type=Path)
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--integration-test", action="store_true")
    args = ap.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        binary = shutil.which(args.clickhouse)
        if binary is None:
            print("未核验：缺少 ClickHouse 可执行文件（用 --clickhouse 指定）", file=sys.stderr)
            return 3
        binary = str(Path(binary).resolve())
        if args.integration_test:
            integration_test(binary)
            return 0
        if not args.jsonl:
            ap.error("测量需要 --jsonl；自证使用 --self-test / --integration-test")
        report = measure(binary, args.jsonl, args.label)
        print(f"✓ {report['label']}：{report['records']} 条，完整读回一致；"
              f"ClickHouse {report['clickhouse_version']}")
        print(f"  active parts：{report['parts']['bytes_on_disk']} B，"
              f"{report['bytes_per_record']:.2f} B/记录；"
              f"单批进程 {report['insert_process_seconds']:.3f} s")
        for note in report["caveats"]:
            print(f"  口径：{note}")
        if args.json:
            args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return 0
    except (ValueError, AssertionError, OSError, subprocess.SubprocessError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
