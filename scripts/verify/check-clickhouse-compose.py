#!/usr/bin/env python3
"""启动隔离 Compose，复用 FlowRecord 检查，测量 Linux 服务并重建容器验证命名卷。

自动从当前源码构建分析器并重建两档语料。
成功后保留服务和本次测量数据库供检查；不删除命名卷或其他数据库。
"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ch_measure", ROOT / "scripts/plan/measure-clickhouse.py")
ch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ch)
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy/docker/compose.storage-test.yml")]


def compose(*args, data=None):
    p = subprocess.run(COMPOSE + list(args), input=data, capture_output=True, timeout=300)
    if p.returncode:
        raise ValueError(f"Compose 退出 {p.returncode}: {p.stderr.decode(errors='replace')[-4000:]}")
    return p.stdout.decode()


def query(sql, database="default", data=None):
    return compose("exec", "-T", "clickhouse", "clickhouse-client", "--user", "cythsec_test",
                   "--password", "local_storage_test", "--database", database,
                   "--multiquery", "--query", ch.SETTINGS + sql, data=data)


def readback(database, table):
    return [json.loads(line) for line in query(
        f"SELECT * FROM {table} FORMAT JSONEachRow", database).splitlines()]


def prepare():
    for script in ("datasets/pcap/generate-samples.py", "datasets/dpi/generate-dpi-samples.py"):
        subprocess.run([sys.executable, script], cwd=ROOT, check=True)
    subprocess.run(["cargo", "build", "--release", "--offline", "--bin", "cythsec-analyze"], cwd=ROOT, check=True)
    directory = ROOT / "build/storage-measurement"
    directory.mkdir(parents=True, exist_ok=True)
    binary = str(ROOT / "target/release/cythsec-analyze")
    corpus = sorted((ROOT / "datasets/dpi").glob("*.pcap")) + [ROOT / "datasets/pcap/sample-session-tcp.pcap"]
    with (directory / "vectors.jsonl").open("wb") as out:
        for path in corpus:
            dest = directory / (path.stem + ".jsonl")
            subprocess.run([binary, "-r", str(path), "-o", str(dest), "--quiet"], check=True)
            out.write(dest.read_bytes())
    subprocess.run([sys.executable, str(ROOT / "datasets/pcap/generate-bench.py"),
                    str(directory / "bench.pcap"), "20182", "50"], check=True)
    subprocess.run([binary, "-r", str(directory / "bench.pcap"), "-o",
                    str(directory / "homogeneous.jsonl"), "--quiet"], check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path, default=ROOT / "build/storage-measurement/clickhouse-compose.json")
    args = ap.parse_args()
    paths = [ROOT / "build/storage-measurement" / f"{name}.jsonl" for name in ("vectors", "homogeneous")]
    run_id = uuid.uuid4().hex[:12]
    database = "cythsec_check_" + run_id
    table_index = 0

    def measure_service(_binary, inputs, label):
        nonlocal table_index
        table_index += 1
        table = f"flow_records_v1_{table_index}"
        expected, provenance = [], []
        for path in inputs:
            data = Path(path).read_bytes()
            records = [json.loads(line) for line in data.splitlines() if line.strip()]
            if not records:
                raise ValueError("空测量语料")
            expected.extend(records)
            provenance.append({"path": str(Path(path).relative_to(ROOT)) if Path(path).is_relative_to(ROOT) else str(path),
                               "records": len(records), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        query(ch.DDL.read_text().replace("CREATE TABLE " + ch.TABLE, "CREATE TABLE " + table), database)
        payload = ("\n".join(json.dumps(r, ensure_ascii=False, allow_nan=False) for r in expected) + "\n").encode()
        started = time.perf_counter()
        query(f"INSERT INTO {table} FORMAT JSONEachRow", database, payload)
        elapsed = time.perf_counter() - started
        ch.verify_records(expected, readback(database, table))
        parts = json.loads(query(f"""SELECT count() AS active_parts, sum(rows) AS records,
sum(bytes_on_disk) AS bytes_on_disk, sum(data_compressed_bytes) AS data_compressed_bytes,
sum(data_uncompressed_bytes) AS data_uncompressed_bytes
FROM system.parts WHERE active AND database = '{database}' AND table = '{table}' FORMAT JSONEachRow"""))
        if parts["records"] != len(expected) or not 0 < parts["data_compressed_bytes"] <= parts["bytes_on_disk"]:
            raise ValueError("system.parts 条数/字节不符")
        return {"label": label, "database": database, "table": table, "inputs": provenance,
                "records": len(expected), "roundtrip_verified": True, "parts": parts,
                "bytes_per_record": parts["bytes_on_disk"] / len(expected),
                "client_insert_seconds": elapsed, "client_records_per_second": len(expected) / elapsed}

    try:
        print("启动 Compose 并等待 ClickHouse 健康……", flush=True)
        compose("up", "-d", "--wait", "--wait-timeout", "90")
        prepare()
        version = query("SELECT version() FORMAT TSV").strip()
        if version != "26.10.2.103":
            raise ValueError(f"引擎版本与编排不符：{version}")
        query(f"CREATE DATABASE {database}")
        ch.self_test()
        ch.integration_test(None, measure_fn=measure_service)
        # 仅移除本次创建的故障注入库；测量库保留供检查。
        query(f"DROP DATABASE {database} SYNC")
        database = "cythsec_measure_" + run_id
        query(f"CREATE DATABASE {database}")
        reports = [measure_service(None, [path], label) for path, label in
                   zip(paths, ("合成协议/会话向量", "同质压测语料"))]
        container_before = compose("ps", "-q", "clickhouse").strip()
        compose("up", "-d", "--force-recreate", "--wait", "--wait-timeout", "90", "clickhouse")
        container_after = compose("ps", "-q", "clickhouse").strip()
        if not container_after or container_before == container_after:
            raise ValueError("容器未真正重建，持久化检查无效")
        for report, path in zip(reports, paths):
            ch.verify_records(ch.read_records(path), readback(database, report["table"]))
            report["recreated_container_roundtrip_verified"] = True
            print(f"✓ {report['label']}：{report['records']} 条，{report['bytes_per_record']:.2f} B/记录；重建容器后逐字段一致")
        container = json.loads(subprocess.check_output(["docker", "inspect", container_after]))[0]
        image = json.loads(subprocess.check_output(["docker", "image", "inspect", container["Image"]]))[0]
        volume = next(m["Name"] for m in container["Mounts"] if m["Destination"] == "/var/lib/clickhouse")
        report = {"measured_at_utc": datetime.now(timezone.utc).isoformat(),
                  "environment": "Docker Desktop Linux server（非物理 Linux 服务器）",
                  "clickhouse_version": version,
                  "image": {k: image[k] for k in ("Id", "RepoTags", "RepoDigests", "Architecture", "Os")},
                  "data_volume": volume,
                  "ddl_sha256": hashlib.sha256(ch.DDL.read_bytes()).hexdigest(),
                  "invalid_input_checks": 8, "container_recreated": True,
                  "container_before": container_before, "container_after": container_after,
                  "measurements": reports,
                  "caveats": ["单批服务写入；计时含 docker exec/客户端启动与传输，非服务持续吞吐。",
                              "active parts 含索引/元数据，不含日志/复制/备份/合并峰值；未替换 gzip 容量默认值。"]}
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(f"✓ 报告：{args.json}\n服务与测量数据库已保留：{database}")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"✗ {exc}\n保留当前 Compose 和本次数据库供排查：{database}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
