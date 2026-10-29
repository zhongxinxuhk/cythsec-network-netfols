#!/usr/bin/env python3
"""实际 native 写入器：正常批量、失败重放、ACK 丢失、背压恢复（隔离 Compose）。"""

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("compose_check", ROOT / "scripts/verify/check-clickhouse-compose.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)
STATS = re.compile(r"\[cythsec-ch-write\] (\{[^\n]+\})")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path, default=ROOT / "build/storage-measurement/clickhouse-writer.json")
    args = ap.parse_args()
    database = "cythsec_writer_" + uuid.uuid4().hex[:12]
    process = None
    try:
        cc.compose("up", "-d", "--wait", "--wait-timeout", "90", "clickhouse")
        cc.prepare()
        directory = ROOT / "build/storage-measurement"
        arch = json.loads(subprocess.check_output(["docker", "image", "inspect", "clickhouse/clickhouse-server:26.10.2.103"]))[0]["Architecture"]
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOWORK="off", GOPROXY="off", GOTOOLCHAIN="local")
        version = (ROOT / "VERSION").read_text().strip()
        subprocess.run(["go", "build", "-ldflags", f"-X cythsec/services/pkg/versioninfo.Version={version}",
                        "-o", str(directory / "cythsec-ch-write-linux"), "./cmd/cythsec-ch-write"],
                       cwd=ROOT / "services/pkg", env=env, check=True)
        # 真实服务已提交 INSERT，但故意向写入器报告失败，模拟 ACK 丢失。
        wrapper = directory / "drop-ack-client.sh"
        wrapper.write_text('#!/bin/sh\n/usr/bin/clickhouse-client "$@" || exit $?\nexit 97\n')
        wrapper.chmod(0o755)
        cc.query(f"CREATE DATABASE {database}")

        def table(name):
            cc.query(cc.ch.DDL.read_text().replace("CREATE TABLE " + cc.ch.TABLE, "CREATE TABLE " + name), database)
            cc.query((ROOT / "storage/clickhouse/flow_records_v1_dedup.sql").read_text().replace(cc.ch.TABLE, name), database)

        def command(name, *extra):
            return cc.COMPOSE + ["run", "--rm", "-T", "--no-deps", "writer", "--database", database,
                "--table", name, "--spool", f"/var/spool/cythsec/{database}/{name}",
                "--batch-rows", "500", "--batch-bytes", "1000000", "--retry-interval", "200ms", "--timeout", "2s"] + list(extra)

        def result(p, success=True):
            if (p.returncode == 0) != success:
                raise ValueError(f"写入器退出 {p.returncode}: {p.stderr[-4000:]}")
            match = STATS.search(p.stderr)
            if not match:
                raise ValueError(f"缺少写入统计: {p.stderr[-2000:]}")
            return json.loads(match.group(1))

        def run(name, *extra, success=True):
            p = subprocess.run(command(name, *extra), capture_output=True, text=True, timeout=120)
            return result(p, success)

        vectors = cc.ch.read_records(directory / "vectors.jsonl")
        bulk = cc.ch.read_records(directory / "homogeneous.jsonl")
        results = {}
        table("normal")
        results["normal"] = run("normal", "--input", "/opt/cythsec/vectors.jsonl")
        cc.ch.verify_records(vectors, cc.readback(database, "normal"))
        print("✓ native 正常批量：37 条逐字段一致", flush=True)

        table("repeat")
        results["repeat_first"] = run("repeat", "--input", "/opt/cythsec/vectors.jsonl")
        results["repeat_second"] = run("repeat", "--input", "/opt/cythsec/vectors.jsonl")
        cc.ch.verify_records(vectors + vectors, cc.readback(database, "repeat"))
        print("✓ 两次独立提交相同内容：保留全部 74 条，不把合法重复当重试吞掉", flush=True)

        table("retry")
        cc.compose("stop", "clickhouse")
        results["outage"] = run("retry", "--input", "/opt/cythsec/vectors.jsonl", "--attempts", "2", success=False)
        if results["outage"]["pending_batches"] != 1 or results["outage"]["accepted_rows"] != len(vectors):
            raise ValueError("服务不可用时未将整批保留到持久化队列")
        cc.compose("up", "-d", "--wait", "--wait-timeout", "90", "clickhouse")
        results["replay"] = run("retry", "--replay-only")
        cc.ch.verify_records(vectors, cc.readback(database, "retry"))
        if results["replay"]["recovered_rows"] != len(vectors) or results["replay"]["pending_bytes"] != 0:
            raise ValueError("新进程未完整重放并确认队列")
        print("✓ 服务停机 -> 失败落盘 -> 新容器重放：37 条完整恢复", flush=True)

        table("ack_loss")
        results["ack_loss"] = run("ack_loss", "--input", "/opt/cythsec/vectors.jsonl", "--attempts", "2",
                                  "--client", "/opt/cythsec/drop-ack-client.sh", success=False)
        cc.ch.verify_records(vectors, cc.readback(database, "ack_loss"))
        results["ack_replay"] = run("ack_loss", "--replay-only")
        cc.ch.verify_records(vectors, cc.readback(database, "ack_loss"))
        print("✓ ACK 丢失：重复 INSERT 与跨进程重放后仍为原 37 条，无重复", flush=True)

        table("pressure")
        cc.compose("stop", "clickhouse")
        started = time.perf_counter()
        process = subprocess.Popen(command("pressure", "--input", "/opt/cythsec/homogeneous.jsonl",
                    "--max-pending-bytes", "1600000", "--attempts", "100"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # 等到在途+待发送批次接近容量，再恢复服务；不把一个空队列当背压证据。
        deadline = time.monotonic() + 30
        observed = 0
        while time.monotonic() < deadline:
            out = cc.compose("run", "--rm", "-T", "--no-deps", "--entrypoint", "/bin/sh", "writer", "-c",
                f"find /var/spool/cythsec/{database}/pressure -name '*.batch' -exec wc -c {{}} + 2>/dev/null | tail -1 || true")
            numbers = re.findall(r"^\s*(\d+)", out)
            observed = int(numbers[0]) if numbers else 0
            if observed > 1000000: break
            if process.poll() is not None: raise ValueError("背压测试进程提前退出")
            time.sleep(0.1)
        if not 1000000 < observed <= 1600000: raise ValueError(f"没有观测到有界积压：{observed}")
        cc.compose("up", "-d", "--wait", "--wait-timeout", "90", "clickhouse")
        stdout, stderr = process.communicate(timeout=120)
        results["pressure"] = result(subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr))
        elapsed = time.perf_counter() - started
        process = None
        if results["pressure"]["backpressure_waits"] == 0 or results["pressure"]["pending_bytes"] != 0:
            raise ValueError("未证明背压等待与服务恢复后的排空")
        cc.ch.verify_records(bulk, cc.readback(database, "pressure"))
        print(f"✓ 背压与恢复：20,182 条逐字段一致，积压 {observed} B，恢复后排空", flush=True)
        report = {"measured_at_utc": datetime.now(timezone.utc).isoformat(), "database": database,
                  "writer_version": version,
                  "writer_binary_sha256": hashlib.sha256((directory / "cythsec-ch-write-linux").read_bytes()).hexdigest(),
                  "inputs": {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                             (directory / "vectors.jsonl", directory / "homogeneous.jsonl")},
                  "clickhouse_version": cc.query("SELECT version() FORMAT TSV").strip(), "architecture": arch,
                  "transport": "official clickhouse-client native TCP", "results": results,
                  "peak_observed_pending_bytes": observed, "pending_limit_bytes": 1600000,
                  "pressure_elapsed_seconds_including_outage": elapsed,
                  "verified_rows": {"normal": len(vectors), "repeat": len(vectors)*2, "retry": len(vectors), "ack_loss": len(vectors), "pressure": len(bulk)},
                  "caveats": ["去重仅在 non_replicated_deduplication_window=10000 的测试窗口内验证。",
                              "每批启动一次官方客户端；该试验含停机恢复，不作为持续吞吐承诺。",
                              "仅已持久化批次属于已接收记录；内存尾批仍由上游检查点负责。"]}
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(f"✓ 写入器报告：{args.json}")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1
    finally:
        if process is not None:
            process.terminate()
            try: process.communicate(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.communicate()
        # 停机注入失败也恢复本任务的测试服务；不影响其他 Compose 项目。
        cc.compose("up", "-d", "--wait", "--wait-timeout", "90", "clickhouse")


if __name__ == "__main__":
    sys.exit(main())
