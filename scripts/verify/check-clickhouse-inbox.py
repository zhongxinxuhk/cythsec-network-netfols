#!/usr/bin/env python3
"""Verify multi-file inbox, restart, ACK loss/SIGKILL and new publications against real ClickHouse."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("cc", ROOT / "scripts/verify/check-clickhouse-compose.py")
cc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cc)
SUMMARY = re.compile(r"\[cythsec-ch-write-inbox\] (\{[^\n]+\})")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", type=Path, default=ROOT / "build/storage-measurement/clickhouse-inbox.json")
    args = parser.parse_args()
    run_id = uuid.uuid4().hex[:12]
    cc.COMPOSE += ["--project-name", "cythsec-inbox-" + run_id]
    database = "inbox_" + run_id
    container = "cythsec-inbox-writer-" + run_id
    directory = ROOT / "build/storage-measurement"
    source = directory / ("inbox-" + run_id)
    published = source / "published"
    published.mkdir(parents=True)
    process = None
    log = None
    try:
        cc.compose("up", "-d", "--wait", "--wait-timeout", "90", "clickhouse")
        cc.prepare()
        architecture = json.loads(
            subprocess.check_output(["docker", "image", "inspect", "clickhouse/clickhouse-server:26.10.2.103"])
        )[0]["Architecture"]
        env = dict(
            os.environ,
            GOOS="linux",
            GOARCH=architecture,
            CGO_ENABLED="0",
            GOWORK="off",
            GOPROXY="off",
            GOTOOLCHAIN="local",
        )
        binary = directory / "cythsec-ch-write-linux"
        subprocess.run(
            ["go", "build", "-o", str(binary), "./cmd/cythsec-ch-write"], cwd=ROOT / "services/pkg", env=env, check=True
        )
        data = (directory / "vectors.jsonl").read_bytes()
        truth = cc.ch.read_records(directory / "vectors.jsonl")
        cc.query(f"CREATE DATABASE {database}")
        cc.query(cc.ch.DDL.read_text(), database)
        cc.query((ROOT / "storage/clickhouse/flow_records_v2_dedup.sql").read_text(), database)

        def publish(name):
            staging = published / ".publishing.tmp"
            with staging.open("wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(staging, published / name)
            fd = os.open(published, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

        def command(*extra, named=False):
            return (
                cc.COMPOSE
                + ["run", "--rm", "-T", "--no-deps"]
                + (["--name", container] if named else [])
                + [
                    "writer",
                    "--database",
                    database,
                    "--table",
                    cc.ch.TABLE,
                    "--input-dir",
                    f"/opt/cythsec/{source.name}/published",
                    "--spool",
                    f"/var/spool/cythsec/{database}",
                    "--scan-interval",
                    "100ms",
                    "--max-source-files",
                    "10",
                    "--batch-rows",
                    "4",
                    "--batch-bytes",
                    "100000",
                    "--max-pending-bytes",
                    "1000000",
                    "--timeout",
                    "2s",
                    "--retry-interval",
                    "100ms",
                    "--attempts",
                    "2",
                ]
                + list(extra)
            )

        def once(success=True):
            result = subprocess.run(command("--scan-once"), capture_output=True, text=True, timeout=90)
            if (result.returncode == 0) != success:
                raise ValueError(f"unexpected writer exit {result.returncode}: {result.stderr[-3000:]}")
            match = SUMMARY.search(result.stderr)
            if not match:
                raise ValueError("missing inbox summary")
            return json.loads(match.group(1))

        def count():
            return int(cc.query(f"SELECT count() FROM {cc.ch.TABLE} FORMAT TSV", database).strip())

        def wait_count(expected):
            deadline = time.monotonic() + 40
            while time.monotonic() < deadline:
                actual = count()
                if actual == expected:
                    return
                if actual > expected or process.poll() is not None:
                    raise ValueError(f"writer terminated or unexpected row count {actual}, expected {expected}")
                time.sleep(0.1)
            raise ValueError(f"row count timeout: expected {expected}, observed {count()}")

        results = {}
        publish("a.jsonl")
        publish("b.jsonl")
        results["two_publications"] = once()
        cc.ch.verify_records(truth * 2, cc.readback(database, cc.ch.TABLE))
        results["completed_restart"] = once()
        if (
            results["completed_restart"]["delivered_rows"] != 0
            or results["completed_restart"]["completed_sources"] != 2
        ):
            raise ValueError("completed sources resent after restart")
        print(f"✓ two independent identical files retain {len(truth)*2} rows; completed restart sends zero", flush=True)

        publish("c.jsonl")
        wrapper = source / "block-ack-client.sh"
        wrapper.write_text('#!/bin/sh\n/usr/bin/clickhouse-client "$@" || exit $?\nsleep 60\n')
        wrapper.chmod(0o755)
        log = (source / "killed.log").open("w")
        process = subprocess.Popen(
            command("--client", f"/opt/cythsec/{source.name}/block-ack-client.sh", "--timeout", "90s", named=True),
            stdout=log,
            stderr=log,
        )
        wait_count(len(truth) * 2 + 4)
        subprocess.run(["docker", "kill", "--signal", "KILL", container], check=True, capture_output=True)
        code = process.wait(timeout=15)
        process = None
        log.close()
        log = None
        if code == 0:
            raise ValueError("SIGKILL injection did not stop the writer")
        results["killed_exit"] = code
        results["ack_loss_resume"] = once()
        cc.ch.verify_records(truth * 3, cc.readback(database, cc.ch.TABLE))
        if results["ack_loss_resume"]["recovered_rows"] < 4 or results["ack_loss_resume"]["completed_sources"] != 3:
            raise ValueError("pending source was not recovered")
        print("✓ INSERT committed then SIGKILL before ACK: restart preserves tokens and exact multiset", flush=True)

        changed = data.replace(b'"schema_version":2', b'"schema_version":9', 1)
        if changed == data:
            raise ValueError("source mutation fixture did not change")
        (published / "a.jsonl").write_bytes(changed)
        try:
            results["changed_source"] = once(success=False)
        finally:
            (published / "a.jsonl").write_bytes(data)
        cc.ch.verify_records(truth * 3, cc.readback(database, cc.ch.TABLE))
        print("✓ equal-size completed source mutation rejected before any resend", flush=True)

        log = (source / "watcher.log").open("w")
        process = subprocess.Popen(command(named=True), stdout=log, stderr=log)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            text = (source / "watcher.log").read_text()
            if text.count("[cythsec-ch-write-source]") >= 3:
                break
            if process.poll() is not None:
                raise ValueError("watcher exited before idle scan")
            time.sleep(0.1)
        else:
            raise ValueError("watcher did not confirm initial sources")
        duplicate = subprocess.run(command("--scan-once"), capture_output=True, text=True, timeout=15)
        if duplicate.returncode == 0 or "占用" not in duplicate.stderr:
            raise ValueError("a second inbox owner was not refused")
        (published / "partial.jsonl.tmp").write_bytes(data[:100])
        time.sleep(0.3)
        if count() != len(truth) * 3:
            raise ValueError("unfinished publication was consumed")
        publish("d.jsonl")
        wait_count(len(truth) * 4)
        # The server commit can precede its durable per-source acknowledgement.
        deadline = time.monotonic() + 15
        while (
            time.monotonic() < deadline and (source / "watcher.log").read_text().count("[cythsec-ch-write-source]") < 4
        ):
            time.sleep(0.1)
        subprocess.run(["docker", "stop", "--time", "5", container], check=True, capture_output=True)
        process.wait(timeout=15)
        process = None
        log.close()
        log = None
        match = SUMMARY.search((source / "watcher.log").read_text())
        if not match:
            raise ValueError("watcher did not emit final summary")
        results["watcher"] = json.loads(match.group(1))
        if results["watcher"]["completed_sources"] != 4 or results["watcher"]["delivered_rows"] != len(truth):
            raise ValueError("new publication was not acknowledged exactly once")
        cc.ch.verify_records(truth * 4, cc.readback(database, cc.ch.TABLE))
        print("✓ watcher discovers new publication, ignores partials and rejects concurrent owners", flush=True)
        report = {
            "measured_at_utc": datetime.now(timezone.utc).isoformat(),  # noqa: UP017 -- system Python 3.9 entry point
            "database": database,
            "clickhouse_version": cc.query("SELECT version() FORMAT TSV").strip(),
            "architecture": architecture,
            "writer_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "rows_per_file": len(truth),
            "verified_final_rows": len(truth) * 4,
            "results": results,
            "scope": "isolated project; immutable files; bounded deduplication window; not a throughput benchmark",
        }
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(f"✓ inbox report: {args.json}")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1
    finally:
        if process is not None:
            subprocess.run(["docker", "kill", container], capture_output=True)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if log is not None:
            log.close()
        cc.compose("down", "--volumes")


if __name__ == "__main__":
    raise SystemExit(main())
