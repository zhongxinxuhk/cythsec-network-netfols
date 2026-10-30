#!/usr/bin/env python3
"""采集器持久化发布 -> 文件断点 -> native 写入；验证失败恢复、SIGKILL、源变更拒绝。"""

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
spec = importlib.util.spec_from_file_location("cc", ROOT / "scripts/verify/check-clickhouse-compose.py")
cc = importlib.util.module_from_spec(spec); spec.loader.exec_module(cc)
STATS = re.compile(r"\[cythsec-ch-write\] (\{[^\n]+\})")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--json", type=Path, default=ROOT / "build/storage-measurement/clickhouse-resume.json")
    args = ap.parse_args()
    run_id = uuid.uuid4().hex[:12]
    database = "cythsec_resume_" + run_id
    kill_name = "cythsec-resume-kill-" + run_id
    process = None
    try:
        cc.compose("up", "-d", "--wait", "--wait-timeout", "90", "clickhouse")
        cc.prepare()
        directory = ROOT / "build/storage-measurement"
        source_dir = directory / ("resume-" + run_id); source_dir.mkdir()
        arch = json.loads(subprocess.check_output(["docker", "image", "inspect", cc.image()]))[0]["Architecture"]
        version = (ROOT / "VERSION").read_text().strip()
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0", GOWORK="off", GOPROXY="off", GOTOOLCHAIN="local")
        subprocess.run(["go", "build", "-ldflags", f"-X cythsec/services/pkg/versioninfo.Version={version}",
                        "-o", str(directory / "cythsec-ch-write-linux"), "./cmd/cythsec-ch-write"], cwd=ROOT / "services/pkg", env=env, check=True)
        subprocess.run(["cargo", "build", "--release", "--offline", "--bin", "cythsec-ipfix-collect"], cwd=ROOT, check=True)
        exported = source_dir / "export.pcap"
        subprocess.run([str(ROOT / "target/release/cythsec-analyze"), "-r", str(ROOT / "datasets/dpi/dns-vectors.pcap"),
                        "-o", str(source_dir / "original.jsonl"), "--ipfix-pcap", str(exported), "--quiet"], check=True)
        collected = source_dir / "collected.jsonl"
        collect_command = [str(ROOT / "target/release/cythsec-ipfix-collect"), "--pcap", str(exported),
                           "-o", str(collected), "--durable-output", "--quiet"]
        publication = subprocess.run(collect_command, capture_output=True, text=True, check=True)
        match = re.search(r"durable_output=(\{[^\n]+\})", publication.stderr)
        if not match: raise ValueError("采集器没有持久化发布回执")
        receipt = json.loads(match.group(1))
        truth = cc.ch.read_records(collected)
        original_data = collected.read_bytes()
        original_hash = hashlib.sha256(original_data).hexdigest()
        if len(truth) != 15 or receipt["records"] != 15 or receipt["bytes"] != len(original_data):
            raise ValueError("采集器回执与 15 条 DNS 流记录不一致")
        refused = subprocess.run(collect_command, capture_output=True, text=True)
        if refused.returncode == 0 or "durable_output=" in refused.stderr or collected.read_bytes() != original_data:
            raise ValueError("采集器错误地覆盖/确认了已有发布文件")
        print("✓ 采集器：15 条持久化发布并确认，重复发布名拒绝覆盖", flush=True)
        cc.query(f"CREATE DATABASE {database}")

        def table(name):
            cc.query(cc.ch.DDL.read_text().replace("CREATE TABLE " + cc.ch.TABLE, "CREATE TABLE " + name), database)
            cc.query((ROOT / "storage/clickhouse/flow_records_v2_dedup.sql").read_text().replace(cc.ch.TABLE,name),database)

        def command(name, path, *extra, named=False):
            options = ["--name",kill_name] if named else []
            mounted = "/opt/cythsec/" + str(path.relative_to(directory))
            return cc.COMPOSE + ["run","--rm","-T","--no-deps"] + options + ["writer", "--database",database,
                "--table",name,"--spool",f"/var/spool/cythsec/{database}/{name}","--input",mounted,"--resume-file",
                "--batch-rows","500","--batch-bytes","1000000","--retry-interval","200ms","--timeout","2s"] + list(extra)

        def stats(p, success=True):
            if (p.returncode == 0) != success: raise ValueError(f"断点写入器退出 {p.returncode}: {p.stderr[-4000:]}")
            m = STATS.search(p.stderr)
            if not m: raise ValueError("缺少源文件/队列统计")
            return json.loads(m.group(1))

        def run(name,path,*extra,success=True):
            return stats(subprocess.run(command(name,path,*extra),capture_output=True,text=True,timeout=120),success)

        results = {}
        table("published")
        results["published"] = run("published",collected,"--batch-rows","4")
        results["completed_rerun"] = run("published",collected,"--batch-rows","4")
        cc.ch.verify_records(truth,cc.readback(database,"published"))
        if results["completed_rerun"]["attempts"] != 0 or results["completed_rerun"]["accepted_rows"] != 0:
            raise ValueError("完整文件重启后重复发送")
        # 等长修改，不能仅用 size/mtime 代替内容身份。
        changed = original_data.replace(b'"schema_version":1',b'"schema_version":2',1)
        if changed == original_data: raise ValueError("源修改注入未生效")
        collected.write_bytes(changed)
        try: results["changed_source"] = run("published",collected,success=False)
        finally: collected.write_bytes(original_data)
        cc.ch.verify_records(truth,cc.readback(database,"published"))
        print("✓ 同文件完成后重跑零发送；等长源变更拒绝，原数据不变", flush=True)

        table("partial")
        bulk_path = directory / "homogeneous.jsonl"
        bulk = cc.ch.read_records(bulk_path)
        cc.compose("stop","clickhouse")
        results["partial_outage"] = run("partial",bulk_path,"--max-pending-bytes","1800000","--attempts","2",success=False)
        old = results["partial_outage"]
        if not 0 < old["source_rows"] < len(bulk) or not 0 < old["source_offset"] < bulk_path.stat().st_size:
            raise ValueError("没有形成可验证的部分输入断点")
        cc.compose("up","-d","--wait","--wait-timeout","90","clickhouse")
        results["partial_resumed"] = run("partial",bulk_path,"--max-pending-bytes","1800000")
        new = results["partial_resumed"]
        if new["recovered_rows"] != old["source_rows"] or new["accepted_rows"] + new["recovered_rows"] != len(bulk):
            raise ValueError("重放与剩余输入不守恒")
        if new["source_offset"] != bulk_path.stat().st_size or new["source_rows"] != len(bulk) or new["pending_bytes"] != 0:
            raise ValueError("断点未推进至完整文件/队列未排空")
        cc.ch.verify_records(bulk,cc.readback(database,"partial"))
        print(f"✓ 部分接收 {old['source_rows']} 条后停机：重启只读取剩余，共 20,182 条逐字段一致", flush=True)

        table("killed")
        wrapper = source_dir / "block-ack-client.sh"
        wrapper.write_text('#!/bin/sh\n/usr/bin/clickhouse-client "$@" || exit $?\nsleep 60\n')
        wrapper.chmod(0o755)
        process = subprocess.Popen(command("killed",collected,"--batch-rows","4","--timeout","90s",
                    "--client",f"/opt/cythsec/{source_dir.name}/block-ack-client.sh",named=True),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        deadline = time.monotonic() + 20
        committed = 0
        while time.monotonic() < deadline:
            committed = int(cc.query("SELECT count() FROM killed FORMAT TSV",database).strip())
            if committed > 0: break
            if process.poll() is not None: raise ValueError("强杀检查前进程提前退出")
            time.sleep(0.1)
        if committed != 4: raise ValueError(f"强杀前没有精确观测到第一批 4 条落库：{committed}")
        subprocess.run(["docker","kill","--signal","KILL",kill_name],check=True,capture_output=True)
        process.communicate(timeout=15)
        if process.returncode == 0: raise ValueError("SIGKILL 注入未生效")
        killed_code = process.returncode; process = None
        results["killed_resumed"] = run("killed",collected,"--batch-rows","4")
        cc.ch.verify_records(truth,cc.readback(database,"killed"))
        if results["killed_resumed"]["source_rows"] != len(truth) or results["killed_resumed"]["pending_bytes"] != 0:
            raise ValueError("强杀后未恢复全部文件进度")
        print("✓ 已落库未确认时 SIGKILL：新进程重放并续读，15 条无缺失无重复", flush=True)

        report = {"measured_at_utc":datetime.now(timezone.utc).isoformat(),"database":database,
            "architecture":arch,"writer_version":version,"publication_receipt":receipt,
            "published_source_sha256":original_hash,"writer_binary_sha256":hashlib.sha256((directory/"cythsec-ch-write-linux").read_bytes()).hexdigest(),
            "results":results,"kill_exit_code":killed_code,"rows_committed_before_kill":committed,
            "verified_rows":{"published":15,"partial":len(bulk),"killed":15},
            "caveats":["不可变普通文件的断点恢复；不追踪追加文件或文件轮转。", "不为实时 UDP 提供端到端确认；native 去重仍受测试表窗口限制。"]}
        args.json.parent.mkdir(parents=True,exist_ok=True)
        args.json.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
        print(f"✓ 采集/断点报告：{args.json}")
        return 0
    except (ValueError,OSError,subprocess.SubprocessError) as exc:
        print(f"✗ {exc}",file=sys.stderr);return 1
    finally:
        if process is not None:
            subprocess.run(["docker","kill",kill_name],capture_output=True)
            try:process.communicate(timeout=10)
            except subprocess.TimeoutExpired:process.kill();process.communicate()
        cc.compose("up","-d","--wait","--wait-timeout","90","clickhouse")


if __name__=="__main__":sys.exit(main())
