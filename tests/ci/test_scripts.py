"""Exercise exit propagation, incomplete acceptance and network cleanup."""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ScriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.log = self.work / "calls"
        self.env = {**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}", "CALLS": str(self.log)}

    def tool(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/bash\nset -eu\n" + body + "\n")
        path.chmod(0o755)

    def run_script(self, name, *args):
        return subprocess.run(
            ["bash", str(ROOT / "scripts/ci" / name), *args], env=self.env, text=True, capture_output=True
        )

    def test_exit_code_and_log_are_preserved(self):
        for status in (0, 7, 13):
            with self.subTest(status=status):
                self.tool("check", f"echo evidence; exit {status}")
                path = self.work / "evidence/run.log"
                run = self.run_script("run-check.sh", str(path), "check")
                self.assertEqual(run.returncode, status, run.stderr)
                self.assertEqual(path.read_text(), "evidence\n")

    def test_incomplete_acceptance_is_failure(self):
        for output in (
            "⚠ [live] SKIPPED（未验收）",
            "  [SKIP] no root",
            "SKIPPED: missing permission",
            "⚠ [branch-policy] 未核验：未安装钩子",
            "==> D. 参考实现复核：⚠ 未找到 clickhouse 二进制",
            "  ⚠ tshark 不可用：产物未经第三方核验（不计为通过）",
        ):
            with self.subTest(output=output):
                self.env["OUTPUT"] = output
                self.tool("check", 'printf "%s\\n" "$OUTPUT"')
                run = self.run_script("run-check.sh", str(self.work / "result.log"), "check")
                self.assertEqual(run.returncode, 1, run.stdout + run.stderr)

    def test_success_descriptions_and_registered_field_exceptions_are_not_false_skips(self):
        self.env["OUTPUT"] = (
            "✓ S6b 扫描脚本缺失时打印「未核验」\n"
            "✓ [live] 真实网卡抓包验收完成（SKIPPED 场景由脚本内部显式标注）\n"
            "SKIP(ech): registered field exception\n"
            "✓ [columnar] A/B/C 全绿；D 的结果见上方，缺参考实现时为「未核验」"
        )
        self.tool("check", 'printf "%s\\n" "$OUTPUT"')
        run = self.run_script("run-check.sh", str(self.work / "result.log"), "check")
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)

    def test_missing_command_is_usage_error(self):
        self.assertEqual(self.run_script("run-check.sh").returncode, 2)

    def test_linux_network_cleanup_after_setup_or_command_failure(self):
        self.tool("uname", "echo Linux")
        self.tool(
            "sudo", 'echo "$*" >> "$CALLS"; if [[ "$*" == "ip addr add "* && "$FAIL_SETUP" == 1 ]]; then exit 19; fi'
        )
        self.tool("check", 'echo "$CYTHSEC_LIVE_IFACE $CYTHSEC_LIVE_TARGET $CYTHSEC_LIVE_SUDO"; exit "$CHECK_STATUS"')
        for fail_setup, status, expected in (("0", "0", 0), ("1", "0", 19), ("0", "23", 23)):
            with self.subTest(fail_setup=fail_setup, status=status):
                self.log.write_text("")
                self.env.update(FAIL_SETUP=fail_setup, CHECK_STATUS=status)
                run = self.run_script("linux-live.sh", "check")
                self.assertEqual(run.returncode, expected, run.stdout + run.stderr)
                self.assertEqual(
                    self.log.read_text().splitlines()[-2:], ["ip netns del cythsec-ci", "ip link del cysci0"]
                )
                if fail_setup == "0":
                    self.assertIn("cysci0 198.18.0.2 1", run.stdout)

    def test_linux_network_rejects_other_platform_without_sudo(self):
        self.tool("uname", "echo Darwin")
        self.tool("sudo", 'echo called >> "$CALLS"')
        self.assertEqual(self.run_script("linux-live.sh").returncode, 2)
        self.assertFalse(self.log.exists())

    def test_go_only_build_uses_only_go_toolchain_and_preserves_failure(self):
        # A minimal PATH makes accidental coupling to cmake/cargo/node fail.
        project = self.work / "project"
        (project / "scripts/build").mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/build/build-all.sh", project / "scripts/build/build-all.sh")
        (project / "VERSION").write_text("0.1.0\n")
        for svc in ("routerd", "policyd", "dnsd", "telemetryd"):
            (project / "services" / svc).mkdir(parents=True)
        for name in ("bash", "dirname", "head", "grep", "sort", "tr", "date", "mkdir"):
            (self.bin / name).symlink_to(shutil.which(name))
        self.env["PATH"] = str(self.bin)
        for status in (0, 17):
            with self.subTest(status=status):
                self.tool(
                    "go",
                    f'if [[ "$1" == version ]]; then echo "go version go1.22.12 linux/amd64"; else echo "$*" >> "$CALLS"; exit {status}; fi',
                )
                run = subprocess.run(
                    [str(self.bin / "bash"), str(project / "scripts/build/build-all.sh"), "--go"],
                    env=self.env,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(run.returncode, 0 if status == 0 else 1, run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
