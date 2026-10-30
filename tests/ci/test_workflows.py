"""Guard the pipeline DAG, trigger coverage and full-suite wiring."""

import unittest
from copy import deepcopy
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class WorkflowLoader(yaml.SafeLoader):
    """GitHub's event key `on` must not become the YAML 1.1 boolean True."""


WorkflowLoader.yaml_implicit_resolvers = {
    key: [(tag, regex) for tag, regex in values if tag != "tag:yaml.org,2002:bool"]
    for key, values in yaml.SafeLoader.yaml_implicit_resolvers.items()
}


def load(path):
    return yaml.load(path.read_text(), Loader=WorkflowLoader)


def needs(job):
    value = job.get("needs", [])
    return [value] if isinstance(value, str) else value


def validate_graph(workflow):
    jobs = workflow["jobs"]
    visiting, visited = set(), set()

    def visit(name):
        if name not in jobs:
            raise ValueError(f"Unknown dependency: {name}")
        if name in visiting:
            raise ValueError(f"Dependency cycle: {name}")
        if name in visited:
            return
        visiting.add(name)
        for prerequisite in needs(jobs[name]):
            visit(prerequisite)
        visiting.remove(name)
        visited.add(name)

    for name in jobs:
        visit(name)
    gate = jobs["ci-required"]
    if set(needs(gate)) != set(jobs) - {"ci-required"}:
        raise ValueError("Required gate must include every other job")
    if gate.get("if") != "${{ always() }}":
        raise ValueError("Required gate must run after failure or skip")


def commands(job):
    return "\n".join(step.get("run", "") for step in job.get("steps", []))


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflows = {p.name: load(p) for p in (ROOT / ".github/workflows").glob("*.yml")}
        cls.ci = cls.workflows["ci.yml"]

    def test_every_push_has_one_orchestrator_and_no_cancellation(self):
        self.assertEqual(set(self.ci["on"]), {"push", "pull_request", "merge_group", "workflow_dispatch"})
        self.assertIsNone(self.ci["on"]["push"], "No branch, tag or path filters")
        for name, workflow in self.workflows.items():
            self.assertNotIn("concurrency", workflow, name)
            if name != "ci.yml":
                self.assertNotIn("push", workflow["on"], name)
                self.assertNotIn("pull_request", workflow["on"], name)
        for name in ("lint", "security", "rust", "cmake-multi-platform", "full-validation"):
            self.assertIn("workflow_call", self.workflows[f"{name}.yml"]["on"])
            self.assertIn("workflow_dispatch", self.workflows[f"{name}.yml"]["on"])
        self.assertIn("schedule", self.workflows["security.yml"]["on"])
        self.assertEqual(
            set(self.workflows["generator-generic-ossf-slsa3-publish.yml"]["on"]), {"release", "workflow_dispatch"}
        )

    def test_graph_is_acyclic_and_gate_covers_every_job(self):
        validate_graph(self.ci)

    def test_invalid_graphs_and_incomplete_gate_are_rejected(self):
        for mutation in ("unknown", "cycle", "omitted", "conditional"):
            workflow = deepcopy(self.ci)
            if mutation == "unknown":
                workflow["jobs"]["cpp"]["needs"] = "typo"
            elif mutation == "cycle":
                workflow["jobs"]["workflow-tests"]["needs"] = "e2e"
            elif mutation == "omitted":
                workflow["jobs"]["ci-required"]["needs"].remove("node")
            else:
                del workflow["jobs"]["ci-required"]["if"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                validate_graph(workflow)

    def test_stages_run_in_order(self):
        stages = ["workflow-tests", "lint", "security", "cpp", "rust", "python", "go", "node", "full-validation", "e2e"]
        self.assertEqual(needs(self.ci["jobs"][stages[0]]), [])
        for previous, current in zip(stages, stages[1:]):
            self.assertEqual(needs(self.ci["jobs"][current]), [previous])
        rust = self.workflows["rust.yml"]["jobs"]
        self.assertEqual(needs(rust["build-test"]), ["quality"])
        self.assertEqual(needs(rust["interoperability"]), ["build-test"])

    def test_full_default_suite_is_connected_without_group_filters(self):
        job = self.workflows["full-validation.yml"]["jobs"]["acceptance"]
        run = commands(job)
        self.assertIn("bash scripts/build/build-all.sh\n", run)
        self.assertIn("bash scripts/lint/lint-all.sh", run)
        self.assertRegex(run, r"run-check.sh \S+ bash scripts/ci/linux-live.sh bash scripts/test/test-all.sh(?:\n|$)")
        self.assertIn("run-check.sh build/ci/capture-modes.log sudo", run)
        self.assertIn("install-clickhouse.sh", run)
        composite = load(ROOT / ".github/actions/full-environment/action.yml")
        bootstrap = "\n".join(s.get("run", "") for s in composite["runs"]["steps"])
        for requirement in ("cargo fetch --locked", "uv sync", "--group quality", "npm ci", "make hooks"):
            self.assertIn(requirement, bootstrap)

    def test_existing_coverage_is_preserved(self):
        jobs = self.ci["jobs"]
        for command in ("typecheck:all", "npm run lint", "test-all.sh --node", "npm run build"):
            self.assertIn(command, commands(jobs["node"]))
        for command in ("go vet", "go test -race", "services/*/go.mod"):
            self.assertIn(command, commands(jobs["go"]))
        self.assertIn("check-training-project.sh", commands(jobs["python"]))
        self.assertIn("e2e-control-plane.sh", commands(jobs["e2e"]))
        self.assertIn("check-aggregate-storage.sh", commands(jobs["e2e"]))
        self.assertIn("scan-go-vulns.sh", commands(self.workflows["security.yml"]["jobs"]["govulncheck"]))
        self.assertIn("--audit-level=low", commands(self.workflows["security.yml"]["jobs"]["npm-audit"]))
        self.assertIn("--no-tests=error", commands(self.workflows["cmake-multi-platform.yml"]["jobs"]["build"]))
        rust = self.workflows["rust.yml"]["jobs"]
        self.assertEqual(set(rust["build-test"]["strategy"]["matrix"]["os"]), {"ubuntu-24.04", "macos-15"})
        self.assertIn("--release", commands(rust["build-test"]))
        self.assertIn("--tshark", commands(rust["interoperability"]))

    def test_prerelease_publishes_only_after_successful_push(self):
        workflow = self.workflows["prerelease.yml"]
        self.assertEqual(set(workflow["on"]), {"workflow_run", "workflow_dispatch"})
        self.assertEqual(workflow["on"]["workflow_run"]["workflows"], ["CI"])
        job = workflow["jobs"]["publish"]
        self.assertEqual(job["permissions"], {"contents": "write"})
        self.assertIn("workflow_run.conclusion == 'success'", job["if"])
        self.assertIn("workflow_run.event == 'push'", job["if"])
        self.assertEqual(job["timeout-minutes"], 45)
        checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        self.assertEqual(checkout["with"]["ref"], "${{ github.event.workflow_run.head_sha || github.sha }}")
        run = commands(job)
        self.assertIn("bash scripts/ci/package-release.sh dist/release", run)
        self.assertIn("bash scripts/ci/publish-prerelease.sh dist/release", run)
        self.assertIn("actions/upload-artifact@", str(job["steps"]))
        self.assertIn("prerelease-packages", str(job["steps"]))

    def test_permissions_pins_and_no_soft_failure(self):
        self.assertEqual(self.ci["jobs"]["security"]["permissions"]["pull-requests"], "read")
        for name, workflow in self.workflows.items():
            self.assertEqual(workflow["permissions"], {"contents": "read"}, name)
            for job in workflow["jobs"].values():
                self.assertNotIn("continue-on-error", job)
                if "runs-on" in job:
                    self.assertGreater(job["timeout-minutes"], 0)
                for step in job.get("steps", []):
                    self.assertNotIn("continue-on-error", step)
                    action = step.get("uses", "")
                    if action and not action.startswith("./"):
                        self.assertRegex(action, r"^[\w./-]+@[a-f0-9]{40}$")
                    if action.startswith("actions/checkout@"):
                        self.assertEqual(step["with"]["persist-credentials"], "false")
                if job.get("uses", "").startswith("./"):
                    self.assertTrue((ROOT / job["uses"]).is_file())
        gate = self.ci["jobs"]["ci-required"]
        self.assertEqual(gate["steps"][-1]["env"]["CI_NEEDS_JSON"], "${{ toJSON(needs) }}")
        self.assertIn("scripts/ci/check-results.py", commands(gate))


if __name__ == "__main__":
    unittest.main()
