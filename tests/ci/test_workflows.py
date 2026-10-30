"""Repository workflow contracts complement actionlint with failure/coverage checks."""
from copy import deepcopy
from pathlib import Path
import re
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[2]
class Loader(yaml.SafeLoader):
    pass
Loader.yaml_implicit_resolvers = {
    k: [(t, r) for t, r in v if t != 'tag:yaml.org,2002:bool']
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
def load(name):
    return yaml.load((ROOT / '.github/workflows' / name).read_text(), Loader=Loader)
def needs(job):
    value = job.get('needs', [])
    return [value] if isinstance(value, str) else value
def validate_graph(workflow):
    jobs, active, done = workflow['jobs'], set(), set()
    def visit(name):
        if name not in jobs: raise ValueError('Unknown job')
        if name in active: raise ValueError('Dependency cycle')
        if name in done: return
        active.add(name)
        for parent in needs(jobs[name]): visit(parent)
        active.remove(name); done.add(name)
    for name in jobs: visit(name)
    if set(needs(jobs['ci-required'])) != set(jobs) - {'ci-required'}: raise ValueError('Missing required dependency')
    if jobs['ci-required'].get('if') != '${{ always() }}': raise ValueError('Gate can be skipped')

class WorkflowTests(unittest.TestCase):
    def setUp(self): self.ci = load('ci.yml')
    def test_complete_graph(self): validate_graph(self.ci)
    def test_injected_bad_graphs_fail(self):
        for mode in ['unknown','cycle','missing','conditional']:
            w = deepcopy(self.ci)
            if mode == 'unknown': w['jobs']['cpp']['needs'] = ['typo']
            elif mode == 'cycle': w['jobs']['workflow-tests']['needs'] = ['cpp']
            elif mode == 'missing': w['jobs']['ci-required']['needs'].remove('clickhouse')
            else: w['jobs']['ci-required'].pop('if')
            with self.subTest(mode=mode), self.assertRaises(ValueError): validate_graph(w)
    def test_single_entry_and_merge_queue(self):
        self.assertEqual(set(self.ci['on']), {'push','pull_request','merge_group','workflow_dispatch','workflow_call'})
        for name in ['lint.yml','security.yml','rust.yml','cmake-multi-platform.yml']:
            events = load(name)['on']
            self.assertIn('workflow_call', events)
            self.assertNotIn('push', events); self.assertNotIn('pull_request', events)
    def test_workflow_bootstrap_preserves_command_boundaries(self):
        steps = self.ci['jobs']['workflow-tests']['steps']
        script = next(s['run'] for s in steps if s.get('name') == 'Validate workflows and negative tests')
        for command in ['python3 -m unittest discover -s tests/ci -v', 'make hooks', 'bash scripts/verify/check-branch-policy.sh']:
            self.assertIn(command, script.splitlines())

    def test_stage_order(self):
        jobs=self.ci['jobs']
        for name in ['lint','security']: self.assertEqual(needs(jobs[name]), ['workflow-tests'])
        for name in ['cpp','rust','python','go','node']: self.assertEqual(set(needs(jobs[name])), {'lint','security'})
        self.assertEqual(set(needs(jobs['clickhouse'])), {'cpp','rust','go'})
        self.assertIn('linux-live', needs(jobs['package']))
        self.assertIn('full-validation', needs(jobs['package']))
        self.assertEqual(set(needs(jobs['full-validation'])), {'cpp', 'rust', 'python', 'go', 'node'})
    def test_no_soft_failure_or_mutable_external_actions(self):
        for path in (ROOT/'.github/workflows').glob('*.yml'):
            w=load(path.name)
            self.assertEqual(w['permissions']['contents'],'read')
            for job in w['jobs'].values():
                self.assertNotIn('continue-on-error',job)
                if 'runs-on' in job: self.assertIn('timeout-minutes',job)
                for step in job.get('steps',[]):
                    self.assertNotIn('continue-on-error',step)
                    action=step.get('uses','')
                    if action and not action.startswith('./'):
                        self.assertRegex(action,r'@[0-9a-f]{40}$')
    def test_storage_and_browser_acceptance_are_wired(self):
        jobs=self.ci['jobs']
        text='\n'.join(s.get('run','') for s in jobs['clickhouse']['steps'])
        for script in ['check-clickhouse-compose.py','check-clickhouse-writer.py','check-clickhouse-resume.py']: self.assertIn(script,text)
        node='\n'.join(s.get('run','') for s in jobs['node']['steps'])
        self.assertIn('playwright install --with-deps chromium',node)
        self.assertIn('npm test',node)
        self.assertEqual(jobs['node']['strategy']['matrix']['node'],['22','24'])
    def test_release_is_verified_tag_only_and_private_draft(self):
        w=load('delivery.yml');job=w['jobs']['draft-release']
        self.assertEqual(needs(job),['verify'])
        self.assertIn("refs/tags/v",job['if'])
        text='\n'.join(s.get('run','') for s in job['steps'])
        self.assertIn('sha256sum --check',text);self.assertIn('--verify-tag --draft',text)
        self.assertIn('m["commit"] == os.environ["GITHUB_SHA"]',text)
    def test_release_contains_every_declared_rust_cli(self):
        manifest = (ROOT / 'dataplane/traffic-engine/Cargo.toml').read_text()
        binaries = re.findall(r'\[\[bin\]\]\s*name\s*=\s*"([^"]+)"', manifest)
        package = (ROOT / 'scripts/release/package.sh').read_text()
        self.assertTrue(binaries)
        for binary in binaries:
            self.assertIn(binary, package)

    def test_rust_regressions_have_bootstrapped_python(self):
        workflow = load('rust.yml')
        def validate(job):
            steps = job['steps']
            target = next(i for i, step in enumerate(steps) if '--rust' in step.get('run', ''))
            prior = steps[:target]
            if not any(step.get('uses', '').startswith('astral-sh/setup-uv@') for step in prior):
                raise ValueError('missing uv before Rust protocol regressions')
            commands = '\n'.join(step.get('run', '') for step in prior)
            if 'uv python install' not in commands or 'uv sync --project ml/training --locked' not in commands:
                raise ValueError('missing locked Python before offline protocol regressions')
        for name in ['build-test', 'interoperability']:
            job = workflow['jobs'][name]
            validate(job)
            broken = deepcopy(job)
            broken['steps'] = [s for s in broken['steps'] if not s.get('uses', '').startswith('astral-sh/setup-uv@')]
            with self.subTest(job=name), self.assertRaises(ValueError): validate(broken)

    def test_node_jobs_use_the_lockfile_package_manager(self):
        import json
        version = (ROOT / '.npm-version').read_text().strip()
        self.assertEqual(json.loads((ROOT / 'web/console/package.json').read_text())['packageManager'], f'npm@{version}')
        shared = (ROOT / '.github/actions/toolchains/action.yml').read_text()
        self.assertIn('npm install --global "npm@$(cat .npm-version)"', shared)
        for name in ['lint.yml', 'security.yml']:
            text = '\n'.join(step.get('run', '') for job in load(name)['jobs'].values() for step in job.get('steps', []))
            self.assertIn('npm install --global', text)
            self.assertIn('.npm-version', text)
        full = (ROOT / '.github/actions/full-environment/action.yml').read_text()
        self.assertLess(full.index('npm install --global'), full.index('npm ci --prefix'))

    def test_source_paths_are_case_portable(self):
        import subprocess
        paths = subprocess.check_output(['git','ls-files'], cwd=ROOT, text=True).splitlines()
        self.assertEqual(len(paths), len({p.casefold() for p in paths}))
        self.assertTrue((ROOT/'web/console/src/app.tsx').is_file())
        self.assertNotIn('web/console/src/App.tsx', paths)

    def test_shell_wrappers_reject_skips(self):
        import subprocess,tempfile
        with tempfile.TemporaryDirectory() as d:
            command=['bash',str(ROOT/'scripts/ci/run-check.sh'),str(Path(d)/'log'),'bash','-c']
            self.assertEqual(subprocess.run(command+['exit 0'],capture_output=True).returncode,0)
            self.assertNotEqual(subprocess.run(command+["echo SKIPPED"],capture_output=True).returncode,0)
            self.assertNotEqual(subprocess.run(command+['exit 7'],capture_output=True).returncode,0)

if __name__ == '__main__': unittest.main()
