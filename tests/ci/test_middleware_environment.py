"""Private CI test profiles must remain usable without production secrets."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('middleware_env', ROOT / 'scripts/ci/middleware_test_env.py')
middleware = importlib.util.module_from_spec(spec)
spec.loader.exec_module(middleware)


class MiddlewareEnvironmentTests(unittest.TestCase):
    def test_self_contained_private_and_reusable(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {'CYTHSEC_MIDDLEWARE_TEST_ENV_FILE': str(Path(tmp) / 'connection.env'),
                   'CLICKHOUSE_HOST': 'production.example', 'CLICKHOUSE_PASSWORD': 'production-placeholder'}
            values, path = middleware.prepare(env)
            self.assertEqual(values['CYTHSEC_TEST_CLICKHOUSE_HOST'], 'clickhouse')
            self.assertNotEqual(values['CYTHSEC_TEST_CLICKHOUSE_PASSWORD'], env['CLICKHOUSE_PASSWORD'])
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            again, _ = middleware.prepare({'CYTHSEC_MIDDLEWARE_TEST_ENV_FILE': str(path)})
            self.assertTrue(values == again, "private test environment was not reused")
            path.chmod(0o644)
            with self.assertRaises(ValueError): middleware.prepare(env)

    def test_explicit_test_overrides_and_external_endpoint_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = {'CYTHSEC_MIDDLEWARE_TEST_ENV_FILE': str(Path(tmp) / 'connection.env')}
            values, _ = middleware.prepare(dict(base, CYTHSEC_TEST_CLICKHOUSE_PORT='19000', CYTHSEC_TEST_CLICKHOUSE_USER='alternate_ci'))
            self.assertEqual(values['CYTHSEC_TEST_CLICKHOUSE_PORT'], '19000')
            self.assertEqual(values['CYTHSEC_TEST_CLICKHOUSE_USER'], 'alternate_ci')
            for override in [{'CYTHSEC_TEST_CLICKHOUSE_HOST':'production.example'},
                             {'CYTHSEC_TEST_CLICKHOUSE_PORT':'broken'},
                             {'CYTHSEC_TEST_CLICKHOUSE_PASSWORD':'unsafe\nvalue'},  # sample invalid fixture
                             {'CYTHSEC_TEST_CLICKHOUSE_IMAGE':'other/image:latest'}]:
                with self.subTest(keys=list(override)), self.assertRaises(ValueError):
                    middleware.prepare(dict(base, **override))

    def test_github_export_masks_generated_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'connection.env'
            output = Path(tmp)/'github-env'
            env = {key:value for key,value in os.environ.items() if not key.startswith('CYTHSEC_TEST_')}
            env.update(GITHUB_ACTIONS='true', GITHUB_ENV=str(output), CYTHSEC_MIDDLEWARE_TEST_ENV_FILE=str(path))
            result = subprocess.run([sys.executable,str(ROOT/'scripts/ci/middleware_test_env.py'),'--github-env'], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            values = middleware.load_private(path)
            credential = values['CYTHSEC_TEST_CLICKHOUSE_PASSWORD']
            self.assertTrue('::add-mask::'+credential in result.stdout)
            self.assertEqual(result.stdout.count(credential), 1)
            self.assertIn('CYTHSEC_TEST_CLICKHOUSE_PASSWORD'+'=', output.read_text())
            # The ordinary local entrypoint must never print a secret.
            result = subprocess.run([sys.executable,str(ROOT/'scripts/ci/middleware_test_env.py')], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0)
            self.assertNotIn(credential,result.stdout+result.stderr)

    def test_workflow_bootstraps_before_compose_and_never_uses_production_secrets(self):
        import test_workflows
        workflow = test_workflows.load('ci.yml')
        steps = workflow['jobs']['clickhouse']['steps']
        bootstrap = next(i for i,s in enumerate(steps) if s.get('uses')=='./.github/actions/middleware-test-environment')
        acceptance = next(i for i,s in enumerate(steps) if s.get('name')=='Compose storage and failure acceptance')
        self.assertLess(bootstrap,acceptance)
        action = (ROOT/'.github/actions/middleware-test-environment/action.yml').read_text()
        self.assertIn('--github-env',action)
        self.assertIn('runner.temp',action)
        self.assertNotRegex(action,r'\$\{\{\s*secrets\.')
        compose = (ROOT/'deploy/docker/compose.storage-test.yml').read_text()
        self.assertNotIn('local_storage_test',compose)
        self.assertNotIn('--password',compose)
        self.assertNotIn('ports:',compose)
        helper = (ROOT/'scripts/verify/check-clickhouse-compose.py').read_text()
        self.assertNotIn('local_storage_test',helper)
        self.assertNotIn('"--password"',helper)


if __name__=='__main__': unittest.main()
