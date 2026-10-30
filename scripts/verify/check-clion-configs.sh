#!/usr/bin/env bash
# Validate shared run configurations and exercise the failure/monitoring paths.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
bash -n scripts/dev/clion.sh scripts/dev/monitor-local.sh
python3 - <<'PY'
import copy
import pathlib
import shlex
import xml.etree.ElementTree as ET

root = pathlib.Path.cwd()
configs = [ET.parse(p).getroot().find('configuration') for p in sorted(root.glob('.run/CythSec_*.run.xml'))]
assert configs, 'No shared CLion configurations'
names = [c.attrib['name'] for c in configs]
assert len(names) == len(set(names)), 'Duplicate CLion names'


def validate(c):
    assert c.attrib['type'] in {'ShConfigurationType', 'CompoundRunConfigurationType'}
    assert not c.findall('.//env'), 'Shared configurations must not store machine environment or credentials'
    if c.attrib['type'] == 'CompoundRunConfigurationType':
        children = c.findall('toRun')
        assert len(children) == 5
        assert len({child.attrib['name'] for child in children}) == 5
        assert {child.attrib['name'] for child in children} == {f'CythSec Run {s}' for s in ['routerd', 'policyd', 'dnsd', 'telemetryd', 'Console']}
        assert all(child.attrib['name'] in names and child.attrib['type'] == 'ShConfigurationType' for child in children)
        return
    options = {o.attrib['name']: o.attrib.get('value') for o in c.findall('option')}
    assert options['SCRIPT_PATH'] == '$PROJECT_DIR$/scripts/dev/clion.sh'
    assert options['SCRIPT_WORKING_DIRECTORY'] == '$PROJECT_DIR$'
    assert options['INTERPRETER_PATH'] == '/bin/bash'
    assert options['EXECUTE_IN_TERMINAL'] == 'false'
    assert options['EXECUTE_SCRIPT_FILE'] == 'true'
    args = shlex.split(options['SCRIPT_OPTIONS'])
    assert args and args[0] in {'preflight', 'build', 'lint', 'check-ide', 'audit', 'test', 'e2e-control', 'run', 'console', 'observe-sample', 'monitor'}
    assert not {'sudo', 'su', '-access-file'} & set(args)


for config in configs:
    validate(config)
for expected in ['Preflight', 'Build All', 'Build Go', 'Build Console', 'Lint All', 'Test All', 'Test Live BPF', 'Run Development', 'Monitor Once', 'Monitor Watch']:
    assert f'CythSec {expected}' in names, f'Missing required configuration: {expected}'
for key, value in [('SCRIPT_PATH', '/tmp/missing.sh'), ('SCRIPT_WORKING_DIRECTORY', '/tmp'), ('SCRIPT_OPTIONS', 'sudo test')]:
    broken = copy.deepcopy(next(c for c in configs if c.attrib['type'] == 'ShConfigurationType'))
    broken.find(f"option[@name='{key}']").set('value', value)
    try:
        validate(broken)
    except AssertionError:
        pass
    else:
        raise AssertionError(f'Broken {key} was accepted')
print(f'CLion: {len(configs)} shared configurations and 3 invalid configuration injections verified')
PY
bash scripts/dev/monitor-local.sh --self-test
set +e
failure="$(bash scripts/dev/clion.sh test --clion-invalid-group 2>&1)"
rc=$?
set -e
[[ "$rc" == 2 ]] || { echo 'IDE wrapper masked an invalid test group' >&2; exit 1; }
evidence="$(printf '%s\n' "$failure" | sed -n 's/^Evidence: //p')"
[[ -n "$evidence" && "$(cat "$evidence/exit-code")" == "$rc" && -s "$evidence/output.log" ]]
echo 'CLion: real failing test command preserves exit 2 and its evidence'
