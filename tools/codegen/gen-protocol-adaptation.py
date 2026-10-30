#!/usr/bin/env python3
"""Generate the evidence-based adaptation checklist; no runtime classification rules."""

import argparse
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / 'configs/registry/protocol-adaptation.json'
CATALOG = ROOT / 'configs/registry/vpn-protocols.json'
OUTPUT = ROOT / 'docs/protocols/ADAPTATION-STATUS.md'
FLAGS = ('implemented', 'local_tested', 'reference_tested', 'accepted')


def validate(data, catalog):
    entries = catalog['entries']
    ids = [e['id'] for e in entries]
    if data['schema_version'] != 1 or data['catalog_revision'] != catalog['revision'] or data['catalog_ids'] != ids:
        raise ValueError('catalog coverage/revision drift')
    rows = data['records']
    by_id = {r['id']: r for r in rows}
    supplemental = data['supplemental_ids']
    if (
        len(by_id) != len(rows)
        or len(set(supplemental)) != len(supplemental)
        or set(by_id) != set(ids) | set(supplemental)
        or set(ids) & set(supplemental)
    ):
        raise ValueError('missing or duplicate adaptation ID')
    for row in rows:
        if (
            not all(type(row.get(f)) is bool for f in FLAGS)
            or not row.get('scope')
            or not isinstance(row.get('gap'), str)
        ):
            raise ValueError('invalid checklist state')
        for field in ('code', 'tests', 'reference'):
            refs = row[field]
            if not isinstance(refs, list):
                raise ValueError('invalid evidence list')
            for ref in refs:
                path, _, marker = ref.partition('#')
                p = (ROOT / path).resolve()
                if not p.is_relative_to(ROOT) or not p.is_file() or marker and marker not in p.read_text():
                    raise ValueError('missing/stale evidence: ' + ref)
        for flag, field in zip(FLAGS[:3], ('code', 'tests', 'reference')):
            if row[flag] and not row[field]:
                raise ValueError('checked step has no evidence')
        if row['accepted'] and (not all(row[f] for f in FLAGS[:3]) or row['gap']):
            raise ValueError('incomplete protocol cannot be checked accepted')
        if row['id'] in supplemental and not row.get('name'):
            raise ValueError('supplemental protocol has no name')
    return by_id


def render(data, catalog):
    by_id = validate(data, catalog)
    objects = {e['id']: e for e in catalog['entries']}
    lines = [
        '<!-- GENERATED: configs/registry/protocol-adaptation.json; gen-protocol-adaptation.py -->',
        '# 流量协议适配状态清单',
        '',
        f"修订：{data['revision']}。目录对象{len(objects)}项，基础/补充核验项{len(data['supplemental_ids'])}项，共{len(by_id)}行；包含同一协议的不同能力范围，不等于全球协议总数。",
        '',
        '每个步骤独立勾选。完整适配只在本行范围的实现、本地测试和独立对照均完成、缺口清空后勾选；目录声明和上下文接口不算线路协议适配。',
        '“本地测试”表示本轮验收记录所列命令实跑结果；文件/测试符号存在检查不能替代运行。真实语料、Linux实机、规模与误报指标必须在范围及缺口中单独说明。',
        '',
        '此表记录现状与通用解析开发，不提供公众规避审查连接的识别指纹、主动探测或封锁实现。',
        '',
        '[状态真源](../../configs/registry/protocol-adaptation.json) · [本轮验收](../planning/protocol-adaptation-verification.md) · [维护规则](../development/protocol-adaptation.md)',
        '',
        '| 完整适配 | ID | 协议/对象 | 目录原有声明 | 实现审查 | 本地测试 | 独立对照 | 本行范围 | 缺口 |',
        '| --- | --- | --- | --- | --- | --- | --- | --- | --- |',
    ]

    def mark(value):
        return '☑' if value else '☐'

    def cell(value):
        return str(value).replace('|', '／').replace('\n', ' ').replace('<', '&lt;').replace('>', '&gt;')

    for row in data['records']:
        pid = row['id']
        obj = objects.get(pid)
        name = obj['name'] if obj else row['name']
        declared = (
            (
                '有界解析声明，待逐项验收'
                if obj['implementation'] == 'bounded_wire_parser'
                else '可信上下文接口，非线路识别'
            )
            if obj
            else '基础/补充核验'
        )
        identity = f'[{pid}]({pid}.md)' if obj else pid
        lines.append(
            '| '
            + ' | '.join(
                [
                    mark(row['accepted']),
                    identity,
                    cell(name),
                    declared,
                    mark(row['implemented']),
                    mark(row['local_tested']),
                    mark(row['reference_tested']),
                    cell(row['scope']),
                    cell(row['gap']) or '—',
                ]
            )
            + ' |'
        )
    counts = {flag: sum(r[flag] for r in by_id.values()) for flag in FLAGS}
    lines += [
        '',
        f"当前统计：实现审查{counts['implemented']}，本地测试{counts['local_tested']}，独立对照{counts['reference_tested']}，完整适配{counts['accepted']}。各列不能相加当成适配数。",
        '',
        '推进顺序：通用L2/L3/L4与采集完整性 → DNS/TCP流边界 → HTTP/TLS/QUIC可见子集 → 导出协议与持久化契约。每批更新对应ID、证据和缺口；不因共同承载、品牌或目录父子关系批量勾选。',
        '',
    ]
    return '\n'.join(lines)


def self_test(data, catalog):
    validate(data, catalog)
    mutations = []
    for kind in ('missing', 'duplicate', 'accepted', 'bool', 'evidence', 'coverage'):
        candidate = copy.deepcopy(data)
        if kind == 'missing':
            candidate['records'].pop()
        elif kind == 'duplicate':
            candidate['records'].append(candidate['records'][0])
        elif kind == 'accepted':
            candidate['records'][0]['accepted'] = True
            candidate['records'][0]['implemented'] = False
        elif kind == 'bool':
            candidate['records'][0]['local_tested'] = 'yes'
        elif kind == 'evidence':
            candidate['records'][0]['code'] = ['dataplane/traffic-engine/src/dpi/dns.rs#missing_test_or_symbol']
        else:
            candidate['catalog_ids'].pop()
        mutations.append(candidate)
    for candidate in mutations:
        try:
            validate(candidate, catalog)
        except ValueError:
            continue
        raise ValueError('checklist guard accepted invalid metadata')
    print('Protocol checklist guards: baseline + 6 invalid metadata injections passed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    data, catalog = json.loads(REGISTRY.read_text()), json.loads(CATALOG.read_text())
    result = render(data, catalog)
    if args.self_test:
        self_test(data, catalog)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Protocol adaptation checklist stale; regenerate from registry')
    else:
        OUTPUT.write_text(result)
    print(f"Protocol adaptation checklist: {len(data['records'])} rows verified")


if __name__ == '__main__':
    main()
