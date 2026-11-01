#!/usr/bin/env python3
"""Generate evidence-based adaptation checklists and an OSI layer view; no runtime classification rules."""

import argparse
import copy
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REGISTRY = ROOT / 'configs/registry/protocol-adaptation.json'
CATALOG = ROOT / 'configs/registry/vpn-protocols.json'
OUTPUT = ROOT / 'docs/protocols/ADAPTATION-STATUS.md'
LAYER_OUTPUT = ROOT / 'docs/protocols/ADAPTATION-STATUS-BY-LAYER.md'
FLAGS = ('implemented', 'local_tested', 'reference_tested', 'accepted')
LAYERS = ('L1', 'L2', 'L3', 'L4', 'L5', 'L6', 'L7', 'cross-layer', 'non-osi')
NON_OSI_ROLES = ('product', 'transform', 'crypto')
ROLES = (
    'base',
    'encapsulation',
    'control',
    'security',
    'session',
    'application',
    'identity',
    'proxy',
    'transform',
    'product',
    'crypto',
)
ROLE_LABELS = {
    'base': '基础',
    'encapsulation': '封装',
    'control': '控制',
    'security': '安全',
    'session': '会话',
    'application': '应用',
    'identity': '身份',
    'proxy': '代理',
    'transform': '变换',
    'product': '产品',
    'crypto': '密码',
}
LAYER_TITLES = {
    'L1': 'L1 物理层',
    'L2': 'L2 数据链路层',
    'L3': 'L3 网络层',
    'L4': 'L4 传输层',
    'L5': 'L5 会话层',
    'L6': 'L6 表示层',
    'L7': 'L7 应用层',
    'cross-layer': '跨层隧道/代理',
    'non-osi': 'non-OSI 产品/变换/密码',
}
LAYER_NOTES = {
    'L1': '物理层只做链路/介质/速率元数据，不从 pcap 伪造 PHY 解析',
    'L2': '帧、VLAN、ARP、PPP/EAP 与 L2 隧道',
    'L3': 'IPv4/IPv6、分片、ICMP、IPsec/GRE 与 L3 隧道',
    'L4': 'TCP/UDP/QUIC',
    'L5': 'TLS/DTLS/SSH/IKE/SOCKS/STUN 等会话与协商',
    'L6': '表示/记录/密码属性；当前无独立主层条目',
    'L7': '应用协议、身份认证与代理控制',
    'cross-layer': 'VPN/隧道/代理链；不递归创建内层流',
    'non-osi': '产品、混淆变换、密码原语；只做上下文证据',
}
EMPTY_LAYER_NOTES = {
    'L1': '当前无主层条目。物理层仅记录 linktype、介质、速率等采集元数据，不假装从 pcap 解码 PHY。',
    'L6': '当前无独立主层条目。TLS record、证书和密码套件作为 L5 条目的表示层属性记录，不重复计数。',
}
CHAIN_RE = re.compile(r'^L[1-7]:[^|]+$')
PREFIX_ORDER = {'B': 0, 'V': 1, 'P': 2, 'O': 3, 'T': 4, 'A': 5, 'C': 6, 'F': 7, 'X': 8}


def validate(data, catalog):
    entries = catalog['entries']
    ids = [e['id'] for e in entries]
    if data['schema_version'] != 2 or data['catalog_revision'] != catalog['revision'] or data['catalog_ids'] != ids:
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
        layer = row.get('osi_layer')
        role = row.get('osi_role')
        sublayer = row.get('osi_sublayer')
        chain = row.get('encap_chain')
        uses = row.get('uses_layers')
        if layer not in LAYERS:
            raise ValueError('invalid OSI layer: ' + str(row.get('id')))
        if role not in ROLES:
            raise ValueError('invalid OSI role: ' + str(row.get('id')))
        if not isinstance(sublayer, str) or not sublayer:
            raise ValueError('invalid OSI sublayer: ' + str(row.get('id')))
        if not isinstance(chain, list) or not all(isinstance(x, str) and CHAIN_RE.fullmatch(x) for x in chain):
            raise ValueError('invalid encapsulation chain: ' + str(row.get('id')))
        if not isinstance(uses, list) or not all(isinstance(x, str) and x in LAYERS[:7] for x in uses):
            raise ValueError('invalid uses_layers: ' + str(row.get('id')))
        if layer == 'cross-layer':
            if len(chain) < 2:
                raise ValueError('cross-layer row needs a visible encapsulation chain')
            if role not in ('encapsulation', 'proxy'):
                raise ValueError('cross-layer row has non-encapsulation role')
        if layer == 'non-osi':
            if role not in NON_OSI_ROLES:
                raise ValueError('non-OSI row has OSI role')
            if chain:
                raise ValueError('non-OSI row must not claim an encapsulation chain')
            if not uses:
                raise ValueError('non-OSI row needs uses_layers')
        else:
            if role in NON_OSI_ROLES:
                raise ValueError('OSI row has non-OSI role')
            if uses:
                raise ValueError('OSI row must not carry uses_layers')
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


def role_label(row):
    return ROLE_LABELS[row['osi_role']]


def osi_label(row):
    layer = row['osi_layer']
    if layer == 'non-osi':
        return 'non-OSI / ' + role_label(row)
    if layer == 'cross-layer':
        return '跨层 / ' + role_label(row)
    sublayer = row['osi_sublayer']
    suffix = '' if sublayer == layer else '（' + sublayer + '）'
    return layer + suffix + ' / ' + role_label(row)


def layer_counts(rows):
    return {
        layer: {
            'total': sum(1 for r in rows if r['osi_layer'] == layer),
            'implemented': sum(1 for r in rows if r['osi_layer'] == layer and r['implemented']),
            'accepted': sum(1 for r in rows if r['osi_layer'] == layer and r['accepted']),
        }
        for layer in LAYERS
    }


def summary_table(rows):
    counts = layer_counts(rows)
    lines = [
        '| 主层 | 条目 | 实现审查 | 完整适配 | 口径 |',
        '| --- | ---: | ---: | ---: | --- |',
    ]
    for layer in LAYERS:
        c = counts[layer]
        lines.append(
            f"| {LAYER_TITLES[layer]} | {c['total']} | {c['implemented']} | {c['accepted']} | {LAYER_NOTES[layer]} |"
        )
    lines.append(
        f"| 合计 | {sum(c['total'] for c in counts.values())} | "
        f"{sum(c['implemented'] for c in counts.values())} | "
        f"{sum(c['accepted'] for c in counts.values())} | 跨层和 non-OSI 不进入七层覆盖率分子 |"
    )
    return lines


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
        'OSI 主层是新增的分类轴，不替代目录原有的 tunnel/overlay/product/transport/identity 轴。主层只表示主要协议层，跨层封装、产品与混淆不强行归入单层。',
        '',
        '此表记录现状与通用解析开发，不提供公众规避审查连接的识别指纹、主动探测或封锁实现。',
        '',
        '[状态真源](../../configs/registry/protocol-adaptation.json) · [按层视图](ADAPTATION-STATUS-BY-LAYER.md) · [OSI 规划](../planning/protocol-osi-classification.md) · [本轮验收](../planning/protocol-adaptation-verification.md) · [维护规则](../development/protocol-adaptation.md)',
        '',
        '## OSI 分层汇总',
        '',
    ]
    lines += summary_table(data['records'])
    lines += [
        '',
        '跨层和 non-OSI 条目不计入七层覆盖率分子；L1/L6 当前没有独立主层条目。L6 的 TLS record、证书和密码套件属性由 L5 行承载，不重复计数。',
        '',
        '| 完整适配 | ID | 协议/对象 | OSI 主层/角色 | 目录原有声明 | 实现审查 | 本地测试 | 独立对照 | 本行范围 | 缺口 |',
        '| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |',
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
                    cell(osi_label(row)),
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
        '推进顺序：OSI 分类基线 → 通用 L2/L3/L4 与采集完整性 → L5 会话/安全 → L7 应用协议 → 跨层隧道/代理 → 产品上下文。每批更新对应ID、证据和缺口；不因共同承载、品牌或目录父子关系批量勾选。',
        '',
    ]
    return '\n'.join(lines)


def render_layers(data, catalog):
    by_id = validate(data, catalog)
    objects = {e['id']: e for e in catalog['entries']}
    lines = [
        '<!-- GENERATED: configs/registry/protocol-adaptation.json; gen-protocol-adaptation.py -->',
        '# 协议适配 OSI 分层视图',
        '',
        f"修订：{data['revision']}。共{len(by_id)}行；一行只有一个主层，跨层封装和 non-OSI 单独列出，不重复计入七层。",
        '',
        '口径：`osi_layer` 是主层，`osi_sublayer` 记录子层/承载关系，`osi_role` 记录协议角色，`encap_chain` 只列可见封装路径，不表示已解析内层或已建立内层流。目录原有 `layer` 轴保留。',
        '',
        '[状态清单](ADAPTATION-STATUS.md) · [状态真源](../../configs/registry/protocol-adaptation.json) · [OSI 规划](../planning/protocol-osi-classification.md) · [维护规则](../development/protocol-adaptation.md)',
        '',
        '## 汇总',
        '',
    ]
    lines += summary_table(data['records'])
    lines += [
        '',
        '跨层和 non-OSI 不进入七层覆盖率分子；L1/L6 当前没有独立主层条目。',
        '',
    ]
    for layer in LAYERS:
        subset = sorted(
            (r for r in data['records'] if r['osi_layer'] == layer),
            key=lambda r: (PREFIX_ORDER.get(r['id'][0], 99), int(r['id'][1:])),
        )
        lines += [f'## {LAYER_TITLES[layer]}', '']
        if not subset:
            lines += [EMPTY_LAYER_NOTES.get(layer, '当前无条目。'), '']
            continue
        lines += [
            '| 完整适配 | ID | 协议/对象 | 角色 | 子层 | 封装链/使用层 | 实现审查 | 本地测试 | 独立对照 |',
            '| --- | --- | --- | --- | --- | --- | --- | --- | --- |',
        ]
        for row in subset:
            pid = row['id']
            obj = objects.get(pid)
            name = obj['name'] if obj else row['name']
            identity = f'[{pid}]({pid}.md)' if obj else pid
            path = (
                ' → '.join(row['encap_chain'])
                if row['encap_chain']
                else ('使用 ' + '/'.join(row['uses_layers']) if row['uses_layers'] else '—')
            )
            lines.append(
                '| '
                + ' | '.join(
                    [
                        '☑' if row['accepted'] else '☐',
                        identity,
                        name.replace('|', '／'),
                        role_label(row),
                        row['osi_sublayer'],
                        path.replace('|', '／'),
                        '☑' if row['implemented'] else '☐',
                        '☑' if row['local_tested'] else '☐',
                        '☑' if row['reference_tested'] else '☐',
                    ]
                )
                + ' |'
            )
        lines.append('')
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
    for kind in ('osi_layer', 'osi_sublayer', 'osi_role', 'cross_chain', 'nonosi_uses', 'nonosi_role'):
        candidate = copy.deepcopy(data)
        if kind == 'osi_layer':
            candidate['records'][0]['osi_layer'] = 'L9'
        elif kind == 'osi_sublayer':
            candidate['records'][0]['osi_sublayer'] = ''
        elif kind == 'osi_role':
            candidate['records'][0]['osi_role'] = 'router'
        elif kind == 'cross_chain':
            next(r for r in candidate['records'] if r['osi_layer'] == 'cross-layer')['encap_chain'] = ['L3:IP']
        elif kind == 'nonosi_uses':
            next(r for r in candidate['records'] if r['osi_layer'] == 'non-osi')['uses_layers'] = []
        else:
            next(r for r in candidate['records'] if r['osi_layer'] == 'non-osi')['osi_role'] = 'base'
        mutations.append(candidate)
    for candidate in mutations:
        try:
            validate(candidate, catalog)
        except ValueError:
            continue
        raise ValueError('checklist guard accepted invalid metadata')
    print('Protocol checklist guards: baseline + 12 invalid metadata injections passed')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    data, catalog = json.loads(REGISTRY.read_text()), json.loads(CATALOG.read_text())
    result = render(data, catalog)
    layer_result = render_layers(data, catalog)
    if args.self_test:
        self_test(data, catalog)
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != result:
            raise SystemExit('Protocol adaptation checklist stale; regenerate from registry')
        if not LAYER_OUTPUT.exists() or LAYER_OUTPUT.read_text() != layer_result:
            raise SystemExit('Protocol OSI layer view stale; regenerate from registry')
    else:
        OUTPUT.write_text(result)
        LAYER_OUTPUT.write_text(layer_result)
    print(f"Protocol adaptation checklist: {len(data['records'])} rows verified")


if __name__ == '__main__':
    main()
