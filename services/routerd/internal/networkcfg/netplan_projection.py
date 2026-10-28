"""Project a Netplan Ethernet subtree; credentials never enter the JSON result."""

import json
import sys

TRACE_PATHS = (
    'mtu',
    'dhcp4',
    'dhcp6',
    'accept-ra',
    'addresses',
    'nameservers.addresses',
    'nameservers.search',
    'routes',
    'gateway4',
    'gateway6',
)


def field_at(profile, path):
    value = profile
    for key in path.split('.'):
        if not isinstance(value, dict) or key not in value:
            return False, None
        value = value[key]
    return True, value


def active_sources(sources):
    if not isinstance(sources, list) or len(sources) > 64:
        raise ValueError('source limit')
    priorities = {'/lib/netplan': 0, '/etc/netplan': 1, '/run/netplan': 2}
    chosen, ids, paths = {}, set(), set()
    for source in sources:
        identity, path = source['id'], source['path']
        directory, sep, name = path.rpartition('/')
        if (
            not isinstance(identity, str)
            or len(identity) != 64
            or any(c not in '0123456789abcdef' for c in identity)
            or directory not in priorities
            or not sep
            or not name.endswith('.yaml')
            or name in {'.yaml', '..yaml'}
            or identity in ids
            or path in paths
        ):
            raise ValueError('source schema')
        ids.add(identity)
        paths.add(path)
        previous = chosen.get(name)
        if previous is None or priorities[directory] > priorities[previous['path'].rpartition('/')[0]]:
            chosen[name] = source
    active = [chosen[name] for name in sorted(chosen)]
    active_ids = {source['id'] for source in active}
    return active, sorted(ids - active_ids)


def trace_sources(documents, merged):
    active, shadowed = active_sources(documents)
    if not isinstance(merged, dict) or len(merged) > 64:
        raise ValueError('merged schema')
    declarations = {}
    for source in active:
        network = source['document'].get('network', {})
        if not isinstance(network, dict):
            raise ValueError('network schema')
        profiles = project(network.get('ethernets', {}))
        for name, profile in profiles.items():
            target = declarations.setdefault(name, {})
            if len(declarations) > 64:
                raise ValueError('profile limit')
            for path in TRACE_PATHS:
                present, value = field_at(profile, path)
                if not present:
                    continue
                sequence = path in {'addresses', 'nameservers.addresses', 'nameservers.search', 'routes'}
                valid = (
                    isinstance(value, list)
                    if sequence
                    else (
                        type(value) is bool
                        if path in {'dhcp4', 'dhcp6', 'accept-ra'}
                        else type(value) is int if path == 'mtu' else isinstance(value, str)
                    )
                )
                item = target.setdefault(path, {'value': [] if sequence else None, 'source_ids': [], 'valid': True})
                item['valid'] = item['valid'] and valid
                if sequence:
                    if valid:
                        if len(item['value']) + len(value) > 256:
                            item['valid'] = False
                        elif item['valid']:
                            item['value'].extend(value)
                    item['source_ids'].append(source['id'])
                else:
                    item['value'] = value
                    item['source_ids'] = [source['id']]
    if set(declarations) != set(merged):
        raise ValueError('profile inventory mismatch')
    result = {}
    for name, profile in merged.items():
        if not isinstance(profile, dict):
            raise ValueError('profile schema')
        fields = []
        for path in TRACE_PATHS:
            present, value = field_at(profile, path)
            if not present:
                continue
            item = declarations.get(name, {}).get(path)
            traced = (
                item is not None
                and item['valid']
                and json.dumps(value, sort_keys=True) == json.dumps(item['value'], sort_keys=True)
            )
            fields.append(
                {
                    'field': path,
                    'state': 'traced' if traced else 'unverified',
                    'source_ids': item['source_ids'] if item is not None else [],
                    'reason': 'projection_matches' if traced else 'projection_not_reconciled',
                }
            )
        result[name] = fields
    return {
        'active_source_ids': [source['id'] for source in active],
        'shadowed_source_ids': shadowed,
        'profiles': result,
    }


def read_source_trace(root, request):
    import os

    import yaml

    class BoundedLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self.depth = 0
            self.nodes = 0

        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent) or getattr(self.peek_event(), 'anchor', None) is not None:
                raise ValueError('aliases unsupported')
            self.nodes += 1
            self.depth += 1
            if self.nodes > 8192 or self.depth > 32:
                raise ValueError('yaml limit')
            try:
                return super().compose_node(parent, index)
            finally:
                self.depth -= 1

        def construct_mapping(self, node, deep=False):
            result = {}
            for key_node, value_node in node.value:
                if key_node.tag != 'tag:yaml.org,2002:str':
                    raise ValueError('non-string key')
                key = self.construct_object(key_node, deep=deep)
                if key in result:
                    raise ValueError('duplicate key')
                result[key] = self.construct_object(value_node, deep=deep)
            return result

    active, _ = active_sources(request['sources'])
    documents = []
    active_ids = {source['id'] for source in active}
    total = 0
    for source in request['sources']:
        item = dict(source)
        if source['id'] in active_ids:
            # The paths refer only to already captured private copies.
            with open(os.path.join(root, source['path'].lstrip('/')), 'rb') as handle:
                data = handle.read(1024 * 1024 + 1)
            total += len(data)
            if len(data) > 1024 * 1024 or total > 2 * 1024 * 1024:
                raise ValueError('source bytes')
            document = yaml.load(data, Loader=BoundedLoader)
            if not isinstance(document, dict):
                raise ValueError('document schema')
            item['document'] = document
        documents.append(item)
    return trace_sources(documents, request['merged'])


def primitive(value, depth=0):
    if depth > 4:
        raise ValueError('schema depth')
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, list) and len(value) <= 256:
        return [primitive(item, depth + 1) for item in value]
    raise ValueError('schema type')


def project(source):
    if source is None:
        return {}
    if not isinstance(source, dict) or len(source) > 64:
        raise ValueError('schema root')
    result = {}
    for name, profile in source.items():
        if not isinstance(name, str) or not isinstance(profile, dict):
            raise ValueError('schema profile')
        item = {}
        if 'routing-policy' in profile:
            item['routing_policy_present'] = True
        for key in ('mtu', 'addresses', 'dhcp4', 'dhcp6', 'accept-ra', 'set-name', 'gateway4', 'gateway6'):
            if key in profile:
                item[key] = primitive(profile[key])
        if 'match' in profile:
            match = profile['match']
            item['match_supported'] = isinstance(match, dict) and set(match) == {'name'}
            if item['match_supported']:
                item['match_name'] = primitive(match['name'])
        if 'nameservers' in profile:
            ns = profile['nameservers']
            if not isinstance(ns, dict):
                raise ValueError('schema nameservers')
            item['nameservers'] = {key: primitive(ns[key]) for key in ('addresses', 'search') if key in ns}
        if 'routes' in profile:
            routes = profile['routes']
            if not isinstance(routes, list) or len(routes) > 256:
                raise ValueError('schema routes')
            item['routes'] = []
            for route in routes:
                if not isinstance(route, dict):
                    raise ValueError('schema route')
                safe = {key: primitive(route[key]) for key in ('to', 'via', 'metric') if key in route}
                safe['unsupported_options'] = bool(set(route) - {'to', 'via', 'metric'})
                item['routes'].append(safe)
        result[name] = item
    return result


if __name__ == '__main__':
    try:
        data = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError('input limit')
        if len(sys.argv) == 3 and sys.argv[1] == '--source-trace':
            result = read_source_trace(sys.argv[2], json.loads(data))
        elif len(sys.argv) == 1:
            import yaml

            result = project(yaml.safe_load(data))
        else:
            raise ValueError('arguments')
        print(json.dumps(result))
    except Exception:
        # Neither YAML diagnostics nor source values may be echoed to logs.
        sys.exit(2)
