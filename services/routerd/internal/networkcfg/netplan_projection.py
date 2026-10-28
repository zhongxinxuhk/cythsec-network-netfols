"""Project a Netplan Ethernet subtree; credentials never enter the JSON result."""

import json
import sys


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
        import yaml

        print(json.dumps(project(yaml.safe_load(data))))
    except Exception:
        # Neither YAML diagnostics nor source values may be echoed to logs.
        sys.exit(2)
