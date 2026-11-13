"""Render the actual CLI ARG; never synthesize graph relationships or edit sources.

Output must not exist. Graphviz is used only for this trusted local development
demonstration, not as a renderer for arbitrary API submissions.
"""
import argparse
from collections import Counter
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import xml.etree.ElementTree as ET


def source_hashes(root):
    result = {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in ('.git', 'target', 'node_modules'))
        for name in sorted(names):
            path = Path(directory) / name
            if name.endswith('.rs') or name in ('Cargo.toml', 'Cargo.lock'):
                result[path.relative_to(root).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def normalize(value, root):
    if isinstance(value, dict):
        return {k: normalize(v, root) for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v, root) for v in value]
    if isinstance(value, str):
        # Engine identities are JSON tuples containing source paths. Decode
        # those identities before normalizing independent snapshot roots.
        if value.startswith('['):
            try:
                decoded = json.loads(value)
                if isinstance(decoded, list):
                    return json.dumps(normalize(decoded, root), separators=(',', ':'), ensure_ascii=False)
            except json.JSONDecodeError:
                pass
        for prefix in (str(root), str(root).replace('\\', '/')):
            value = value.replace(prefix, '[SOURCE]')
        return value
    return value


def graph_check(dot_json, report, svg):
    native = report['graph']
    objects = dot_json.get('objects', [])
    # Graphviz retains doubled literal backslashes in DOT node identifiers;
    # its JSON and SVG titles expose that DOT spelling, not the native string.
    spelling = {node['id'].replace('\\', '\\\\'): node['id'] for node in native['nodes']}
    assert Counter(node['name'] for node in objects) == Counter(spelling.keys())
    names = {node['_gvid']: spelling[node['name']] for node in objects}
    expected = Counter((edge['from'], edge['to'], edge['relation']) for edge in native['edges'])
    actual = Counter((names[e['tail']], names[e['head']], e['label']) for e in dot_json.get('edges', []))
    assert actual == expected, 'Graphviz topology differs from analyzer graph'
    document = ET.parse(svg)
    namespace = {'svg': 'http://www.w3.org/2000/svg'}
    node_titles, edge_titles = [], []
    for group in document.findall('.//svg:g', namespace):
        title = group.find('svg:title', namespace)
        if title is not None and group.get('class') == 'node':
            node_titles.append(title.text)
        if title is not None and group.get('class') == 'edge':
            edge_titles.append(title.text)
    assert Counter(node_titles) == Counter(spelling.keys())
    assert Counter(edge_titles) == Counter((e['from'] + '->' + e['to']).replace('\\', '\\\\') for e in native['edges'])
    known = set(names.values())
    assert all(e['from'] in known and e['to'] in known for e in native['edges'])
    return {'nodes': len(node_titles), 'edges': len(edge_titles),
            'node_kinds': dict(Counter(n['kind'] for n in native['nodes'])),
            'edge_relations': dict(Counter(e['relation'] for e in native['edges'])),
            'graphviz_and_svg_topology_matches_analyzer': True}


def provenance_check(report):
    """Audit existing nodes against native report inputs; construct no graph."""
    audit = []
    for node in report['graph']['nodes']:
        kind, label, identity = node['kind'], node['label'], node['id']
        entry = {'id': identity, 'kind': kind, 'label': label, 'file': node.get('file'), 'line': node.get('line')}
        if node.get('file'):
            source = Path(node['file'])
            assert source.is_file(), source
            if node.get('line') is not None:
                assert 1 <= node['line'] <= len(source.read_text(encoding='utf-8').splitlines()), node
        if kind in ('Scope', 'Route', 'Handler'):
            key = json.loads(identity)
            if kind == 'Scope':
                assert any(r['application'] == key[1] and r['scope_prefix'] == key[2] for r in report['routes'])
                assert label == 'Scope: ' + (key[2] or '/')
                entry['origin'] = 'synthetic grouping of observed registration scope; not a Rust scope node'
            elif kind == 'Route':
                matches = [r for r in report['routes'] if (r['method'], r['path'], r['application']) == tuple(key[1:])]
                assert matches and any(r['file'] == node['file'] and r['line'] == node['line'] for r in matches)
                assert label == key[1] + ' ' + key[2]
                entry['origin'] = 'observed registration in report.routes'
            else:
                assert label == 'fn ' + key[3] + '()'
                definitions = [d for d in report['handler_resolution_evidence'] if d.get('definition_path') == key[3] and d.get('definition_file') == node['file']]
                assert definitions and any(d.get('definition_line') == node.get('line') for d in definitions)
                entry['origin'] = 'resolved handler definition; route-specific placeholder fallback is possible in other reports'
        elif kind in ('Guard', 'Middleware', 'AuthorizationCheck', 'IdentityExtraction', 'UnresolvedCheck'):
            key = json.loads(identity)
            route_key = json.loads(key[1])
            route = next(r for r in report['routes'] if (r['method'], r['path'], r['application']) == tuple(route_key[1:]))
            evidence = route['authorization'][key[2]]
            assert key[3] == evidence['mechanism']
            assert node['file'] == evidence['file'] and node['line'] == evidence['line']
            assert label == evidence['kind'] + ': ' + evidence['mechanism']
            entry['origin'] = 'route.authorization observation, including inherited registration context; not necessarily verified enforcement'
        elif kind == 'InvariantContract':
            assert any(identity == 'contract:' + f['peer_group_id'] + ':' + f['invariant']['description'] and label == 'Invariant: ' + f['invariant']['description'] for f in report['finding_details'])
            entry['origin'] = 'inferred contract referenced by a verified finding; not all report.invariants are drawn'
        elif kind == 'Finding':
            assert any(identity == f"finding:{i + 1}:{f['category']}" and label == f"Drift ({f['category']}): {f['suspicious_route']['method']} {f['suspicious_route']['path']}" for i, f in enumerate(report['finding_details']))
            entry['origin'] = 'deterministic verified finding, not an exploratory observation'
        else:
            raise AssertionError('Unknown node kind: ' + kind)
        audit.append(entry)
    return audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--dot', type=Path, required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--clean', type=Path, required=True)
    parser.add_argument('--mutated', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    output = args.output.resolve()
    binary, dot = args.binary.resolve(), args.dot.resolve()
    reports, roots, manifest = {}, {}, {}
    for name, source in [('actual', args.source), ('clean', args.clean), ('mutated', args.mutated)]:
        source = source.resolve()
        before = source_hashes(source)
        roots[name] = source
        start = time.perf_counter()
        report_bytes = subprocess.check_output([str(binary), str(source), '--json'], timeout=180)
        report = json.loads(report_bytes)
        reports[name] = report
        (output / (name + '.json')).write_bytes(report_bytes)
        dot_path = output / (name + '.dot')
        dot_path.write_bytes(subprocess.check_output([str(binary), str(source), '--graph'], timeout=180))
        for fmt in ('svg', 'png', 'json'):
            subprocess.run([str(dot), '-Kdot', '-T' + fmt, str(dot_path), '-o', str(output / (name + '.graphviz.' + fmt))], check=True, timeout=30)
        rendered = json.loads((output / (name + '.graphviz.json')).read_text(encoding='utf-8'))
        metrics = graph_check(rendered, report, output / (name + '.graphviz.svg'))
        (output / (name + '.provenance.json')).write_text(json.dumps(provenance_check(report), indent=2), encoding='utf-8')
        assert before == source_hashes(source), f'Source changed: {source}'
        manifest[name] = dict(source=str(source), source_sha256=before, seconds=time.perf_counter() - start,
                              source_preserved=True, graph=metrics,
                              routes=len(report['routes']), peer_groups=len(report['peer_groups']),
                              invariants=len(report['invariants']), findings=report['finding_details'],
                              summary=report['summary'])
        print(name, json.dumps(metrics), 'verified findings:', len(report['finding_details']), flush=True)
    clean, mutated = reports['clean'], reports['mutated']
    a, b = normalize(clean['graph'], roots['clean']), normalize(mutated['graph'], roots['mutated'])
    def difference(left, right):
        available = Counter(json.dumps(x, sort_keys=True) for x in right)
        result = []
        for item in left:
            key = json.dumps(item, sort_keys=True)
            if available[key]:
                available[key] -= 1
            else:
                result.append(item)
        return result
    changes = {'removed_nodes': difference(a['nodes'], b['nodes']), 'added_nodes': difference(b['nodes'], a['nodes']),
               'removed_edges': difference(a['edges'], b['edges']), 'added_edges': difference(b['edges'], a['edges']),
               'clean_findings': clean['finding_details'], 'mutated_findings': mutated['finding_details']}
    (output / 'graph-delta.json').write_text(json.dumps(changes, indent=2), encoding='utf-8')
    # Keep the historical source mutation visible separately from any drift in
    # the current desktop checkout versus the frozen mutation baseline.
    for old, new, filename in [('clean', 'mutated', 'mutation.patch'), ('actual', 'clean', 'actual-to-frozen-baseline.patch')]:
        lines = []
        old_hashes, new_hashes = manifest[old]['source_sha256'], manifest[new]['source_sha256']
        for relative in sorted(old_hashes.keys() | new_hashes.keys()):
            if old_hashes.get(relative) == new_hashes.get(relative):
                continue
            first, second = roots[old] / relative, roots[new] / relative
            first_text = first.read_text(encoding='utf-8', errors='replace').splitlines(True) if first.exists() else []
            second_text = second.read_text(encoding='utf-8', errors='replace').splitlines(True) if second.exists() else []
            lines.extend(difflib.unified_diff(first_text, second_text, fromfile=old + '/' + relative, tofile=new + '/' + relative))
        (output / filename).write_text(''.join(lines), encoding='utf-8')
    manifest['binary_sha256'] = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest['graphviz_version'] = subprocess.check_output([str(dot), '-V'], stderr=subprocess.STDOUT).decode().strip()
    manifest['artifacts_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir()) if p.is_file()}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')


if __name__ == '__main__':
    main()
