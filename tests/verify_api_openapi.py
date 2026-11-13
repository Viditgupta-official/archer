"""Optional live HTTP/OpenAPI verification, no frontend or submitted code execution.

Requires openapi-spec-validator (also supplies jsonschema). Run after building
both binaries with --features api. Writes new artifacts only under target/.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import time
import urllib.error
import urllib.request

from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--repository', type=Path, default=ROOT / 'demo', help='Explicit consumed development source; no submitted code is executed')
REPOSITORY = parser.parse_args().repository.resolve(strict=True)
OUT = ROOT / 'target' / ('backend-live-' + secrets.token_hex(8))
OUT.mkdir()
SUFFIX = '.exe' if os.name == 'nt' else ''
API = ROOT / 'target/debug' / ('archer-api' + SUFFIX)
CLI = ROOT / 'target/debug' / ('archer' + SUFFIX)
TOKEN = secrets.token_hex(32)
with socket.socket() as sock:
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
BASE = f'http://127.0.0.1:{port}'
environment = dict(os.environ, ARCHER_API_TOKEN=TOKEN, ARCHER_BIND=f'127.0.0.1:{port}',
                   ARCHER_WORK_ROOT=str(OUT / 'work'), ARCHER_GITHUB_REPOSITORIES='',
                   ARCHER_CORS_ORIGINS='http://localhost:5173', ARCHER_EVIDENCE_TEXT='redact')
server_log = (OUT / 'server.log').open('wb')
server = subprocess.Popen([str(API)], env=environment, stdout=subprocess.DEVNULL,
                          stderr=server_log,
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)


def request(path, method='GET', body=None, authorized=True):
    headers = {'Authorization': 'Bearer ' + TOKEN} if authorized else {}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request(BASE + path, method=method, headers=headers,
                                 data=json.dumps(body).encode() if body is not None else None)
    try:
        response = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=20)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read()
        return response.status, json.loads(data) if data and response.headers.get_content_type() == 'application/json' else data


def contract(document, schema, value):
    Draft202012Validator({'$ref': '#/components/schemas/' + schema,
                         'components': document['components']}).validate(value)


try:
    last_error = None
    startup_deadline = time.monotonic() + 25
    for _ in range(200):
        try:
            code, health = request('/api/v1/health', authorized=False)
            break
        except OSError as error:
            last_error = error
            assert server.poll() is None, 'API exited during startup'
            if time.monotonic() >= startup_deadline:
                raise AssertionError(f'Loopback connection failed: {error}') from error
            time.sleep(.1)
    else:
        raise AssertionError(f'API startup deadline exceeded: {last_error}; see {OUT / "server.log"}')
    assert code == 200
    code, spec = request('/api/v1/openapi.json', authorized=False)
    assert code == 200
    validate(spec)
    contract(spec, 'Health', health)
    generated = json.loads(subprocess.check_output([str(API), '--print-openapi']))
    assert generated == spec
    checked_in = json.loads((ROOT / 'docs/openapi.json').read_text(encoding='utf-8'))
    assert checked_in == spec, 'Regenerate docs/openapi.json'
    for path in ['/api/v1/analyses/' + '0' * 32, '/api/v1/analyses/' + '0' * 32 + '/result']:
        code, error = request(path)
        assert code == 404
        contract(spec, 'Error', error)
    code, error = request('/api/v1/analyses', 'POST', {}, authorized=False)
    assert code == 401
    contract(spec, 'Error', error)
    for path, item in spec['paths'].items():
        for operation in item.values():
            for media in operation.get('requestBody', {}).get('content', {}).values():
                for example in media.get('examples', {}).values():
                    contract(spec, 'AnalysisRequest', example['value'])
    # Exercise the clean development demonstration first, then each existing
    # deterministic mutation category. Never modify the original demo files.
    files = []
    for directory, dirs, names in os.walk(REPOSITORY, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in ('.git', 'target', 'node_modules'))
        for name in sorted(names):
            path = Path(directory) / name
            if name.endswith('.rs') or name in ('Cargo.toml', 'Cargo.lock'):
                assert not path.is_symlink()
                files.append({'path': path.relative_to(REPOSITORY).as_posix(), 'content': path.read_text(encoding='utf-8')})
    payload = {'source': {'type': 'snapshot', 'files': files}}
    contract(spec, 'AnalysisRequest', payload)
    code, job = request('/api/v1/analyses', 'POST', payload)
    assert code == 202, job
    contract(spec, 'JobStatus', job)
    deadline = time.monotonic() + 90
    while True:
        code, status = request(job['status_url'])
        assert code == 200
        contract(spec, 'JobStatus', status)
        if status['status'] == 'succeeded':
            break
        assert status['status'] in ('queued', 'running'), status
        assert time.monotonic() < deadline
        time.sleep(.05)
    code, result = request(job['result_url'])
    assert code == 200
    contract(spec, 'AnalysisResult', result)
    code, dot = request(job['arg_url'])
    assert code == 200 and b'digraph' in dot
    cli = json.loads(subprocess.check_output([str(CLI), str(REPOSITORY), '--json']))
    # Full privacy-normalized parity is covered by Rust integration tests.
    # Native determinism and classification must also match on this real app.
    for field in ('routes', 'peer_groups', 'invariants', 'finding_details', 'review_observations', 'check_comparisons'):
        assert len(cli[field]) == len(result['report'][field]), field
    assert [f['category'] for f in cli['finding_details']] == [f['category'] for f in result['report']['finding_details']]
    graph = result['report']['graph']
    assert len(cli['graph']['nodes']) == len(graph['nodes'])
    assert len(cli['graph']['edges']) == len(graph['edges'])
    assert [n['kind'] for n in cli['graph']['nodes']] == [n['kind'] for n in graph['nodes']]
    native_ids = {n['id']: i for i, n in enumerate(cli['graph']['nodes'])}
    api_ids = {n['id']: i for i, n in enumerate(graph['nodes'])}
    assert [(native_ids[e['from']], native_ids[e['to']], e['relation']) for e in cli['graph']['edges']] == [(api_ids[e['from']], api_ids[e['to']], e['relation']) for e in graph['edges']]
    dot_text = dot.decode('utf-8')
    for edge in graph['edges']:
        assert f'"{edge["from"]}" -> "{edge["to"]}" [label="{edge["relation"]}"' in dot_text
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(urllib.request.Request(BASE + job['arg_url'], headers={'Authorization': 'Bearer ' + TOKEN, 'Origin': 'http://localhost:5173'}), timeout=20) as response:
        assert response.headers['Content-Type'] == 'text/vnd.graphviz; charset=utf-8'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
        assert response.headers['Content-Security-Policy'] == "default-src 'none'; sandbox"
        assert 'attachment;' in response.headers['Content-Disposition']
        assert job['result_url'] in response.headers['Link']
        assert 'Link' in response.headers['Access-Control-Expose-Headers']
        assert response.read() == dot
    assert request(job['status_url'] + '/arg.svg')[0] == 404
    assert request(job['status_url'], 'DELETE')[0] == 204
    assert not list((OUT / 'work').iterdir()), 'Source workspace leaked'
    for name, value in [('health', health), ('job', job), ('status', status), ('result', result)]:
        (OUT / (name + '.json')).write_text(json.dumps(value, indent=2), encoding='utf-8')
    (OUT / 'arg.dot').write_bytes(dot)
    mutation_categories = []
    demo_mutations = [('ARCHER_ROLE_MUTATION', 'InconsistentRoleOrPermission'),
                             ('ARCHER_AUTH_MUTATION', 'MissingEnforcement'),
                             ('ARCHER_OWNER_MUTATION', 'MissingOwnershipValidation')] if REPOSITORY == (ROOT / 'demo').resolve() else []
    for marker, category in demo_mutations:
        variant = json.loads(json.dumps(payload))
        for file in variant['source']['files']:
            if file['path'] == 'src/main.rs':
                assert file['content'].count(marker) == 1
                file['content'] = '\n'.join(line for line in file['content'].splitlines() if marker not in line) + '\n'
        fixture = OUT / marker.lower()
        for file in variant['source']['files']:
            path = fixture / file['path']
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(file['content'], encoding='utf-8')
        code, mutation_job = request('/api/v1/analyses', 'POST', variant)
        assert code == 202, mutation_job
        deadline = time.monotonic() + 90
        while True:
            code, mutation_status = request(mutation_job['status_url'])
            assert code == 200
            if mutation_status['status'] == 'succeeded':
                break
            assert mutation_status['status'] in ('queued', 'running'), mutation_status
            assert time.monotonic() < deadline
            time.sleep(.05)
        code, mutation = request(mutation_job['result_url'])
        assert code == 200
        contract(spec, 'AnalysisResult', mutation)
        native = json.loads(subprocess.check_output([str(CLI), str(fixture), '--json']))
        assert [f['category'] for f in native['finding_details']] == [category]
        assert [f['category'] for f in mutation['report']['finding_details']] == [category]
        for field in ('routes', 'peer_groups', 'invariants', 'review_observations', 'check_comparisons'):
            assert len(native[field]) == len(mutation['report'][field]), (marker, field)
        (OUT / (marker.lower() + '.json')).write_text(json.dumps(mutation, indent=2), encoding='utf-8')
        assert request(mutation_job['status_url'], 'DELETE')[0] == 204
        assert not list((OUT / 'work').iterdir())
        mutation_categories.append(category)
    print(json.dumps({'outcome': 'passed', 'openapi': spec['openapi'], 'paths': len(spec['paths']),
                      'demo_routes': len(result['report']['routes']),
                      'demo_findings': len(result['report']['finding_details']),
                      'repository': str(REPOSITORY), 'arg_nodes': len(graph['nodes']), 'arg_edges': len(graph['edges']),
                      'mutation_categories': mutation_categories, 'artifacts': str(OUT)}))
finally:
    server.terminate()
    server.wait(timeout=15)
    server_log.close()
