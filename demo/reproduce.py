"""Verify source mutations and Git diff in isolated copies; never edit demo/main.

Run: python demo/reproduce.py [--runtime]
Build ARCHER first. --runtime additionally executes the Actix request tests for
each copy (requires the existing demo dependencies in Cargo's cache).
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('--runtime', action='store_true')
args = parser.parse_args()
binary = ROOT / 'target/debug/archer.exe'
if not binary.exists():
    binary = binary.with_suffix('')
source = (ROOT / 'demo/src/main.rs').read_text(encoding='utf-8')
cases = {
    'clean': (None, None),
    'role': ('ARCHER_ROLE_MUTATION', 'InconsistentRoleOrPermission'),
    'authentication': ('ARCHER_AUTH_MUTATION', 'MissingEnforcement'),
    'ownership': ('ARCHER_OWNER_MUTATION', 'MissingOwnershipValidation'),
}


def run(command, cwd):
    return subprocess.check_output(command, cwd=cwd, text=True, encoding='utf-8')


for name, (marker, category) in cases.items():
    with tempfile.TemporaryDirectory(prefix='archer-demo-release-') as directory:
        copy = Path(directory)
        (copy / 'src').mkdir()
        shutil.copyfile(ROOT / 'demo/Cargo.toml', copy / 'Cargo.toml')
        if (ROOT / 'demo/Cargo.lock').exists():
            shutil.copyfile(ROOT / 'demo/Cargo.lock', copy / 'Cargo.lock')
        (copy / 'src/main.rs').write_text(source, encoding='utf-8')
        run(['git', 'init', '-q'], copy)
        run(['git', 'add', '.'], copy)
        run(['git', '-c', 'user.name=ARCHER Demo', '-c',
             'user.email=demo@example.invalid', '-c', 'commit.gpgsign=false',
             'commit', '-qm', 'clean demonstration'], copy)
        modified = source
        if marker:
            assert source.count(marker) == 1
            modified = '\n'.join(line for line in source.splitlines() if marker not in line) + '\n'
            # Runtime controls follow the intentionally weakened target behavior.
            if name == 'role':
                modified = modified.replace('("/roles/owned", "demo-member", 403)', '("/roles/owned", "demo-member", 200)')
            elif name == 'authentication':
                modified = modified.replace('("/sessions/owned", "invalid", 403)', '("/sessions/owned", "invalid", 200)')
            else:
                modified = modified.replace('("/documents/another", "demo-owner", 403)', '("/documents/another", "demo-owner", 200)')
                modified = modified.replace('("/documents/owned", "demo-member", 403)', '("/documents/owned", "demo-member", 200)')
        (copy / 'src/main.rs').write_text(modified, encoding='utf-8')
        report = json.loads(run([str(binary), str(copy), '--json'], ROOT))
        diff = json.loads(run([str(binary), str(copy), '--diff', 'HEAD', '--json'], ROOT))
        assert not report['parse_errors']
        actual = [f['category'] for f in report['finding_details']]
        assert actual == ([] if category is None else [category]), (name, actual)
        assert len(diff['newly_introduced_drifts']) == int(category is not None), diff
        assert not diff['unchanged_drifts'] and not diff['resolved_drifts'] and not diff['unverified_drifts']
        assert bool(diff['regressions']) == bool(category)
        assert not any(f['suspicious_route']['path'].startswith(('/profiles', '/public')) for f in report['finding_details'])
        if args.runtime:
            run(['cargo', 'test', '--offline', '--manifest-path', str(copy / 'Cargo.toml'),
                 '--target-dir', str(ROOT / 'demo/target')], ROOT)
        print(json.dumps({'case': name, 'summary': report['summary'],
                          'categories': actual, 'diff_new': len(diff['newly_introduced_drifts']),
                          'runtime_verified': args.runtime}), flush=True)
