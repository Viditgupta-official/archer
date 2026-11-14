"""Syntactic rendering regression only; never replaces the real SeaORM graph."""
import argparse
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from render_real_arg import graph_check

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--binary', type=Path, required=True)
parser.add_argument('--dot', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
out = args.output.resolve()
source = out / 'fixture'
(source / 'src').mkdir(parents=True)
(source / 'Cargo.toml').write_text("[package]\nname='arg_label_regression'\nversion='0.1.0'\nedition='2024'\n", encoding='utf-8')
(source / 'src/main.rs').write_text(r'''
mod left { pub async fn duplicate() { check_role("Admin"); } }
mod right { pub async fn duplicate() {} }
fn config(c: &mut Config) {
 c.route(r#"/quote"; image="file:///forbidden"; <script>alert(1)</script> \ line
next"#, web::get().to(left::duplicate));
 c.route("/right", web::get().to(right::duplicate));
 c.route("/unresolved", web::get().to(missing::handler));
}
fn main() {}
''', encoding='utf-8')
binary, dot = args.binary.resolve(), args.dot.resolve()
report = json.loads(subprocess.check_output([str(binary), str(source), '--json'], timeout=60))
graph = report['graph']
assert len(report['routes']) == 3
handlers = [n for n in graph['nodes'] if n['kind'] == 'Handler']
assert len(handlers) == 3 and len({n['id'] for n in handlers}) == 3
assert any('crate::left::duplicate' in n['label'] for n in handlers)
assert any('crate::right::duplicate' in n['label'] for n in handlers)
assert any(e['relation'] == 'UnresolvedEvidence' for e in graph['edges'])
assert not any(e['relation'] == 'EnforcesCheck' for e in graph['edges'])
dot_file = out / 'labels.dot'
dot_file.write_bytes(subprocess.check_output([str(binary), str(source), '--graph'], timeout=60))
for fmt in ('svg', 'png', 'json'):
    subprocess.run([str(dot), '-Kdot', '-T' + fmt, str(dot_file), '-o', str(out / ('labels.' + fmt))], check=True, timeout=30)
metrics = graph_check(json.loads((out / 'labels.json').read_text()), report, out / 'labels.svg')
document = ET.parse(out / 'labels.svg')
assert all(e.tag.rsplit('}', 1)[-1] not in ('script', 'image', 'a', 'foreignObject', 'use') for e in document.iter())
assert all(not k.lower().startswith('on') and k.rsplit('}', 1)[-1] not in ('href', 'src') for e in document.iter() for k in e.attrib)
(out / 'report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps({'outcome': 'passed', 'graph': metrics, 'syntactic_fixture_only': True}))
