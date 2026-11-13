"""Fresh per-job ARG/HTTP acceptance; optional real allowlisted GitHub archive.

Build debug API/CLI binaries first. Requires requirements-dev.txt and Graphviz
for this development test only. Never executes submitted application code.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

from jsonschema import Draft202012Validator
from openapi_spec_validator import validate

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "demo"))
from render_real_arg import graph_check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dot", type=Path, required=True, help="Trusted Graphviz executable, for this local test only")
    parser.add_argument("--bin-dir", type=Path, default=ROOT / "target/debug")
    parser.add_argument("--github-url", help="Optional already approved public GitHub repository URL")
    parser.add_argument("--commit", help="Full immutable 40-hex SHA for --github-url")
    args = parser.parse_args()
    if bool(args.github_url) != bool(args.commit):
        parser.error("--github-url and --commit must be supplied together")
    dot = args.dot.resolve(strict=True)
    suffix = ".exe" if os.name == "nt" else ""
    api = (args.bin_dir / ("archer-api" + suffix)).resolve(strict=True)
    out = ROOT / "target" / ("dynamic-arg-" + secrets.token_hex(8))
    out.mkdir(parents=True)
    token = secrets.token_hex(32)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    allowed = ""
    if args.github_url:
        from urllib.parse import urlparse
        allowed = urlparse(args.github_url).path.strip("/").removesuffix(".git")
    env = dict(os.environ, ARCHER_API_TOKEN=token, ARCHER_BIND=f"127.0.0.1:{port}",
               ARCHER_GITHUB_REPOSITORIES=allowed, ARCHER_CORS_ORIGINS="",
               ARCHER_WORK_ROOT=str(out / "work"), ARCHER_EVIDENCE_TEXT="redact")
    log = (out / "server.log").open("wb")
    server = subprocess.Popen([str(api)], env=env, stdout=subprocess.DEVNULL, stderr=log,
                              creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(path, method="GET", body=None, authorized=True):
        headers = {"Authorization": "Bearer " + token} if authorized else {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(base + path, method=method, headers=headers,
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            response = opener.open(req, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read()
            return response.status, json.loads(data) if data and response.headers.get_content_type() == "application/json" else data

    spec = None

    def contract(schema, value):
        Draft202012Validator({"$ref": "#/components/schemas/" + schema,
                              "components": spec["components"]}).validate(value)

    def analyze(name, payload, expected_paths=None, expected_findings=None):
        contract("AnalysisRequest", payload)
        code, job = request("/api/v1/analyses", "POST", payload)
        assert code == 202, job
        contract("JobStatus", job)
        deadline = time.monotonic() + 110
        while True:
            code, status = request(job["status_url"])
            assert code == 200, status
            contract("JobStatus", status)
            if status["status"] == "succeeded":
                break
            assert status["status"] in ("queued", "running"), status
            assert time.monotonic() < deadline, status
            time.sleep(.05)
        code, result = request(job["result_url"])
        assert code == 200
        contract("AnalysisResult", result)
        code, data = request(job["arg_url"])
        assert code == 200 and data.startswith(b"digraph ARCHER_Authorization_Graph"), data
        assert request(job["arg_url"], authorized=False)[0] == 401
        report = result["report"]
        assert report["routes"] and not report["parse_errors"], report["parse_errors"]
        if expected_paths is not None:
            assert {r["path"] for r in report["routes"]} == expected_paths
        if expected_findings is not None:
            assert len(report["finding_details"]) == expected_findings
        graph = report["graph"]
        ids = {n["id"] for n in graph["nodes"]}
        assert all(e["from"] in ids and e["to"] in ids for e in graph["edges"])
        assert sum(n["kind"] == "Route" for n in graph["nodes"]) == len({(r["method"], r["path"], r.get("application")) for r in report["routes"]})
        dotfile = out / (name + ".dot")
        dotfile.write_bytes(data)
        for fmt in ("svg", "json"):
            subprocess.run([str(dot), "-T" + fmt, str(dotfile), "-o", str(out / (name + "." + fmt))], check=True, timeout=30)
        topology = graph_check(json.loads((out / (name + ".json")).read_text(encoding="utf8")), report, out / (name + ".svg"))
        (out / (name + "-result.json")).write_text(json.dumps(result, indent=2), encoding="utf8")
        assert request(job["status_url"], "DELETE")[0] == 204
        assert not list((out / "work").iterdir()), "Worker source workspace leaked"
        return {"case": name, "summary": report["summary"], "graph": topology}, data

    try:
        deadline = time.monotonic() + 25
        while True:
            try:
                code, health = request("/api/v1/health", authorized=False)
                assert code == 200
                break
            except OSError:
                assert server.poll() is None, "API exited"
                if time.monotonic() > deadline:
                    raise
                time.sleep(.1)
        code, spec = request("/api/v1/openapi.json", authorized=False)
        assert code == 200
        validate(spec)
        contract("Health", health)
        assert bool(health["capabilities"]["github"]) == bool(allowed)
        assert request("/api/v1/analyses", "POST", {}, authorized=False)[0] == 401
        assert request("/api/v1/analyses", "POST", {"source": {"type": "github", "url": "https://github.com/not-approved/fixture", "commit": "0" * 40}})[0] == 403
        results = []
        dots = []
        for index in range(2):
            marker = "fresh-" + secrets.token_hex(8)
            check = 'check_role("Admin")?;' if index else ""
            source = f'''use actix_web::{{web,App,Error,HttpResponse,error::ErrorForbidden}};
fn check_role(role:&str)->Result<(),Error>{{if std::env::var("ARCHER_ACCEPTANCE_ROLE").ok().as_deref()!=Some(role){{return Err(ErrorForbidden("denied"));}}Ok(())}}
async fn one()->Result<HttpResponse,Error>{{check_role("Admin")?;Ok(HttpResponse::Ok().finish())}}
async fn two()->Result<HttpResponse,Error>{{check_role("Admin")?;Ok(HttpResponse::Ok().finish())}}
async fn three()->Result<HttpResponse,Error>{{{check}Ok(HttpResponse::Ok().finish())}}
fn main(){{App::new().route("/{marker}/{{id}}",web::get().to(one)).route("/{marker}/{{id}}",web::put().to(two)).route("/{marker}/{{id}}",web::delete().to(three));}}
'''
            payload = {"source": {"type": "snapshot", "files": [
                {"path": "Cargo.toml", "content": "[package]\nname='fresh_acceptance'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nactix-web='4'\n"},
                {"path": "src/main.rs", "content": source}]}}
            row, data = analyze("fresh-mutated" if not index else "fresh-clean", payload,
                                {"/" + marker + "/{id}"}, 1 if not index else 0)
            assert row["summary"]["peer_groups_count"] == 1
            assert row["summary"]["inferred_invariants_count"] >= 1
            results.append(row)
            dots.append(data)
        assert dots[0] != dots[1], "Different source jobs returned the same graph"
        if args.github_url:
            row, _ = analyze("github", {"source": {"type": "github", "url": args.github_url, "commit": args.commit}})
            results.append(row)
        summary = {"outcome": "passed", "fresh_source_jobs": 2,
                   "github_url": args.github_url, "commit": args.commit,
                   "cases": results, "artifacts": str(out)}
        (out / "acceptance.json").write_text(json.dumps(summary, indent=2), encoding="utf8")
        print(json.dumps(summary))
    finally:
        server.terminate()
        server.wait(timeout=15)
        log.close()


if __name__ == "__main__":
    main()
