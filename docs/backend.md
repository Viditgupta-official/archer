# ARCHER backend integration

This backend reuses the current Rust analyzer. It adds no frontend, dashboard or custom Swagger UI. The versioned [OpenAPI 3.1 contract](openapi.json) is also served at `GET /api/v1/openapi.json`; import it into standard Swagger tooling. Deterministic results remain authoritative. No LLM provider, network call or explanation endpoint is implemented.

See [ARG visualization and backend contract](arg-visualization.md) for dynamically generated graph data, the DOT/JSON handoff and safe rendering. Saved demo images and reports are not runtime dependencies. The ARG response is a DOT attachment with security/link headers; there is no SVG rendering endpoint.

## Run from PowerShell

Use a supported Rust toolchain and Windows or Linux. Windows workers use Job Objects; unsupported platforms fail closed when creating a worker. Linux resource-limit code requires a dedicated service account and has not been exercised by the Windows verification run.

```powershell
cargo build --locked --features api --bins
$bytes = New-Object byte[] 32
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
$rng.Dispose()
$env:ARCHER_API_TOKEN = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
$env:ARCHER_CORS_ORIGINS = 'http://localhost:5173'
# Optional: a private, service-owned directory, outside submitted repositories.
# $env:ARCHER_WORK_ROOT = 'C:\private-archer-work'
.\target\debug\archer-api.exe
```

Keep the environment/token in the calling terminal for the examples below, and run the server in a second terminal with the same secret or use a service secret store. The default bind is `127.0.0.1:8080`. Configure a TLS reverse proxy before exposing it beyond loopback. Health and OpenAPI are public; analysis endpoints require `Authorization: Bearer <secret>`. This is a **single-tenant trusted-client API**: possession of that token allows access to all retained jobs. CORS is not authentication. Do not publish the operator token inside a public frontend bundle; a trusted backend gateway/session layer must hold it if public users use the teammate's frontend. There is no multi-user identity or per-job ownership system in this minimal API.

## Submit and consume a source snapshot

Only UTF-8 Rust files, Cargo.toml and Cargo.lock are accepted, using portable repository-relative paths. Snapshots carry file contents in JSON; local filesystem paths, uploaded archives and arbitrary Git servers are deliberately unsupported. No checkout/submitted build script is run. Preserve the original file layout for module and workspace analysis.

```powershell
$base = 'http://127.0.0.1:8080'
$headers = @{ Authorization = "Bearer $env:ARCHER_API_TOKEN" }
$body = @{
  source = @{
    type = 'snapshot'
    files = @(
      @{ path = 'Cargo.toml'; content = "[package]`nname='sample'`nversion='0.1.0'`nedition='2024'`n" },
      @{ path = 'src/main.rs'; content = 'use actix_web::{web, App}; async fn list() {} fn main() { App::new().route("/items", web::get().to(list)); }' }
    )
  }
} | ConvertTo-Json -Depth 10
$job = Invoke-RestMethod "$base/api/v1/analyses" -Method Post -Headers $headers -ContentType 'application/json' -Body $body
do {
  Start-Sleep -Milliseconds 250
  $status = Invoke-RestMethod "$base$($job.status_url)" -Headers $headers
} while ($status.status -in @('queued', 'running'))
if ($status.status -ne 'succeeded') { throw ($status.error | ConvertTo-Json -Compress) }
$result = Invoke-RestMethod "$base$($job.result_url)" -Headers $headers
$result.report.routes
$result.report.finding_details
Invoke-WebRequest "$base$($job.arg_url)" -Headers $headers -OutFile 'analysis.dot'
Invoke-RestMethod "$base$($job.status_url)" -Method Delete -Headers $headers
```

Equivalent curl requests (save the JSON body above as UTF-8 `request.json`; PowerShell 7: `$body | Set-Content request.json -Encoding utf8NoBOM`):

```powershell
curl.exe -sS "$base/api/v1/health"
curl.exe -sS "$base/api/v1/openapi.json" -o openapi.json
curl.exe -sS -i -X POST "$base/api/v1/analyses" -H "Authorization: Bearer $env:ARCHER_API_TOKEN" -H 'Content-Type: application/json' --data-binary '@request.json'
# Replace ID with the returned 32-character id. Poll status before fetching results.
curl.exe -sS "$base/api/v1/analyses/ID" -H "Authorization: Bearer $env:ARCHER_API_TOKEN"
curl.exe -sS "$base/api/v1/analyses/ID/result" -H "Authorization: Bearer $env:ARCHER_API_TOKEN"
curl.exe -sS "$base/api/v1/analyses/ID/arg" -H "Authorization: Bearer $env:ARCHER_API_TOKEN" -o analysis.dot
curl.exe -sS -X DELETE "$base/api/v1/analyses/ID" -H "Authorization: Bearer $env:ARCHER_API_TOKEN"
```

`POST` returns 202 with `Location` and a JobStatus. Poll status until `succeeded`, `failed` or `timed_out`; terminal errors are sanitized in `error`. A successful HTTP status response does not imply successful analysis. Pending/failed result requests return 409. Delete supports completed jobs only. Completed jobs expire after ten minutes by default, and all jobs/results are lost on restart.

Errors use `{ "schema_version": "1.0", "error": { "code": "...", "message": "..." } }`. HTTP codes: 400 invalid JSON/source, 401 missing/invalid bearer, 403 forbidden origin/repository, 404 missing/expired resource, 405 unsupported method, 408 HTTP processing deadline, 409 result unavailable/active deletion, 413 body/source limit, 415 unsupported media/encoding, 429 processing/retention capacity, 500 internal setup failure. Worker failures (including 422 analysis/output validation errors) appear in the job's terminal `error`, rather than changing the POST's accepted response.

## Result contract and categories

`AnalysisResult` wraps the native analyzer JSON as `report`, adding `schema_version`, `analysis_id`, `engine_version`, `privacy`, `arg_url` and `llm_enabled: false`. No inference logic is duplicated. Consumers should allow additive evidence fields and use the schema version for breaking changes. Unknown/uncertain evidence retains the native analyzer's semantics.

| Native report field | Meaning |
| --- | --- |
| `routes` | Inventory, qualified handlers, source locations, mount and authorization evidence |
| `candidate_relationships` | Discovery candidates; not automatically eligible security peers |
| `peer_groups` | Supported inferred resource-peer membership; intended policy equivalence is not proven |
| `invariants` | Independently supported deterministic contracts |
| `finding_details` | Supported deterministic drift findings, not independently confirmed vulnerabilities; use this array for finding counts |
| `review_observations` | Exploratory security reviews, not verified drift |
| `check_comparisons` | Informational contrasts, not security warnings/findings |
| `security_assessments`, `analysis_evidence`, `resource_evidence` | Requirements, uncertainty and source provenance |
| `handler_resolution_evidence`, `diagnostics`, `parse_errors`, `summary` | Coverage, errors and limitations |
| `graph` | ARG nodes/edges; `/arg` renders the same graph through the existing DOT renderer |

Default privacy replaces free source-derived evidence strings with consistent, per-report opaque IDs; equal strings retain equal IDs. It also redacts graph labels/IDs and converts source paths to repository-relative paths. Route paths, handler identifiers, controlled categories and numeric/boolean facts remain visible. The API intentionally discloses route/handler inventory to authenticated clients, so these results must still be treated as confidential. There is no raw-file endpoint and no source excerpt field is added. For trusted internal use, `ARCHER_EVIDENCE_TEXT=include` opts into native evidence text (which may contain secrets); paths remain normalized. Privacy affects presentation, never classification, thresholds or graph topology. CLI output remains unchanged. API and CLI results are compared after the same privacy projection; default API output is intentionally not byte-identical to native CLI JSON.

## Optional public GitHub submissions

Remote access is **disabled by default**. An operator may allow specific public repositories:

```powershell
$env:ARCHER_GITHUB_REPOSITORIES = 'owner/repository,other/project'
# Restart API, then POST this source object with an actual full commit SHA:
# {"source":{"type":"github","url":"https://github.com/owner/repository","commit":"0123456789abcdef0123456789abcdef01234567"}}
```

Only credential-free HTTPS github.com repository URLs and full 40-hex commits are supported. No refs, authentication, submodules, LFS, Git configuration or arbitrary remote hosts. Retrieval uses a bounded archive from a fixed `codeload.github.com` endpoint, not git clone. DNS answers must be public addresses and the chosen address is pinned for the TLS request. Redirects and proxies are disabled. `curl` **8.4+** is required for streaming size enforcement; otherwise remote jobs fail closed. Windows defaults to System32 curl; `ARCHER_CURL_BIN` may specify another trusted absolute binary. Archive links, special files, traversal, ambiguous metadata, duplicate source paths and expansion-budget violations are rejected. Unsupported repository archive layouts may fail rather than being guessed. Remote retrieval needs outbound DNS and HTTPS; no other analyzer network access is required.

## Limits, isolation and operation

| Setting | Default / accepted range |
| --- | --- |
| `ARCHER_BIND` | `127.0.0.1:8080` |
| `ARCHER_API_TOKEN` | Required; 32–256 ASCII graphic characters |
| `ARCHER_CORS_ORIGINS` | Empty; comma-separated exact http(s) origins, no trailing slash/wildcard; max 32 |
| `ARCHER_GITHUB_REPOSITORIES` | Empty; comma-separated owner/repo entries, max 64 |
| `ARCHER_CONCURRENCY` | 1; 1–4, no unbounded waiting queue |
| `ARCHER_RETAINED_JOBS` | 8; 1–32, at least concurrency |
| `ARCHER_RETENTION_SECONDS` | 600; 10–3600 |
| `ARCHER_TIMEOUT_SECONDS` | 90; 1–300 |
| `ARCHER_MEMORY_MIB` | 1024; 128–4096 |
| `ARCHER_EVIDENCE_TEXT` | `redact`; `include` is explicit sensitive-text opt-in |
| `ARCHER_WORK_ROOT` | Random private temporary directory; service-owned isolated directory recommended |
| `ARCHER_CARGO_BIN` | Trusted toolchain cargo discovered with `rustup which cargo`; absolute override supported |
| `ARCHER_CURL_BIN` | OS curl; trusted absolute override supported |

Fixed defaults exposed by `/health`: request JSON 2 MiB, 5,000 accepted source files, 1 MiB/file, total source 32 MiB, compressed archive 32 MiB, expanded archive 64 MiB, JSON/ARG outputs each 64 MiB. Tar entry count and PAX metadata are separately bounded. Limits can be configured through the Rust `ApiConfig` embedding API; validation enforces hard upper bounds. HTTP headers must arrive within ten seconds, HTTP handlers have a 15-second deadline, two HTTP workers accept at most 16 connections each, and child work runs outside those async workers. Stored outputs are bounded by job count and output limits; size service memory accordingly (default worst-case retained JSON+DOT is approximately 1 GiB, in addition to workers and transient serialization).

Each job gets a fresh private source tree, HOME, Cargo home and temp directory. The worker environment is cleared of API tokens, proxy settings and unrelated credentials. Only supported source files/manifests are staged. Cargo metadata runs frozen/offline/no-deps using the existing analyzer; submitted code, build scripts and procedural macros are never executed. Manifest paths are validated to remain inside the staged tree. The worker waits for a parent gate until OS limits are attached; setup failure prevents analysis. Windows Job Objects bound memory, process count and CPU time and terminate descendants on close. Linux uses process groups, no-new-privileges and resource limits (address space, CPU, file size, descriptors, processes). Parent wall-clock monitoring kills timed-out workers and removes their workspaces. Source directories are removed after normal success/failure/timeout; retained results are in memory only.

These process/workspace controls are **not** a container, restricted Windows token or filesystem/network sandbox. Run under a dedicated unprivileged account with no access to unrelated secrets, service-owned restrictive workspace ACLs on Windows (0700 ownership is checked on Unix), container/job supervision, outbound allowlists and a TLS/rate-limiting reverse proxy where needed. Local users sharing the service identity are trusted. Protect parent directories from other writers. A crash can leave private temporary directories requiring operator cleanup; never point the work root at valuable files. Linux per-user process limits require a dedicated UID; use container supervision for crash-time descendant cleanup. No Linux isolation claim is based on the Windows test run. Review [Microsoft Job Object limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information) for host deployment constraints.

## LLM extension boundary

`src/api/explanation.rs` defines `ExplanationProvider`, immutable privacy-projected `ExplanationEvidence` and a separate `ExplanationSupplement`. A future optional provider may return prose, evidence references and limitations; it cannot mutate the deterministic report through this interface. Implement provider timeouts, consent/privacy rules and evidence-reference validation before enabling one. There is currently no provider configured or called, no LLM credential handling, and deterministic analysis has no AI availability dependency.

## Self-contained verification

```sh
cargo build --locked --features api --bins
cargo test --locked
cargo test --locked --features api --all-targets
python -m pip install -r requirements-dev.txt
python tests/verify_api_openapi.py
python tests/verify_dynamic_arg.py --dot /path/to/dot
```

Graphviz is required only for the optional rendering acceptance tests. Tests use embedded/generated fixtures and the retained demo source, not historical evaluation datasets. Source hashes and externally replayed SeaORM/RealWorld research regressions are recorded in `docs/backend-integration.md`. Those larger development repositories remain outside this source tree and are not dependencies of the test commands above.

`--diff` remains a CLI operation requiring a Git repository. The API accepts source snapshots or a pinned archive without Git history and does not expose remote diff analysis. No frontend, LLM provider or SVG endpoint is implemented.
