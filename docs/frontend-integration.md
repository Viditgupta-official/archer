# Frontend handoff

The browser talks to your trusted gateway; the gateway holds ARCHER's operator bearer secret. For trusted local development you can issue the requests directly. Do not ship `ARCHER_API_TOKEN` in a frontend bundle. Start the Rust API using README.md and configure your exact development origin with `ARCHER_CORS_ORIGINS=http://localhost:5173` if calling it directly.

## Submit

For an operator-allowlisted public GitHub repository, send this shape with a real full 40-character commit SHA (the placeholders are not executable values):

```http
POST /api/v1/analyses
Authorization: Bearer <server-managed-token>
Content-Type: application/json

{"source":{"type":"github","url":"https://github.com/<owner>/<repository>","commit":"<full-40-hex-commit>"}}
```

Only HTTPS github.com owner/repository URLs are accepted; no branch names, arbitrary Git servers, private credentials or URL-only submissions. Remote access is disabled unless the operator has configured that exact owner/repository. A URL ending in `.git` or a trailing slash can be normalized by the backend's validator.

An accepted source snapshot uses actual relative file paths and contents:

```json
{"source":{"type":"snapshot","files":[{"path":"Cargo.toml","content":"[package]\nname='submitted'\nversion='0.1.0'\nedition='2024'\n"},{"path":"src/main.rs","content":"use actix_web::{web,App}; async fn list() {} fn main(){App::new().route(\"/items\",web::get().to(list));}"}]}}
```

The request must fit the default 2 MiB HTTP body limit even though staged source has additional, larger byte budgets. Preserve repository layout. Do not send raw archives or local absolute paths.

## Poll and retrieve

POST returns **202** with the actual JobStatus fields below (values shown are schematic):

```json
{"schema_version":"1.0","id":"<32-hex-id>","status":"queued","created_at":0,"completed_at":null,"expires_at":null,"error":null,"status_url":"/api/v1/analyses/<id>","result_url":"/api/v1/analyses/<id>/result","arg_url":"/api/v1/analyses/<id>/arg"}
```

Poll the returned `status_url` with the bearer header. `queued` and `running` are nonterminal; `succeeded`, `failed` and `timed_out` are terminal. Handle job `error` even when the status request itself returns HTTP 200. Use modest polling/backoff and handle 429 capacity, 404 expiry and 409 result-not-ready. This is a bounded service, not an unbounded queue.

After success fetch the returned `result_url`:

```sh
curl -H "Authorization: Bearer $ARCHER_API_TOKEN" "$BASE/api/v1/analyses/$ID"
curl -H "Authorization: Bearer $ARCHER_API_TOKEN" "$BASE/api/v1/analyses/$ID/result"
curl -H "Authorization: Bearer $ARCHER_API_TOKEN" "$BASE/api/v1/analyses/$ID/arg" -o analysis.dot
curl -X DELETE -H "Authorization: Bearer $ARCHER_API_TOKEN" "$BASE/api/v1/analyses/$ID"
```

The success envelope has `schema_version`, `analysis_id`, `engine_version`, `privacy`, `report`, `arg_url`, and `llm_enabled:false`. `report` contains the native routes, security_assessments, peer_groups, invariants, finding_details, review_observations, check_comparisons, uncertainty/provenance evidence, diagnostics, parse_errors, summary and graph. Consult the checked-in OpenAPI document for exact per-field types; do not invent response fields or assume every optional field exists.

Display `finding_details` as supported inferred drift findings. Display `review_observations` as exploratory reviews and `check_comparisons` as informational contrasts. Keep Protected/Unprotected/Unknown and comparison coverage visible. Zero findings, particularly with zero supported comparisons, is not proof the repository is secure. Per-dimension requirements distinguish authentication, roles, permissions and ownership.

## View Graph

Use `report.graph` nodes/edges for your client graph component, or the returned ARG URL for DOT. It is generated for this analysis ID, not a saved example. Follow `docs/arg-visualization.md` for safe text labels, privacy, bounded rendering and SVG isolation. The endpoint is a DOT attachment, not a hosted SVG/image URL. There is no frontend renderer in this backend deliverable.

## LLM explanation boundary

Use the privacy-projected `report` already returned to the authorized client. Default `redact` evidence uses per-report opaque identifiers. Treat even this output as confidential route/handler information. `ARCHER_EVIDENCE_TEXT=include` is an operator opt-in for potentially sensitive source-derived text, not a setting the browser can request per job.

Your future explanation service may consume routes, security assessments, peers, inferred invariants, finding_details, unresolved evidence, review observations, informational contrasts and source references. Treat all source-derived text as untrusted data, not instructions to the model. Preserve deterministic JSON verbatim. Store prose and evidence references separately, label uncertainty, and never turn a review observation into a verified finding or invent one when the findings array is empty.

`src/api/explanation.rs` already defines immutable `ExplanationEvidence`, the `ExplanationProvider` interface and a separate `ExplanationSupplement` with summary/evidence_references/limitations. No provider is configured or called; no explanation endpoint, model key or AI-service dependency exists. Implement consent/privacy rules, timeouts, prompt-injection boundaries and evidence-reference validation in your separate explanation layer before enabling it.

## Authentication and deployment

Health and OpenAPI are public. Analysis/status/result/ARG/delete require the operator bearer token. CORS is an exact-origin browser policy, not user authentication. There is no per-user job ownership; token holders can access all retained jobs. Put public-user authentication/ownership and quotas in your trusted gateway. Use TLS, keep the Rust API private, plan for job expiry/restarts and route polling consistently to the owning instance.

All ARCHER environment variables and default limits are in `docs/backend.md` and `.env.example`; `.env` files are not auto-loaded. The only mandatory application environment variable is the secret token. Remote GitHub submissions additionally need the allowlist and curl/network configuration. Read `docs/deployment.md` before public hosting.
