# Backend integration scope and verification

This contribution is based on `Viditgupta-official/archer:main` at `95aedab89482bc198eabe5129d319c243231bc47` and imports the completed backend from `lavishxgambhir/archer-research:main` at `8557854d00fef6e12c0320ebe55996242920d17e`. The source commit descends from target main; no unrelated-history merge is needed. The contribution is one focused local commit rather than importing release packaging/history artifacts.

## Files and preservation

- Existing files updated: `.gitignore` additively; Cargo.toml/Cargo.lock for the API feature/binary/dependencies; src/analyzer.rs and src/main.rs for the published engine/CLI; README.md for current entry-point instructions.
- All 23 incoming Rust files, Cargo metadata and docs/openapi.json match the pinned source Git blobs. The analyzer algorithms, uncertainty handling, thresholds, API security controls and informational analyses are not modified during integration.
- New analyzer/security/registration/reporting modules, API/library/binary, essential tests/demo, OpenAPI, integration/deployment docs and launchers are included. The lockfile grows from 33 to 150 package/version entries for API dependencies; every original locked package/version remains present.
- No target file is deleted. The existing context, development log, checkpoint/benchmark documents, fixture and tracked machine artifacts remain. The exact target README is retained at docs/history/README-before-backend.md.
- Source `packaging/*` self-inventories are omitted: they describe that release package, not this larger original repository. No old evaluation data, generated report, screenshot, binary or build cache is newly introduced.

## Existing unmerged work

Draft [PR #1](https://github.com/Viditgupta-official/archer/pull/1) contains the older ARG/three-state/drift-taxonomy change at `899832b`. That commit is an ancestor of source `8557854`; this contribution overlaps and advances it. No review comments/reviews were present at inspection. The existing PR is not edited, closed or merged. Reviewers should choose one integration path rather than landing both implementations independently.

The target also has `feature/archer-improvements` at `05561a3`, a single divergent commit from `59dda67`. It changes older route-method/evidence/drift logic and overlaps these areas. The branch is not merged or rewritten here; it will require separate reconciliation if it is also to land. Main remains the default and appropriate integration target.

## Behavior and compatibility

The CLI path argument and --json remain; --graph, --diff and --explain are supported by the incoming backend. Existing top-level report categories remain and structured requirements, diagnostics, graph/summary and uncertainty evidence are added. Output is richer and security/peer semantics are more conservative than the prototype; strict JSON consumers or terminal-output parsers should be reviewed. No frontend implementation or prior REST API existed on target main.

The unchanged original fixture at tests/fixtures has five routes. Target main emits one prototype alert, one group and one invariant. The completed backend discovers the same five routes but emits zero findings/groups/invariants, with three Unknown and two locally Unprotected routes and zero supported comparisons. The fixture does not establish the newer source-backed enforcement/resource requirements. This intentional change is inherited from the published source, not a merge workaround; no lexical check is promoted merely to reproduce an old alert.

All 50 original test function names remain in the incoming source, including the published test-only legacy helpers. They preserve regression context; their presence does not mean that the production engine must retain every old verdict. The new executable demo separately has 12 routes, four peer groups, three invariants, nine compared routes and zero clean findings; independent role/authentication/ownership weakenings each produce their supported finding category.

## Verification executed for this contribution

Windows host with Rust/Cargo 1.99.1. No remote CI result or Linux runtime validation is claimed.

| Check | Result |
| --- | --- |
| Target-main baseline tests | 50 passed, zero failed/ignored |
| Integration default analyzer suite | 153 passed, zero failed/ignored |
| API-enabled unit suite | 158 passed, zero failed/ignored |
| API contract/worker integration suite | Four passed |
| Locked/offline CLI and API binary build | Passed |
| Live OpenAPI 3.1 and actual HTTP response contracts | Passed, including auth, jobs, results, ARG, privacy/topology, cleanup and three demo mutation categories |
| Fresh clean/weakened per-job ARGs | Distinct generated DOT; JSON/Graphviz/SVG topology matches; source is not a saved graph |
| Real allowlisted GitHub archive job | Passed for pinned ddimaria/rust-actix-example; eight routes, 34 graph nodes/31 edges |
| Hostile ARG labels and duplicate/unresolved handlers | Passed |
| Published-backend development/mutation parity | 24 full reports equivalent after list-order canonicalization; source hashes preserved |

Twenty-four previously consumed development/frozen-mutation reports match the published backend after canonicalizing list order (duplicates retained); input source hashes are unchanged. SeaORM retains all four detected actual-source mutation cases and the complete suite remains **4 TP / 0 FP / 4 FN**. RealWorld retains six peer groups, 13 group-covered routes, three informational contrasts, 20 Unknown routes and zero supported comparisons/findings. These are static development mutation/regression results, not natural vulnerability accuracy.

A source-equivalent reference executable was used for published-backend differential replay: every Rust source file, Cargo.toml, Cargo.lock and OpenAPI was checked against the pinned commit with CRLF normalization only. The integration branch itself was freshly built and its tests/HTTP scripts executed. Larger consumed regression repositories and raw reports stay outside the contribution and are not required by normal builds or essential tests.

Reproduce the self-contained checks:

```sh
cargo test --locked --offline
cargo test --locked --offline --features api --all-targets
cargo build --locked --offline --features api --bins
python -m pip install -r requirements-dev.txt
python tests/verify_api_openapi.py
python tests/verify_dynamic_arg.py --dot /path/to/dot
```

Omit --offline on a fresh machine without cached crates. Graphviz/Python are development verification tools, not dependencies of the Rust HTTP runtime. Use the optional --github-url/--commit flags for a configured public repository when reproducing real remote acceptance.

## Frontend and deployment boundaries

See frontend-integration.md, backend.md, arg-visualization.md and deployment.md. The API requires a server-managed bearer token for analysis/job/result/ARG operations and exact-origin CORS configuration where applicable. It is a single-tenant trusted-client service; a public multi-user site requires a trusted gateway with user/job ownership, quotas and TLS.

GitHub fetching is off by default and limited to explicit allowlists, full immutable 40-hex commits, curl 8.4+ and safe/bounded supported archives/manifests/paths. Private credentials, arbitrary public URLs/branches and archives containing links/special entries are not supported. These restrictions remain.

ARG is dynamic DOT plus JSON graph data, not a hosted SVG endpoint. The frontend must render untrusted labels safely. The explanation-provider interface remains a future immutable-evidence/supplement boundary; no LLM provider, model credential or frontend is added. Jobs are bounded/in-memory and expire or disappear on restart. Linux/systemd/process limits require target-host validation.
