# Backend deployment

## Runtime closure

Build on the deployment OS using `cargo build --locked --release --features api --bins`. Ship `archer-api` (or `archer-api.exe`); it launches itself as an isolated worker. Ship `archer` too if CLI/`--diff` is desired. Source-based rebuilds need Cargo.lock, Cargo.toml and the full src tree. Essential regression tests additionally require the retained demo source and tests. No old graph image, evidence ZIP, Python research dataset or hidden workspace is required.

For full workspace/path-dependency resolution install a trusted Cargo and rustc toolchain at runtime. `ARCHER_CARGO_BIN` should identify the actual toolchain Cargo binary, not a rustup proxy which depends on a user home removed from worker environments. Discovery uses `rustup which cargo`; the worker also uses the adjacent rustc when present. Missing/unusable metadata reduces resolution coverage and is reported; do not present that as a fully resolved scan.

Remote public GitHub archive retrieval requires trusted **curl 8.4+**, public IPv4 provider DNS and HTTPS egress to `codeload.github.com`. Check the target host's version: older distribution curl fails closed. No private repository token support exists. Python/OpenAPI packages and Graphviz are verification tools, not Rust API runtime dependencies. Git is only required for CLI diff and Git-based tests.

## Hosting

Run as a dedicated unprivileged service account with no unrelated secrets and a private work root. Configure a random bearer secret through service secrets management. Keep the API on loopback behind a TLS-terminating trusted gateway; browser JavaScript must not receive the operator token. The gateway provides user authentication, authorization, request/rate quotas and session-to-job ownership if the website is public. The current bearer token grants access to every retained job on the instance.

Use `scripts/run-api.ps1 release` on Windows or `sh scripts/run-api.sh release` on POSIX after building. These launchers use paths relative to the repository and fail if the token is missing; they do not read arbitrary dotenv files. `.env.example` documents the environment. Install the executable/toolchain outside submitted repositories and make them non-writable by untrusted users.

`deploy/archer-api.service` is an optional Linux systemd template. Create the `archer` account, install the binary at `/opt/archer/bin/archer-api`, configure `/etc/archer/archer.env` with restrictive permissions, and install a trusted Cargo/rustc toolchain outside protected home directories. The template creates private state under `/var/lib/archer`. Validate the unit and run all worker/deadline/security tests on the actual Linux host before public deployment. This backend integration is verified on Windows; neither the systemd unit nor Linux isolation is represented as tested here.

Windows Job Objects and Linux process groups/resource limits are retained. They are not a complete filesystem/network sandbox. Restrict host permissions, outbound traffic and workload identity at the hosting layer. On Windows apply restrictive ACLs to the work root and its parents. On Linux use a dedicated UID because process limits are per user; supervisor/cgroup cleanup should terminate descendants after a parent crash.

Size service memory for retained JSON+DOT, worker budgets and transient parsing/serialization. At defaults eight retained jobs can consume approximately 1 GiB for output alone, in addition to workers. Jobs are in memory, expire after ten minutes by default, and are lost on restart. Multiple instances need consistent routing to the job-owning instance; durable/shared jobs are not implemented.

## GitHub submission restriction

The browser's repository URL alone is insufficient. A trusted integration layer must select an operator-approved repository, resolve/select a full immutable commit SHA, and POST both values. Set `ARCHER_GITHUB_REPOSITORIES=owner/repository,other/project`; the maximum is 64 entries and changes require restarting the service. Do not add arbitrary submitted URLs automatically to this allowlist.

Alternatively a trusted gateway may fetch a user-authorized repository under its own equivalent SSRF/archive/size policies and submit an accepted source snapshot. This gateway is not part of this backend. Do not bypass backend path/manifest/source limits or forward arbitrary server filesystem paths.

**Current deployment limitation:** arbitrary public GitHub URL submission is not supported. A controlled allowlisted website can be integrated immediately after target-host configuration. An unrestricted public multi-user website requires an authenticated gateway/ownership/quotas layer and a separately designed repository-admission policy. No changes to the analyzer or weakening of fetch restrictions were made to hide this limitation.

## Operational boundaries

Source snapshots accept UTF-8 `.rs`, Cargo.toml and Cargo.lock files with safe relative paths. Accepted source limits and supported URL syntax are in `docs/backend.md`. Cargo metadata runs frozen/offline/no-deps; submitted build scripts, procedural macros and application executables are not run. Failed setup, unknown evidence, parse failures and analysis timeouts must be surfaced to users.

Keep request logging free of bearer secrets, source contents and result evidence. Monitor terminal job errors, available capacity, memory and orphaned workspaces after crashes. Cleanup orphaned workspaces only inside the dedicated work root. Do not mount valuable source or secrets there. No public rollout, hosting change, push or deployment was performed during integration preparation.
