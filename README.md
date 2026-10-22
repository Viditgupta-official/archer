# ARCHER

**Authorization Drift Detection for Actix-Web Applications**

ARCHER is a Rust-based static analysis research prototype that identifies **potential authorization drift** in Actix-Web applications. It analyzes route definitions and recognized authorization evidence, compares structurally related routes, and reports deviations from authorization patterns observed elsewhere in the repository.

The goal is to help developers identify endpoints that may have inconsistent authorization protections without relying exclusively on manually written security rules.

> **Research prototype:** ARCHER produces evidence-backed potential findings, not confirmed vulnerability verdicts. Results require developer review. "No recognized authorization evidence" never means "confirmed absence of authorization".

## How It Works

ARCHER follows a repository-local analysis pipeline:

```text
Rust Source Code
       |
       v
Route and Handler Extraction
       |
       v
Authorization Evidence Analysis
       |
       v
Structural Peer Grouping
       |
       v
Authorization Invariant Inference
       |
       v
Potential Drift Detection
       |
       v
Evidence-Backed Findings
```

1. **Route extraction:** Scans Rust source files and extracts recognized Actix-Web route definitions, HTTP methods, paths, and source locations, then resolves each route's handler to a single function definition, including handlers defined in other files.
2. **Authorization evidence analysis:** Looks for recognized authorization-related evidence in route configurations, middleware or guards, and the resolved handler's code.
3. **Structural peer grouping:** Groups comparable routes so authorization patterns can be evaluated in context.
4. **Invariant inference:** Identifies authorization patterns consistently present among comparable routes.
5. **Drift detection:** Flags routes without recognized authorization evidence in peer groups that contain at least two authorized routes.
6. **Evidence reporting:** Presents suspicious routes alongside supporting peer routes and the inferred invariant.

## Key Features

- Static analysis of Rust and Actix-Web source code.
- Route extraction with nested scope-prefix handling.
- HTTP method and route-path tracking.
- Cross-file handler resolution that reports how each handler was resolved and never merges evidence from same-named functions.
- Recognition of typed authorization-related evidence (role, permission, ownership, guard, middleware, manual check, identity).
- Repository-local authorization pattern inference.
- Detection of potential authorization drift among comparable routes.
- Source-location and supporting-peer evidence for findings.
- Human-readable terminal output and machine-readable JSON reports.
- Graceful reporting of source parsing errors.

## Technology Stack

| Technology | Purpose |
|---|---|
| Rust | Core analysis engine |
| `syn` | Rust syntax-tree parsing and traversal |
| `walkdir` | Repository source-file traversal |
| `clap` | Command-line interface |
| `serde` / `serde_json` | Structured report serialization |
| `anyhow` | Error handling |

## Getting Started

### Prerequisites

- Rust toolchain with Cargo
- A local Rust/Actix-Web repository to analyze

### Build

Clone the repository:

```bash
git clone https://github.com/Viditgupta-official/archer.git
cd archer
```

Build the project:

```bash
cargo build --locked
```

### Run the Analysis

Pass the path to the repository you want to analyze:

```bash
cargo run --locked -- /path/to/actix-web-project
```

To analyze the bundled test fixture:

```bash
cargo run --locked -- tests/fixtures
```

The bundled fixture yields five `/admin/*` routes and one potential drift finding for `GET /admin/payments`, supported by guard, middleware, and `require_admin` evidence on three GET peers; `POST /admin/audit` is not a peer.

### Generate JSON Output

ARCHER supports JSON output for integration with other tools and applications:

```bash
cargo run --locked -- /path/to/actix-web-project --json
```

The JSON report can be consumed by a backend or other programmatic workflow.

## Understanding the Results

A report includes information such as:

- **Files scanned:** Number of Rust source files processed.
- **Parse errors:** Source files that could not be parsed successfully; they are skipped.
- **Routes:** Extracted route candidates, including HTTP methods, paths, handlers, and how each handler was resolved (`handler_path`, `handler_resolution`).
- **Authorization evidence:** Recognized mechanisms, symbols, source locations, handlers, and evidence strength where available.
- **Peer groups:** Structurally comparable routes used for analysis.
- **Invariants:** Authorization patterns inferred from those groups.
- **Potential drift findings:** Routes that deviate from a supported inferred pattern, together with available supporting evidence.

### Example Scenario

Consider an application with several administrative endpoints:

| Route | Recognized authorization evidence |
|---|---|
| `GET /api/admin/users` | Present |
| `GET /api/admin/orders` | Present |
| `GET /api/admin/reports` | Present |
| `GET /api/admin/payments` | Not recognized |

If the routes are considered comparable and the evidence supports a consistent authorization invariant, ARCHER may flag `GET /api/admin/payments` as a potential authorization-drift candidate.

This does **not** automatically establish that the endpoint is exploitable. Authorization may be enforced through mechanisms that ARCHER does not recognize, including custom abstractions or protections outside the analyzed source.

## Implementation Details

### Current implementation

The analyzer (`src/analyzer.rs`):
- walks a Rust repository and parses every `.rs` file with `syn`; unparsable files are reported in `parse_errors` and skipped;
- indexes every free function in the repository by crate and module path before extracting routes;
- extracts `.route(...)` / `.resource(...)` registrations and `#[get]`/`#[post]`/... attribute routes, with nested `web::scope(...)` and `.service(...)` prefixes;
- resolves each route's `.to(...)` handler to a single definition (see below) and attaches that definition's authorization evidence;
- records typed evidence (role, permission, ownership, guard, middleware, manual check, identity) with file, line, handler, and strength; identity extraction alone is not authorization;
- groups structurally comparable routes (same scope prefix, method, segment count, and dynamic-segment shape), infers an invariant per group, and reports unauthorized routes in groups with at least two authorized peers.

### Handler resolution

Each route reports `handler_path` (the path as written) and `handler_resolution`, a tagged `kind`:

| Kind | Meaning | Evidence attached |
|---|---|---|
| `Definition` | Attribute route; the annotated function itself | yes |
| `Local` | Defined in the registering module, or a function declared in an enclosing block | yes |
| `Imported` | Explicit, renamed, grouped, or `self` `use` import, including re-exports | yes |
| `GlobImported` | Exactly one matching glob import | yes |
| `Qualified` | `handlers::x`, `crate::`, `self::`, `super::`, or an imported module alias | yes |
| `UniqueName` | Path rules found nothing; exactly one compatible definition exists in the crate | yes |
| `Ambiguous` | Several definitions match; `candidates` lists their Rust paths | no |
| `Unresolved` | No single definition could be identified | no |

Resolution follows Rust's order: local definitions, then explicit imports, then globs. Files map to modules by Cargo layout (`main.rs`/`lib.rs` = crate root, `foo.rs` or `foo/mod.rs` = `foo`, inline `mod`). Files outside `src/` and under `src/bin/` are isolated namespaces.

Bare names are first resolved lexically, innermost scope first:
- functions declared in an enclosing block are visible throughout that block, including before their declaration, and stay out of the repository index, so sibling functions never share them;
- `let` bindings (after their statement), function and closure parameters, `for`/`match`/`if let`/`while let` patterns, and block `const`/`static` items shadow handler names;
- a shadowed name, a duplicate block function, or a name hidden inside a function-local `mod` is `Unresolved`.

### Authorization evidence heuristics

Evidence comes from the resolved handler's body, from the route's own `.guard(...)` arguments, and from the `.guard(...)` and `.wrap(...)` calls of its scope and every enclosing scope. A scope's middleware applies to all of that scope's routes and nested scopes wherever the call appears in its builder chain, and never to sibling scopes or to a sibling route's own guards. All of it is kept: guard or middleware evidence never replaces handler evidence. Route paths and handler names are never evidence.

- **Helper calls and method calls** are classified by their snake_case words. Exact names such as `require_admin`, `has_role`, `is_admin`, `check_permission`, `authorize`, and `owns` count, as do `require_`/`check_`/`verify_`/`assert_`/`ensure_` names whose words include a role (`admin`, `manager`, `role`), permission, owner, or a final `access` (`verify_resource_access`), and `authorize_*` names.
- Names ending in a data, lookup, or logging word are not checks: `ensure_admin_exists`, `check_admin_token`, `role_name`, `permissions_list`, `check_access_log`. Token validation, user lookups, and OAuth state checks (`verify_access_token`, `check_username`, `ensure_user_exists`, `verify_oauth_state`) are not authorization.
- Authentication helpers (`require_auth`, `is_authenticated`, `require_authenticated_user`) and identity values (`Claims`, `Identity`) are recorded as weak identity evidence, which never makes a route authorized.
- **Guard and middleware types** need an authorization word (`admin`, `role`, `permission`, `authorization`, `acl`, `rbac`) and a guard-like word (`Guard`, `Middleware`, `Filter`, `Require`, `Check`, `Only`, ...): `AdminGuard`, `RequireAdmin`, `AdminAuthMiddleware`. Authentication-only types (`AuthMiddleware`, `AuthGuard`, `JwtGuard`, `HttpAuthentication`) are identity evidence. Error-mapping and logging types (`UnauthorizedHandler`, `AuthorizationErrorMiddleware`, `RoleLogger`) and unrelated types such as `PermissionsPolicy` are ignored. Guard functions such as `guard::fn_guard(check_admin)` use the helper-name rules.

### Conservative cases

ARCHER never merges evidence from same-named functions and never guesses:
- several candidates (through globs, duplicates, or the fallback) produce `Ambiguous` with no evidence;
- `UniqueName` is used only when no path rule matched, never after an ambiguity, an explicit import that leaves the crate, or a qualifier that is not a module of this crate; a written qualifier must prefix the candidate's module;
- absolute (`::x`) and other-crate paths, `impl` methods (`Type::method`), closures, and shadowed names are `Unresolved`;
- evidence inside functions, `impl` methods, or `trait` methods declared within a handler body belongs to them, not to the enclosing handler.

## Testing

Run the test suite:

```bash
cargo test --locked
```

Build the optimized executable:

```bash
cargo build --locked --release
```

For reproducible evaluation, run ARCHER against controlled fixtures with known authorization patterns and compare its findings with the expected results.

### Validation status

- `cargo test --offline --locked`: 35 tests pass.
- A synthetic single-file integration fixture produces its expected 16 routes, 3 peer groups, and the one intended `GET /api/admin/payments` finding.
- These are controlled synthetic checks. They do not establish accuracy or generalization on real-world Actix-Web codebases. Historical benchmark figures in `docs/evaluation/` were produced by an earlier engine version and have not been rerun.

## Limitations

ARCHER is an evolving research prototype, and its results depend on the authorization patterns and Actix-Web constructs it can recognize.

- Helper recognition is a name-based heuristic; custom authorization abstractions may not be detected, and a recognized name does not prove what a helper does. Middleware whose name says only "auth" is treated as authentication, even if it also enforces permissions.
- Scope middleware is linked only through builder chains in one expression: `.wrap(...)` on an `App` or scope does not reach routes registered in another function (`App::new().wrap(X).configure(routes)`) or through a `ServiceConfig` passed elsewhere.
- Calls are not followed: a handler that calls a protected helper with an unrecognized name has no recognized evidence.
- Not modeled: `use` declarations inside function bodies, macro-generated items and bindings, `#[path]` modules, `impl`-method handlers, cross-crate workspace dependencies, Rust 2015 crate-relative paths, and attribute routes registered through `.service(handler)` inside a scope (their scope prefix is not applied).
- `main.rs` and `lib.rs` share one namespace; same-named functions in both are `Ambiguous`.
- Local closures used as handlers carry no evidence.
- Structural similarity does not guarantee that two routes should have identical authorization requirements.
- Peer groups require at least two authorized routes; there is no majority threshold, so every unauthorized route in a qualifying group is reported.
- Missing recognized evidence does not necessarily mean authorization is absent.
- Inferred invariants may produce false positives or miss genuine authorization inconsistencies.
- Findings should be validated against the application's intended access-control policy and runtime behavior.

ARCHER is intended to support security analysis and developer review, not replace comprehensive security testing or manual verification.

## Research Objective

ARCHER investigates whether repository-local authorization invariants can help detect authorization drift while reducing false positives compared with simpler route-level heuristics or manually specified rules.

Evaluation should measure detection precision, recall, false-positive rates, and behavior across diverse applications. Results on synthetic fixtures are useful for controlled validation but do not, by themselves, establish generalization to real-world repositories.

## Contributing

Contributions that improve route extraction, authorization evidence recognition, peer grouping, invariant inference, test coverage, or report quality are welcome.

When adding detection logic, include regression tests for both the intended finding and relevant negative cases.

## License

This repository does not currently include a license file, and `Cargo.toml` does not declare a license. Contact the maintainers for terms governing use and distribution.
