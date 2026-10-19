# ARCHER

ARCHER is a research prototype for detecting authorization drift in Actix-Web applications.

Findings are potential drift for developer review, not confirmed vulnerabilities. "No recognized authorization evidence" never means "confirmed absence of authorization".

## Current implementation

The analyzer (`src/analyzer.rs`):
- walks a Rust repository and parses every `.rs` file with `syn`; unparsable files are reported in `parse_errors` and skipped;
- indexes every free function in the repository by crate and module path before extracting routes;
- extracts `.route(...)` / `.resource(...)` registrations and `#[get]`/`#[post]`/... attribute routes, with nested `web::scope(...)` and `.service(...)` prefixes;
- resolves each route's `.to(...)` handler to a single definition (see below) and attaches that definition's authorization evidence;
- records typed evidence (role, permission, ownership, guard, middleware, manual check, identity) with file, line, handler, and strength; identity extraction alone is not authorization;
- groups structurally comparable routes (same scope prefix, method, segment count, and dynamic-segment shape), infers an invariant per group, and reports unauthorized routes in groups with at least two authorized peers.

## Handler resolution

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

### Conservative cases

ARCHER never merges evidence from same-named functions and never guesses:
- several candidates (through globs, duplicates, or the fallback) produce `Ambiguous` with no evidence;
- `UniqueName` is used only when no path rule matched, never after an ambiguity, an explicit import that leaves the crate, or a qualifier that is not a module of this crate; a written qualifier must prefix the candidate's module;
- absolute (`::x`) and other-crate paths, `impl` methods (`Type::method`), closures, and shadowed names are `Unresolved`;
- evidence inside functions, `impl` methods, or `trait` methods declared within a handler body belongs to them, not to the enclosing handler.

### Limitations

- Helper recognition is a name-based heuristic; it does not prove what a helper does.
- Calls are not followed: a handler that calls a protected helper with an unrecognized name has no recognized evidence.
- Not modeled: `use` declarations inside function bodies, macro-generated items and bindings, `#[path]` modules, `impl`-method handlers, cross-crate workspace dependencies, Rust 2015 crate-relative paths, scope-level `.wrap(...)` applied after routes or inherited from parent scopes, and attribute routes registered through `.service(handler)` inside a scope (their scope prefix is not applied).
- `main.rs` and `lib.rs` share one namespace; same-named functions in both are `Ambiguous`.
- Local closures used as handlers carry no evidence.
- Peer groups require at least two authorized routes; there is no majority threshold, so every unauthorized route in a qualifying group is reported.

## Run

```bash
cargo run -- tests/fixtures
cargo run -- --json tests/fixtures
```

The bundled fixture yields five `/admin/*` routes and one potential drift finding for `GET /admin/payments`, supported by guard, middleware, and `require_admin` evidence on three GET peers; `POST /admin/audit` is not a peer.

## Validation status

- `cargo test --offline --locked`: 35 tests pass.
- A synthetic single-file integration fixture produces its expected 16 routes, 3 peer groups, and the one intended `GET /api/admin/payments` finding.
- These are controlled synthetic checks. They do not establish accuracy or generalization on real-world Actix-Web codebases. Historical benchmark figures in `docs/evaluation/` were produced by an earlier engine version and have not been rerun.

## Research direction

```text
Rust source
  -> Actix route extraction
  -> authorization evidence
  -> peer groups
  -> repository-local invariant inference
  -> drift detection
  -> evidence-backed finding
```
