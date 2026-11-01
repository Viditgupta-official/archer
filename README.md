# ARCHER

**Repository-Aware Authorization Consistency & Drift Detection Framework**

ARCHER is a deterministic, AST-based static analysis security framework designed to detect **authorization drift** in web applications (starting with Rust and Actix-Web). Rather than relying exclusively on hand-written static rules or treating endpoints in isolation, ARCHER infers **repository-local authorization contracts** across structurally and contextually related routes and flags deviations with complete source provenance.

> **Security Research Tool:** ARCHER solves the "Oracle Problem" of authorization testing: it derives authorization invariants directly from peer consensus within the repository, categorizing drift into first-class security taxonomies (e.g. Missing Enforcement, Authentication-Only without Authorization, Insecure Direct Object Reference / Missing Ownership Validation, and Inconsistent Roles).

---

## The Core Philosophy: Authorization Drift

In modern web development, authorization is fractured across disparate architectural layers:
- Route-level guards (`.guard(AdminGuard)`)
- Scope middleware (`.wrap(AuthorizationMiddleware)`)
- Handler-level role enforcement (`require_admin(&user)`)
- Resource ownership validation (`is_owner(doc_id)`)
- Extractors and session attributes (`AuthenticatedUser`, `Claims`)

When a developer introduces a new route or modifies an existing handler, the application typically compiles cleanly and passes unit tests, yet violates implicit repository access-control invariants:

```text
GET /api/v1/admin/users       -> Guarded (AdminGuard)
GET /api/v1/admin/reports     -> Checked (require_admin)
GET /api/v1/admin/audit_logs  -> Wrapped (AuthorizationMiddleware)
GET /api/v1/admin/analytics   -> NO AUTHORIZATION (Authorization Drift!)
```

ARCHER detects these discrepancies automatically without requiring developers to manually write a custom query for every endpoint.

---

## Key Capabilities & Technical Highlights

1. **Three-State Route Security Model:**
   - `Protected`: Route has verified authorization evidence.
   - `Unprotected`: Route handler is resolved and verified to lack authorization.
   - `Unknown`: Security posture is indeterminate (unresolved external handler, ambiguous symbols, or opaque macro boundaries). *Unknown routes are never falsely reported as unprotected vulnerabilities.*

2. **First-Class Drift Taxonomy:**
   - `MissingEnforcement`: Peer routes enforce protection, but target route contains none.
   - `AuthenticationOnlyWithoutAuthorization`: Route extracts identity (`Claims`, `AuthenticatedUser`) but never validates permissions or roles (CWE-285 / CWE-862).
   - `MissingOwnershipValidation`: Parameterized resource route (`/{id}`) omits ownership verification where peers enforce it (IDOR / CWE-639).
   - `InconsistentRoleOrPermission`: Route role policy deviates from consensus peer role.
   - `InconsistentMechanism`: Architectural guard/middleware convention bypassed in favor of ad-hoc handler checks.

3. **Authorization Relationship Graph (ARG):**
   - Explicit graph representation connecting `Scope -> Route -> Handler -> Guard/Middleware -> Check -> InvariantContract -> Finding`.
   - Exportable to Graphviz DOT format (`--graph`) for visual security architecture analysis.

4. **Change-Aware Authorization Drift (`--diff`):**
   - Integrates with Git to analyze commits, pull requests, or working tree modifications (`--diff [git-ref]`).
   - Distinguishes newly introduced drift and authorization regressions from pre-existing repository debt.

5. **Deep Route Explainability (`--explain`):**
   - Detailed terminal breakdown (`--explain <path>`) presenting exact handler resolution, security status, peer consensus ratio, source provenance, and actionable remediation instructions.

6. **Operational Endpoint Discrimination:**
   - Built-in recognition of public operational endpoints (`/health`, `/metrics`, `/status`, `/ping`, `/docs`, `/swagger`) preventing false positives in administrative or API scopes.

---

## Competitor & Research Comparison

| Capability | Semgrep | CodeQL | ACMiner (USENIX/MobiSys '17) | RoleCast (USENIX Sec '11) | ARCHER |
|---|---|---|---|---|---|
| **Analysis Type** | AST Pattern Matching | Relational AST / Taint Datalog | Association Rule Mining | Context Variable Clustering | AST Peer Consensus & Contract Inference |
| **Framework Awareness** | Syntactic / Generic | Extensible Libraries | Android IPC Middleware | Web Scripts (PHP/JSP) | Actix-Web / Framework IR |
| **Needs Explicit Policy Rule?** | **Yes** (manual YAML rule) | **Yes** (bespoke QL query) | No (statistical mining) | No (data-sink clustering) | **No** (inferred from repository peers) |
| **Solves Oracle Problem?** | No | No | Partial (statistical IPC) | Partial (DB write sinks) | **Yes** (Structural & resource peer consensus) |
| **Three-State Model** | Binary match | Binary predicate | Threshold confidence | Threshold confidence | **Yes** (`Protected` / `Unprotected` / `Unknown`) |
| **IDOR / Ownership Drift** | Complex custom rule | Taint path required | Not supported | Sensitive sink only | **Yes** (Parameterized resource consensus) |
| **Graph Representation** | No | AST/CFG/PDG | IPC dependency graph | Calling context graph | **Authorization Relationship Graph (ARG)** |
| **Change-Aware Diff Mode** | PR rule diff | Commit comparison | Batch re-analysis | Batch re-analysis | **Yes** (`--diff` contract impact analysis) |

---

## Technology Stack

| Component | Technology | Role |
|---|---|---|
| Language | **Rust** (2024 edition) | High-performance, memory-safe static analysis engine |
| AST Engine | **`syn`** (v3.0) | High-fidelity Rust AST parsing, token streams, and visitor traversal |
| Code Generation | **`quote`** / **`proc-macro2`** | AST symbol re-construction and span location tracking |
| CLI Parser | **`clap`** (v4.6) | Command-line interface with subcommands and flags |
| Serialization | **`serde`** / **`serde_json`** | Typed JSON report serialization |
| File Traversal | **`walkdir`** (v2.5) | Fast, deterministic repository filesystem scanning |

---

## Installation & Build

Ensure you have a recent Rust toolchain installed:

```bash
# Clone the repository
git clone https://github.com/Viditgupta-official/archer.git
cd archer

# Build release binary
cargo build --release --locked
```

The compiled binary will be available at `./target/release/archer`.

---

## Usage Guide

### 1. Standard Repository Scan
```bash
cargo run --release -- /path/to/actix-web-repo
```

### 2. Structured JSON Output
```bash
cargo run --release -- /path/to/actix-web-repo --json
```

### 3. Generate Authorization Relationship Graph (DOT Format)
```bash
cargo run --release -- /path/to/actix-web-repo --graph > auth_graph.dot
# Render with Graphviz
dot -Tpng auth_graph.dot -o auth_graph.png
```

### 4. Change-Aware Drift Detection (Git Diff Mode)
```bash
# Compare current changes against HEAD~1 or a specific branch
cargo run --release -- /path/to/actix-web-repo --diff HEAD~1
```

### 5. Explain Route Authorization Contract
```bash
cargo run --release -- /path/to/actix-web-repo --explain /api/v1/admin/analytics
```

---

## End-to-End Demonstration

A complete representative Actix-Web application is provided in `./demo`:

```rust
// Administrative scope: 3 peers protected, 1 unprotected drift, 1 operational public
cfg.service(
    web::scope("/api/v1/admin")
        .route("/users", web::get().to(admin_get_users))                           // require_admin()
        .route("/reports", web::get().guard(AdminGuard).to(admin_get_reports))      // AdminGuard
        .route("/audit_logs", web::get().wrap(AuthorizationMiddleware).to(admin_get_audit_logs)) // Middleware
        .route("/analytics", web::get().to(admin_get_analytics))                   // ⚠️ DRIFT: MissingEnforcement
        .route("/status", web::get().to(admin_get_status))                         // ✓ Operational Public (/status)
);

// Parameterized documents scope: 2 peers enforce ownership, 1 omits ownership
cfg.service(
    web::scope("/api/v1/documents")
        .route("/{id}", web::get().to(get_document_by_id))        // is_owner()
        .route("/{id}", web::delete().to(delete_document_by_id))  // verify_ownership()
        .route("/{id}", web::put().to(update_document_by_id))     // ⚠️ DRIFT: MissingOwnershipValidation (IDOR)
);
```

Running ARCHER against `demo`:
```bash
cargo run -- demo
```
Yields:
```text
============================================================
ARCHER Authorization Analysis Report
============================================================
Repository Scanned : demo
Rust Files Scanned : 1
Route Inventory    : 10 routes (6 Protected, 4 Unprotected, 0 Unknown)
Analysis Layers    : 3 Peer Groups, 3 Inferred Invariants
------------------------------------------------------------
...
============================================================
Potential Authorization Drift Findings (2):
============================================================

[1] MissingEnforcement (Confidence: High)
  Suspicious Route : GET /api/v1/admin/analytics (demo\src\main.rs:94)
  Inferred Contract: Peer routes under /api/v1/admin consistently contain authorization evidence.
  Explanation      : Route in scope '/api/v1/admin' lacks recognized authorization protection while 3 peer routes consistently enforce authorization.
  Remediation      : Apply the inferred authorization invariant to this route via a guard, middleware, or handler check.
  Peer Consensus   : 3/4 authorized peers in group 'peer-group-001'

[2] MissingOwnershipValidation (Confidence: Medium)
  Suspicious Route : PUT /api/v1/documents/{id} (demo\src\main.rs:103)
  Inferred Contract: Peer routes under /api/v1/documents consistently contain authorization evidence.
  Explanation      : Peer parameterized resource routes enforce resource ownership validation, but this route does not validate that the authenticated entity owns the requested resource (IDOR risk).
  Remediation      : Add ownership verification logic (e.g. `check_ownership(user_id, resource_id)`) before serving sensitive resource data.
  Peer Consensus   : 2/3 authorized peers in group 'peer-group-002'
```

---

## Test Suite & Validation

The test suite contains **55 unit and regression tests** covering:
- Lexical scoping and handler resolution across files and modules
- Guard and middleware builder chain inheritance
- Macro-based authorization evidence and non-check keyword filtering
- Three-state security classification (`Protected`, `Unprotected`, `Unknown`)
- Drift categorization (Authentication-only, Missing ownership, Role mismatch)
- Operational endpoint exclusion (`/health`, `/metrics`, `/status`)
- Parameterized route scope fallback
- Authorization Relationship Graph generation and DOT serialization

Execute the test suite:
```bash
cargo test
```
All 55 tests pass deterministically.

---

## Known Scope & Future Framework Architecture

ARCHER is engineered around a clean abstraction decoupling framework-specific frontends from the authorization reasoning core:
```text
Framework Frontends (Actix-Web, Axum, FastAPI, Express)
                   │
                   ▼
       Universal Route & Auth IR (URAIR)
                   │
                   ▼
  ARCHER Core (Peer Clustering & Invariant Engine)
                   │
                   ▼
   ARG & Change-Aware Regression Analyzer
                   │
                   ▼
         Multi-Format Reporting
```

Current limitations:
- Trait/impl method handlers with dynamic dispatch are categorized as `Unknown`.
- Inter-procedural helper call-depth beyond direct invocations requires whole-program call-graph construction.
- Macros with unrecognized identifiers are not expanded.

---

## Authors & Maintenance

ARCHER is developed as an academic security research prototype for authorization consistency verification.
Maintainer: Vidit Gupta (`viditgupta.official@gmail.com`).
