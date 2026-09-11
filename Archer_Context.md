# ARCHER — Project Context

## 1. What is ARCHER?

ARCHER is a framework-specific developer tool for detecting
authorization drift in Rust/Actix-Web applications.

The goal is NOT to build a generic vulnerability scanner.

ARCHER focuses specifically on cases where a route deviates from
the authorization pattern established by comparable routes in the
same repository.

---

## 2. The Problem

Authorization in Actix-Web applications can be expressed through
different mechanisms such as:

- route guards
- middleware
- role extraction
- permission checks
- authorization logic in handlers

A repository may develop an implicit authorization convention.

For example:

    GET /admin/users    -> ADMIN
    GET /admin/orders   -> ADMIN
    GET /admin/reports  -> ADMIN

A developer may later add:

    GET /admin/payments -> NO AUTHORIZATION

The application may still compile and run correctly, but the new
route has deviated from the authorization convention established
by its peers.

This is the type of authorization drift ARCHER aims to detect.

---

## 3. Core Research Question

Can repository-local authorization invariants detect
authorization drift while reducing false positives compared
with simple or manually specified rules?

---

## 4. Core ARCHER Pipeline

ARCHER should conceptually implement:

    Rust source
        ↓
    Route / Handler Extraction
        ↓
    Authorization Evidence Extraction
        ↓
    Peer Group Formation
        ↓
    Repository-Local Invariant Inference
        ↓
    Authorization Drift Detection
        ↓
    Evidence-Backed Finding
        ↓
    Developer Review

---

## 5. What ARCHER IS NOT

ARCHER is NOT:

- a generic Rust vulnerability scanner
- an AI-powered vulnerability detector
- a system that automatically declares vulnerabilities
- a replacement for CodeQL or Semgrep
- a system that assumes every route needs authorization

LLMs may optionally be used later for explanations, but an LLM
must NOT make the core detection decision.

The detector should be deterministic and reproducible.

---

## 6. Initial Scope

For the first implementation, support only a defined subset of
Actix-Web.

Initial constructs of interest:

- routes
- handlers
- scopes
- services
- guards
- middleware
- role extraction
- permission checks

Do NOT attempt to support every possible Rust or Actix-Web
programming pattern initially.

Prefer a small, well-tested subset that can be expanded later.

---

## 7. Route Representation

ARCHER should eventually represent a route approximately as:

    Route {
        method
        full_path
        scope
        handler
        authorization_evidence
        source_location
    }

This representation should preserve enough information for
later peer grouping, invariant inference and evidence reporting.

---

## 8. Authorization Evidence

Authorization evidence should eventually be structured rather
than determined by simple string searches.

Possible evidence categories include:

- Guard
- Middleware
- Role
- Permission
- Handler-level authorization check

Every piece of evidence should ideally have a source location.

Example:

    Route:
        GET /admin/users

    Authorization:
        permission = "admin.read"

    Location:
        src/auth.rs:31

---

## 9. Peer Groups

ARCHER should group structurally comparable routes.

Possible features for determining similarity:

- scope
- HTTP method
- path structure
- resource structure
- handler structure
- authorization context

Do NOT simply assume that routes sharing a path prefix are
always peers.

Peer grouping is a research/design problem and should be
implemented conservatively.

---

## 10. Invariant Inference

For a peer group such as:

    /admin/users     -> ADMIN
    /admin/orders    -> ADMIN
    /admin/reports   -> ADMIN
    /admin/payments  -> NONE

ARCHER should infer that ADMIN is the dominant authorization
pattern and identify /admin/payments as a possible deviation.

The exact threshold for considering a pattern an invariant must
be evaluated experimentally.

Do NOT hard-code the assumption that one deviation is always
a vulnerability.

---

## 11. Findings

ARCHER should report evidence rather than simply saying:

    "Vulnerability detected"

A useful finding should contain:

    Potential Authorization Drift

    Suspicious route:
        GET /admin/payments

    Inferred invariant:
        ADMIN

    Peer evidence:
        GET /admin/users     -> ADMIN
        GET /admin/orders    -> ADMIN
        GET /admin/reports   -> ADMIN

    Source locations:
        ...

The developer makes the final security decision.

---

## 12. Current Implementation Status

This is an EARLY PROTOTYPE.

Currently implemented:

- Rust CLI
- recursive `.rs` file discovery
- Rust AST parsing using `syn`
- basic Actix route candidate extraction
- basic prototype authorization classification
- basic prototype drift detection

Current implementation is intentionally incomplete.

DO NOT treat the current implementation as the final ARCHER
architecture.

---

## 13. Immediate Development Goal

The immediate goal is to create a reliable end-to-end prototype.

Priority order:

1. Correct Actix-Web route extraction
2. Scope-aware route paths
3. Handler extraction
4. Structured authorization evidence extraction
5. Peer grouping
6. Basic invariant inference
7. Drift detection
8. Evidence-backed findings
9. Tests and controlled fixtures
10. CLI polish

Do not build the hosted UI yet.

Do not add LLM-based detection.

Do not prematurely optimize.

---

## 14. Current Known Prototype Problem

The current prototype incorrectly loses Actix scope information.

For:

    web::scope("/admin")
        .route("/users", ...)
        .route("/orders", ...)

it currently reports:

    /users
    /orders

but should report:

    /admin/users
    /admin/orders

The authorization classifier also currently searches too broadly
and can incorrectly mark every route as authorized if authorization
keywords exist elsewhere in the file.

These are known prototype limitations that should be fixed.

---

## 15. Engineering Principles

When modifying ARCHER:

1. Read the existing implementation before changing it.
2. Prefer small, testable changes.
3. Do not rewrite unrelated code.
4. Run `cargo fmt` after Rust changes.
5. Run `cargo check`.
6. Run the relevant tests.
7. Add regression tests for bugs that are fixed.
8. Explain architectural changes before making large changes.
9. Keep detection deterministic.
10. Preserve source locations wherever possible.
11. Avoid regex/string-search approaches when structured AST
    information can be used instead.
12. Do not silently expand the project scope.

---

## 16. Definition of Success for the First Demo

Given a small Actix-Web fixture:

    /admin/users       -> ADMIN
    /admin/orders      -> ADMIN
    /admin/reports     -> ADMIN
    /admin/payments    -> NONE

ARCHER should eventually produce a finding similar to:

    Potential Authorization Drift

    Route:
        GET /admin/payments

    Expected pattern:
        ADMIN

    Supporting peers:
        /admin/users
        /admin/orders
        /admin/reports

The finding must explain WHY the route was considered suspicious.

---

## 17. Development Style

This is a university research project.

Prioritize:

- correctness
- explainability
- reproducibility
- testability
- clear architecture

over:

- flashy UI
- unnecessary abstraction
- premature optimization
- AI-generated complexity

Every major implementation decision should be explainable
to a project supervisor.