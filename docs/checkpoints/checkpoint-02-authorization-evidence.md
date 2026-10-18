# Checkpoint 02: Authorization Evidence

## Objective
Move ARCHER from simple route-level authorization detection toward structured, source-backed authorization evidence.

## Authorization Evidence
The analysis recognizes authorization-related evidence from several parts of an Actix-Web application:

- Handler-level authorization calls
- Authorization guards
- Authorization middleware
- Role- and permission-related mechanisms
- Identity extraction as a distinct evidence category

Identity extraction is not automatically equivalent to authorization. Obtaining a user's identity does not by itself establish that a route checks permissions or enforces an access policy.

## Evidence Fields
Evidence is represented with source and mechanism context, including fields such as:

- `kind`
- `mechanism`
- `symbol`
- `file`
- `line`
- `handler`
- `strength`

These fields support tracing a route's authorization classification back to source rather than presenting an unexplained label.

## Route Analysis Improvements
The route-analysis work includes:

- AST-based Actix scope-prefix tracking, including nested scopes
- More precise route source locations
- Support for Actix attribute routes
- Deterministic file traversal
- Handling malformed Rust files without aborting analysis of the remaining files
- Preservation of route extraction, peer analysis, and finding functionality as these improvements were introduced

## Peer-Group Improvements
Peer grouping was refined to use structural signals rather than relying only on a broad path prefix. Relevant signals include scope, HTTP method, route structure, path-segment structure, and dynamic parameters. Handler or surrounding context can add information where appropriate.

An important false-positive lesson is that routes such as `login`, `register`, and `logout` must not automatically become one authorization peer group merely because they share `/api`. Their shared mount prefix is not enough to establish that they have the same authorization invariant.

## Evidence-Backed Finding Format
A useful finding communicates the chain of evidence:

```text
Suspicious route
    -> inferred invariant
    -> peer routes
    -> peer authorization evidence
    -> suspicious-route evidence
    -> source locations
```

This frames the result as potential authorization drift for developer review, not as a confirmed vulnerability.

## Outcome
ARCHER evolved from a basic route scanner into an evidence-oriented authorization-drift analyzer. Findings can be interpreted in the context of route structure, peer behavior, and source-backed authorization evidence.

## Next Step
Evaluate the peer and invariant rules against controlled cases, including intentional public routes and parameterized route patterns, and document where the current thresholds limit recall.
