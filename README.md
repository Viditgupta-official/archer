# ARCHER

ARCHER is a research prototype for detecting authorization drift in Actix-Web applications.

## Current milestone

The first prototype:
- walks a Rust repository;
- parses `.rs` files with `syn`;
- extracts simple `.route(...)` / `.resource(...)` candidates;
- records HTTP method, route path and source line;
- performs a deliberately conservative prototype authorization classification;
- reports a simple peer-pattern deviation.

This is **not yet the final detector**. The next milestone replaces the prototype authorization heuristic with structured Actix-Web authorization evidence extraction.

## Run

```bash
cargo run -- tests/fixtures
```

Expected output contains the four `/admin/*` routes and a prototype drift finding.

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
