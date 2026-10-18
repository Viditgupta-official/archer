# ARCHER

**Authorization Drift Detection for Actix-Web Applications**

ARCHER is a Rust-based static analysis research prototype that identifies **potential authorization drift** in Actix-Web applications. It analyzes route definitions and recognized authorization evidence, compares structurally related routes, and reports deviations from authorization patterns observed elsewhere in the repository.

The goal is to help developers identify endpoints that may have inconsistent authorization protections without relying exclusively on manually written security rules.

> **Research prototype:** ARCHER produces evidence-backed potential findings, not confirmed vulnerability verdicts. Results require developer review.

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

1. **Route extraction:** Scans Rust source files and extracts recognized Actix-Web route definitions, HTTP methods, paths, and source locations.
2. **Authorization evidence analysis:** Looks for recognized authorization-related evidence in route configurations, middleware or guards, and handler code.
3. **Structural peer grouping:** Groups comparable routes so authorization patterns can be evaluated in context.
4. **Invariant inference:** Identifies authorization patterns consistently present among comparable routes.
5. **Drift detection:** Flags routes that deviate from an inferred authorization pattern when sufficient supporting evidence exists.
6. **Evidence reporting:** Presents suspicious routes alongside supporting peer routes and the inferred invariant.

## Key Features

- Static analysis of Rust and Actix-Web source code.
- Route extraction with nested scope-prefix handling.
- HTTP method and route-path tracking.
- Recognition of authorization-related evidence.
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

To analyze a local test fixture:

```bash
cargo run --locked -- tests/fixtures
```

### Generate JSON Output

ARCHER supports JSON output for integration with other tools and applications:

```bash
cargo run --locked -- /path/to/actix-web-project --json
```

The JSON report can be consumed by a backend or other programmatic workflow.

## Understanding the Results

A report includes information such as:

- **Files scanned:** Number of Rust source files processed.
- **Parse errors:** Source files that could not be parsed successfully.
- **Routes:** Extracted route candidates, including HTTP methods and paths.
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

## Limitations

ARCHER is an evolving research prototype, and its results depend on the authorization patterns and Actix-Web constructs it can recognize.

- Custom authorization abstractions may not be detected.
- Structural similarity does not guarantee that two routes should have identical authorization requirements.
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

See the repository's license information for the terms governing use and distribution.
