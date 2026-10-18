# Checkpoint 01: Initial Prototype

## Objective
Build the first working Actix-Web authorization-drift analysis prototype.

## Initial Capabilities
The initial milestone established an end-to-end command-line analyzer with:

- Recursive Rust repository scanning
- Rust source parsing using `syn` and `proc-macro2`
- Actix route extraction
- HTTP method and path extraction
- Handler identification
- Basic authorization evidence detection
- Initial peer grouping
- Initial drift detection
- CLI-based analysis

## Initial Architecture

```text
Rust repository
    -> source parsing
    -> route extraction
    -> authorization evidence
    -> peer grouping
    -> drift detection
    -> CLI report
```

## Initial Limitation
The first prototype used overly broad authorization detection and peer grouping. Authorization evidence could be associated too broadly, and route source locations were initially imprecise. These were limitations of the prototype stage, not statements about the later analysis design.

## Outcome
The prototype established the basic end-to-end ARCHER analysis pipeline and provided the foundation for subsequent authorization-evidence extraction and peer-group improvements.

## Next Step
Improve source-backed authorization evidence, route locations, scope handling, and peer selection so that findings explain their evidence and compare more structurally similar routes.
