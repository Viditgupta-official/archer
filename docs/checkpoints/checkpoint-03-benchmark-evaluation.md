# Checkpoint 03: Controlled Benchmark Evaluation

## Objective
Measure ARCHER against a controlled set of Actix-Web repositories with explicit ground truth, and identify where the current peer-group and invariant-inference behavior succeeds or falls short.

## Benchmark Methodology
The controlled benchmark contains 20 small, independent Actix-Web repositories. Each repository provides an `expected.json` file declaring whether drift is expected and, for drift cases, which routes should be reported. Expected behavior was specified before ARCHER was run.

The dataset covers protected routes, intentionally public routes, authentication endpoints, nested scopes, different authorization styles, parameterized routes, HTTP-method separation, and controlled authorization drift. Route comparisons use HTTP method and normalized path. A reported finding is evaluated as a route-level result; it is not a claim that the route is a confirmed security vulnerability.

## Results

| Metric | Result |
|---|---:|
| Repositories | 20/20 |
| Routes | 73 |
| Findings | 5 |
| TP | 5 |
| FP | 0 |
| FN | 1 |
| TN | 67 |
| Precision | 100% |
| Recall | 83.33% |
| F1 | 90.91% |
| FP / 1000 routes | 0 |

## False Positives
None were observed in this controlled benchmark.

## False Negative
`18_parameter_drift` — `GET /admin/payments/{id}`.

ARCHER extracted the route as unauthenticated but did not flag it because only one protected peer had the same HTTP method and route shape. That peer count was below the detector's current two-authorized-peer threshold.

**Category:** Peer-grouping / invariant-inference limitation.

## Interpretation
The benchmark demonstrates strong initial precision and no false positives across this controlled dataset. The main limitation identified is recall: one known drift case was missed because its corresponding peer group contained only one authorized peer, while the current detector requires at least two authorized peers before inferring a sufficiently strong authorization pattern.

These results apply to the supplied controlled benchmark only. ARCHER findings are evidence-backed potential drift for developer review, not confirmed security vulnerabilities. No comparison with Semgrep, CodeQL, or another baseline was performed.

## Next Step
Investigate whether single-peer situations can be handled using stronger structural evidence without sacrificing the current zero-false-positive behavior. Evaluate any change by rerunning the same 20-repository benchmark and comparing precision, recall, F1, and false positives.
