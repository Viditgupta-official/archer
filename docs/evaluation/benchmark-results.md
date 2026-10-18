# ARCHER Controlled Benchmark Results

## Evaluation Objective
Evaluate ARCHER's repository-local authorization-drift analysis against a controlled Actix-Web dataset with explicit ground truth.

## Dataset Description
The dataset contains 20 small, independent Actix-Web repositories and 73 routes. Scenarios include protected and intentionally public routes, authentication endpoints, nested scopes, varied authorization styles, parameterized routes, HTTP-method separation, and controlled authorization drift.

## Ground-Truth Methodology
Each repository includes `expected.json`, which identifies `clean` or `drift` ground truth and lists expected drift routes. Expected behavior was established before running ARCHER. Evaluation matches HTTP method and normalized path. The benchmark measures agreement with its specified ground truth; a finding is not a confirmed vulnerability.

## Metrics
Precision = TP / (TP + FP). Recall = TP / (TP + FN). F1 is the harmonic mean of precision and recall. False positives per 1,000 routes = FP / routes x 1,000.

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

## False-Negative Analysis
The one false negative was `18_parameter_drift` — `GET /admin/payments/{id}`. ARCHER extracted the route as unauthenticated but did not report it because the corresponding method-and-route-shape peer group contained only one protected route, below the current two-authorized-peer threshold. This is a peer-grouping / invariant-inference limitation.

## Interpretation
The benchmark demonstrates strong initial precision and no false positives across the controlled dataset. Recall is limited by the missed parameterized-route case.

> On the initial controlled benchmark of 20 Actix-Web repositories containing 73 routes, ARCHER achieved 100% precision, 83.33% recall, and 90.91% F1, with zero false positives. One known drift case was missed because the relevant peer group contained only one authorized peer, exposing a limitation in the current invariant-inference threshold.

This result does not establish superiority over Semgrep, CodeQL, or another tool. Findings are evidence-backed potential drift intended for developer review, not confirmed security vulnerabilities.

## Limitations
The evaluation covers a small, purpose-built controlled benchmark. It does not establish performance on the full variety of production Actix-Web code or authorization idioms. The current invariant threshold also misses the tested case when only one protected peer of matching shape is available.

## Next Experiment
Investigate whether stronger structural evidence can support single-peer inference without sacrificing the current zero-false-positive behavior. Rerun the same 20 repositories after any change and compare precision, recall, F1, and false positives.
