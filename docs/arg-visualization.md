# Authorization Relationship Graph integration

Every successful analysis builds a new ARG from that job's analyzer-derived routes, resolved handlers and evidence. No sample DOT, SVG, JSON or PNG is loaded at runtime. The graph is available as `result.report.graph` and through `GET /api/v1/analyses/{id}/arg` after the job succeeds.

The ARG endpoint returns **Graphviz DOT**, `Content-Type: text/vnd.graphviz; charset=utf-8`, with attachment disposition, `nosniff`, a restrictive CSP and a `Link` header to its JSON result. It does not return SVG. There is no `/arg.svg`, hosted image, or server-side Graphviz rendering endpoint.

## Graph data

`report.graph.nodes` contains `id`, `label`, `kind`, and optional `file`/`line`. `report.graph.edges` contains `from`, `to`, `relation`. IDs are opaque; use them to join endpoints, not to infer meaning or expose raw DOM IDs. Privacy projection can replace source-derived labels/IDs with per-report opaque strings; topology and controlled node/relation categories are retained. If readable native labels are needed for trusted repositories, the operator may explicitly select `ARCHER_EVIDENCE_TEXT=include` after reviewing the source-text disclosure risk; the browser cannot opt in per request.

Node kinds include `Scope`, `Route`, `Handler`, `Guard`, `Middleware`, `AuthorizationCheck`, `IdentityExtraction`, `InvariantContract`, `Finding`, and `UnresolvedCheck`. Relations include `RoutesTo`, `BelongsToScope`, `EnforcesCheck`, `PotentialEvidence`, `UnresolvedEvidence`, `ExtractsIdentity`, `GuardedBy`, `WrappedBy`, `ImplementsContract`, `ViolatesContract`, and `FlagsRoute`.

Keep potential/unresolved evidence visibly distinct from observed enforcement. Merely extracting identity is not authorization. Contract/finding nodes occur only where the analyzer emits the corresponding supported finding relationships; the current ARG does not draw every peer group or every inferred invariant. Do not synthesize unsupported finding nodes to make a clean graph appear more interesting.

## View Graph flow

1. Submit a source and retain the returned job ID/URLs.
2. Poll `status_url` until `succeeded`; handle `failed`, `timed_out` and expiry.
3. Fetch `result_url`. Use `report.graph` directly, or fetch the returned `arg_url` for DOT through the trusted backend gateway.
4. Render that job's data when View Graph is selected. Cache by analysis ID only for its retention period. Do not fall back silently to a saved SeaORM image.

Preferred safe integration: render the JSON graph using the teammate's client graph component. Pass labels as text, use a controlled mapping from `kind`/`relation` to style, and disable HTML labels, arbitrary URLs, images and event attributes. Treat route paths and all evidence text as untrusted source content. Do not use raw `innerHTML` for labels.

If DOT rendering is chosen, use a bounded client-side/WASM renderer in an isolated worker. Do not send confidential graph data to a third-party rendering service. Limit graph size and rendering time. Do not insert returned SVG directly into the application DOM: sanitize SVG with a maintained allowlist, remove active content, external references/links/images and event attributes, and display through a sandboxed isolated frame or inert image. Keep network access disabled for rendering. DOT escaping by the backend does not make arbitrary renderer output trusted HTML.

Graphviz may be installed on a development machine to run the provided tests. It is not installed or invoked by the Rust HTTP backend. The test verifies node/edge topology against JSON and demonstrates rendering compatibility without implementing frontend code.
