//! Versioned API contract; no UI assets or executable macro expansion.
use serde_json::{Value, json};

fn reference(name: &str) -> Value {
    json!({"$ref":format!("#/components/schemas/{name}")})
}
fn response(name: &str) -> Value {
    json!({"description":name,"content":{"application/json":{"schema":reference(name)}}})
}
fn operation(id: &str, description: &str, success: &str, schema: &str, job: bool) -> Value {
    let mut value =
        json!({"operationId":id,"description":description,"responses":{success:response(schema)}});
    for code in [
        "400", "401", "403", "404", "405", "408", "409", "413", "415", "429", "500",
    ] {
        value["responses"][code] = response("Error");
    }
    if job {
        value["parameters"] = json!([{"name":"id","in":"path","required":true,"schema":{"type":"string","pattern":"^[a-f0-9]{32}$"}}]);
    }
    value
}

pub fn document() -> Value {
    let mut schemas = json!({
        "SourceFile":{"type":"object","additionalProperties":false,"required":["path","content"],"properties":{"path":{"type":"string","maxLength":240,"description":"Portable repository-relative Rust source, Cargo.toml or Cargo.lock. No absolute/dot/hidden paths or links."},"content":{"type":"string"}}},
        "Snapshot":{"type":"object","additionalProperties":false,"required":["type","files"],"properties":{"type":{"const":"snapshot"},"files":{"type":"array","minItems":1,"items":reference("SourceFile")}}},
        "Github":{"type":"object","additionalProperties":false,"required":["type","url","commit"],"properties":{"type":{"const":"github"},"url":{"type":"string","format":"uri","description":"HTTPS github.com/owner/repo; repository must be explicitly operator-allowlisted. Public repositories only; no credentials, ports, redirects or query."},"commit":{"type":"string","pattern":"^[a-fA-F0-9]{40}$"}}},
        "AnalysisRequest":{"type":"object","additionalProperties":false,"required":["source"],"properties":{"source":{"oneOf":[reference("Snapshot"),reference("Github")],"discriminator":{"propertyName":"type","mapping":{"snapshot":"#/components/schemas/Snapshot","github":"#/components/schemas/Github"}}}}},
        "PublicError":{"type":"object","required":["code","message"],"properties":{"code":{"type":"string"},"message":{"type":"string"}}},
        "Error":{"type":"object","required":["schema_version","error"],"properties":{"schema_version":{"const":"1.0"},"error":reference("PublicError")},"example":{"schema_version":"1.0","error":{"code":"capacity_exceeded","message":"Analysis capacity is currently full"}}},
        "JobStatus":{"type":"object","required":["schema_version","id","status","created_at","completed_at","expires_at","error","status_url","result_url","arg_url"],"properties":{"schema_version":{"const":"1.0"},"id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"status":{"enum":["queued","running","succeeded","failed","timed_out"]},"created_at":{"type":"integer","minimum":0,"description":"Unix seconds"},"completed_at":{"type":["integer","null"]},"expires_at":{"type":["integer","null"],"description":"Completed jobs expire; pending jobs have null expiry"},"error":{"oneOf":[reference("PublicError"),{"type":"null"}]},"status_url":{"type":"string"},"result_url":{"type":"string"},"arg_url":{"type":"string"}}},
        "Privacy":{"type":"object","required":["evidence_text","source_paths","raw_files_available"],"properties":{"evidence_text":{"enum":["redacted","included"]},"source_paths":{"const":"repository_relative"},"raw_files_available":{"const":false}}},
        "AnalysisResult":{"type":"object","required":["schema_version","analysis_id","engine_version","privacy","report","arg_url","llm_enabled"],"properties":{"schema_version":{"const":"1.0"},"analysis_id":{"type":"string"},"engine_version":{"type":"string"},"privacy":reference("Privacy"),"report":reference("Report"),"arg_url":{"type":"string"},"llm_enabled":{"const":false}}},
        "Health":{"type":"object","required":["schema_version","status","engine_version","capabilities","limits"],"properties":{"schema_version":{"const":"1.0"},"status":{"const":"ok"},"engine_version":{"type":"string"},"capabilities":{"type":"object","properties":{"snapshot":{"const":true},"github":{"type":"boolean"},"llm_explanations":{"const":false}},"required":["snapshot","github","llm_explanations"]},"limits":reference("Limits")}},
        "Route":{"type":"object","required":["method","path","scope_prefix","handler","file","line","authorization"],"properties":{"application":{"type":["string","null"]},"method":{"type":"string"},"path":{"type":"string"},"scope_prefix":{"type":"string"},"handler":{"type":["string","null"]},"handler_path":{"type":["string","null"]},"handler_resolution":{"type":["object","null"],"additionalProperties":true},"file":{"type":"string"},"line":{"type":"integer","minimum":0},"authorization":{"type":"array","items":reference("Evidence")}}},
        "Evidence":{"type":"object","additionalProperties":true,"description":"Native deterministic analyzer evidence. Free source-derived strings use consistent per-report opaque IDs by default. Structured identifiers and route metadata remain available; this is not raw source."},
        "PeerGroup":{"type":"object","required":["id","description","routes"],"properties":{"id":{"type":"string"},"description":{"type":"string"},"routes":{"type":"array","items":reference("RouteReference")}}},
        "RouteReference":{"type":"object","required":["method","path","handler","file","line","authorized","authorization","status"],"properties":{"method":{"type":"string"},"path":{"type":"string"},"handler":{"type":["string","null"]},"file":{"type":"string"},"line":{"type":"integer"},"authorized":{"type":"boolean"},"authorization":{"type":"array","items":reference("Evidence")},"status":{"type":"object","required":["status"],"properties":{"status":{"enum":["Protected","Unprotected","Unknown"]},"reason":{"type":"string"}}}}},
        "Invariant":{"type":"object","required":["peer_group_id","description","total_routes","routes_with_authorization","routes_without_authorization","evidence_patterns","strength"],"properties":{"peer_group_id":{"type":"string"},"description":{"type":"string"},"total_routes":{"type":"integer"},"routes_with_authorization":{"type":"integer"},"routes_without_authorization":{"type":"integer"},"evidence_patterns":{"type":"array","items":{"type":"string"}},"strength":{"type":"string"}}},
        "Finding":{"type":"object","description":"Verified deterministic drift only. Exploratory observations and informational contrasts are separate arrays.","required":["peer_group_id","invariant","suspicious_route","suspicious_route_evidence","authorized_peer_routes","category","confidence","explanation"],"properties":{"peer_group_id":{"type":"string"},"invariant":reference("Invariant"),"suspicious_route":reference("RouteReference"),"suspicious_route_evidence":{"type":"array","items":reference("Evidence")},"authorized_peer_routes":{"type":"array","items":reference("RouteReference")},"category":{"enum":["MissingEnforcement","AuthenticationOnlyWithoutAuthorization","MissingOwnershipValidation","InconsistentRoleOrPermission","InconsistentMechanism","UnresolvedSecurityPosture"]},"confidence":{"enum":["High","Medium","Low"]},"explanation":{"type":"string"}}},
        "Graph":{"type":"object","required":["nodes","edges"],"properties":{"nodes":{"type":"array","items":reference("Evidence")},"edges":{"type":"array","items":reference("Evidence")}}}
    });
    schemas["GraphNode"] = json!({"type":"object","required":["id","label","kind"],"properties":{"id":{"type":"string","description":"Graph-local presentation identity. Do not treat as a file path, URL or cross-analysis identity."},"label":{"type":"string","description":"Untrusted display text under the API privacy policy; never HTML."},"kind":{"enum":["Scope","Route","Handler","Guard","Middleware","AuthorizationCheck","IdentityExtraction","InvariantContract","Finding","UnresolvedCheck"]},"file":{"type":"string","description":"Repository-relative source location, if available"},"line":{"type":"integer","minimum":0}}});
    schemas["GraphEdge"] = json!({"type":"object","required":["from","to","relation"],"properties":{"from":{"type":"string","description":"Existing node id in the same graph"},"to":{"type":"string","description":"Existing node id in the same graph"},"relation":{"enum":["BelongsToScope","RoutesTo","GuardedBy","WrappedBy","EnforcesCheck","ExtractsIdentity","ImplementsContract","ViolatesContract","FlagsRoute","UnresolvedEvidence","PotentialEvidence"]}}});
    schemas["Graph"] = json!({"type":"object","description":"Native ARG topology under a privacy projection. Peer groups, all inferred invariants, exploratory observations and informational contrasts are not exhaustively drawn. Duplicate edges may occur; see docs/arg-visualization.md for the exact semantics.","required":["nodes","edges"],"properties":{"nodes":{"type":"array","items":reference("GraphNode")},"edges":{"type":"array","items":reference("GraphEdge")}}});
    schemas["Requirement"] = json!({"type":"object","required":["dimension","values","mechanism","enforcement","confidence","file","line","symbol","explanation"],"properties":{"dimension":{"type":"string"},"values":{"type":"array","items":{"type":"string"}},"mechanism":{"type":"string"},"enforcement":{"type":"string"},"confidence":{"type":"string"},"file":{"type":"string"},"line":{"type":"integer"},"symbol":{"type":"string"},"explanation":{"type":"string"}}});
    schemas["Relationship"] = json!({"type":"object","description":"Indices reference report.routes; contract_eligible is independent of authorization evidence.","required":["left","right","kind","evidence","conflicts","evidence_score","confidence","contract_eligible"],"properties":{"left":{"type":"integer","minimum":0},"right":{"type":"integer","minimum":0},"kind":{"type":"string"},"evidence":{"type":"array","items":{"type":"string"}},"conflicts":{"type":"array","items":{"type":"string"}},"evidence_score":{"type":"integer"},"confidence":{"type":"string"},"contract_eligible":{"type":"boolean"}}});
    schemas["Assessment"] = json!({"type":"object","required":["route","requirements","uncertainty"],"properties":{"route":reference("RouteReference"),"requirements":{"type":"array","items":reference("Requirement")},"uncertainty":{"type":"array","items":{"type":"string"}}}});
    for (name, classification, required) in [
        (
            "ReviewObservation",
            "ExploratoryReview",
            vec![
                "classification",
                "target",
                "related_routes",
                "dimension",
                "observed_difference",
                "relationship_evidence",
                "supporting_requirements",
                "target_requirements",
                "unresolved_evidence",
                "not_verified_reason",
                "verification_steps",
            ],
        ),
        (
            "CheckContrast",
            "InformationalCheckContrast",
            vec![
                "classification",
                "target",
                "related_routes",
                "target_handler_file",
                "target_handler_line",
                "target_requirements",
                "target_checks",
                "not_verified_reason",
                "observed_difference",
                "relationship_evidence",
                "supporting_checks",
                "unresolved_evidence",
                "confidence",
                "investigation",
            ],
        ),
    ] {
        let mut schema = json!({"type":"object","description":"Separate from verified drift. A comparison is not proof that a check is missing.","required":required,"properties":{}});
        for key in required {
            schema["properties"][key] = if key == "target" {
                reference("RouteReference")
            } else if key == "related_routes" {
                json!({"type":"array","items":reference("RouteReference")})
            } else if matches!(
                key,
                "supporting_requirements"
                    | "target_requirements"
                    | "target_checks"
                    | "supporting_checks"
            ) {
                json!({"type":"array","items":reference("Requirement")})
            } else if matches!(
                key,
                "unresolved_evidence" | "verification_steps" | "investigation"
            ) || (key == "relationship_evidence" && name == "CheckContrast")
            {
                json!({"type":"array","items":{"type":"string"}})
            } else if key == "target_handler_line" {
                json!({"type":"integer"})
            } else {
                json!({"type":"string"})
            };
        }
        // Classification values are native engine strings, documented rather
        // than inferred from evidence or promoted into verified categories.
        schema["description"] = json!(format!(
            "{classification}: separate from verified drift; insufficient proof for a verified finding."
        ));
        schemas[name] = schema;
    }
    let mut limits = json!({"type":"object","properties":{},"required":[]});
    for name in [
        "request_bytes",
        "source_files",
        "source_bytes",
        "file_bytes",
        "archive_bytes",
        "expanded_bytes",
        "result_bytes",
        "memory_bytes",
        "wall_ms",
    ]
    .iter()
    {
        limits["properties"][name] = json!({"type":"integer","minimum":1});
        limits["required"].as_array_mut().unwrap().push(json!(name));
    }
    schemas["Limits"] = limits;
    let mut report = json!({"type":"object","description":"Native analyzer JSON with a privacy projection only. Candidate relationships are not verified peers. review_observations are exploratory; check_comparisons are informational. Neither counts as a verified finding. Additive evidence fields may appear.","properties":{},"required":[]});
    for (name, ty) in [
        ("routes", "Route"),
        ("candidate_relationships", "Relationship"),
        ("peer_groups", "PeerGroup"),
        ("invariants", "Invariant"),
        ("finding_details", "Finding"),
        ("review_observations", "ReviewObservation"),
        ("check_comparisons", "CheckContrast"),
        ("analysis_evidence", "Evidence"),
        ("resource_evidence", "Evidence"),
        ("handler_resolution_evidence", "Evidence"),
        ("security_assessments", "Assessment"),
        ("diagnostics", "Evidence"),
    ]
    .iter()
    {
        report["properties"][name] = json!({"type":"array","items":reference(ty)});
        report["required"].as_array_mut().unwrap().push(json!(name));
    }
    report["properties"]["files_scanned"] = json!({"type":"integer"});
    for name in ["findings", "parse_errors"] {
        report["properties"][name] = json!({"type":"array","items":{"type":"string"}});
    }
    report["properties"]["graph"] = reference("Graph");
    report["properties"]["summary"] = reference("Evidence");
    report["properties"]["diff_report"] = reference("Evidence");
    schemas["Report"] = report;
    let mut paths = json!({});
    let mut submit = operation(
        "submitAnalysis",
        "Validate and enqueue source-only analysis. No submitted code is executed. No local server paths accepted. 202 Location identifies the job. Capacity/retention limits return 429; there is no unbounded queue.",
        "202",
        "JobStatus",
        false,
    );
    submit["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":reference("AnalysisRequest"),"examples":{"snapshot":{"value":{"source":{"type":"snapshot","files":[{"path":"src/main.rs","content":"fn main() {}"}]}}},"github":{"value":{"source":{"type":"github","url":"https://github.com/example/project","commit":"0123456789abcdef0123456789abcdef01234567"}}}}}}});
    submit["responses"]["202"]["headers"] =
        json!({"Location":{"description":"Relative status URL","schema":{"type":"string"}}});
    paths["/api/v1/analyses"] = json!({"post":submit});
    let mut delete = operation(
        "deleteAnalysis",
        "Delete a completed job and its retained output. Running jobs return 409; this endpoint does not cancel them.",
        "204",
        "JobStatus",
        true,
    );
    delete["responses"]["204"] = json!({"description":"Deleted; no body"});
    paths["/api/v1/analyses/{id}"] = json!({"get":operation("analysisStatus","Poll status. Missing, deleted and expired jobs return 404. Failure details are sanitized in error; HTTP 200 can represent a failed job.","200","JobStatus",true),"delete":delete});
    paths["/api/v1/analyses/{id}/result"] = json!({"get":operation("analysisResult","Completed deterministic report. Pending or failed jobs return 409. Source files are never served.","200","AnalysisResult",true)});
    let mut arg = operation(
        "analysisArg",
        "Native ARG as a DOT attachment, not an image. IDs and labels follow the report privacy policy. JSON graph is available in the result report.graph; the Link response header points to that result. No arg.svg endpoint is provided. See docs/arg-visualization.md for the frontend handoff contract.",
        "200",
        "Graph",
        true,
    );
    arg["responses"]["200"] = json!({"description":"Graphviz DOT","content":{"text/vnd.graphviz":{"schema":{"type":"string"},"example":"digraph ARG {\n}\n"}}});
    arg["responses"]["200"]["headers"] = json!({"Content-Disposition":{"schema":{"type":"string"},"example":"attachment; filename=\"authorization-graph.dot\""},"Content-Security-Policy":{"schema":{"type":"string"},"example":"default-src 'none'; sandbox"},"X-Content-Type-Options":{"schema":{"type":"string"},"example":"nosniff"},"Link":{"schema":{"type":"string"},"description":"Result JSON containing this graph's nodes and edges; exposed to configured CORS origins"}});
    paths["/api/v1/analyses/{id}/arg"] = json!({"get":arg});
    let mut health = operation(
        "health",
        "Public readiness/configured capabilities; no credentials, source paths or allowlist disclosed.",
        "200",
        "Health",
        false,
    );
    health["security"] = json!([]);
    paths["/api/v1/health"] = json!({"get":health});
    paths["/api/v1/openapi.json"] = json!({"get":{"operationId":"openapi","security":[],"description":"This OpenAPI document. Import into standard Swagger tooling; no custom UI is hosted.","responses":{"200":{"description":"OpenAPI 3.1 document","content":{"application/json":{"schema":{"type":"object"}}}}}}});
    json!({"openapi":"3.1.0","info":{"title":"ARCHER analysis API","version":"1.0","description":"Single-tenant trusted-client API. Bearer access controls all analyses. Deterministic engine is authoritative; LLM integration is not enabled. Use TLS at a trusted reverse proxy outside loopback. All responses are no-store. Exact-origin CORS is operator configured. See docs/backend.md for limits and isolation boundaries."},"servers":[{"url":"http://127.0.0.1:8080"}],"security":[{"bearerAuth":[]}],"paths":paths,"components":{"securitySchemes":{"bearerAuth":{"type":"http","scheme":"bearer","description":"Operator-managed ASCII secret of 32–256 characters. Do not embed in a public frontend bundle."}},"schemas":schemas}})
}
