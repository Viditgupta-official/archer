//! Existing graph output and change-aware report selection.
use super::*;

pub fn build_authorization_graph(
    routes: &[Route],
    findings: &[Finding],
) -> AuthorizationRelationshipGraph {
    graph_with_definitions(routes, findings, &[], &[])
}

pub(super) fn graph_with_definitions(
    routes: &[Route],
    findings: &[Finding],
    definitions: &[HandlerResolutionEvidence],
    assessments: &[security::Assessment],
) -> AuthorizationRelationshipGraph {
    let route_key = |method: &str, path: &str, application: &Option<String>| {
        serde_json::to_string(&("route", method, path, application)).expect("serializable identity")
    };
    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut node_ids = HashSet::new();

    let add_node = |nodes: &mut Vec<GraphNode>,
                    node_ids: &mut HashSet<String>,
                    id: String,
                    label: String,
                    kind: NodeKind,
                    file: Option<PathBuf>,
                    line: Option<usize>| {
        if node_ids.insert(id.clone()) {
            nodes.push(GraphNode {
                id,
                label,
                kind,
                file,
                line,
            });
        }
    };

    // Scopes and Routes
    for route in routes {
        let route_id = route_key(&route.method, &route.path, &route.application);
        let scope_id = serde_json::to_string(&("scope", &route.application, &route.scope_prefix))
            .expect("serializable identity");

        add_node(
            &mut nodes,
            &mut node_ids,
            scope_id.clone(),
            format!(
                "Scope: {}",
                if route.scope_prefix.is_empty() {
                    "/"
                } else {
                    &route.scope_prefix
                }
            ),
            NodeKind::Scope,
            None,
            None,
        );

        add_node(
            &mut nodes,
            &mut node_ids,
            route_id.clone(),
            format!("{} {}", route.method, route.path),
            NodeKind::Route,
            Some(route.file.clone()),
            Some(route.line),
        );

        edges.push(GraphEdge {
            from: route_id.clone(),
            to: scope_id,
            relation: EdgeRelation::BelongsToScope,
        });

        if let Some(handler) = &route.handler {
            let definition = definitions.iter().find(|d| {
                d.route.application == route.application
                    && d.route.method == route.method
                    && d.route.path == route.path
                    && d.route.file == route.file
            });
            let qualified = definition
                .and_then(|d| d.definition_path.as_deref())
                .or(route.handler_path.as_deref())
                .unwrap_or(handler);
            let definition_file = definition
                .and_then(|d| d.definition_file.as_ref())
                .unwrap_or(&route.file);
            let handler_id = serde_json::to_string(&(
                "handler",
                &route.application,
                definition_file,
                qualified,
                definition
                    .and_then(|d| d.definition_path.as_ref())
                    .is_none()
                    .then_some(&route_id),
            ))
            .expect("serializable identity");
            add_node(
                &mut nodes,
                &mut node_ids,
                handler_id.clone(),
                format!("fn {}()", qualified),
                NodeKind::Handler,
                Some(definition_file.clone()),
                definition.and_then(|d| d.definition_line),
            );
            edges.push(GraphEdge {
                from: route_id.clone(),
                to: handler_id.clone(),
                relation: EdgeRelation::RoutesTo,
            });

            for (idx, evidence) in route.authorization.iter().enumerate() {
                let evidence_id =
                    serde_json::to_string(&("evidence", &route_id, idx, &evidence.mechanism))
                        .expect("serializable identity");
                let (kind, relation) = match evidence.kind {
                    AuthEvidenceKind::Unknown => {
                        (NodeKind::UnresolvedCheck, EdgeRelation::UnresolvedEvidence)
                    }
                    AuthEvidenceKind::AuthorizationGuard => {
                        (NodeKind::Guard, EdgeRelation::GuardedBy)
                    }
                    AuthEvidenceKind::AuthorizationMiddleware => {
                        (NodeKind::Middleware, EdgeRelation::WrappedBy)
                    }
                    AuthEvidenceKind::IdentityExtraction => {
                        let observed = assessments.iter().any(|a| {
                            a.route.application == route.application
                                && a.route.path == route.path
                                && a.route.method == route.method
                                && a.requirements.iter().any(|r| {
                                    r.dimension == "authentication"
                                        && r.enforcement == security::Enforcement::Observed
                                        && evidence.symbol.as_deref() == Some(r.symbol.as_str())
                                })
                        });
                        (
                            NodeKind::IdentityExtraction,
                            if observed {
                                EdgeRelation::ExtractsIdentity
                            } else {
                                EdgeRelation::PotentialEvidence
                            },
                        )
                    }
                    _ => (NodeKind::AuthorizationCheck, EdgeRelation::EnforcesCheck),
                };
                add_node(
                    &mut nodes,
                    &mut node_ids,
                    evidence_id.clone(),
                    format!("{:?}: {}", evidence.kind, evidence.mechanism),
                    kind,
                    Some(evidence.file.clone()),
                    Some(evidence.line),
                );
                edges.push(GraphEdge {
                    from: handler_id.clone(),
                    to: evidence_id,
                    relation,
                });
            }
        }
    }

    // Invariants & Findings
    for (i, finding) in findings.iter().enumerate() {
        let contract_id = format!(
            "contract:{}:{}",
            finding.peer_group_id, finding.invariant.description
        );
        let finding_id = format!("finding:{}:{:?}", i + 1, finding.category);

        add_node(
            &mut nodes,
            &mut node_ids,
            contract_id.clone(),
            format!("Invariant: {}", finding.invariant.description),
            NodeKind::InvariantContract,
            None,
            None,
        );

        for peer in &finding.authorized_peer_routes {
            let peer_id = route_key(&peer.method, &peer.path, &peer.application);
            edges.push(GraphEdge {
                from: peer_id,
                to: contract_id.clone(),
                relation: EdgeRelation::ImplementsContract,
            });
        }

        add_node(
            &mut nodes,
            &mut node_ids,
            finding_id.clone(),
            format!(
                "Drift ({:?}): {} {}",
                finding.category, finding.suspicious_route.method, finding.suspicious_route.path
            ),
            NodeKind::Finding,
            Some(finding.suspicious_route.file.clone()),
            Some(finding.suspicious_route.line),
        );

        let suspicious_id = route_key(
            &finding.suspicious_route.method,
            &finding.suspicious_route.path,
            &finding.suspicious_route.application,
        );
        edges.push(GraphEdge {
            from: finding_id.clone(),
            to: suspicious_id,
            relation: EdgeRelation::FlagsRoute,
        });

        edges.push(GraphEdge {
            from: finding_id,
            to: contract_id,
            relation: EdgeRelation::ViolatesContract,
        });
    }

    AuthorizationRelationshipGraph { nodes, edges }
}

// Snapshot committed source through Git object reads, never checkout/reset the caller.
struct RevisionSnapshot(PathBuf);
impl RevisionSnapshot {
    fn create(repo: &Path, revision: &str) -> Result<Self> {
        let id = git(
            repo,
            &[
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{revision}^{{commit}}"),
            ],
        )?;
        let id = String::from_utf8(id)?.trim().to_owned();
        let dir = std::env::temp_dir().join(format!(
            "archer-base-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        fs::create_dir(&dir).context("Create isolated base snapshot")?;
        let snapshot = Self(dir);
        let tree = git(repo, &["ls-tree", "-rz", "--full-tree", &id])?;
        let mut files = Vec::new();
        for entry in tree.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let entry = std::str::from_utf8(entry).context("Non-UTF8 Git path unsupported")?;
            let (meta, path) = entry.split_once('\t').context("Malformed Git tree entry")?;
            let parts: Vec<_> = meta.split_whitespace().collect();
            if parts[1] == "commit" {
                anyhow::bail!("Submodule source cannot be snapshotted reliably: {path}");
            }
            let path = Path::new(path);
            if path.is_absolute()
                || path
                    .components()
                    .any(|c| !matches!(c, std::path::Component::Normal(_)))
            {
                anyhow::bail!("Unsafe Git source path: {}", path.display());
            }
            if path.extension().is_none_or(|e| e != "rs")
                && path
                    .file_name()
                    .is_none_or(|n| n != "Cargo.toml" && n != "Cargo.lock")
            {
                continue;
            }
            if parts[0] != "100644" && parts[0] != "100755" {
                anyhow::bail!("Unsupported source file mode: {}", path.display());
            }
            files.push((parts[2].to_owned(), path.to_owned()));
        }
        // Drain stdout while writing stdin: large workspaces cannot deadlock pipe buffers.
        let mut child = std::process::Command::new("git")
            .args(["cat-file", "--batch"])
            .current_dir(repo)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let mut stdin = child.stdin.take().context("Git batch stdin")?;
        let input = files
            .iter()
            .map(|(id, _)| format!("{id}\n"))
            .collect::<String>();
        let writer = std::thread::spawn(move || {
            use std::io::Write;
            stdin.write_all(input.as_bytes())
        });
        let output = child.wait_with_output()?;
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("Git batch writer failed"))??;
        if !output.status.success() {
            anyhow::bail!(
                "Git object read failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let mut remaining = output.stdout.as_slice();
        for (id, path) in files {
            let end = remaining
                .iter()
                .position(|b| *b == b'\n')
                .context("Truncated Git object header")?;
            let header: Vec<_> = std::str::from_utf8(&remaining[..end])?
                .split_whitespace()
                .collect();
            if header.len() != 3 || header[0] != id || header[1] != "blob" {
                anyhow::bail!("Unexpected Git object response");
            }
            let size: usize = header[2].parse()?;
            remaining = &remaining[end + 1..];
            if remaining.len() < size + 1 || remaining[size] != b'\n' {
                anyhow::bail!("Truncated Git object content");
            }
            let dest = snapshot.0.join(path);
            fs::create_dir_all(dest.parent().context("Source parent")?)?;
            fs::write(dest, &remaining[..size])?;
            remaining = &remaining[size + 1..];
        }
        Ok(snapshot)
    }
}
impl Drop for RevisionSnapshot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .context("Run Git")?;
    if !output.status.success() {
        anyhow::bail!(
            "Git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(output.stdout)
}
fn normalized(value: &str, root: &Path) -> String {
    value
        .replace('\\', "/")
        .replace(&root.to_string_lossy().replace('\\', "/"), "<repository>")
}
fn dimension(f: &Finding) -> &str {
    f.invariant
        .description
        .strip_prefix("Comparable peers support ")
        .and_then(|s| s.split_once(':'))
        .map(|(d, _)| d)
        .unwrap_or("unknown")
}
// Match application populations by unique endpoint overlap, never file/line numbers.
// Multiple plausible App instances require abstention rather than cross-App matches.
fn application_map(
    base: &Report,
    current: &Report,
) -> Result<(
    HashMap<Option<String>, usize>,
    HashMap<Option<String>, usize>,
)> {
    fn populations(
        r: &Report,
    ) -> std::collections::BTreeMap<Option<String>, HashSet<(String, String, String)>> {
        let mut apps = std::collections::BTreeMap::new();
        for route in &r.routes {
            apps.entry(route.application.clone())
                .or_insert_with(HashSet::new)
                .insert((
                    route.method.clone(),
                    route.path.clone(),
                    route.scope_prefix.clone(),
                ));
        }
        apps
    }
    let a = populations(base);
    let b = populations(current);
    let am: HashMap<_, _> = a.keys().enumerate().map(|(i, k)| (k.clone(), i)).collect();
    let mut bm = HashMap::new();
    let mut used = HashSet::new();
    let mut next = am.len();
    for (app, routes) in &b {
        let candidates: Vec<_> = a
            .iter()
            .filter(|(_, other)| !other.is_disjoint(routes))
            .collect();
        let id = match candidates.as_slice() {
            [] => {
                let id = next;
                next += 1;
                id
            }
            [(key, _)] => {
                let id = am[*key];
                if !used.insert(id) {
                    anyhow::bail!("Ambiguous application correspondence in diff");
                }
                id
            }
            _ => anyhow::bail!(
                "Ambiguous application correspondence in diff; overlapping App populations cannot be compared safely"
            ),
        };
        bm.insert(app.clone(), id);
    }
    Ok((am, bm))
}
fn route_identity(
    r: &RouteReference,
    apps: &HashMap<Option<String>, usize>,
) -> (usize, String, String, String) {
    (
        apps[&r.application],
        r.method.to_uppercase(),
        r.path.clone(),
        r.scope_prefix.clone(),
    )
}
fn finding_identity(f: &Finding, apps: &HashMap<Option<String>, usize>, root: &Path) -> String {
    let mut values: Vec<_> = f
        .invariant
        .evidence_patterns
        .iter()
        .map(|v| normalized(v, root))
        .collect();
    values.sort();
    values.dedup();
    format!(
        "{:?}|{}|{:?}",
        route_identity(&f.suspicious_route, apps),
        dimension(f),
        values
    )
}
fn same_contract(
    report: &Report,
    e: &policy_drift::StageEvidence,
    f: &Finding,
    report_root: &Path,
    finding_root: &Path,
) -> bool {
    let values = |patterns: &[String], root: &Path| {
        let mut v: Vec<_> = patterns.iter().map(|s| normalized(s, root)).collect();
        v.sort();
        v.dedup();
        v
    };
    report.invariants.iter().any(|i| {
        i.peer_group_id == e.peer_group_id
            && i.description
                .starts_with(&format!("Supported {} requirement:", dimension(f)))
            && values(&i.evidence_patterns, report_root)
                == values(&f.invariant.evidence_patterns, finding_root)
    })
}
fn assessment_identity(
    report: &Report,
    route: &RouteReference,
    apps: &HashMap<Option<String>, usize>,
    root: &Path,
) -> Vec<String> {
    let mut values = report
        .security_assessments
        .iter()
        .find(|a| route_identity(&a.route, apps) == route_identity(route, apps))
        .map(|a| {
            a.requirements
                .iter()
                .map(|r| {
                    format!(
                        "{}|{:?}|{:?}",
                        r.dimension,
                        r.enforcement,
                        r.values
                            .iter()
                            .map(|v| normalized(v, root))
                            .collect::<Vec<_>>()
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    values.sort();
    values
}
// Base findings retain base source coordinates, presented beneath the repository
// root rather than a temporary snapshot directory which is removed on return.
fn present_base_finding(f: &mut Finding, base: &Path, current: &Path) {
    fn path(p: &mut PathBuf, base: &Path, current: &Path) {
        if let Ok(rel) = p.strip_prefix(base) {
            *p = current.join(rel);
        }
    }
    fn route(r: &mut RouteReference, base: &Path, current: &Path) {
        path(&mut r.file, base, current);
        if let Some(app) = &mut r.application {
            *app = app.replace(&*base.to_string_lossy(), &current.to_string_lossy());
        }
        for e in &mut r.authorization {
            path(&mut e.file, base, current);
        }
    }
    route(&mut f.suspicious_route, base, current);
    for r in &mut f.authorized_peer_routes {
        route(r, base, current);
    }
    for e in &mut f.suspicious_route_evidence {
        path(&mut e.file, base, current);
    }
    f.invariant.description = f
        .invariant
        .description
        .replace(&*base.to_string_lossy(), &current.to_string_lossy());
    for p in &mut f.invariant.evidence_patterns {
        *p = p.replace(&*base.to_string_lossy(), &current.to_string_lossy());
    }
}
fn checked_analysis(root: &Path) -> Result<Report> {
    let report = analyze_repository(root)?;
    if report.files_scanned == 0 {
        anyhow::bail!(
            "No Rust source available for a meaningful analysis: {}",
            root.display()
        );
    }
    if !report.parse_errors.is_empty() {
        anyhow::bail!(
            "Incomplete analysis of {}: {}",
            root.display(),
            report.parse_errors.join("; ")
        );
    }
    Ok(report)
}
fn baseline_checks(
    base:&Report,current:&Report,ba:&HashMap<Option<String>,usize>,ca:&HashMap<Option<String>,usize>,
    base_root:&Path,current_root:&Path,regressions:&[RouteRegression],
)->Vec<BaselineRegressionCheck> {
    fn policies(a:&security::Assessment,dimension:&str,root:&Path)->Vec<Vec<String>> {
        let mut result:Vec<_>=a.requirements.iter().filter(|r|r.dimension==dimension && r.enforcement==security::Enforcement::Observed)
            .map(|r|{let mut v=if dimension=="authentication" {vec!["authenticated identity".into()]} else {r.values.iter().map(|v|normalized(v,root)).collect()};v.sort();v.dedup();v})
            .filter(|v|!v.is_empty()).collect();result.sort();result.dedup();result
    }
    let mut checks=Vec::new();
    for old in &base.security_assessments {
        let key=route_identity(&old.route,ba);
        let candidates:Vec<_>=current.security_assessments.iter().filter(|a|route_identity(&a.route,ca)==key).collect();
        // A duplicate route observation is not an unambiguous baseline match.
        let [now]=candidates.as_slice() else {continue;};
        for dimension in ["authentication","roles","permissions","ownership"] {
            let before=policies(old,dimension,base_root);if before.is_empty() {continue;}
            let after=policies(now,dimension,current_root);
            if before==after {continue;}
            // Preserve alternate observed enforcement; role allowlists may narrow.
            if before.iter().all(|expected|after.iter().any(|actual|actual==expected ||
                (dimension=="roles" && !actual.is_empty() && actual.iter().all(|v|expected.contains(v))))) {continue;}
            let unresolved=matches!(old.route.status,RouteSecurityStatus::Unknown{..}) || matches!(now.route.status,RouteSecurityStatus::Unknown{..}) ||
                old.requirements.iter().chain(now.requirements.iter()).any(|r|r.enforcement==security::Enforcement::Unresolved);
            let supported=!unresolved && regressions.iter().any(|r|route_identity(&r.route,ca)==key);
            checks.push(BaselineRegressionCheck{
                route:now.route.clone(),dimension:dimension.into(),change:if after.is_empty(){"ObservedRequirementLost"}else{"ObservedPolicyChanged"}.into(),
                status:if supported {"SupportedByExistingDiffAnalysis"} else {"ReviewRequired"}.into(),
                before:before.iter().map(|v|v.join(", ")).collect(),after:after.iter().map(|v|v.join(", ")).collect(),
                reason:if supported {"The existing posture/policy diff supports a regression; this is not a proof of exploitability."}
                    else {"Previously observed evidence is no longer equivalent. Unresolved behavior, alternate policies or lost source resolution prevent a confirmed effective regression. Review the complete request path."}.into(),
            });
        }
    }
    for old in &base.local_rejections {
        let key=route_identity(&old.route,ba);
        let candidates:Vec<_>=current.routes.iter().filter(|r|route_identity(&RouteReference::from(*r),ca)==key).collect();
        let [now]=candidates.as_slice() else {continue;};
        if current.local_rejections.iter().any(|r|route_identity(&r.route,ca)==key && r.condition==old.condition) {continue;}
        checks.push(BaselineRegressionCheck{route:RouteReference::from(*now),dimension:"unclassified_rejection".into(),change:"LocalRejectionChanged".into(),status:"ReviewRequired".into(),
            before:vec![old.condition.clone()],after:vec![],reason:"A previously explicit Result error-return branch is absent or refactored. Its authorization meaning, replacement enforcement and position relative to side effects are unverified; this is not an ownership finding or confirmed vulnerability.".into()});
    }
    checks
}

pub fn analyze_repository_diff(root: &Path, git_ref: Option<&str>) -> Result<DiffAnalysisReport> {
    let root = root.canonicalize()?;
    let repo = String::from_utf8(git(&root, &["rev-parse", "--show-toplevel"])?)?;
    let repo = PathBuf::from(repo.trim()).canonicalize()?;
    // Snapshot the full Git root so workspace path dependencies keep their context.
    if root != repo {
        anyhow::bail!("Diff analysis requires the Git repository root, not a subdirectory");
    }
    let base_ref = git_ref.unwrap_or("HEAD~1");
    let snapshot = RevisionSnapshot::create(&repo, base_ref)?;
    let base = checked_analysis(&snapshot.0).context("Base revision analysis failed")?;
    let current = checked_analysis(&root).context("Current working-tree analysis failed")?;
    let base_oid = String::from_utf8(git(
        &repo,
        &[
            "rev-parse",
            "--verify",
            "--end-of-options",
            &format!("{base_ref}^{{commit}}"),
        ],
    )?)?;
    let changed = git(&repo, &["diff", "--name-only", "-z", base_oid.trim(), "--"])?;
    let changed_files = changed
        .split(|b| *b == 0)
        .filter(|b| !b.is_empty())
        .map(|p| std::str::from_utf8(p).map(|p| repo.join(p)))
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|p| p.extension().is_some_and(|e| e == "rs"))
        .collect::<Vec<_>>();
    let (ba, ca) = application_map(&base, &current)?;
    let old: HashSet<_> = base
        .finding_details
        .iter()
        .map(|f| finding_identity(f, &ba, &snapshot.0))
        .collect();
    let now: HashSet<_> = current
        .finding_details
        .iter()
        .map(|f| finding_identity(f, &ca, &root))
        .collect();
    let mut newly_introduced_drifts = Vec::new();
    let mut unchanged_drifts = Vec::new();
    let mut resolved_drifts = Vec::new();
    let mut unverified_drifts = Vec::new();
    let mut regressions = Vec::new();
    let mut affected_routes = Vec::new();
    for route in &current.routes {
        let r = RouteReference::from(route);
        let key = route_identity(&r, &ca);
        let previous = base
            .routes
            .iter()
            .find(|b| route_identity(&RouteReference::from(*b), &ba) == key);
        if previous.is_none_or(|b| {
            assessment_identity(&base, &RouteReference::from(b), &ba, &snapshot.0)
                != assessment_identity(&current, &r, &ca, &root)
                || b.security_status() != route.security_status()
        }) || changed_files.contains(&route.file)
        {
            affected_routes.push(r.clone());
        }
        if previous.is_some_and(|b| matches!(b.security_status(), RouteSecurityStatus::Protected))
            && matches!(r.status, RouteSecurityStatus::Unprotected)
        {
            regressions.push(RouteRegression{route:r,reason:"Observed protected posture became unprotected; Unknown is not treated as a verified regression".into()});
        }
    }
    for f in &current.finding_details {
        if old.contains(&finding_identity(f, &ca, &root)) {
            unchanged_drifts.push(f.clone());
        } else {
            let key = route_identity(&f.suspicious_route, &ca);
            if base.security_assessments.iter().any(|a| {
                route_identity(&a.route, &ba) == key
                    && (matches!(a.route.status, RouteSecurityStatus::Unknown { .. })
                        || a.requirements
                            .iter()
                            .any(|r| r.enforcement == security::Enforcement::Unresolved))
            }) {
                let mut uncertain = f.clone();
                uncertain.explanation = format!(
                    "Unverified introduction: base route enforcement was unresolved. {}",
                    uncertain.explanation
                );
                unverified_drifts.push(uncertain);
                continue;
            }
            if base.finding_details.iter().any(|old| {
                route_identity(&old.suspicious_route, &ba) == key && dimension(old) == dimension(f)
            }) {
                let mut uncertain = f.clone();
                uncertain.explanation = format!(
                    "Unverified requirement correspondence: an existing finding in this dimension has a different expected policy identity. {}",
                    uncertain.explanation
                );
                unverified_drifts.push(uncertain);
                continue;
            }
            // A new consensus alone is not proof that an existing target weakened.
            let key = route_identity(&f.suspicious_route, &ca);
            let before = base.analysis_evidence.iter().any(|e| {
                e.stage == "drift"
                    && e.dimension.as_deref() == Some(dimension(f))
                    && e.abstention_reasons.is_empty()
                    && e.evidence
                        .iter()
                        .any(|s| s == "Target satisfies the supported comparison")
                    && same_contract(&base, e, f, &snapshot.0, &root)
                    && e.route
                        .as_ref()
                        .is_some_and(|r| route_identity(r, &ba) == key)
            });
            if before {
                regressions.push(RouteRegression {
                    route: f.suspicious_route.clone(),
                    reason: format!(
                        "Previously supported {} comparison now deviates",
                        dimension(f)
                    ),
                });
            }
            newly_introduced_drifts.push(f.clone());
        }
    }
    for f in &base.finding_details {
        if now.contains(&finding_identity(f, &ba, &snapshot.0)) {
            continue;
        }
        let key = route_identity(&f.suspicious_route, &ba);
        if current.finding_details.iter().any(|now| {
            route_identity(&now.suspicious_route, &ca) == key && dimension(now) == dimension(f)
        }) {
            continue;
        }
        let exists = current
            .routes
            .iter()
            .any(|r| route_identity(&RouteReference::from(r), &ca) == key);
        let satisfies = current.analysis_evidence.iter().any(|e| {
            e.stage == "drift"
                && e.dimension.as_deref() == Some(dimension(f))
                && e.abstention_reasons.is_empty()
                && e.evidence
                    .iter()
                    .any(|s| s == "Target satisfies the supported comparison")
                && same_contract(&current, e, f, &root, &snapshot.0)
                && e.route
                    .as_ref()
                    .is_some_and(|r| route_identity(r, &ca) == key)
        });
        if !exists || satisfies {
            resolved_drifts.push(f.clone());
        } else {
            let mut uncertain = f.clone();
            uncertain.explanation = format!(
                "Unverified resolution: the original requirement no longer has a supported satisfying comparison. {}",
                uncertain.explanation
            );
            unverified_drifts.push(uncertain);
        }
    }
    let mut combined: Vec<RouteRegression> = Vec::new();
    for regression in regressions {
        if let Some(previous) = combined.iter_mut().find(|previous| {
            route_identity(&previous.route, &ca) == route_identity(&regression.route, &ca)
        }) {
            previous.reason.push_str("; ");
            previous.reason.push_str(&regression.reason);
        } else {
            combined.push(regression);
        }
    }
    let regressions = combined;
    let baseline_regression_checks=baseline_checks(&base,&current,&ba,&ca,&snapshot.0,&root,&regressions);
    let baseline_comparison_routes=current.routes.iter().filter(|r|base.routes.iter().any(|b|route_identity(&RouteReference::from(b),&ba)==route_identity(&RouteReference::from(*r),&ca))).count();
    for f in resolved_drifts
        .iter_mut()
        .chain(unverified_drifts.iter_mut())
    {
        present_base_finding(f, &snapshot.0, &root);
    }
    let summary = format!(
        "Compared base {base_ref} with current working tree: {} new, {} unchanged, {} resolved, {} no longer comparable drift(s); {} verified regression(s).",
        newly_introduced_drifts.len(),
        unchanged_drifts.len(),
        resolved_drifts.len(),
        unverified_drifts.len(),
        regressions.len()
    );
    let base_summary = base.summary;
    let current_summary = current.summary;
    let analysis_warnings = base
        .diagnostics
        .iter()
        .map(|d| {
            format!("base: {d:?}").replace(&*snapshot.0.to_string_lossy(), &root.to_string_lossy())
        })
        .chain(
            current
                .diagnostics
                .iter()
                .map(|d| format!("current: {d:?}")),
        )
        .collect();
    Ok(DiffAnalysisReport {
        base_ref: base_ref.into(),
        changed_files,
        affected_routes,
        newly_introduced_drifts,
        regressions,
        baseline_regression_checks,
        baseline_comparison_routes,
        unchanged_drifts,
        resolved_drifts,
        unverified_drifts,
        base_summary,
        current_summary,
        analysis_warnings,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyzer::tests::TempRepo;
    fn command(root: &Path, args: &[&str]) {
        git(root, args).unwrap();
    }
    fn source(body: &str) -> String {
        format!(
            r#"
fn check_role(role:&str)->Result<(),Error> {{if allowed(role) {{Ok(())}} else {{Err(denied())}}}}
pub async fn one() {{check_role("Admin")?;sqlx::query("SELECT * FROM records");}}
pub async fn two() {{check_role("Admin")?;sqlx::query("SELECT * FROM records");}}
pub async fn three() {{{body}sqlx::query("SELECT * FROM records");}}
"#
        )
    }
    #[test]
    fn diff_compares_revisions_not_changed_filenames() {
        for case in [
            "comment",
            "helper-only",
            "new",
            "consensus-only",
            "policy-relabel",
            "resolved",
            "renamed",
            "unchanged",
            "unknown",
            "unknown-base",
            "invalid-ref",
            "broken-base",
            "broken-current",
        ] {
            let clean = matches!(case, "helper-only" | "new" | "consensus-only");
            let initial = source(if clean {
                "check_role(\"Admin\")?;"
            } else if case == "unknown-base" {
                "check_role(\"Admin\");"
            } else {
                ""
            });
            let app = r#"mod handlers; fn app(c:&mut Config) {c.route("/records/one/{id}",web::get().to(handlers::one)).route("/records/two/{id}",web::get().to(handlers::two)).route("/records/three/{id}",web::get().to(handlers::three));}"#;
            let repo = TempRepo::new(
                &format!("diff-{case}"),
                &[
                    ("main.rs", app),
                    (
                        "handlers.rs",
                        if case == "broken-base" {
                            "invalid rust !!!"
                        } else {
                            &initial
                        },
                    ),
                ],
            );
            let root = repo.path();
            command(root, &["init", "-q"]);
            command(root, &["add", "."]);
            command(
                root,
                &[
                    "-c",
                    "user.name=ARCHER Test",
                    "-c",
                    "user.email=archer@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-qm",
                    "base",
                ],
            );
            match case {
                "comment" => fs::write(
                    root.join("handlers.rs"),
                    format!("// shifted lines\n{initial}"),
                )
                .unwrap(),
                "helper-only" | "new" | "unknown-base" => {
                    fs::write(root.join("handlers.rs"), source("")).unwrap()
                }
                "policy-relabel" => fs::write(
                    root.join("handlers.rs"),
                    initial.replace("check_role(\"Admin\")?;", "check_role(\"Member\")?;"),
                )
                .unwrap(),
                "consensus-only" => fs::write(
                    root.join("handlers.rs"),
                    initial.replacen("check_role(\"Admin\")?;", "check_role(\"Member\")?;", 2),
                )
                .unwrap(),
                "resolved" => {
                    fs::write(root.join("handlers.rs"), source("check_role(\"Admin\")?;")).unwrap()
                }
                "renamed" => {
                    fs::rename(root.join("handlers.rs"), root.join("actions.rs")).unwrap();
                    fs::write(root.join("main.rs"), app.replace("handlers", "actions")).unwrap();
                    command(root, &["add", "-A"]);
                }
                "unknown" => {
                    fs::write(root.join("handlers.rs"), source("check_role(\"Admin\");")).unwrap()
                }
                "broken-current" => {
                    fs::write(root.join("handlers.rs"), "invalid rust !!!").unwrap()
                }
                "broken-base" => fs::write(root.join("handlers.rs"), initial).unwrap(),
                _ => {}
            }
            let result = analyze_repository_diff(
                root,
                Some(if case == "invalid-ref" {
                    "definitely-missing"
                } else {
                    "HEAD"
                }),
            );
            if matches!(case, "invalid-ref" | "broken-base" | "broken-current") {
                assert!(result.is_err(), "{case}");
                continue;
            }
            let d = result.unwrap();
            assert_eq!(
                d.newly_introduced_drifts.len(),
                usize::from(clean),
                "{case}: {}",
                d.summary
            );
            assert_eq!(
                d.resolved_drifts.len(),
                usize::from(case == "resolved"),
                "{case}: {}",
                d.summary
            );
            assert_eq!(
                d.unverified_drifts.len(),
                usize::from(matches!(
                    case,
                    "unknown" | "unknown-base" | "policy-relabel"
                )),
                "{case}: {}",
                d.summary
            );
            assert_eq!(
                d.unchanged_drifts.len(),
                usize::from(matches!(case, "comment" | "renamed" | "unchanged")),
                "{case}: {}",
                d.summary
            );
            assert_eq!(
                d.regressions.len(),
                usize::from(clean && case != "consensus-only"),
                "{case}: {:?}",
                d.regressions
            );
            assert_eq!(git(root, &["rev-list", "--count", "HEAD"]).unwrap(), b"1\n");
        }
    }
    #[test]
    fn graph_uses_resolved_module_identity_and_uncertainty_edges() {
        let source = r#"mod a {pub async fn show() {check_role("Admin");}} mod b {pub async fn show() {}}
fn app(c:&mut Config) {c.route("/a",web::get().to(a::show)).route("/b",web::get().to(b::show));}"#;
        let report = TempRepo::new("graph-qualified-modules", &[("main.rs", source)]).analyze();
        let mut unresolved = report.routes.clone();
        for r in &mut unresolved {
            r.handler_path = Some("show".into());
            r.handler_resolution = Some(HandlerResolution::Unresolved);
        }
        let fallback = build_authorization_graph(&unresolved, &[]);
        assert_eq!(
            fallback
                .nodes
                .iter()
                .filter(|n| n.kind == NodeKind::Handler)
                .count(),
            2
        );
        let graph = report.graph.unwrap();
        let handlers: Vec<_> = graph
            .nodes
            .iter()
            .filter(|n| n.kind == NodeKind::Handler)
            .collect();
        assert_eq!(handlers.len(), 2);
        assert!(handlers.iter().any(|n| n.label.contains("crate::a::show")));
        assert!(handlers.iter().any(|n| n.label.contains("crate::b::show")));
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.relation == EdgeRelation::UnresolvedEvidence)
        );
        assert!(
            !graph
                .edges
                .iter()
                .any(|e| e.relation == EdgeRelation::EnforcesCheck)
        );
    }
    #[test]
    fn dot_escapes_every_quoted_string_position() {
        let value = "quote\"\\next\nline\rreturn";
        let graph = AuthorizationRelationshipGraph {
            nodes: vec![GraphNode {
                id: value.into(),
                label: value.into(),
                kind: NodeKind::UnresolvedCheck,
                file: None,
                line: None,
            }],
            edges: vec![GraphEdge {
                from: value.into(),
                to: value.into(),
                relation: EdgeRelation::UnresolvedEvidence,
            }],
        };
        let escaped = "quote\\\"\\\\next\\nline\\rreturn";
        assert_eq!(dot_escape(value), escaped);
        let dot = graph.to_dot();
        assert_eq!(dot.matches(escaped).count(), 4);
        assert!(!dot.contains(value));
    }

    #[test]
    fn production_demo_emits_each_supported_category_and_clean_controls() {
        let source = include_str!("../../demo/src/main.rs");
        for (marker, category) in [
            ("", None),
            (
                "ARCHER_ROLE_MUTATION",
                Some(DriftCategory::InconsistentRoleOrPermission),
            ),
            (
                "ARCHER_AUTH_MUTATION",
                Some(DriftCategory::MissingEnforcement),
            ),
            (
                "ARCHER_OWNER_MUTATION",
                Some(DriftCategory::MissingOwnershipValidation),
            ),
        ] {
            let changed = source
                .lines()
                .filter(|line| marker.is_empty() || !line.contains(marker))
                .collect::<Vec<_>>()
                .join("\n");
            let report = TempRepo::new(
                &format!("production-demo-{marker}"),
                &[("main.rs", &changed)],
            )
            .analyze();
            assert_eq!(report.invariants.len(), 3);
            assert_eq!(
                report.finding_details.len(),
                usize::from(category.is_some())
            );
            if let Some(category) = category {
                assert_eq!(report.finding_details[0].category, category);
            }
            assert!(
                report.finding_details.iter().all(|f| !f
                    .suspicious_route
                    .path
                    .starts_with("/profiles")
                    && !f.suspicious_route.path.starts_with("/public"))
            );
            if marker.is_empty() {
                let graph = report.graph.as_ref().unwrap();
                assert!(
                    graph
                        .edges
                        .iter()
                        .any(|e| e.relation == EdgeRelation::ExtractsIdentity)
                );
            }
        }
    }
}
