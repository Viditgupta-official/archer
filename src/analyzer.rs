use anyhow::{Context, Result};
use quote::ToTokens;
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Arm, BinOp, Block, Expr, ExprCall, ExprClosure, ExprForLoop, ExprIf, ExprLit, ExprMethodCall,
    ExprPath, ExprWhile, FnArg, ImplItemFn, Item, ItemFn, ItemMod, Lit, Pat, Signature, Stmt,
    TraitItemFn, UseTree,
    spanned::Spanned,
    visit::{self, Visit},
};
use walkdir::WalkDir;

// Active production stages: discovery/indexing below -> registration ->
// security assessment -> policy_drift discovery/groups/invariants/findings.
// reporting consumes results; legacy is never compiled into production.
mod reporting;
pub use reporting::{analyze_repository_diff, build_authorization_graph};
#[cfg(test)]
mod legacy;
#[cfg(test)]
use legacy::*;
mod policy_drift;
#[cfg(test)]
mod policy_drift_tests;
mod registration;
#[cfg(test)]
mod registration_security_tests;
mod security;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum AuthEvidenceKind {
    RoleCheck,
    PermissionCheck,
    AuthorizationGuard,
    AuthorizationMiddleware,
    IdentityExtraction,
    OwnershipCheck,
    ManualAuthorizationCheck,
    Unknown,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum AuthStrength {
    Strong,
    Medium,
    Weak,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AuthEvidence {
    pub kind: AuthEvidenceKind,
    pub mechanism: String,
    pub symbol: Option<String>,
    pub file: PathBuf,
    pub line: usize,
    pub handler: Option<String>,
    pub strength: AuthStrength,
}

impl AuthEvidence {
    pub fn is_authorization(&self) -> bool {
        matches!(
            self.kind,
            AuthEvidenceKind::RoleCheck
                | AuthEvidenceKind::PermissionCheck
                | AuthEvidenceKind::AuthorizationGuard
                | AuthEvidenceKind::AuthorizationMiddleware
                | AuthEvidenceKind::OwnershipCheck
                | AuthEvidenceKind::ManualAuthorizationCheck
        )
    }
}

/// How a route's handler expression was matched to a handler definition.
/// Only `Definition`, `Local`, `Imported`, `GlobImported`, `Qualified`, and
/// `UniqueName` attach the definition's evidence to the route.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum HandlerResolution {
    /// Attribute route: the annotated function is the handler.
    Definition,
    /// Defined in the module that registers the route.
    Local,
    /// Brought into scope by an explicit, possibly renamed, `use`.
    Imported,
    /// Brought into scope by exactly one matching glob `use`.
    GlobImported,
    /// Module-qualified path such as `handlers::payments`.
    Qualified,
    /// Path rules found nothing; the crate holds exactly one compatible definition.
    UniqueName,
    /// Several definitions match; no evidence is attached.
    Ambiguous { candidates: Vec<String> },
    /// No definition could be identified; no evidence is attached.
    Unresolved,
}

#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub application: Option<String>,
    pub method: String,
    pub path: String,
    pub scope_prefix: String,
    pub handler: Option<String>,
    pub handler_path: Option<String>,
    pub handler_resolution: Option<HandlerResolution>,
    pub authorization: Vec<AuthEvidence>,
    pub line: usize,
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "status")]
pub enum RouteSecurityStatus {
    /// Route has verified authorization evidence (Guard, Middleware, RoleCheck, PermissionCheck, etc.)
    Protected,
    /// Route handler is resolved and verified to lack any authorization enforcement.
    Unprotected,
    /// Security posture cannot be determined statically (e.g. handler unresolved, ambiguous, or indirect).
    Unknown { reason: String },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum DriftCategory {
    /// Peer routes enforce authorization checks, but the target route contains none.
    MissingEnforcement,
    /// Route extracts identity/claims (authentication), but fails to enforce authorization.
    AuthenticationOnlyWithoutAuthorization,
    /// Peer parameterized routes validate resource ownership, but target route omits it.
    MissingOwnershipValidation,
    /// Peer routes enforce a role (e.g. Admin), but target route enforces an inconsistent role.
    InconsistentRoleOrPermission,
    /// Peer routes enforce architectural guard/middleware, but target route uses ad-hoc logic.
    InconsistentMechanism,
    /// Route security posture could not be definitively validated due to resolution limits.
    #[allow(dead_code)]
    UnresolvedSecurityPosture,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum DriftConfidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteReference {
    pub scope_prefix: String,
    pub application: Option<String>,
    pub method: String,
    pub path: String,
    pub handler: Option<String>,
    pub file: PathBuf,
    pub line: usize,
    pub authorized: bool,
    pub authorization: Vec<AuthEvidence>,
    pub status: RouteSecurityStatus,
}

impl From<&Route> for RouteReference {
    fn from(route: &Route) -> Self {
        Self {
            scope_prefix: route.scope_prefix.clone(),
            application: route.application.clone(),
            method: route.method.clone(),
            path: route.path.clone(),
            handler: route.handler.clone(),
            file: route.file.clone(),
            line: route.line,
            authorized: route.is_authorized(),
            authorization: route.authorization.clone(),
            status: route.security_status(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerGroup {
    pub id: String,
    pub description: String,
    pub routes: Vec<RouteReference>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationInvariant {
    pub peer_group_id: String,
    pub description: String,
    pub total_routes: usize,
    pub routes_with_authorization: usize,
    pub routes_without_authorization: usize,
    pub evidence_patterns: Vec<String>,
    pub strength: AuthStrength,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub peer_group_id: String,
    pub invariant: AuthorizationInvariant,
    pub suspicious_route: RouteReference,
    pub suspicious_route_evidence: Vec<AuthEvidence>,
    pub authorized_peer_routes: Vec<RouteReference>,
    pub category: DriftCategory,
    pub confidence: DriftConfidence,
    pub explanation: String,
    pub remediation: String,
}

impl Route {
    pub fn is_authorized(&self) -> bool {
        self.authorization
            .iter()
            .any(AuthEvidence::is_authorization)
    }

    pub fn security_status(&self) -> RouteSecurityStatus {
        if matches!(self.handler_resolution, Some(HandlerResolution::Definition))
            && self
                .application
                .as_ref()
                .is_none_or(|app| app.starts_with("declaration:"))
        {
            // An attribute declares a service, not its effective App/scope.
            // Keep body evidence, but do not certify security at an unknown mount.
            RouteSecurityStatus::Unknown {
                reason: "Attribute service has no verified application/middleware mount context"
                    .into(),
            }
        } else if self.is_authorized() {
            RouteSecurityStatus::Protected
        } else if matches!(
            self.handler_resolution,
            Some(HandlerResolution::Unresolved) | Some(HandlerResolution::Ambiguous { .. })
        ) {
            RouteSecurityStatus::Unknown {
                reason: "Handler symbol could not be uniquely resolved in repository AST".into(),
            }
        } else if self
            .authorization
            .iter()
            .any(|e| matches!(e.kind, AuthEvidenceKind::Unknown))
        {
            RouteSecurityStatus::Unknown {
                reason: "Route contains unrecognized authorization evidence".into(),
            }
        } else {
            RouteSecurityStatus::Unprotected
        }
    }

    pub fn evidence_summary(&self) -> String {
        if self.authorization.is_empty() {
            return "No recognized authorization evidence".into();
        }
        self.authorization
            .iter()
            .map(|evidence| format!("{:?}: {}", evidence.kind, evidence.mechanism))
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[allow(dead_code)]
    pub fn strongest_evidence(&self) -> Option<&AuthEvidence> {
        self.authorization
            .iter()
            .filter(|evidence| evidence.is_authorization())
            .min_by_key(|evidence| match evidence.strength {
                AuthStrength::Strong => 0,
                AuthStrength::Medium => 1,
                AuthStrength::Weak => 2,
            })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisSummary {
    pub total_routes: usize,
    pub peer_group_covered_routes: usize,
    pub peer_compared_routes: usize,
    pub routes_without_peer_comparison: usize,
    pub protected_routes: usize,
    pub unprotected_routes: usize,
    pub unknown_routes: usize,
    pub peer_groups_count: usize,
    pub inferred_invariants_count: usize,
    pub drift_findings_count: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum NodeKind {
    Scope,
    Route,
    Handler,
    Guard,
    Middleware,
    AuthorizationCheck,
    IdentityExtraction,
    InvariantContract,
    Finding,
    UnresolvedCheck,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum EdgeRelation {
    BelongsToScope,
    RoutesTo,
    GuardedBy,
    WrappedBy,
    EnforcesCheck,
    ExtractsIdentity,
    ImplementsContract,
    ViolatesContract,
    FlagsRoute,
    UnresolvedEvidence,
    PotentialEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub relation: EdgeRelation,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuthorizationRelationshipGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

fn dot_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"").replace('\r', "\\r").replace('\n', "\\n")
}

impl AuthorizationRelationshipGraph {
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph ARCHER_Authorization_Graph {\n");
        dot.push_str("  rankdir=LR;\n");
        dot.push_str("  node [shape=box, style=rounded, fontname=\"Helvetica\"];\n");
        dot.push_str("  edge [fontname=\"Helvetica\", fontsize=10];\n\n");

        for node in &self.nodes {
            let (color, shape) = match node.kind {
                NodeKind::Scope => ("#e1d5e7", "folder"),
                NodeKind::Route => ("#dae8fc", "box"),
                NodeKind::Handler => ("#d5e8d4", "ellipse"),
                NodeKind::Guard => ("#ffe6cc", "diamond"),
                NodeKind::Middleware => ("#fff2cc", "hexagon"),
                NodeKind::AuthorizationCheck => ("#d5e8d4", "component"),
                NodeKind::IdentityExtraction => ("#f8cecc", "parallelogram"),
                NodeKind::InvariantContract => ("#e1d5e7", "septagon"),
                NodeKind::Finding => ("#f8cecc", "octagon"),
                NodeKind::UnresolvedCheck => ("#eeeeee", "diamond"),
            };
            dot.push_str(&format!(
                "  \"{}\" [label=\"{}\", fillcolor=\"{}\", style=\"filled,rounded\", shape={}];\n",
                dot_escape(&node.id),
                dot_escape(&node.label),
                color,
                shape
            ));
        }

        dot.push('\n');
        for edge in &self.edges {
            let style = match edge.relation {
                EdgeRelation::ViolatesContract => "color=\"red\", style=dashed",
                EdgeRelation::FlagsRoute => "color=\"red\", style=bold",
                _ => "color=\"#666666\"",
            };
            dot.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{:?}\", {}];\n",
                dot_escape(&edge.from), dot_escape(&edge.to), edge.relation, style
            ));
        }

        dot.push_str("}\n");
        dot
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffAnalysisReport {
    pub base_ref: String,
    pub changed_files: Vec<PathBuf>,
    pub affected_routes: Vec<RouteReference>,
    pub newly_introduced_drifts: Vec<Finding>,
    pub regressions: Vec<RouteRegression>,
    pub baseline_regression_checks: Vec<BaselineRegressionCheck>,
    pub baseline_comparison_routes: usize,
    pub unchanged_drifts: Vec<Finding>,
    pub resolved_drifts: Vec<Finding>,
    pub unverified_drifts: Vec<Finding>,
    pub base_summary: Option<AnalysisSummary>,
    pub current_summary: Option<AnalysisSummary>,
    pub analysis_warnings: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteRegression {
    pub route: RouteReference,
    pub reason: String,
}

/// A baseline-relative observation, not a standalone peer finding or vulnerability.
#[derive(Debug, Clone, Serialize)]
pub struct BaselineRegressionCheck {
    pub route: RouteReference,
    pub dimension: String,
    pub change: String,
    pub status: String,
    pub before: Vec<String>,
    pub after: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Serialize)]
pub struct HandlerResolutionEvidence {
    pub route: RouteReference,
    pub definition_file: Option<PathBuf>,
    pub definition_line: Option<usize>,
    pub definition_path: Option<String>,
    pub confidence: String,
}

#[derive(Debug, Serialize)]
pub struct Report {
    #[serde(skip_serializing)]
    pub local_rejections: Vec<security::LocalRejection>,
    pub candidate_relationships: Vec<policy_drift::Relationship>,
    pub review_observations: Vec<policy_drift::ReviewObservation>,
    pub check_comparisons: Vec<security::CheckContrast>,
    pub analysis_evidence: Vec<policy_drift::StageEvidence>,
    pub resource_evidence: Vec<policy_drift::ResourceEvidence>,
    pub handler_resolution_evidence: Vec<HandlerResolutionEvidence>,
    pub security_assessments: Vec<security::Assessment>,
    pub diagnostics: Vec<registration::Diagnostic>,
    pub files_scanned: usize,
    pub parse_errors: Vec<String>,
    pub routes: Vec<Route>,
    pub peer_groups: Vec<PeerGroup>,
    pub invariants: Vec<AuthorizationInvariant>,
    pub findings: Vec<String>,
    pub finding_details: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph: Option<AuthorizationRelationshipGraph>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<AnalysisSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_report: Option<DiffAnalysisReport>,
}

/// One lexical scope: a block, or the binding region of a function, closure,
/// loop, match arm, or `if let`/`while let`.
#[derive(Default)]
struct BlockScope {
    app_builders: HashMap<String, Expr>,
    nonsecurity_middleware: HashSet<String>,
    /// Value bindings in scope at the current point of the walk. A `let`
    /// binding is added only after its statement, so earlier statements and its
    /// own initializer are not shadowed.
    locals: HashSet<String>,
    /// Functions declared directly in a block. They are visible by bare name
    /// throughout that block, including before the declaration, but have no
    /// path and stay out of `HandlerIndex`. `None` marks a name that cannot be
    /// resolved to one function: a duplicate `fn`, or a `const`/`static`.
    items: HashMap<String, Option<Vec<AuthEvidence>>>,
}

impl BlockScope {
    fn with_locals(locals: HashSet<String>) -> Self {
        Self {
            app_builders: HashMap::new(),
            nonsecurity_middleware: HashSet::new(),
            locals,
            items: HashMap::new(),
        }
    }
}

struct RouteVisitor<'a> {
    application: Option<String>,
    conservative_security: bool,
    diagnostics: Vec<registration::Diagnostic>,
    mounted_routes: Vec<Route>,
    expansion_depth: usize,
    file: PathBuf,
    index: &'a HandlerIndex,
    crate_key: PathBuf,
    module: Vec<String>,
    block_scopes: Vec<BlockScope>,
    /// Guard and middleware evidence of the builder chains being visited,
    /// keyed by chain root: the current scope and its enclosing scopes.
    chain_scopes: Vec<(*const Expr, Vec<AuthEvidence>)>,
    scope_context: String,
    routes: Vec<Route>,
}

impl<'a> RouteVisitor<'a> {
    fn new(file: PathBuf, index: &'a HandlerIndex) -> Self {
        let (crate_key, module) = index
            .file_modules
            .get(&file)
            .cloned()
            .unwrap_or_else(|| (file.clone(), Vec::new()));
        Self {
            application: None,
            conservative_security: false,
            diagnostics: Vec::new(),
            mounted_routes: Vec::new(),
            expansion_depth: 0,
            file,
            index,
            crate_key,
            module,
            block_scopes: Vec::new(),
            chain_scopes: Vec::new(),
            scope_context: String::new(),
            routes: Vec::new(),
        }
    }

    /// Looks a bare handler name up in the enclosing scopes, innermost first;
    /// within a scope, local bindings shadow block items. `None` means no scope
    /// declares the name; `Some(None)` means the innermost declaring scope binds
    /// it to a local value or to more than one item, so it must not resolve.
    fn block_local_handler(&self, target: &HandlerTarget) -> Option<Option<&[AuthEvidence]>> {
        let HandlerTarget::Path {
            segments,
            leading_colon: false,
        } = target
        else {
            return None;
        };
        let [name] = segments.as_slice() else {
            return None;
        };
        self.block_scopes.iter().rev().find_map(|scope| {
            if scope.locals.contains(name) {
                Some(None)
            } else {
                scope.items.get(name).map(Option::as_deref)
            }
        })
    }

    fn with_locals(&mut self, locals: HashSet<String>, visit: impl FnOnce(&mut Self)) {
        self.block_scopes.push(BlockScope::with_locals(locals));
        visit(self);
        self.block_scopes.pop();
    }

    /// Visits an `if`/`while` condition. In a `let` chain, each operand sees
    /// the bindings of the `let`s before it, but not its own.
    fn visit_condition(&mut self, condition: &Expr, bound: &mut HashSet<String>) {
        match condition {
            Expr::Binary(binary) if matches!(binary.op, BinOp::And(_)) => {
                self.visit_condition(&binary.left, bound);
                self.visit_condition(&binary.right, bound);
            }
            Expr::Let(expr_let) => {
                self.with_locals(bound.clone(), |visitor| visitor.visit_expr(&expr_let.expr));
                pattern_bindings(&expr_let.pat, bound);
            }
            other => self.with_locals(bound.clone(), |visitor| visitor.visit_expr(other)),
        }
    }

    fn add_route(&mut self, node: &ExprMethodCall) {
        let name = node.method.to_string();
        if name != "route" && name != "resource" {
            return;
        }

        let Some(path) = first_string_arg(&node.args) else {
            self.diagnostic(
                "unsupported_registration",
                node.span().start().line,
                "Route path is not a supported string literal",
            );
            return;
        };

        let local_prefix = scope_prefix(&node.receiver);
        let prefix = join_paths(&self.scope_context, &local_prefix);
        let path = join_paths(&prefix, &path);
        let context = (self.crate_key.clone(), self.module.clone());
        let target = find_handler(&node.args, self.index, &context);
        let (handler_evidence, handler_resolution) = match &target {
            None => {
                self.diagnostic(
                    "unsupported_registration",
                    node.span().start().line,
                    "Route has no supported handler target; security enforcement is unknown",
                );
                (Vec::new(), None)
            }
            Some(target) => match self.block_local_handler(target) {
                Some(Some(evidence)) => (evidence.to_vec(), Some(HandlerResolution::Local)),
                Some(None) => (Vec::new(), Some(HandlerResolution::Unresolved)),
                None => {
                    let (definition, resolution) =
                        self.index
                            .resolve_handler(&self.crate_key, &self.module, target);
                    (
                        definition.map_or_else(Vec::new, |definition| definition.evidence.clone()),
                        Some(resolution),
                    )
                }
            },
        };
        let handler = target.as_ref().and_then(HandlerTarget::name);
        let mut authorization =
            classify_authorization(node, handler.as_deref(), &handler_evidence, &self.file);
        if target.is_none() {
            // Preserve the existing null handler-resolution JSON representation.
            // Missing registration evidence is uncertainty, never a public policy.
            authorization.push(AuthEvidence {
                kind: AuthEvidenceKind::Unknown,
                mechanism: "UnsupportedRegistration".into(),
                symbol: None,
                file: self.file.clone(),
                line: node.span().start().line,
                handler: None,
                strength: AuthStrength::Weak,
            });
        }
        if self.conservative_security {
            // A route builder argument is visited after add_route, so capture
            // its opaque middleware here without borrowing sibling arguments.
            for arg in node.args.iter().skip(1) {
                if let Expr::MethodCall(builder) = arg {
                    for mut evidence in security::unknown_middleware(builder, &self.file) {
                        evidence.handler = handler.clone();
                        if !authorization.contains(&evidence) {
                            authorization.push(evidence);
                        }
                    }
                }
            }
        }
        // Middleware and guards of this route's scope, wherever they appear in
        // its builder chain, and of every enclosing scope. Evidence already
        // found on the route's own receiver chain is not repeated.
        for inherited in self.chain_scopes.iter().flat_map(|(_, evidence)| evidence) {
            let mut inherited = inherited.clone();
            inherited.handler = handler.clone();
            if !authorization.contains(&inherited) {
                authorization.push(inherited);
            }
        }

        let line = first_string_arg_line(&node.args).unwrap_or_else(|| node.span().start().line);

        self.routes.push(Route {
            application: self.application.clone(),
            method: node
                .args
                .last()
                .and_then(|builder| {
                    registration::resolved_route_builder(self.index, &context, builder)
                })
                .as_ref()
                .and_then(route_builder_method)
                .unwrap_or_else(|| extract_http_method(node)),
            path,
            scope_prefix: prefix,
            handler,
            handler_path: target.as_ref().and_then(HandlerTarget::written),
            handler_resolution,
            authorization,
            line,
            file: self.file.clone(),
        });
    }
}

impl<'ast> Visit<'ast> for RouteVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.add_attribute_routes(node);
        let previous_application = self.application.clone();
        if self.application.is_none() {
            self.application = Some(format!(
                "declaration:{}:{}:{}",
                self.file.display(),
                self.module.join("::"),
                node.sig.ident
            ));
        }
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_item_fn(visitor, node)
        });
        self.application = previous_application;
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_impl_item_fn(visitor, node)
        });
    }

    fn visit_trait_item_fn(&mut self, node: &'ast TraitItemFn) {
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_trait_item_fn(visitor, node)
        });
    }

    fn visit_expr_closure(&mut self, node: &'ast ExprClosure) {
        let mut locals = HashSet::new();
        for input in &node.inputs {
            pattern_bindings(input, &mut locals);
        }
        self.with_locals(locals, |visitor| visit::visit_expr_closure(visitor, node));
    }

    fn visit_expr_for_loop(&mut self, node: &'ast ExprForLoop) {
        self.visit_expr(&node.expr);
        let mut locals = HashSet::new();
        pattern_bindings(&node.pat, &mut locals);
        self.with_locals(locals, |visitor| visitor.visit_block(&node.body));
    }

    fn visit_arm(&mut self, node: &'ast Arm) {
        // The pattern's bindings cover its guard (part of the pattern) and body.
        let mut locals = HashSet::new();
        pattern_bindings(&node.pat, &mut locals);
        self.with_locals(locals, |visitor| visit::visit_arm(visitor, node));
    }

    fn visit_expr_if(&mut self, node: &'ast ExprIf) {
        let mut bound = HashSet::new();
        self.visit_condition(&node.cond, &mut bound);
        self.with_locals(bound, |visitor| visitor.visit_block(&node.then_branch));
        if let Some((_, else_branch)) = &node.else_branch {
            self.visit_expr(else_branch);
        }
    }

    fn visit_expr_while(&mut self, node: &'ast ExprWhile) {
        let mut bound = HashSet::new();
        self.visit_condition(&node.cond, &mut bound);
        self.with_locals(bound, |visitor| visitor.visit_block(&node.body));
    }

    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if node.content.is_some() {
            // Items of an enclosing function block are not visible inside a module.
            let block_scopes = std::mem::take(&mut self.block_scopes);
            self.module.push(node.ident.to_string());
            visit::visit_item_mod(self, node);
            self.module.pop();
            self.block_scopes = block_scopes;
        }
    }

    fn visit_block(&mut self, node: &'ast Block) {
        let mut scope = BlockScope::default();
        for statement in &node.stmts {
            match statement {
                Stmt::Item(Item::Fn(function)) => {
                    scope
                        .items
                        .entry(function.sig.ident.to_string())
                        .and_modify(|entry| *entry = None)
                        .or_insert_with(|| Some(handler_evidence(&self.file, function)));
                }
                Stmt::Item(Item::Const(item)) => {
                    scope.items.insert(item.ident.to_string(), None);
                }
                Stmt::Item(Item::Static(item)) => {
                    scope.items.insert(item.ident.to_string(), None);
                }
                _ => {}
            }
        }
        self.block_scopes.push(scope);
        for statement in &node.stmts {
            self.visit_stmt(statement);
            if let Stmt::Local(local) = statement {
                let scope = self
                    .block_scopes
                    .last_mut()
                    .expect("block scope pushed above");
                pattern_bindings(&local.pat, &mut scope.locals);
                if let Pat::Ident(binding) = &local.pat {
                    scope.app_builders.remove(&binding.ident.to_string());
                    if binding.mutability.is_none() {
                        if let Some(init) = &local.init {
                            if registration::is_app_builder(&init.expr) {
                                scope
                                    .app_builders
                                    .insert(binding.ident.to_string(), (*init.expr).clone());
                            }
                        }
                    }
                    scope
                        .nonsecurity_middleware
                        .remove(&binding.ident.to_string());
                    if binding.mutability.is_none()
                        && local
                            .init
                            .as_ref()
                            .is_some_and(|init| security::known_nonsecurity_constructor(&init.expr))
                    {
                        scope
                            .nonsecurity_middleware
                            .insert(binding.ident.to_string());
                    }
                }
            }
        }
        self.block_scopes.pop();
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        // Expand only immutable, lexically scoped App values. Mutable/conditional
        // builders and arbitrary value aliases remain unsupported.
        let mut binding_root = &*node.receiver;
        while let Expr::MethodCall(call) = binding_root {
            binding_root = &call.receiver;
        }
        if let Expr::Path(path) = binding_root {
            if let Some(name) = path.path.get_ident() {
                let value = self
                    .block_scopes
                    .iter()
                    .rev()
                    .find(|s| s.locals.contains(&name.to_string()))
                    .and_then(|s| s.app_builders.get(&name.to_string()))
                    .cloned();
                if let Some(value) = value {
                    let mut expanded = node.clone();
                    fn replace_root(receiver: &mut Expr, value: Expr) {
                        match receiver {
                            Expr::MethodCall(call) => replace_root(&mut call.receiver, value),
                            _ => *receiver = value,
                        }
                    }
                    replace_root(&mut expanded.receiver, value);
                    self.visit_expr_method_call(&expanded);
                    return;
                }
            }
        }
        let previous_application = self.application.clone();
        let mut app_root = &*node.receiver;
        while let Expr::MethodCall(call) = app_root {
            app_root = &call.receiver;
        }
        if let Expr::Call(call) = app_root {
            if matches!(&*call.func, Expr::Path(p) if p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().ends_with(&["App".into(), "new".into()]))
            {
                self.application = Some(format!(
                    "{}:{}:{}",
                    self.file.display(),
                    call.span().start().line,
                    call.span().start().column
                ));
            }
        }
        if node.method == "wrap"
            && node
                .args
                .iter()
                .any(|arg| route_configuration_name_in_expr(arg).is_none())
        {
            self.diagnostic("unresolved_middleware", node.span().start().line, "Middleware has no security model; absence of recognized evidence does not prove it is non-security middleware");
        }
        if self.visit_resource_registration(node) {
            self.application = previous_application;
            return;
        }
        // The outermost call of a builder chain is visited first; collect the
        // chain's guards and middleware there so that every route in the chain,
        // and in scopes nested under it, receives them.
        let root = chain_root(node);
        let starts_chain = self.chain_scopes.last().map(|(chain, _)| *chain) != Some(root);
        if starts_chain {
            let mut evidence = chain_configuration_evidence(node, &self.file);
            if self.conservative_security {
                evidence.extend(
                    security::unknown_middleware(node, &self.file)
                        .into_iter()
                        .filter(|e| {
                            !e.symbol.as_ref().is_some_and(|name| {
                                self.block_scopes
                                    .iter()
                                    .rev()
                                    .find(|s| s.locals.contains(name))
                                    .is_some_and(|s| s.nonsecurity_middleware.contains(name))
                            })
                        }),
                );
            }
            self.chain_scopes.push((root, evidence));
        }

        if node.method == "configure" {
            self.expand_configuration(node);
            self.visit_expr(&node.receiver);
        } else if node.method == "service" {
            let previous_context = self.scope_context.clone();
            self.scope_context = join_paths(&previous_context, &scope_prefix(&node.receiver));
            for arg in &node.args {
                if !self.expand_service(arg) {
                    self.visit_expr(arg);
                }
            }
            self.scope_context = previous_context;
            self.visit_expr(&node.receiver);
        } else {
            self.add_route(node);
            visit::visit_expr_method_call(self, node);
        }

        if starts_chain {
            self.chain_scopes.pop();
        }
        self.application = previous_application;
    }
}

pub(super) struct AttributeRouteInfo {
    pub(super) path: String,
    pub(super) methods: Vec<String>,
    pub(super) line: usize,
    modifiers: Vec<String>,
}

fn attribute_route_name(attribute: &syn::Attribute) -> Option<String> {
    let path = attribute.path();
    if !(path.segments.len() == 1
        || (path.segments.len() == 2 && path.segments[0].ident == "actix_web"))
    {
        return None;
    }
    let name = path.segments.last()?.ident.to_string();
    matches!(
        name.as_str(),
        "get"
            | "post"
            | "put"
            | "patch"
            | "delete"
            | "head"
            | "options"
            | "trace"
            | "connect"
            | "route"
    )
    .then_some(name)
}

pub(super) fn parse_attribute_route(attribute: &syn::Attribute) -> Option<AttributeRouteInfo> {
    let name = attribute_route_name(attribute)?;
    let args = attribute
        .parse_args_with(syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        .ok()?;
    let Expr::Lit(ExprLit {
        lit: Lit::Str(path),
        ..
    }) = args.first()?
    else {
        return None;
    };
    let mut methods = if name == "route" {
        Vec::new()
    } else {
        vec![name.to_uppercase()]
    };
    let mut modifiers = Vec::new();
    for arg in args.iter().skip(1) {
        let Expr::Assign(assign) = arg else {
            return None;
        };
        let Expr::Path(key) = &*assign.left else {
            return None;
        };
        let Expr::Lit(ExprLit {
            lit: Lit::Str(value),
            ..
        }) = &*assign.right
        else {
            return None;
        };
        if key.path.is_ident("method") && name == "route" {
            let method = value.value();
            if !matches!(
                method.as_str(),
                "GET"
                    | "POST"
                    | "PUT"
                    | "PATCH"
                    | "DELETE"
                    | "HEAD"
                    | "OPTIONS"
                    | "TRACE"
                    | "CONNECT"
            ) {
                return None;
            }
            if !methods.contains(&method) {
                methods.push(method);
            }
        } else if key.path.is_ident("wrap") || key.path.is_ident("guard") {
            modifiers.push(format!("{} = {}", key.to_token_stream(), value.value()));
        } else {
            return None;
        }
    }
    // A generic route attribute must supply methods; never invent GET.
    if methods.is_empty() {
        return None;
    }
    Some(AttributeRouteInfo {
        path: path.value(),
        methods,
        line: path.span().start().line,
        modifiers,
    })
}

impl RouteVisitor<'_> {
    fn add_attribute_routes(&mut self, node: &ItemFn) {
        for attribute in &node.attrs {
            // An explicit conflicting/foreign import overrides a bare macro name.
            // Do not treat another framework's `get` as Actix registration.
            if attribute.path().segments.len() == 1 {
                let name = attribute.path().segments[0].ident.to_string();
                if let Some(imports) = self
                    .index
                    .scopes
                    .get(&(self.crate_key.clone(), self.module.clone()))
                    .and_then(|scope| scope.imports.get(&name))
                {
                    if imports.len() != 1
                        || imports[0].segments != ["actix_web".to_string(), name.clone()]
                    {
                        if attribute_route_name(attribute).is_some() {
                            self.diagnostic(
                                "unsupported_attribute",
                                attribute.span().start().line,
                                "Route attribute import is foreign, renamed or ambiguous",
                            );
                        }
                        continue;
                    }
                }
            }
            let Some(info) = parse_attribute_route(attribute) else {
                if attribute_route_name(attribute).is_some() {
                    self.diagnostic("unsupported_attribute", attribute.span().start().line,
                        "Route attribute requires a literal path, explicit valid methods and supported literal arguments");
                }
                continue;
            };

            let prefix = self.scope_context.clone();
            let path = join_paths(&prefix, &info.path);
            let handler = node.sig.ident.to_string();
            let mut authorization = handler_evidence(&self.file, node);
            for modifier in info.modifiers {
                authorization.push(AuthEvidence {
                    kind: AuthEvidenceKind::Unknown,
                    mechanism: "UnresolvedAttributeConfiguration".into(),
                    symbol: Some(modifier),
                    file: self.file.clone(),
                    line: info.line,
                    handler: Some(handler.clone()),
                    strength: AuthStrength::Weak,
                });
            }

            for method in info.methods {
                self.routes.push(Route {
                    application: self.application.clone(),
                    method,
                    path: path.clone(),
                    scope_prefix: prefix.clone(),
                    authorization: authorization.clone(),
                    handler_path: Some(handler.clone()),
                    handler_resolution: Some(HandlerResolution::Definition),
                    handler: Some(handler.clone()),
                    line: info.line,
                    file: self.file.clone(),
                });
            }
        }
    }
}

fn first_string_arg(args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>) -> Option<String> {
    let first = args.first()?;
    match first {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Some(s.value()),
        _ => None,
    }
}

fn first_string_arg_line(
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<usize> {
    let first = args.first()?;
    match first {
        Expr::Lit(ExprLit {
            lit: Lit::Str(s), ..
        }) => Some(s.span().start().line),
        _ => None,
    }
}

/// Method-specific `Route` constructors provided by `actix_web::web`.
const ROUTE_METHOD_CONSTRUCTORS: [&str; 7] =
    ["get", "post", "put", "patch", "delete", "head", "trace"];

/// `http::Method` constants accepted by `web::method(...)` and `Route::method(...)`.
const HTTP_METHOD_CONSTANTS: [&str; 9] = [
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

/// Reads the HTTP method from a route's builder (its last argument). Only the
/// builder's own call chain is followed, so calls nested in guard, handler, or
/// configuration arguments cannot supply the method.
fn extract_http_method(expr: &ExprMethodCall) -> String {
    expr.args
        .last()
        .and_then(route_builder_method)
        .unwrap_or_else(|| "UNKNOWN".into())
}

fn route_builder_method(builder: &Expr) -> Option<String> {
    let mut methods = Vec::new();
    let mut expr = builder;
    let root = loop {
        match expr {
            Expr::MethodCall(call) => {
                // `Route::method` adds a method guard; other builder calls
                // (`to`, `guard`, ...) do not constrain the method.
                if call.method == "method" {
                    methods.push(method_constant(call.args.first()?)?);
                }
                expr = &call.receiver;
            }
            Expr::Paren(paren) => expr = &paren.expr,
            Expr::Group(group) => expr = &group.expr,
            Expr::Call(call) => break call,
            _ => return None,
        }
    };

    let Expr::Path(function) = &*root.func else {
        return None;
    };
    if function.qself.is_some() {
        return None;
    }
    let segments: Vec<String> = function
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    let (name, module) = segments.split_last()?;
    let module: Vec<&str> = module.iter().map(String::as_str).collect();
    let web_function = matches!(module.as_slice(), [] | ["web"] | ["actix_web", "web"]);
    let any_method_route = (web_function && name == "route")
        || (matches!(module.as_slice(), ["Route"] | ["actix_web", "Route"]) && name == "new");

    if web_function && ROUTE_METHOD_CONSTRUCTORS.contains(&name.as_str()) {
        methods.push(name.to_uppercase());
    } else if web_function && name == "method" {
        methods.push(method_constant(root.args.first()?)?);
    } else if !any_method_route {
        // Not a recognized `Route` constructor.
        return None;
    }

    methods.dedup();
    match methods.as_slice() {
        [method] => Some(method.clone()),
        // An any-method route without a method guard, or conflicting guards.
        _ => None,
    }
}

/// Reads `Method::PUT`, `http::Method::PUT`, or `actix_web::http::Method::PUT`.
fn method_constant(expr: &Expr) -> Option<String> {
    let Expr::Path(path) = expr else {
        return None;
    };
    let segments: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    match segments.as_slice() {
        [.., kind, method]
            if kind == "Method" && HTTP_METHOD_CONSTANTS.contains(&method.as_str()) =>
        {
            Some(method.clone())
        }
        _ => None,
    }
}

fn classify_authorization(
    route_expr: &ExprMethodCall,
    handler: Option<&str>,
    handler_evidence: &[AuthEvidence],
    file: &Path,
) -> Vec<AuthEvidence> {
    let mut evidence = route_configuration_evidence(route_expr, file, handler);
    evidence.extend(handler_evidence.iter().cloned());
    evidence
}

fn route_configuration_evidence(
    route_expr: &ExprMethodCall,
    file: &Path,
    handler: Option<&str>,
) -> Vec<AuthEvidence> {
    let mut evidence = Vec::new();
    for arg in &route_expr.args {
        visit_route_configuration(arg, file, handler, &mut evidence);
    }
    visit_scope_configuration(&route_expr.receiver, file, handler, &mut evidence);
    evidence
}

fn visit_route_configuration(
    expr: &Expr,
    file: &Path,
    handler: Option<&str>,
    evidence: &mut Vec<AuthEvidence>,
) {
    match expr {
        Expr::MethodCall(method) => {
            configuration_call_evidence(method, file, handler, evidence);
            visit_route_configuration(&method.receiver, file, handler, evidence);
            for arg in &method.args {
                visit_route_configuration(arg, file, handler, evidence);
            }
        }
        Expr::Paren(paren) => visit_route_configuration(&paren.expr, file, handler, evidence),
        Expr::Group(group) => visit_route_configuration(&group.expr, file, handler, evidence),
        _ => {}
    }
}

fn visit_scope_configuration(
    expr: &Expr,
    file: &Path,
    handler: Option<&str>,
    evidence: &mut Vec<AuthEvidence>,
) {
    // Walk the scope's own builder chain. Sibling `.route(...)`, `.resource(...)`,
    // and `.service(...)` registrations are passed through without reading
    // their arguments, so one route's guards never apply to another.
    let Expr::MethodCall(method) = expr else {
        return;
    };
    configuration_call_evidence(method, file, handler, evidence);
    visit_scope_configuration(&method.receiver, file, handler, evidence);
}

/// Records evidence from one `.guard(...)` or `.wrap(...)` call's arguments.
fn configuration_call_evidence(
    method: &ExprMethodCall,
    file: &Path,
    handler: Option<&str>,
    evidence: &mut Vec<AuthEvidence>,
) {
    let (authorization_kind, authorization_strength) = match method.method.to_string().as_str() {
        "guard" => (AuthEvidenceKind::AuthorizationGuard, AuthStrength::Strong),
        "wrap" => (
            AuthEvidenceKind::AuthorizationMiddleware,
            AuthStrength::Medium,
        ),
        _ => return,
    };
    for arg in &method.args {
        let Some((class, identifier)) = route_configuration_name_in_expr(arg) else {
            continue;
        };
        // Authentication-only guards and middleware establish who the caller
        // is, not what they may do.
        let (kind, strength) = match class {
            RouteConfigurationName::Authorization => {
                (authorization_kind.clone(), authorization_strength.clone())
            }
            RouteConfigurationName::Authentication => {
                (AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak)
            }
        };
        evidence.push(AuthEvidence {
            kind,
            mechanism: identifier.name.clone(),
            symbol: Some(if matches!(arg, Expr::Call(_)) { arg.to_token_stream().to_string() } else { identifier.name }),
            file: file.to_path_buf(),
            line: identifier.line,
            handler: handler.map(str::to_owned),
            strength,
        });
    }
}

/// Evidence from every `.guard(...)` / `.wrap(...)` call in a builder chain,
/// starting at its outermost call. Actix applies a scope's middleware to all
/// of the scope's routes, wherever the call appears in the chain.
fn chain_configuration_evidence(outermost: &ExprMethodCall, file: &Path) -> Vec<AuthEvidence> {
    let mut evidence = Vec::new();
    let mut call = outermost;
    loop {
        configuration_call_evidence(call, file, None, &mut evidence);
        match &*call.receiver {
            Expr::MethodCall(receiver) => call = receiver,
            _ => return evidence,
        }
    }
}

/// The expression a method-call chain starts from (`web::scope("/s")` in
/// `web::scope("/s").wrap(X).route(...)`); it identifies the chain.
fn chain_root(call: &ExprMethodCall) -> *const Expr {
    let mut expr = &*call.receiver;
    while let Expr::MethodCall(receiver) = expr {
        expr = &receiver.receiver;
    }
    expr
}

/// Collects the names a pattern binds. A bare identifier is always counted,
/// even when it names a unit variant or constant (`None`), which can only make
/// handler resolution more conservative. Macro and verbatim patterns are opaque.
fn pattern_bindings(pat: &Pat, names: &mut HashSet<String>) {
    match pat {
        Pat::Ident(pat) => {
            names.insert(pat.ident.to_string());
            if let Some((_, subpattern)) = &pat.subpat {
                pattern_bindings(subpattern, names);
            }
        }
        Pat::Guard(pat) => pattern_bindings(&pat.pat, names),
        Pat::Or(pat) => pat
            .cases
            .iter()
            .for_each(|case| pattern_bindings(case, names)),
        Pat::Paren(pat) => pattern_bindings(&pat.pat, names),
        Pat::Reference(pat) => pattern_bindings(&pat.pat, names),
        Pat::Slice(pat) => pat
            .elems
            .iter()
            .for_each(|element| pattern_bindings(element, names)),
        Pat::Struct(pat) => pat
            .fields
            .iter()
            .for_each(|field| pattern_bindings(&field.pat, names)),
        Pat::Tuple(pat) => pat
            .elems
            .iter()
            .for_each(|element| pattern_bindings(element, names)),
        Pat::TupleStruct(pat) => pat
            .elems
            .iter()
            .for_each(|element| pattern_bindings(element, names)),
        Pat::Type(pat) => pattern_bindings(&pat.pat, names),
        _ => {}
    }
}

fn signature_bindings(signature: &Signature) -> HashSet<String> {
    let mut names = HashSet::new();
    for input in &signature.inputs {
        if let FnArg::Typed(argument) = input {
            pattern_bindings(&argument.pat, &mut names);
        }
    }
    names
}

fn handler_evidence(file: &Path, item: &ItemFn) -> Vec<AuthEvidence> {
    let mut visitor = AuthEvidenceVisitor::new(file, &item.sig.ident.to_string());
    visitor.visit_block(&item.block);
    visitor.evidence
}

/// Name-keyed evidence map used by evidence-classification tests. Route
/// analysis resolves handlers through `HandlerIndex` instead.
#[cfg(test)]
fn collect_authorized_handlers(
    file_path: &Path,
    file: &syn::File,
) -> HashMap<String, Vec<AuthEvidence>> {
    let mut visitor = FunctionVisitor {
        file: file_path.to_path_buf(),
        ..Default::default()
    };
    visitor.visit_file(file);
    visitor.authorized_handlers
}

#[cfg(test)]
#[derive(Default)]
struct FunctionVisitor {
    file: PathBuf,
    authorized_handlers: HashMap<String, Vec<AuthEvidence>>,
}

#[cfg(test)]
impl<'ast> Visit<'ast> for FunctionVisitor {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let evidence = handler_evidence(&self.file, item);
        if !evidence.is_empty() {
            self.authorized_handlers
                .insert(item.sig.ident.to_string(), evidence);
        }
        visit::visit_item_fn(self, item);
    }
}

type ModuleKey = (PathBuf, Vec<String>);

const MAX_RESOLUTION_DEPTH: usize = 16;

#[derive(Clone)]
struct HandlerDefinition {
    file: PathBuf,
    function: ItemFn,
    crate_key: PathBuf,
    module: Vec<String>,
    name: String,
    evidence: Vec<AuthEvidence>,
    owner: Option<ModuleKey>,
    implemented_trait: Option<ModuleKey>,
}

impl std::fmt::Debug for HandlerDefinition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerDefinition")
            .field("name", &self.name)
            .field("file", &self.file)
            .finish()
    }
}

impl HandlerDefinition {
    fn rust_path(&self) -> String {
        std::iter::once("crate")
            .chain(
                self.owner
                    .as_ref()
                    .map(|k| &k.1)
                    .unwrap_or(&self.module)
                    .iter()
                    .map(String::as_str),
            )
            .chain(std::iter::once(self.name.as_str()))
            .collect::<Vec<_>>()
            .join("::")
    }
}

#[derive(Debug, Clone)]
struct UsePath {
    segments: Vec<String>,
    leading_colon: bool,
}

#[derive(Debug, Default)]
struct ModuleScope {
    imports: HashMap<String, Vec<UsePath>>,
    globs: Vec<UsePath>,
    public_imports: HashSet<String>,
    public_globs: Vec<UsePath>,
}

enum Lookup {
    Found(usize, HandlerResolution),
    Ambiguous(Vec<usize>),
    /// `explicit` marks lookups that an explicit import or an unresolvable
    /// path already pinned to something outside the index; these never fall
    /// back to unique-name matching.
    NotFound {
        explicit: bool,
    },
}

/// Every free function in the scanned repository, keyed by crate and module
/// path, together with each module's `use` declarations.
#[derive(Default)]
struct HandlerIndex {
    definitions: Vec<HandlerDefinition>,
    by_name: HashMap<String, Vec<usize>>,
    scopes: HashMap<ModuleKey, ModuleScope>,
    modules: HashSet<ModuleKey>,
    file_modules: HashMap<PathBuf, ModuleKey>,
    dependencies: HashMap<(PathBuf, String), PathBuf>,
    public_modules: HashSet<ModuleKey>,
    record_types: HashSet<ModuleKey>,
    pending_impls: Vec<(PathBuf, ModuleKey, syn::ItemImpl)>,
    traits: HashMap<ModuleKey, (PathBuf, syn::ItemTrait)>,
    type_aliases: HashMap<ModuleKey, syn::ItemType>,
    conditional_result_kinds: HashSet<ModuleKey>,
    methods: Vec<usize>,
    record_attributes: HashMap<ModuleKey, Vec<syn::Attribute>>,
    record_fields: HashMap<ModuleKey, HashMap<String, (syn::Type, bool)>>,
    schema_macros: Vec<(ModuleKey, syn::ItemMacro)>,
    macro_uses: Vec<(ModuleKey, String)>,
    diesel_tables: HashSet<ModuleKey>,
}

impl HandlerIndex {
    fn attach_conditional_result_aliases(&mut self) {
        // Model only standard cfg_select's configuration-invariant Result aliases.
        // No feature is selected and no arbitrary macro body is expanded.
        struct Branches(Vec<Vec<Item>>);
        impl syn::parse::Parse for Branches {
            fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
                let mut branches = Vec::new();
                while !input.is_empty() {
                    while !input.peek(syn::Token![=>]) {
                        let _: proc_macro2::TokenTree = input.parse()?;
                    }
                    let _: syn::Token![=>] = input.parse()?;
                    let body;
                    syn::braced!(body in input);
                    let mut items = Vec::new();
                    while !body.is_empty() {
                        items.push(body.parse()?);
                    }
                    branches.push(items);
                    if input.peek(syn::Token![,]) {
                        let _: syn::Token![,] = input.parse()?;
                    }
                }
                Ok(Self(branches))
            }
        }
        fn shadows(tree: &UseTree, name: &str) -> bool {
            match tree {
                UseTree::Path(p) => shadows(&p.tree, name),
                UseTree::Name(n) => n.ident == name,
                UseTree::Rename(r) => r.rename == name,
                UseTree::Group(g) => g.items.iter().any(|u| shadows(u, name)),
                UseTree::Glob(_) => true,
            }
        }
        let mut additions = Vec::new();
        for (context, item) in &self.schema_macros {
            if !matches!(
                security::external_path(self, context, &item.mac.path, 0).as_deref(),
                Some("cfg_select" | "std::cfg_select")
            ) {
                continue;
            }
            if self.macro_uses.iter().any(|(c, _)| c.0 == context.0)
                || self.schema_macros.iter().any(|(c, m)| {
                    c.0 == context.0
                        && m.mac.path.is_ident("macro_rules")
                        && m.ident.as_ref().is_some_and(|n| n == "cfg_select")
                })
            {
                continue;
            }
            let Ok(Branches(branches)) = syn::parse2(item.mac.tokens.clone()) else {
                continue;
            };
            let mut aliases: HashMap<String, Vec<&syn::ItemType>> = HashMap::new();
            for branch in &branches {
                for item in branch {
                    if let Item::Type(alias) = item {
                        aliases
                            .entry(alias.ident.to_string())
                            .or_default()
                            .push(alias);
                    }
                }
            }
            for (name, definitions) in aliases {
                let first = definitions[0];
                if !definitions.iter().all(|d| {
                    d.ty.to_token_stream().to_string() == first.ty.to_token_stream().to_string()
                        && d.generics.to_token_stream().to_string()
                            == first.generics.to_token_stream().to_string()
                }) {
                    continue;
                }
                if branches.iter().any(|b| {
                    b.iter()
                        .filter(|i| matches!(i,Item::Type(t) if t.ident==name))
                        .count()
                        > 1
                }) {
                    continue;
                }
                let syn::Type::Path(p) = &*first.ty else {
                    continue;
                };
                let Some(root) = p.path.segments.first() else {
                    continue;
                };
                if first.generics.type_params().any(|p| p.ident == root.ident) {
                    continue;
                }
                if !matches!(
                    security::external_path(self, context, &p.path, 0).as_deref(),
                    Some("Result" | "std::result::Result" | "core::result::Result")
                ) {
                    continue;
                }
                if branches.iter().flatten().any(|i| match i {
                    Item::Use(u) => shadows(&u.tree, &root.ident.to_string()),
                    Item::Type(t) => t.ident == root.ident,
                    Item::Struct(t) => t.ident == root.ident,
                    Item::Enum(t) => t.ident == root.ident,
                    Item::Mod(t) => t.ident == root.ident,
                    Item::Trait(t) => t.ident == root.ident,
                    Item::Union(t) => t.ident == root.ident,
                    Item::ExternCrate(t) => {
                        t.rename.as_ref().map(|(_, n)| n).unwrap_or(&t.ident) == &root.ident
                    }
                    Item::Macro(_) => true,
                    _ => false,
                }) {
                    continue;
                }
                let mut path = context.1.clone();
                path.push(name);
                let key = (context.0.clone(), path);
                if !self.modules.contains(&key) {
                    additions.push((key, first.clone()));
                }
            }
        }
        let mut counts = HashMap::new();
        for (k, _) in &additions {
            *counts.entry(k.clone()).or_insert(0usize) += 1;
        }
        for (key, alias) in additions {
            if counts[&key] != 1 {
                continue;
            }
            self.modules.insert(key.clone());
            if matches!(alias.vis, syn::Visibility::Public(_)) {
                self.public_modules.insert(key.clone());
            }
            // This proves Result's control-flow kind, not a complete expanded
            // payload/record definition. Do not turn it into resource identity.
            self.conditional_result_kinds.insert(key);
        }
    }

    fn attach_diesel_tables(&mut self) {
        // Parse only the public table!/dsl declaration contract. This is not a
        // macro expander and does not manufacture model-to-table associations.
        struct Declaration {
            name: String,
        }
        impl syn::parse::Parse for Declaration {
            fn parse(input: syn::parse::ParseStream<'_>) -> syn::Result<Self> {
                while input.peek(syn::Token![use]) {
                    let _: syn::ItemUse = input.parse()?;
                }
                let _ = input.call(syn::Attribute::parse_outer)?;
                let visibility: syn::Visibility = input.parse()?;
                if matches!(visibility, syn::Visibility::Restricted(_)) {
                    return Err(input.error("restricted schema visibility is not modeled"));
                }
                let mut name: syn::Ident = input.parse()?;
                if input.peek(syn::Token![.]) {
                    let _: syn::Token![.] = input.parse()?;
                    name = input.parse()?;
                }
                let keys = if input.peek(syn::token::Paren) {
                    let content;
                    syn::parenthesized!(content in input);
                    content
                        .parse_terminated(|p| p.parse::<syn::Ident>(), syn::Token![,])?
                        .into_iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                } else {
                    vec!["id".into()]
                };
                let content;
                syn::braced!(content in input);
                let mut columns = HashSet::new();
                while !content.is_empty() {
                    let _ = content.call(syn::Attribute::parse_outer)?;
                    let column: syn::Ident = content.parse()?;
                    let _: syn::Token![->] = content.parse()?;
                    let _: syn::Type = content.parse()?;
                    if !columns.insert(column.to_string()) {
                        return Err(content.error("duplicate column"));
                    }
                    if !content.is_empty() {
                        let _: syn::Token![,] = content.parse()?;
                    }
                }
                if keys.is_empty() || !keys.iter().all(|k| columns.contains(k)) {
                    return Err(input.error("unresolved primary key"));
                }
                Ok(Self {
                    name: name.to_string(),
                })
            }
        }
        let mut declarations: HashMap<ModuleKey, usize> = HashMap::new();
        for (context, item) in &self.schema_macros {
            let qualified = security::external_path(self, context, &item.mac.path, 0).as_deref()
                == Some("diesel::table");
            let visible: Vec<_> = self
                .macro_uses
                .iter()
                .filter(|(key, _)| key.0 == context.0 && context.1.starts_with(&key.1))
                .collect();
            let bare = item.mac.path.is_ident("table")
                && visible.len() == 1
                && visible[0].1 == "diesel"
                && !self
                    .dependencies
                    .contains_key(&(context.0.clone(), "diesel".into()))
                && !self.schema_macros.iter().any(|(key, m)| {
                    key.0 == context.0
                        && m.mac.path.is_ident("macro_rules")
                        && m.ident.as_ref().is_some_and(|n| n == "table")
                })
                && self
                    .scope(&context.0, &context.1)
                    .is_none_or(|s| s.globs.is_empty() && !s.imports.contains_key("table"));
            if !qualified && !bare {
                continue;
            }
            let Ok(declaration) = syn::parse2::<Declaration>(item.mac.tokens.clone()) else {
                continue;
            };
            let mut path = context.1.clone();
            path.push(declaration.name);
            *declarations.entry((context.0.clone(), path)).or_default() += 1;
        }
        for (table, count) in declarations {
            if count != 1 || self.modules.contains(&table) {
                continue;
            }
            let mut dsl = table.1.clone();
            dsl.push("dsl".into());
            let dsl = (table.0.clone(), dsl);
            self.modules.insert(table.clone());
            self.modules.insert(dsl.clone());
            self.public_modules.insert(table.clone());
            self.public_modules.insert(dsl.clone());
            let path = UsePath {
                segments: std::iter::once("crate".into())
                    .chain(table.1.iter().cloned())
                    .collect(),
                leading_colon: false,
            };
            for (key, name) in [
                (table.clone(), "table".to_owned()),
                (dsl, table.1.last().unwrap().clone()),
            ] {
                let scope = self.scopes.entry(key).or_default();
                scope.public_imports.insert(name.clone());
                scope.imports.entry(name).or_default().push(path.clone());
            }
            self.diesel_tables.insert(table);
        }
    }

    fn route_handler(&self, route: &Route) -> Option<&HandlerDefinition> {
        if matches!(
            route.handler_resolution,
            Some(HandlerResolution::Unresolved | HandlerResolution::Ambiguous { .. })
        ) {
            return None;
        }
        let (crate_key, module) = self.file_modules.get(&route.file)?;
        let path = route.handler_path.as_ref()?;
        self.resolve_handler(
            crate_key,
            module,
            &HandlerTarget::Path {
                segments: path
                    .trim_start_matches("::")
                    .split("::")
                    .map(str::to_owned)
                    .collect(),
                leading_colon: path.starts_with("::"),
            },
        )
        .0
        .or_else(|| {
            let mut matches = self
                .definitions
                .iter()
                .filter(|d| d.file == route.file && Some(&d.name) == route.handler.as_ref());
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        })
    }
    fn build<'a>(files: impl IntoIterator<Item = (&'a Path, ModuleKey, &'a syn::File)>) -> Self {
        let mut index = Self::default();
        for (file, (crate_key, mut module), syntax) in files {
            for depth in 0..=module.len() {
                index
                    .modules
                    .insert((crate_key.clone(), module[..depth].to_vec()));
            }
            index
                .file_modules
                .insert(file.to_path_buf(), (crate_key.clone(), module.clone()));
            index.add_items(file, &crate_key, &mut module, &syntax.items);
        }
        index.attach_impls();
        index
    }

    fn load_workspace(&mut self, root: &Path) -> Option<String> {
        let start = if root.is_file() { root.parent()? } else { root };
        let manifest = start
            .ancestors()
            .map(|p| p.join("Cargo.toml"))
            .find(|p| p.is_file())?;
        let output = std::process::Command::new("cargo")
            .args([
                "metadata",
                "--frozen",
                "--no-deps",
                "--format-version",
                "1",
                "--manifest-path",
            ])
            .arg(&manifest)
            .output();
        let metadata = output
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| serde_json::from_slice::<serde_json::Value>(&o.stdout).ok());
        let Some(metadata) = metadata else {
            return Some(
                "Offline Cargo metadata unavailable; cross-crate resolution abstains".into(),
            );
        };
        let keys: HashMap<_, _> = self
            .modules
            .iter()
            .filter_map(|(key, _)| {
                key.canonicalize()
                    .ok()
                    .map(|canonical| (canonical, key.clone()))
            })
            .collect();
        let packages = metadata["packages"].as_array()?;
        for package in packages {
            let Some(directory) = package["manifest_path"]
                .as_str()
                .and_then(|p| Path::new(p).parent())
                .and_then(|p| p.canonicalize().ok())
            else {
                continue;
            };
            let Some(source) = keys.get(&directory) else {
                continue;
            };
            if let Some(deps) = package["dependencies"].as_array() {
                for dep in deps {
                    if dep["kind"].as_str() == Some("dev") {
                        continue;
                    }
                    let Some(target) = dep["path"]
                        .as_str()
                        .and_then(|p| Path::new(p).canonicalize().ok())
                        .and_then(|p| keys.get(&p))
                    else {
                        continue;
                    };
                    let Some(name) = dep["rename"].as_str().or_else(|| dep["name"].as_str()) else {
                        continue;
                    };
                    self.dependencies
                        .insert((source.clone(), name.replace('-', "_")), target.clone());
                }
            }
        }
        self.attach_impls();
        None
    }

    fn exported_lookup(&self, target: &ModuleKey, name: &str, lookup: Lookup) -> Lookup {
        // Cross-crate access must be through public modules and exported items.
        let scope = self.scope(&target.0, &target.1);
        let public_item = if scope.is_some_and(|s| s.imports.contains_key(name)) {
            scope.is_some_and(|s| s.public_imports.contains(name))
        } else {
            matches!(&lookup, Lookup::Found(i, _) if {
                let d = &self.definitions[*i];
                matches!(d.function.vis, syn::Visibility::Public(_)) &&
                ((d.crate_key == target.0 && d.owner.as_ref().map(|k| k.1.as_slice()).unwrap_or(&d.module) == target.1) || scope.is_some_and(|s|
                    s.public_globs.iter().any(|glob| self.resolve_module(&target.0, &target.1, glob, 0)
                        .is_some_and(|m| m.0 == d.crate_key && m.1 == d.module))))
            })
        };
        if public_item {
            lookup
        } else {
            Lookup::NotFound { explicit: true }
        }
    }

    fn attach_impls(&mut self) {
        for (file, lexical, item) in self.pending_impls.clone() {
            // Generic specialization, blanket impls and trait-object dispatch
            // require type inference we do not have. Lifetimes alone are safe.
            if item.generics.type_params().next().is_some()
                || item.generics.const_params().next().is_some()
            {
                continue;
            }
            let syn::Type::Path(ty) = &*item.self_ty else {
                continue;
            };
            if ty.path.segments.iter().any(|s| matches!(&s.arguments, syn::PathArguments::AngleBracketed(a) if a.args.iter().any(|g| !matches!(g, syn::GenericArgument::Lifetime(_))))) { continue; }
            let path = UsePath {
                segments: ty
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect(),
                leading_colon: ty.path.leading_colon.is_some(),
            };
            let Some(owner) = self
                .resolve_module(&lexical.0, &lexical.1, &path, 0)
                .filter(|k| self.record_types.contains(k))
            else {
                continue;
            };
            let implemented_trait = if let Some((path, _)) = &item.trait_ {
                let path = UsePath {
                    segments: path.segments.iter().map(|s| s.ident.to_string()).collect(),
                    leading_colon: path.leading_colon.is_some(),
                };
                let Some(key) = self
                    .resolve_module(&lexical.0, &lexical.1, &path, 0)
                    .filter(|k| self.traits.contains_key(k))
                else {
                    continue;
                };
                Some(key)
            } else {
                None
            };
            let mut methods: Vec<(ItemFn, ModuleKey, PathBuf)> = item
                .items
                .iter()
                .filter_map(|member| {
                    let syn::ImplItem::Fn(method) = member else {
                        return None;
                    };
                    let function = syn::parse2::<ItemFn>(method.to_token_stream()).ok()?;
                    Some((function, lexical.clone(), file.clone()))
                })
                .collect();
            if let Some(key) = &implemented_trait {
                if let Some((trait_file, definition)) = self.traits.get(key) {
                    for member in &definition.items {
                        let syn::TraitItem::Fn(method) = member else {
                            continue;
                        };
                        let Some(body) = &method.default else {
                            continue;
                        };
                        if item.items.iter().any(|m| matches!(m, syn::ImplItem::Fn(m) if m.sig.ident == method.sig.ident)) { continue; }
                        let sig = &method.sig;
                        if let Ok(function) = syn::parse2::<ItemFn>(quote::quote!(#sig #body)) {
                            methods.push((
                                function,
                                (key.0.clone(), key.1[..key.1.len() - 1].to_vec()),
                                trait_file.clone(),
                            ));
                        }
                    }
                }
            }
            for (function, context, source) in methods {
                let name = function.sig.ident.to_string();
                if self.methods.iter().any(|&i| {
                    let d = &self.definitions[i];
                    d.owner.as_ref() == Some(&owner)
                        && d.implemented_trait == implemented_trait
                        && d.file == source
                        && d.function.sig.ident.span().start() == function.sig.ident.span().start()
                        && d.name == name
                }) {
                    continue;
                }
                let i = self.definitions.len();
                // Only inherent static methods participate in ordinary path lookup.
                // Resource tracing separately checks scoped trait applicability.
                if implemented_trait.is_none()
                    && function.sig.receiver().is_none()
                    && matches!(function.vis, syn::Visibility::Public(_))
                {
                    self.by_name.entry(name.clone()).or_default().push(i);
                }
                self.methods.push(i);
                self.definitions.push(HandlerDefinition {
                    file: source.clone(),
                    evidence: handler_evidence(&source, &function),
                    function,
                    crate_key: context.0,
                    module: context.1,
                    name,
                    owner: Some(owner.clone()),
                    implemented_trait: implemented_trait.clone(),
                });
            }
        }
    }

    fn resource_method(
        &self,
        caller: &HandlerDefinition,
        owner: &ModuleKey,
        name: &str,
        receiver_call: bool,
    ) -> Option<&HandlerDefinition> {
        let candidates: Vec<_> = self
            .methods
            .iter()
            .map(|&i| &self.definitions[i])
            .filter(|d| d.owner.as_ref() == Some(owner) && d.name == name)
            .filter(|d| !receiver_call || d.function.sig.receiver().is_some())
            .collect();
        let inherent: Vec<_> = candidates
            .iter()
            .copied()
            .filter(|d| d.implemented_trait.is_none())
            .filter(|d| {
                matches!(d.function.vis, syn::Visibility::Public(_))
                    || (d.crate_key == caller.crate_key && caller.module.starts_with(&d.module))
            })
            .collect();
        if !receiver_call && !inherent.is_empty() {
            return (inherent.len() == 1).then(|| inherent[0]);
        }
        let scoped: Vec<_> = candidates
            .into_iter()
            .filter(|d| {
                let Some(trait_key) = &d.implemented_trait else {
                    return false;
                };
                if caller.crate_key == trait_key.0
                    && caller.module == trait_key.1[..trait_key.1.len() - 1]
                {
                    return true;
                }
                let Some(scope) = self.scope(&caller.crate_key, &caller.module) else {
                    return false;
                };
                scope
                    .imports
                    .values()
                    .flatten()
                    .chain(scope.globs.iter())
                    .any(|path| {
                        self.resolve_module(&caller.crate_key, &caller.module, path, 0)
                            .as_ref()
                            == Some(trait_key)
                    })
                    || (caller.crate_key == trait_key.0
                        && caller.module == trait_key.1[..trait_key.1.len() - 1])
            })
            .collect();
        if receiver_call && !inherent.is_empty() {
            // Receiver adjustment/autoref can change Rust's preference. Without
            // that inference, conflicting inherent/trait candidates abstain.
            return (inherent.len() == 1 && scoped.is_empty()).then(|| inherent[0]);
        }
        (scoped.len() == 1).then(|| scoped[0])
    }

    fn resource_call(
        &self,
        caller: &HandlerDefinition,
        segments: &[String],
    ) -> Option<&HandlerDefinition> {
        if segments.len() > 1 {
            let owner = if segments[0] == "Self" {
                caller.owner.clone()
            } else {
                self.resolve_module(
                    &caller.crate_key,
                    &caller.module,
                    &UsePath {
                        segments: segments[..segments.len() - 1].to_vec(),
                        leading_colon: false,
                    },
                    0,
                )
            };
            if let Some(owner) = owner.filter(|k| self.record_types.contains(k)) {
                return self.resource_method(caller, &owner, segments.last()?, false);
            }
        }
        let (definition, resolution) = self.resolve_handler(
            &caller.crate_key,
            &caller.module,
            &HandlerTarget::Path {
                segments: segments.to_vec(),
                leading_colon: false,
            },
        );
        if resolution == HandlerResolution::UniqueName {
            None
        } else {
            definition
        }
    }

    #[cfg(test)]
    fn single_file(file: &Path, syntax: &syn::File) -> Self {
        Self::build([(file, (file.to_path_buf(), Vec::new()), syntax)])
    }

    fn add_items(
        &mut self,
        file: &Path,
        crate_key: &Path,
        module: &mut Vec<String>,
        items: &[Item],
    ) {
        for item in items {
            match item {
                Item::Fn(function) => {
                    let name = function.sig.ident.to_string();
                    self.by_name
                        .entry(name.clone())
                        .or_default()
                        .push(self.definitions.len());
                    self.definitions.push(HandlerDefinition {
                        file: file.to_path_buf(),
                        function: function.clone(),
                        crate_key: crate_key.to_path_buf(),
                        module: module.clone(),
                        name,
                        evidence: handler_evidence(file, function),
                        owner: None,
                        implemented_trait: None,
                    });
                }
                Item::Mod(item_mod) => {
                    module.push(item_mod.ident.to_string());
                    if matches!(item_mod.vis, syn::Visibility::Public(_)) {
                        self.public_modules
                            .insert((crate_key.to_path_buf(), module.clone()));
                    }
                    self.modules
                        .insert((crate_key.to_path_buf(), module.clone()));
                    if let Some((_, items)) = &item_mod.content {
                        self.add_items(file, crate_key, module, items);
                    }
                    module.pop();
                }
                Item::Impl(item_impl) => {
                    self.pending_impls.push((
                        file.to_path_buf(),
                        (crate_key.to_path_buf(), module.clone()),
                        item_impl.clone(),
                    ));
                }
                Item::Macro(item) => self
                    .schema_macros
                    .push(((crate_key.to_path_buf(), module.clone()), item.clone())),
                Item::ExternCrate(item)
                    if item.attrs.iter().any(|a| a.path().is_ident("macro_use")) =>
                {
                    self.macro_uses.push((
                        (crate_key.to_path_buf(), module.clone()),
                        item.ident.to_string(),
                    ));
                }
                Item::Type(item) => {
                    let mut path = module.clone();
                    path.push(item.ident.to_string());
                    let key = (crate_key.to_path_buf(), path);
                    self.modules.insert(key.clone());
                    if matches!(item.vis, syn::Visibility::Public(_)) {
                        self.public_modules.insert(key.clone());
                    }
                    self.type_aliases.insert(key, item.clone());
                }
                Item::Trait(item) => {
                    let mut path = module.clone();
                    path.push(item.ident.to_string());
                    let key = (crate_key.to_path_buf(), path);
                    self.modules.insert(key.clone());
                    if matches!(item.vis, syn::Visibility::Public(_)) {
                        self.public_modules.insert(key.clone());
                    }
                    self.traits.insert(key, (file.to_path_buf(), item.clone()));
                }
                Item::Struct(item) => {
                    let mut ty = module.clone();
                    ty.push(item.ident.to_string());
                    self.modules.insert((crate_key.to_path_buf(), ty.clone()));
                    self.record_types
                        .insert((crate_key.to_path_buf(), ty.clone()));
                    self.record_attributes
                        .insert((crate_key.to_path_buf(), ty.clone()), item.attrs.clone());
                    self.record_fields.insert(
                        (crate_key.to_path_buf(), ty.clone()),
                        item.fields
                            .iter()
                            .filter_map(|f| {
                                f.ident.as_ref().map(|name| {
                                    (
                                        name.to_string(),
                                        (f.ty.clone(), matches!(f.vis, syn::Visibility::Public(_))),
                                    )
                                })
                            })
                            .collect(),
                    );
                    if matches!(item.vis, syn::Visibility::Public(_)) {
                        self.public_modules.insert((crate_key.to_path_buf(), ty));
                    }
                }
                Item::Use(item_use) => {
                    let scope = self
                        .scopes
                        .entry((crate_key.to_path_buf(), module.clone()))
                        .or_default();
                    if matches!(item_use.vis, syn::Visibility::Public(_)) {
                        let mut exported = ModuleScope::default();
                        collect_use_tree(
                            &item_use.tree,
                            &mut Vec::new(),
                            item_use.leading_colon.is_some(),
                            &mut exported,
                        );
                        scope.public_imports.extend(exported.imports.into_keys());
                        scope.public_globs.extend(exported.globs);
                    }
                    collect_use_tree(
                        &item_use.tree,
                        &mut Vec::new(),
                        item_use.leading_colon.is_some(),
                        scope,
                    );
                }
                _ => {}
            }
        }
    }

    fn is_module(&self, crate_key: &Path, module: &[String]) -> bool {
        self.modules
            .contains(&(crate_key.to_path_buf(), module.to_vec()))
    }

    fn scope(&self, crate_key: &Path, module: &[String]) -> Option<&ModuleScope> {
        self.scopes.get(&(crate_key.to_path_buf(), module.to_vec()))
    }

    fn definitions_named<'s>(
        &'s self,
        crate_key: &'s Path,
        name: &str,
    ) -> impl Iterator<Item = usize> + 's {
        self.by_name
            .get(name)
            .into_iter()
            .flatten()
            .copied()
            .filter(move |&index| self.definitions[index].crate_key == crate_key)
    }

    /// Resolves a handler expression from the module that registers the route.
    fn resolve_handler(
        &self,
        crate_key: &Path,
        module: &[String],
        target: &HandlerTarget,
    ) -> (Option<&HandlerDefinition>, HandlerResolution) {
        let module = if self
            .record_types
            .contains(&(crate_key.to_path_buf(), module.to_vec()))
        {
            &module[..module.len() - 1]
        } else {
            module
        };
        let HandlerTarget::Path {
            segments,
            leading_colon,
        } = target
        else {
            return (None, HandlerResolution::Unresolved);
        };
        if *leading_colon
            && !segments.first().is_some_and(|name| {
                self.dependencies
                    .contains_key(&(crate_key.to_path_buf(), name.clone()))
            })
        {
            return (None, HandlerResolution::Unresolved);
        }
        let Some((name, qualifier)) = segments.split_last() else {
            return (None, HandlerResolution::Unresolved);
        };

        let (lookup, qualifier_module) = if qualifier.is_empty() {
            let lookup = self.resolve_item(crate_key, module, name, &mut HashSet::new(), 0);
            (lookup, None)
        } else {
            let qualifier_path = UsePath {
                segments: qualifier.to_vec(),
                leading_colon: false,
            };
            let Some(qualifier_module) = self.resolve_module(crate_key, module, &qualifier_path, 0)
            else {
                return (None, HandlerResolution::Unresolved);
            };
            let mut visited = HashSet::new();
            let lookup = match self.resolve_item(
                &qualifier_module.0,
                &qualifier_module.1,
                name,
                &mut visited,
                0,
            ) {
                Lookup::Found(index, _) => Lookup::Found(index, HandlerResolution::Qualified),
                other => other,
            };
            let lookup = if qualifier_module.0 != crate_key {
                self.exported_lookup(&qualifier_module, name, lookup)
            } else {
                lookup
            };
            (lookup, Some(qualifier_module))
        };

        match lookup {
            Lookup::Found(index, resolution) => (Some(&self.definitions[index]), resolution),
            Lookup::Ambiguous(candidates) => (None, self.ambiguous(candidates)),
            Lookup::NotFound { explicit: true } => (None, HandlerResolution::Unresolved),
            Lookup::NotFound { explicit: false } => {
                let candidates: Vec<usize> = self
                    .definitions_named(crate_key, name)
                    .filter(|&index| self.definitions[index].owner.is_none())
                    .filter(|&index| {
                        qualifier_module.as_ref().is_none_or(|qualifier| {
                            self.definitions[index].crate_key == qualifier.0
                                && self.definitions[index].module.starts_with(&qualifier.1)
                        })
                    })
                    .collect();
                match candidates.as_slice() {
                    [] => (None, HandlerResolution::Unresolved),
                    [index] => (
                        Some(&self.definitions[*index]),
                        HandlerResolution::UniqueName,
                    ),
                    _ => (None, self.ambiguous(candidates)),
                }
            }
        }
    }

    fn ambiguous(&self, candidates: Vec<usize>) -> HandlerResolution {
        let mut candidates: Vec<String> = candidates
            .into_iter()
            .map(|index| self.definitions[index].rust_path())
            .collect();
        candidates.sort();
        HandlerResolution::Ambiguous { candidates }
    }

    /// Resolves `name` as seen from `module`: local definitions first, then
    /// explicit imports, then glob imports, mirroring Rust's shadowing order.
    fn resolve_item(
        &self,
        crate_key: &Path,
        module: &[String],
        name: &str,
        visited: &mut HashSet<(PathBuf, Vec<String>, String)>,
        depth: usize,
    ) -> Lookup {
        if depth > MAX_RESOLUTION_DEPTH
            || !visited.insert((crate_key.to_path_buf(), module.to_vec(), name.to_owned()))
        {
            return Lookup::NotFound { explicit: true };
        }

        let local: Vec<usize> = self
            .definitions_named(crate_key, name)
            .filter(|&index| {
                self.definitions[index]
                    .owner
                    .as_ref()
                    .map(|k| k.1.as_slice())
                    .unwrap_or(&self.definitions[index].module)
                    == module
            })
            .collect();
        match local.as_slice() {
            [index] => return Lookup::Found(*index, HandlerResolution::Local),
            [_, _, ..] => return Lookup::Ambiguous(local),
            [] => {}
        }

        let Some(scope) = self.scope(crate_key, module) else {
            return Lookup::NotFound { explicit: false };
        };
        if let Some(imports) = scope.imports.get(name) {
            let lookups = imports
                .iter()
                .map(|path| self.resolve_use_item(crate_key, module, path, visited, depth + 1))
                .collect();
            return combine_lookups(lookups, HandlerResolution::Imported)
                .unwrap_or(Lookup::NotFound { explicit: true });
        }

        if scope.globs.iter().any(|glob| {
            self.resolve_module(crate_key, module, glob, depth + 1)
                .is_none()
        }) {
            // An unknown glob could export the same name; do not select a known
            // branch merely because the other dependency was not indexed.
            return Lookup::NotFound { explicit: true };
        }
        let lookups = scope
            .globs
            .iter()
            .filter_map(|glob| self.resolve_module(crate_key, module, glob, depth + 1))
            .map(|glob_module| {
                let lookup = self.resolve_item(
                    &glob_module.0,
                    &glob_module.1,
                    name,
                    &mut visited.clone(),
                    depth + 1,
                );
                if glob_module.0 != crate_key {
                    self.exported_lookup(&glob_module, name, lookup)
                } else {
                    lookup
                }
            })
            .collect();
        combine_lookups(lookups, HandlerResolution::GlobImported)
            .unwrap_or(Lookup::NotFound { explicit: false })
    }

    fn resolve_use_item(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        visited: &mut HashSet<(PathBuf, Vec<String>, String)>,
        depth: usize,
    ) -> Lookup {
        let Some((name, prefix)) = path.segments.split_last() else {
            return Lookup::NotFound { explicit: true };
        };
        if prefix.is_empty() {
            return Lookup::NotFound { explicit: true };
        }
        let prefix = UsePath {
            segments: prefix.to_vec(),
            leading_colon: path.leading_colon,
        };
        match self.resolve_module(crate_key, module, &prefix, depth) {
            Some(target) => {
                let lookup = self.resolve_item(&target.0, &target.1, name, visited, depth);
                if target.0 != crate_key {
                    self.exported_lookup(&target, name, lookup)
                } else {
                    match lookup {
                        Lookup::NotFound { .. } => Lookup::NotFound { explicit: true },
                        other => other,
                    }
                }
            }
            None => Lookup::NotFound { explicit: true },
        }
    }

    /// Resolve modules/types through dependency aliases and each qualified
    /// re-export segment. Public access is checked on the written external path.
    fn resolve_module(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        depth: usize,
    ) -> Option<ModuleKey> {
        self.module_path(crate_key, module, path, depth, false)
    }

    fn module_path(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        depth: usize,
        external: bool,
    ) -> Option<ModuleKey> {
        if depth > MAX_RESOLUTION_DEPTH {
            return None;
        }
        let segments = &path.segments;
        let first = segments.first().map(String::as_str);
        let mut key = crate_key.to_path_buf();
        let mut resolved = module.to_vec();
        let mut position = 0;
        match first {
            Some("crate") => {
                resolved.clear();
                position = 1;
            }
            Some("self") => {
                position = 1;
            }
            Some("super") => {
                let supers = segments
                    .iter()
                    .take_while(|s| s.as_str() == "super")
                    .count();
                if supers > module.len() {
                    return None;
                }
                resolved.truncate(module.len() - supers);
                position = supers;
            }
            Some(name) => {
                let mut child = resolved.clone();
                child.push(name.into());
                let local = self.is_module(&key, &child)
                    || self
                        .scope(&key, &resolved)
                        .is_some_and(|s| s.imports.contains_key(name));
                if path.leading_colon || !local {
                    if let Some(dependency) = self.dependencies.get(&(key.clone(), name.into())) {
                        return self.module_path(
                            dependency,
                            &[],
                            &UsePath {
                                segments: segments[1..].to_vec(),
                                leading_colon: false,
                            },
                            depth + 1,
                            true,
                        );
                    }
                    if path.leading_colon {
                        return None;
                    }
                }
            }
            None => return Some((key, resolved)),
        }
        for segment in &segments[position..] {
            let mut child = resolved.clone();
            child.push(segment.clone());
            if self.is_module(&key, &child) {
                if external && !self.public_modules.contains(&(key.clone(), child.clone())) {
                    return None;
                }
                resolved = child;
            } else {
                let scope = self.scope(&key, &resolved)?;
                if external && !scope.public_imports.contains(segment) {
                    return None;
                }
                let [import] = scope.imports.get(segment)?.as_slice() else {
                    return None;
                };
                // A public re-export may legitimately point into a private
                // implementation module. Check its export, not that private path.
                (key, resolved) = self.module_path(&key, &resolved, import, depth + 1, false)?;
            }
        }
        self.is_module(&key, &resolved).then_some((key, resolved))
    }
}

/// Merges lookups through several imports. Distinct definitions, or any
/// ambiguous branch, make the whole lookup ambiguous; evidence is never merged.
fn combine_lookups(lookups: Vec<Lookup>, resolution: HandlerResolution) -> Option<Lookup> {
    let mut found = Vec::new();
    let mut ambiguous = false;
    for lookup in lookups {
        let indices = match lookup {
            Lookup::Found(index, _) => vec![index],
            Lookup::Ambiguous(indices) => {
                ambiguous = true;
                indices
            }
            Lookup::NotFound { .. } => continue,
        };
        for index in indices {
            if !found.contains(&index) {
                found.push(index);
            }
        }
    }
    match found.as_slice() {
        [] => None,
        [index] if !ambiguous => Some(Lookup::Found(*index, resolution)),
        _ => Some(Lookup::Ambiguous(found)),
    }
}

fn collect_use_tree(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    leading_colon: bool,
    scope: &mut ModuleScope,
) {
    let mut import = |alias: String, ident: String, prefix: &Vec<String>| {
        if alias == "_" {
            return;
        }
        let mut segments = prefix.clone();
        if ident != "self" {
            segments.push(ident);
        }
        scope.imports.entry(alias).or_default().push(UsePath {
            segments,
            leading_colon,
        });
    };
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            collect_use_tree(&path.tree, prefix, leading_colon, scope);
            prefix.pop();
        }
        UseTree::Name(name) => {
            let ident = name.ident.to_string();
            let alias = if ident == "self" {
                match prefix.last() {
                    Some(last) => last.clone(),
                    None => return,
                }
            } else {
                ident.clone()
            };
            import(alias, ident, prefix);
        }
        UseTree::Rename(rename) => {
            import(rename.rename.to_string(), rename.ident.to_string(), prefix);
        }
        UseTree::Glob(_) => scope.globs.push(UsePath {
            segments: prefix.clone(),
            leading_colon,
        }),
        UseTree::Group(group) => {
            for item in &group.items {
                collect_use_tree(item, prefix, leading_colon, scope);
            }
        }
    }
}

/// Maps a scanned file to its crate and module path using Cargo's
/// conventional layout. Files outside `src/` (tests, examples, build
/// scripts) and binaries under `src/bin/` get their own isolated namespace.
fn module_location(root: &Path, file: &Path) -> ModuleKey {
    let isolated = || (file.to_path_buf(), Vec::new());
    let crate_dir = file
        .ancestors()
        .skip(1)
        .take_while(|directory| directory.starts_with(root))
        .find(|directory| directory.join("Cargo.toml").is_file())
        .unwrap_or(root);
    let source_dir = crate_dir.join("src");
    let relative = if source_dir.is_dir() {
        file.strip_prefix(&source_dir)
    } else {
        file.strip_prefix(crate_dir)
    };
    let Ok(relative) = relative else {
        return isolated();
    };
    let mut segments: Vec<String> = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let Some(file_name) = segments.pop() else {
        return isolated();
    };
    if segments.first().is_some_and(|segment| segment == "bin") {
        return isolated();
    }
    let stem = file_name.strip_suffix(".rs").unwrap_or(&file_name);
    let crate_root = segments.is_empty() && (stem == "main" || stem == "lib");
    if !crate_root && stem != "mod" {
        segments.push(stem.to_owned());
    }
    (crate_dir.to_path_buf(), segments)
}

struct AuthEvidenceVisitor {
    file: PathBuf,
    handler: String,
    evidence: Vec<AuthEvidence>,
}

impl AuthEvidenceVisitor {
    fn new(file: &Path, handler: &str) -> Self {
        Self {
            file: file.to_path_buf(),
            handler: handler.into(),
            evidence: Vec::new(),
        }
    }
}

impl<'ast> Visit<'ast> for AuthEvidenceVisitor {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        let symbol = node.func.to_token_stream().to_string().replace(' ', "");
        let line = node.func.span().start().line;
        let evidence = evidence_for_handler_call(&symbol, line, &self.file, &self.handler)
            .or_else(|| evidence_for_handler_symbol(&symbol, line, &self.file, &self.handler));
        if let Some(evidence) = evidence {
            self.evidence.push(evidence);
        }
        for argument in &node.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if let Some(evidence) = evidence_for_handler_method(
            &method,
            node.span().start().line,
            &self.file,
            &self.handler,
        ) {
            self.evidence.push(evidence);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        let symbol = node.path.to_token_stream().to_string().replace(' ', "");
        if let Some(evidence) = evidence_for_handler_symbol(
            &symbol,
            node.span().start().line,
            &self.file,
            &self.handler,
        ) {
            self.evidence.push(evidence);
        }
        visit::visit_expr_path(self, node);
    }

    // Expression and statement macros both reach this hook once. Only the
    // macro's own name is classified, with the helper-name rules; its tokens
    // are opaque, so calls written inside a macro (`assert!(is_admin(&user))`)
    // are not evidence.
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let Some(name) = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
        else {
            return;
        };
        let Some((kind, strength)) = classify_check_name(&name) else {
            return;
        };
        let symbol = node.path.to_token_stream().to_string().replace(' ', "");
        self.evidence.push(AuthEvidence {
            kind,
            mechanism: name,
            symbol: Some(format!("{symbol}!")),
            file: self.file.clone(),
            line: node.path.span().start().line,
            handler: Some(self.handler.clone()),
            strength,
        });
    }

    // Functions declared inside the handler body, including methods of nested
    // `impl` and `trait` items, do not run as part of that body. Their
    // evidence belongs to them, not to the enclosing handler.
    fn visit_item_fn(&mut self, _: &'ast ItemFn) {}

    fn visit_impl_item_fn(&mut self, _: &'ast ImplItemFn) {}

    fn visit_trait_item_fn(&mut self, _: &'ast TraitItemFn) {}
}

fn evidence_for_handler_method(
    method: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let (kind, strength) = classify_check_name(method).or_else(|| {
        (method.contains("identity") || method.contains("claims"))
            .then_some((AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak))
    })?;
    Some(AuthEvidence {
        kind,
        mechanism: method.into(),
        symbol: Some(method.into()),
        file: file.to_path_buf(),
        line,
        handler: Some(handler.into()),
        strength,
    })
}

fn evidence_for_handler_call(
    symbol: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let name = symbol.rsplit("::").next().unwrap_or(symbol);
    let (kind, strength) = classify_check_name(name)?;
    Some(AuthEvidence {
        kind,
        mechanism: name.into(),
        symbol: Some(symbol.into()),
        file: file.to_path_buf(),
        line,
        handler: Some(handler.into()),
        strength,
    })
}

/// Final words that make a helper name a data, lookup, or logging operation
/// rather than an enforcement check (`ensure_admin_exists`, `check_admin_token`,
/// `role_name`, `permissions_list`, `check_access_log`).
const NON_CHECK_FINAL_WORDS: [&str; 26] = [
    "exists",
    "exist",
    "list",
    "count",
    "name",
    "names",
    "title",
    "id",
    "ids",
    "status",
    "description",
    "log",
    "logs",
    "token",
    "tokens",
    "info",
    "data",
    "config",
    "settings",
    "cache",
    "url",
    "path",
    "email",
    "header",
    "headers",
    "lookup",
];

/// Classifies a called helper by its snake_case name. This is a lexical
/// heuristic: it recognizes conventional enforcement names but cannot see what
/// a helper does, and identity/authentication helpers are never authorization.
fn classify_check_name(name: &str) -> Option<(AuthEvidenceKind, AuthStrength)> {
    let lower = name.to_ascii_lowercase();
    if ["error", "exception", "fault"]
        .iter()
        .any(|marker| lower.contains(marker))
        || (lower.starts_with("author")
            && !lower.starts_with("authoriz")
            && !lower.starts_with("authoris"))
        || lower.starts_with("authority")
    {
        return None;
    }

    let tokens: Vec<&str> = lower.split('_').filter(|token| !token.is_empty()).collect();
    let last = *tokens.last()?;
    if NON_CHECK_FINAL_WORDS.contains(&last) {
        return None;
    }
    let has_token = |candidates: &[&str]| tokens.iter().any(|token| candidates.contains(token));
    let is_one_of = |names: &[&str]| names.contains(&lower.as_str());
    // `access` is an authorization subject only as the final noun (`check_access`,
    // `verify_resource_access`); as a modifier it names authentication artifacts
    // such as `verify_access_token` or logging helpers such as `check_access_log`.
    let ends_with_access = last == "access";
    let uses_check_prefix = ["require_", "check_", "verify_", "assert_", "ensure_"]
        .iter()
        .any(|prefix| lower.starts_with(prefix));

    let classification = if is_one_of(&[
        "require_auth",
        "is_authenticated",
        "require_authenticated_user",
        "current_user",
        "authenticated_user",
    ]) {
        (AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak)
    } else if is_one_of(&["authorize", "authorise", "is_authorized", "permit"])
        || ["authorize_", "authorise_", "is_authorized_"]
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    {
        (
            AuthEvidenceKind::ManualAuthorizationCheck,
            AuthStrength::Strong,
        )
    } else if is_one_of(&[
        "has_role",
        "has_roles",
        "has_any_role",
        "is_admin",
        "require_admin",
        "require_manager",
    ]) || (uses_check_prefix
        && has_token(&["admin", "admins", "manager", "role", "roles"]))
    {
        (AuthEvidenceKind::RoleCheck, AuthStrength::Strong)
    } else if is_one_of(&[
        "has_permission",
        "has_permissions",
        "has_any_permission",
        "check_permission",
        "verify_permission",
    ]) || (uses_check_prefix
        && (has_token(&["permission", "permissions"]) || ends_with_access))
    {
        (AuthEvidenceKind::PermissionCheck, AuthStrength::Strong)
    } else if is_one_of(&["owns", "is_owner", "is_owned_by"])
        || (uses_check_prefix && has_token(&["owner", "ownership"]))
    {
        (AuthEvidenceKind::OwnershipCheck, AuthStrength::Medium)
    } else {
        return None;
    };
    Some(classification)
}

fn evidence_for_handler_symbol(
    symbol: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let name = symbol.rsplit("::").next().unwrap_or(symbol);
    if name == "require_admin" {
        return Some(AuthEvidence {
            kind: AuthEvidenceKind::RoleCheck,
            mechanism: name.into(),
            symbol: Some(symbol.into()),
            file: file.to_path_buf(),
            line,
            handler: Some(handler.into()),
            strength: AuthStrength::Strong,
        });
    }
    if name.ends_with("Guard") || name.ends_with("Middleware") {
        return None;
    }
    if symbol.contains("Claims") || name == "Identity" || name == "AuthenticatedUser" {
        return Some(AuthEvidence {
            kind: AuthEvidenceKind::IdentityExtraction,
            mechanism: name.into(),
            symbol: Some(symbol.into()),
            file: file.to_path_buf(),
            line,
            handler: Some(handler.into()),
            strength: AuthStrength::Weak,
        });
    }
    if symbol.contains("UnknownSecurity") || name == "custom_auth_marker" {
        return Some(AuthEvidence {
            kind: AuthEvidenceKind::Unknown,
            mechanism: name.into(),
            symbol: Some(symbol.into()),
            file: file.to_path_buf(),
            line,
            handler: Some(handler.into()),
            strength: AuthStrength::Weak,
        });
    }
    None
}

/// What a `.guard(...)` or `.wrap(...)` argument name indicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteConfigurationName {
    /// An authorization guard or middleware, such as `AdminGuard` or `check_admin`.
    Authorization,
    /// Authentication only, such as `AuthMiddleware` or `HttpAuthentication`.
    Authentication,
}

const CONFIGURATION_EXCLUDED_WORDS: [&str; 15] = [
    "error",
    "errors",
    "err",
    "exception",
    "fault",
    "unauthorized",
    "forbidden",
    "log",
    "logs",
    "logger",
    "logging",
    "metrics",
    "tracing",
    "telemetry",
    "audit",
];
const CONFIGURATION_AUTHORIZATION_WORDS: [&str; 12] = [
    "admin",
    "admins",
    "role",
    "roles",
    "permission",
    "permissions",
    "authorization",
    "authorize",
    "authorized",
    "authz",
    "acl",
    "rbac",
];
const CONFIGURATION_AUTHENTICATION_WORDS: [&str; 10] = [
    "auth",
    "authn",
    "authentication",
    "authenticate",
    "authenticated",
    "jwt",
    "bearer",
    "login",
    "oauth",
    "identity",
];
const CONFIGURATION_SHAPE_WORDS: [&str; 11] = [
    "guard",
    "middleware",
    "filter",
    "gate",
    "only",
    "require",
    "requires",
    "check",
    "verify",
    "enforce",
    "enforcer",
];

/// Classifies one path segment of a guard or middleware argument. snake_case
/// names (guard functions) use the helper-name classifier; type names need an
/// authorization word and a guard-like word, so `PermissionsPolicy`,
/// `RoleLogger`, and `UnauthorizedHandler` are not authorization.
fn classify_route_configuration_name(identifier: &str) -> Option<RouteConfigurationName> {
    if !identifier.chars().any(char::is_uppercase) {
        let (kind, _) = classify_check_name(identifier)?;
        return Some(if kind == AuthEvidenceKind::IdentityExtraction {
            RouteConfigurationName::Authentication
        } else {
            RouteConfigurationName::Authorization
        });
    }

    let words = camel_case_words(identifier);
    let has_word =
        |candidates: &[&str]| words.iter().any(|word| candidates.contains(&word.as_str()));
    if has_word(&CONFIGURATION_EXCLUDED_WORDS) {
        None
    } else if has_word(&CONFIGURATION_AUTHORIZATION_WORDS) && has_word(&CONFIGURATION_SHAPE_WORDS) {
        Some(RouteConfigurationName::Authorization)
    } else if identifier == "HttpAuthentication"
        || (has_word(&CONFIGURATION_AUTHENTICATION_WORDS) && has_word(&CONFIGURATION_SHAPE_WORDS))
    {
        Some(RouteConfigurationName::Authentication)
    } else {
        None
    }
}

/// Splits `AdminAuthMiddleware` or `JWTGuard` into lowercase words.
fn camel_case_words(identifier: &str) -> Vec<String> {
    let characters: Vec<char> = identifier.chars().collect();
    let mut words: Vec<String> = Vec::new();
    for (index, &character) in characters.iter().enumerate() {
        let starts_word = index == 0
            || character == '_'
            || character.is_uppercase()
                && (characters[index - 1].is_lowercase()
                    || characters
                        .get(index + 1)
                        .is_some_and(|next| next.is_lowercase()));
        if character == '_' {
            continue;
        }
        if starts_word || words.is_empty() {
            words.push(String::new());
        }
        if let Some(word) = words.last_mut() {
            word.extend(character.to_lowercase());
        }
    }
    words.retain(|word| !word.is_empty());
    words
}

#[derive(Debug, Clone)]
struct NamedIdentifier {
    name: String,
    line: usize,
}

/// Finds the most specific authorization-related name in a guard or
/// middleware argument; an authorization name wins over an authentication one.
fn route_configuration_name_in_expr(
    expr: &Expr,
) -> Option<(RouteConfigurationName, NamedIdentifier)> {
    let mut visitor = RouteConfigurationNameVisitor::default();
    visitor.visit_expr(expr);
    visitor
        .authorization
        .map(|name| (RouteConfigurationName::Authorization, name))
        .or_else(|| {
            visitor
                .authentication
                .map(|name| (RouteConfigurationName::Authentication, name))
        })
}

#[derive(Default)]
struct RouteConfigurationNameVisitor {
    authorization: Option<NamedIdentifier>,
    authentication: Option<NamedIdentifier>,
}

impl<'ast> Visit<'ast> for RouteConfigurationNameVisitor {
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        for segment in &node.path.segments {
            let name = segment.ident.to_string();
            let slot = match classify_route_configuration_name(&name) {
                Some(RouteConfigurationName::Authorization) => &mut self.authorization,
                Some(RouteConfigurationName::Authentication) => &mut self.authentication,
                None => continue,
            };
            if slot.is_none() {
                *slot = Some(NamedIdentifier {
                    name,
                    line: node.span().start().line,
                });
            }
        }
        visit::visit_expr_path(self, node);
    }
}

fn scope_prefix(expr: &Expr) -> String {
    match expr {
        Expr::MethodCall(method) => {
            let prefix = if method.method == "scope" {
                first_string_arg(&method.args).unwrap_or_default()
            } else {
                String::new()
            };
            join_paths(&scope_prefix(&method.receiver), &prefix)
        }
        Expr::Call(call) if call.args.first().is_some() && is_scope_call(&call.func) => {
            join_paths("", &first_string_arg(&call.args).unwrap_or_default())
        }
        Expr::Paren(paren) => scope_prefix(&paren.expr),
        Expr::Group(group) => scope_prefix(&group.expr),
        _ => String::new(),
    }
}

fn is_scope_call(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "scope")
    )
}

/// The argument of a route's `.to(...)` or legacy `.to_async(...)` call.
#[derive(Debug, Clone)]
enum HandlerTarget {
    Path {
        segments: Vec<String>,
        leading_colon: bool,
    },
    /// Closures and other expressions that do not name a function.
    Other,
}

impl HandlerTarget {
    fn name(&self) -> Option<String> {
        match self {
            Self::Path { segments, .. } => segments.last().cloned(),
            Self::Other => None,
        }
    }

    fn written(&self) -> Option<String> {
        match self {
            Self::Path {
                segments,
                leading_colon,
            } => Some(format!(
                "{}{}",
                if *leading_colon { "::" } else { "" },
                segments.join("::")
            )),
            Self::Other => None,
        }
    }
}

fn find_handler(
    exprs: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
    index: &HandlerIndex,
    context: &ModuleKey,
) -> Option<HandlerTarget> {
    exprs
        .iter()
        .find_map(|expr| find_handler_in_expr(expr, index, context))
}

fn find_handler_in_expr(
    expr: &Expr,
    index: &HandlerIndex,
    context: &ModuleKey,
) -> Option<HandlerTarget> {
    match expr {
        Expr::MethodCall(method)
            if method.method == "to_async"
                && registration::resolved_route_builder(index, context, &method.receiver)
                    .is_none() =>
        {
            Some(HandlerTarget::Other)
        }
        Expr::MethodCall(method) if method.method == "to" || method.method == "to_async" => {
            Some(match method.args.first()? {
                Expr::Path(path) if path.qself.is_none() => HandlerTarget::Path {
                    segments: path
                        .path
                        .segments
                        .iter()
                        .map(|segment| segment.ident.to_string())
                        .collect(),
                    leading_colon: path.path.leading_colon.is_some(),
                },
                _ => HandlerTarget::Other,
            })
        }
        Expr::MethodCall(method) => find_handler_in_expr(&method.receiver, index, context),
        _ => None,
    }
}

fn join_paths(prefix: &str, path: &str) -> String {
    let prefix = prefix.trim_matches('/');
    let path = path.trim_start_matches('/');
    match (prefix.is_empty(), path.is_empty()) {
        (true, true) => "/".into(),
        (true, false) => format!("/{path}"),
        (false, true) => format!("/{prefix}"),
        (false, false) => format!("/{prefix}/{path}"),
    }
}

// Identity used by comparison coverage and overlap detection. This deliberately
// differs from source-registration and mounted-route deduplication identities.
fn comparison_key(route: &RouteReference) -> String {
    format!(
        "{:?}:{}:{}:{}",
        route.application,
        route.file.display(),
        route.method,
        route.path
    )
}

pub fn analyze_repository(root: &Path) -> Result<Report> {
    let mut files_scanned = 0;
    let mut parse_errors = Vec::new();
    let mut routes = Vec::new();

    let mut rust_files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            entry.path() == root
                || !entry.file_type().is_dir()
                || !matches!(
                    entry.file_name().to_str(),
                    Some("target" | ".git" | "tests" | "benches" | "examples")
                )
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
        .map(|e| e.path().to_path_buf())
        .collect();
    rust_files.sort();

    let mut parsed_files = Vec::new();
    for file_path in rust_files {
        let source = fs::read_to_string(&file_path)
            .with_context(|| format!("failed to read {}", file_path.display()))?;

        files_scanned += 1;
        let mut syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(error) => {
                parse_errors.push(format!("{}: {}", file_path.display(), error));
                continue;
            }
        };
        registration::strip_test_items(&mut syntax.items);
        parsed_files.push((module_location(root, &file_path), file_path, syntax));
    }

    // Index every handler definition before extracting routes so that route
    // registrations can resolve handlers defined in other files.
    let mut index = HandlerIndex::build(
        parsed_files
            .iter()
            .map(|(location, file_path, syntax)| (file_path.as_path(), location.clone(), syntax)),
    );
    let mut diagnostics = Vec::new();
    if let Some(message) = index.load_workspace(root) {
        diagnostics.push(registration::Diagnostic {
            code: "workspace_resolution_unavailable".into(),
            file: root.to_path_buf(),
            line: 1,
            message,
        });
    }
    index.attach_conditional_result_aliases();
    index.attach_diesel_tables();
    let mut mounted_routes = Vec::new();
    for (_, file_path, syntax) in &parsed_files {
        let mut visitor = RouteVisitor::new(file_path.clone(), &index);
        visitor.conservative_security = true;
        visitor.visit_file(syntax);
        routes.extend(visitor.routes);
        mounted_routes.extend(visitor.mounted_routes);
        diagnostics.extend(visitor.diagnostics);
    }

    diagnostics.extend(registration::missing_context(
        &routes,
        &mounted_routes,
        &index,
    ));
    registration::merge_mounts(&mut routes, mounted_routes);
    let security_assessments = security::assess(&mut routes, &parsed_files, &index);
    let (candidate_relationships, resource_evidence) =
        policy_drift::discover(root, &routes, &index);
    let peer_groups = policy_drift::families(&routes, &candidate_relationships);
    let mut invariants = Vec::new();
    let mut finding_details = Vec::new();
    let mut findings = Vec::new();
    let mut compared = HashSet::new();
    let mut analysis_evidence = Vec::new();
    policy_drift::infer(
        &peer_groups,
        &security_assessments,
        &mut finding_details,
        &mut findings,
        &mut invariants,
        &mut compared,
        &mut analysis_evidence,
    );
    analysis_evidence.extend(policy_drift::group_evidence(
        &peer_groups,
        &routes,
        &candidate_relationships,
        &invariants,
        &security_assessments,
    ));
    for group in &peer_groups {
        if !invariants.iter().any(|i| i.peer_group_id == group.id) {
            diagnostics.push(registration::Diagnostic {
                code: "invariant_unavailable".into(), file: group.routes[0].file.clone(), line: group.routes[0].line,
                message: format!("{}: no unambiguous observed requirement has at least two supporters and a strict group majority; unknown checks and legitimate policy differences do not establish an invariant", group.id),
            });
        }
    }
    let peer_compared_routes = compared.len();
    for (i, route) in routes.iter().enumerate() {
        let key = comparison_key(&RouteReference::from(route));
        if compared.contains(&key) {
            continue;
        }
        let related: Vec<_> = candidate_relationships
            .iter()
            .filter(|r| r.left == i || r.right == i)
            .collect();
        let reason = if related.is_empty() {
            "No supported resource or structural relationship within this application"
        } else if !peer_groups.iter().any(|g| {
            g.routes
                .iter()
                .any(|p| policy_drift::same_route(p, &RouteReference::from(route)))
        }) {
            "Structural relationships exist, but insufficient shared resource evidence supports peer membership"
        } else {
            "Peer group membership exists, but held-out policy evidence is unresolved, insufficient, ambiguous, or conflicting; no supported drift comparison was made"
        };
        diagnostics.push(registration::Diagnostic {
            code: "policy_comparison_unavailable".into(),
            file: route.file.clone(),
            line: route.line,
            message: format!("{} {}: {reason}", route.method, route.path),
        });
    }

    let protected_routes = routes
        .iter()
        .filter(|r| matches!(r.security_status(), RouteSecurityStatus::Protected))
        .count();
    let unknown_routes = routes
        .iter()
        .filter(|r| matches!(r.security_status(), RouteSecurityStatus::Unknown { .. }))
        .count();
    let unprotected_routes = routes
        .len()
        .saturating_sub(protected_routes + unknown_routes);

    let summary = Some(AnalysisSummary {
        total_routes: routes.len(),
        peer_group_covered_routes: routes
            .iter()
            .filter(|r| {
                peer_groups.iter().any(|g| {
                    g.routes
                        .iter()
                        .any(|p| policy_drift::same_route(p, &RouteReference::from(*r)))
                })
            })
            .count(),
        peer_compared_routes,
        routes_without_peer_comparison: routes.len().saturating_sub(peer_compared_routes),
        protected_routes,
        unprotected_routes,
        unknown_routes,
        peer_groups_count: peer_groups.len(),
        inferred_invariants_count: invariants.len(),
        drift_findings_count: finding_details.len(),
    });

    let handler_resolution_evidence: Vec<_> = routes
        .iter()
        .map(|route| {
            let definition = index.route_handler(route);
            HandlerResolutionEvidence {
                route: RouteReference::from(route),
                definition_file: definition.map(|d| d.file.clone()),
                definition_line: definition.map(|d| d.function.sig.ident.span().start().line),
                definition_path: definition.map(HandlerDefinition::rust_path),
                confidence: if definition.is_none() {
                    "Unavailable"
                } else if route.handler_resolution == Some(HandlerResolution::UniqueName) {
                    "Low"
                } else {
                    "Medium"
                }
                .into(),
            }
        })
        .collect();

    let graph = Some(reporting::graph_with_definitions(&routes, &finding_details, &handler_resolution_evidence, &security_assessments));
    let local_rejections = security::local_rejections(&routes, &index);
    let review_observations = policy_drift::reviews(&peer_groups, &security_assessments, &finding_details);
    let check_comparisons = security::check_contrasts(&routes, &candidate_relationships, &security_assessments, &index);
    Ok(Report {
        check_comparisons,
        review_observations,
        local_rejections,
        candidate_relationships,
        analysis_evidence,
        resource_evidence,
        handler_resolution_evidence,
        security_assessments,
        diagnostics,
        files_scanned,
        parse_errors,
        routes,
        peer_groups,
        invariants,
        findings,
        finding_details,
        graph,
        summary,
        diff_report: None,
    })
}

fn is_operational_public_route(route: &Route) -> bool {
    let public_operational_names = [
        "health", "healthz", "live", "ready", "status", "ping", "metrics", "version", "info",
        "docs", "swagger", "openapi", "favicon",
    ];
    let path_segments: Vec<String> = route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_ascii_lowercase)
        .collect();
    if let Some(last) = path_segments.last() {
        if public_operational_names.contains(&last.as_str()) {
            return true;
        }
    }
    false
}

fn dynamic_segment_shape(route: &Route) -> Vec<bool> {
    route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(is_dynamic_segment)
        .collect()
}

fn is_dynamic_segment(segment: &str) -> bool {
    (segment.starts_with('{') && segment.ends_with('}'))
        || (segment.starts_with('<') && segment.ends_with('>'))
}

fn is_authentication_route(route: &Route) -> bool {
    let authentication_names = [
        "auth", "login", "logout", "register", "signup", "signin", "token", "refresh",
    ];
    route
        .path
        .split('/')
        .chain(route.scope_prefix.split('/'))
        .filter(|segment| !segment.is_empty())
        .map(str::to_ascii_lowercase)
        .any(|segment| authentication_names.contains(&segment.as_str()))
}

#[cfg(test)]
mod tests;
