use anyhow::{Context, Result};
use quote::ToTokens;
use serde::Serialize;
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Expr, ExprCall, ExprLit, ExprMethodCall, ExprPath, ItemFn, Lit,
    spanned::Spanned,
    visit::{self, Visit},
};
use walkdir::WalkDir;

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

#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub scope_prefix: String,
    pub handler: Option<String>,
    pub authorization: Vec<AuthEvidence>,
    pub line: usize,
    pub file: PathBuf,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteReference {
    pub method: String,
    pub path: String,
    pub handler: Option<String>,
    pub file: PathBuf,
    pub line: usize,
    pub authorized: bool,
    pub authorization: Vec<AuthEvidence>,
}

impl From<&Route> for RouteReference {
    fn from(route: &Route) -> Self {
        Self {
            method: route.method.clone(),
            path: route.path.clone(),
            handler: route.handler.clone(),
            file: route.file.clone(),
            line: route.line,
            authorized: route.is_authorized(),
            authorization: route.authorization.clone(),
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
}

impl Route {
    pub fn is_authorized(&self) -> bool {
        self.authorization
            .iter()
            .any(AuthEvidence::is_authorization)
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

#[derive(Debug, Serialize)]
pub struct Report {
    pub files_scanned: usize,
    pub parse_errors: Vec<String>,
    pub routes: Vec<Route>,
    pub peer_groups: Vec<PeerGroup>,
    pub invariants: Vec<AuthorizationInvariant>,
    pub findings: Vec<String>,
    pub finding_details: Vec<Finding>,
}

struct RouteVisitor<'a> {
    file: PathBuf,
    authorized_handlers: &'a HashMap<String, Vec<AuthEvidence>>,
    scope_context: String,
    routes: Vec<Route>,
}

impl<'a> RouteVisitor<'a> {
    fn new(file: PathBuf, authorized_handlers: &'a HashMap<String, Vec<AuthEvidence>>) -> Self {
        Self {
            file,
            authorized_handlers,
            scope_context: String::new(),
            routes: Vec::new(),
        }
    }

    fn add_route(&mut self, node: &ExprMethodCall) {
        let name = node.method.to_string();
        if name != "route" && name != "resource" {
            return;
        }

        let Some(path) = first_string_arg(&node.args) else {
            return;
        };

        let local_prefix = scope_prefix(&node.receiver);
        let prefix = join_paths(&self.scope_context, &local_prefix);
        let path = join_paths(&prefix, &path);
        let handler = handler_name(node);
        let authorization = classify_authorization(
            node,
            handler.as_deref(),
            self.authorized_handlers,
            &self.file,
        );

        let line = first_string_arg_line(&node.args).unwrap_or_else(|| node.span().start().line);

        self.routes.push(Route {
            method: extract_http_method(node),
            path,
            scope_prefix: prefix,
            handler,
            authorization,
            line,
            file: self.file.clone(),
        });
    }
}

impl<'ast> Visit<'ast> for RouteVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        self.add_attribute_routes(node);
        visit::visit_item_fn(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if node.method == "service" {
            let previous_context = self.scope_context.clone();
            self.scope_context = join_paths(&previous_context, &scope_prefix(&node.receiver));
            for arg in &node.args {
                self.visit_expr(arg);
            }
            self.scope_context = previous_context;
            self.visit_expr(&node.receiver);
            return;
        }

        self.add_route(node);
        visit::visit_expr_method_call(self, node);
    }
}

impl RouteVisitor<'_> {
    fn add_attribute_routes(&mut self, node: &ItemFn) {
        for attribute in &node.attrs {
            let Some(method) = attribute_route_method(attribute) else {
                continue;
            };
            let Ok(path_literal) = attribute.parse_args::<syn::LitStr>() else {
                continue;
            };

            let prefix = self.scope_context.clone();
            let path = join_paths(&prefix, &path_literal.value());
            let handler = node.sig.ident.to_string();
            let authorization = self
                .authorized_handlers
                .get(&handler)
                .cloned()
                .unwrap_or_default();

            self.routes.push(Route {
                method: method.into(),
                path,
                scope_prefix: prefix,
                authorization,
                handler: Some(handler),
                line: path_literal.span().start().line,
                file: self.file.clone(),
            });
        }
    }
}

fn attribute_route_method(attribute: &syn::Attribute) -> Option<&'static str> {
    for (name, method) in [
        ("get", "GET"),
        ("post", "POST"),
        ("put", "PUT"),
        ("patch", "PATCH"),
        ("delete", "DELETE"),
        ("head", "HEAD"),
    ] {
        if attribute.path().is_ident(name) {
            return Some(method);
        }
    }
    None
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

fn extract_http_method(expr: &ExprMethodCall) -> String {
    let rendered = expr.args.to_token_stream().to_string();
    for method in ["get", "post", "put", "patch", "delete", "head"] {
        if rendered.contains(&format!("web :: {method}"))
            || rendered.contains(&format!("web::{method}"))
        {
            return method.to_uppercase();
        }
    }
    "UNKNOWN".into()
}

fn classify_authorization(
    route_expr: &ExprMethodCall,
    handler: Option<&str>,
    authorized_handlers: &HashMap<String, Vec<AuthEvidence>>,
    file: &Path,
) -> Vec<AuthEvidence> {
    let mut evidence = route_configuration_evidence(route_expr, file, handler);
    if let Some(name) = handler {
        if let Some(handler_evidence) = authorized_handlers.get(name) {
            evidence.extend(handler_evidence.iter().cloned());
        }
    }
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
            if method.method == "guard" || method.method == "wrap" {
                let kind = if method.method == "guard" {
                    AuthEvidenceKind::AuthorizationGuard
                } else {
                    AuthEvidenceKind::AuthorizationMiddleware
                };
                let strength = if method.method == "guard" {
                    AuthStrength::Strong
                } else {
                    AuthStrength::Medium
                };
                for arg in &method.args {
                    if let Some(identifier) = authorization_identifier_in_expr(arg) {
                        evidence.push(AuthEvidence {
                            kind: kind.clone(),
                            mechanism: identifier.name.clone(),
                            symbol: Some(identifier.name),
                            file: file.to_path_buf(),
                            line: identifier.line,
                            handler: handler.map(str::to_owned),
                            strength: strength.clone(),
                        });
                    }
                }
            }
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
    let Expr::MethodCall(method) = expr else {
        return;
    };
    if method.method == "route" || method.method == "resource" {
        return;
    }
    visit_route_configuration(expr, file, handler, evidence);
    visit_scope_configuration(&method.receiver, file, handler, evidence);
}

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

#[derive(Default)]
struct FunctionVisitor {
    file: PathBuf,
    authorized_handlers: HashMap<String, Vec<AuthEvidence>>,
}

impl<'ast> Visit<'ast> for FunctionVisitor {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let handler = item.sig.ident.to_string();
        let mut evidence = AuthEvidenceVisitor::new(&self.file, &handler);
        evidence.visit_block(&item.block);
        if !evidence.evidence.is_empty() {
            self.authorized_handlers.insert(handler, evidence.evidence);
        }
        visit::visit_item_fn(self, item);
    }
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
}

fn evidence_for_handler_method(
    method: &str,
    line: usize,
    file: &Path,
    handler: &str,
) -> Option<AuthEvidence> {
    let (kind, strength) =
        if method == "require_admin" || method.contains("role") || method.contains("authorize") {
            (AuthEvidenceKind::RoleCheck, AuthStrength::Strong)
        } else if method.contains("permission") || method == "has_permission" {
            (AuthEvidenceKind::PermissionCheck, AuthStrength::Strong)
        } else if method.contains("ownership") || method.contains("owns") {
            (AuthEvidenceKind::OwnershipCheck, AuthStrength::Medium)
        } else if method.contains("identity")
            || method.contains("claims")
            || method == "current_user"
            || method == "authenticated_user"
        {
            (AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak)
        } else {
            return None;
        };
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
    let lower = name.to_ascii_lowercase();
    if ["error", "exception", "fault"]
        .iter()
        .any(|marker| lower.contains(marker))
        || ["_title", "_name", "_status", "_id", "_count", "_description"]
            .iter()
            .any(|suffix| lower.ends_with(suffix))
        || (lower.starts_with("author")
            && !lower.starts_with("authoriz")
            && !lower.starts_with("authoris"))
        || lower.starts_with("authority")
    {
        return None;
    }

    let tokens: Vec<&str> = lower.split('_').collect();
    let has_token = |candidates: &[&str]| tokens.iter().any(|token| candidates.contains(token));
    let uses_check_prefix = ["require_", "check_", "verify_", "assert_", "ensure_"]
        .iter()
        .any(|prefix| lower.starts_with(prefix));

    let (kind, strength) = if lower == "require_auth"
        || lower == "is_authenticated"
        || lower == "require_authenticated_user"
        || lower == "current_user"
        || lower == "authenticated_user"
    {
        (AuthEvidenceKind::IdentityExtraction, AuthStrength::Weak)
    } else if ["authorize", "authorise", "is_authorized", "permit"].contains(&lower.as_str()) {
        (
            AuthEvidenceKind::ManualAuthorizationCheck,
            AuthStrength::Strong,
        )
    } else if ["has_role", "has_any_role", "is_admin", "require_admin", "require_manager"]
        .contains(&lower.as_str())
        || (uses_check_prefix && has_token(&["admin", "manager", "role"]))
    {
        (AuthEvidenceKind::RoleCheck, AuthStrength::Strong)
    } else if ["has_permission", "check_permission", "verify_permission"]
        .contains(&lower.as_str())
        || (uses_check_prefix && has_token(&["permission", "access"]))
    {
        (AuthEvidenceKind::PermissionCheck, AuthStrength::Strong)
    } else if uses_check_prefix && has_token(&["owner", "ownership"]) {
        (AuthEvidenceKind::OwnershipCheck, AuthStrength::Medium)
    } else {
        return None;
    };

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
    None
}

fn is_authorization_identifier(identifier: &str) -> bool {
    let identifier = identifier.to_lowercase();
    identifier == "require_admin"
        || identifier.ends_with("guard")
            && (identifier.contains("admin")
                || identifier.contains("auth")
                || identifier.contains("role")
                || identifier.contains("permission"))
        || identifier.ends_with("middleware")
            && (identifier.contains("auth")
                || identifier.contains("authoriz")
                || identifier.contains("permission")
                || identifier.contains("role")
                || identifier.contains("admin"))
}

fn is_authorization_name(identifier: &str) -> bool {
    is_authorization_identifier(identifier)
        || identifier.contains("permission")
        || identifier.contains("authorize")
        || identifier.contains("role")
}

fn authorization_identifier_in_expr(expr: &Expr) -> Option<NamedIdentifier> {
    let mut visitor = AuthorizationNameVisitor::default();
    visitor.visit_expr(expr);
    visitor.identifier
}

#[derive(Debug, Clone)]
struct NamedIdentifier {
    name: String,
    line: usize,
}

#[derive(Default)]
struct AuthorizationNameVisitor {
    identifier: Option<NamedIdentifier>,
}

impl<'ast> Visit<'ast> for AuthorizationNameVisitor {
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        if self.identifier.is_none() {
            self.identifier = node
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .find(|identifier| is_authorization_name(&identifier.to_lowercase()))
                .map(|name| NamedIdentifier {
                    name,
                    line: node.span().start().line,
                });
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

fn handler_name(route: &ExprMethodCall) -> Option<String> {
    find_handler(&route.args)
}

fn find_handler(exprs: &syn::punctuated::Punctuated<Expr, syn::token::Comma>) -> Option<String> {
    exprs.iter().find_map(find_handler_in_expr)
}

fn find_handler_in_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::MethodCall(method) if method.method == "to" => match method.args.first()? {
            Expr::Path(path) if path.path.segments.len() == 1 => path
                .path
                .segments
                .first()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        },
        Expr::MethodCall(method) => {
            find_handler(&method.args).or_else(|| find_handler_in_expr(&method.receiver))
        }
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

pub fn analyze_repository(root: &Path) -> Result<Report> {
    let mut files_scanned = 0;
    let mut parse_errors = Vec::new();
    let mut routes = Vec::new();

    let mut rust_files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rs"))
        .map(|e| e.path().to_path_buf())
        .collect();
    rust_files.sort();

    for file_path in rust_files {
        let source = fs::read_to_string(&file_path)
            .with_context(|| format!("failed to read {}", file_path.display()))?;

        files_scanned += 1;
        let syntax = match syn::parse_file(&source) {
            Ok(syntax) => syntax,
            Err(error) => {
                parse_errors.push(format!("{}: {}", file_path.display(), error));
                continue;
            }
        };

        let authorized_handlers = collect_authorized_handlers(&file_path, &syntax);
        let mut visitor = RouteVisitor::new(file_path, &authorized_handlers);
        visitor.visit_file(&syntax);
        routes.extend(visitor.routes);
    }

    let (peer_groups, invariants, finding_details, findings) = build_analysis_layers(&routes);

    Ok(Report {
        files_scanned,
        parse_errors,
        routes,
        peer_groups,
        invariants,
        findings,
        finding_details,
    })
}

fn build_analysis_layers(
    routes: &[Route],
) -> (
    Vec<PeerGroup>,
    Vec<AuthorizationInvariant>,
    Vec<Finding>,
    Vec<String>,
) {
    let mut grouped_routes: Vec<Vec<&Route>> = Vec::new();
    for route in routes {
        if is_authentication_route(route)
            || grouped_routes.iter().any(|group| {
                group
                    .iter()
                    .any(|candidate| route_identity(candidate) == route_identity(route))
            })
        {
            continue;
        }
        let peers = unique_routes(
            routes
                .iter()
                .filter(|candidate| same_peer_group(route, candidate)),
        );
        if peers.len() >= 2 && peers.iter().any(|peer| peer.is_authorized()) {
            grouped_routes.push(peers);
        }
    }

    let mut peer_groups = Vec::new();
    let mut invariants = Vec::new();
    let mut finding_details = Vec::new();
    let mut findings = Vec::new();

    for (index, peers) in grouped_routes.iter().enumerate() {
        let id = format!("peer-group-{:03}", index + 1);
        let first = peers[0];
        let description = format!(
            "{} {} routes under {}",
            first.method,
            route_shape_description(first),
            if first.scope_prefix.is_empty() {
                "/"
            } else {
                &first.scope_prefix
            }
        );
        let references: Vec<RouteReference> = peers.iter().map(|route| (*route).into()).collect();
        peer_groups.push(PeerGroup {
            id: id.clone(),
            description: description.clone(),
            routes: references.clone(),
        });

        let authorized = peers.iter().filter(|route| route.is_authorized()).count();
        let unauthorized = peers.len() - authorized;
        let mut evidence_patterns: Vec<String> = peers
            .iter()
            .flat_map(|route| {
                route
                    .authorization
                    .iter()
                    .map(|evidence| evidence.mechanism.clone())
            })
            .collect();
        evidence_patterns.sort();
        evidence_patterns.dedup();
        let strength = invariant_strength(authorized, peers.len());
        let invariant = AuthorizationInvariant {
            peer_group_id: id.clone(),
            description: format!(
                "Peer routes under {} consistently contain authorization evidence.",
                if first.scope_prefix.is_empty() {
                    "/"
                } else {
                    &first.scope_prefix
                }
            ),
            total_routes: peers.len(),
            routes_with_authorization: authorized,
            routes_without_authorization: unauthorized,
            evidence_patterns,
            strength,
        };
        invariants.push(invariant.clone());

        if authorized < 2 || unauthorized == 0 {
            continue;
        }
        for route in peers.iter().filter(|route| !route.is_authorized()) {
            let authorized_peer_routes: Vec<RouteReference> = peers
                .iter()
                .filter(|peer| peer.is_authorized())
                .map(|peer| (*peer).into())
                .collect();
            finding_details.push(Finding {
                peer_group_id: id.clone(),
                invariant: invariant.clone(),
                suspicious_route: (*route).into(),
                suspicious_route_evidence: route.authorization.clone(),
                authorized_peer_routes,
            });
            let peer_lines = peers
                .iter()
                .filter(|peer| peer.is_authorized())
                .map(|peer| {
                    format!(
                        "    - {} {}\n      {}",
                        peer.method,
                        peer.path,
                        format_evidence(peer)
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");
            findings.push(format!(
                "  Suspicious route: {} {} ({}:{})\n\
  Inferred invariant: {}\n\
  Authorized peer evidence ({} route(s)):\n{}\n\
  Suspicious route evidence: {}.",
                route.method,
                route.path,
                route.file.display(),
                route.line,
                invariant.description,
                authorized,
                peer_lines,
                format_evidence(route)
            ));
        }
    }

    (peer_groups, invariants, finding_details, findings)
}

fn infer_prototype_drift(routes: &[Route]) -> Vec<String> {
    build_analysis_layers(routes).3
}

fn invariant_strength(authorized: usize, total: usize) -> AuthStrength {
    if authorized == total || authorized >= 3 {
        AuthStrength::Strong
    } else if authorized >= 2 {
        AuthStrength::Medium
    } else {
        AuthStrength::Weak
    }
}

fn route_shape_description(route: &Route) -> String {
    if dynamic_segment_shape(route).iter().any(|dynamic| *dynamic) {
        "parameterized".into()
    } else {
        "static".into()
    }
}

fn format_evidence(route: &Route) -> String {
    if route.authorization.is_empty() {
        return "No recognized authorization evidence".into();
    }
    route
        .authorization
        .iter()
        .map(|evidence| {
            format!(
                "{:?}: {} at {}:{} ({:?})",
                evidence.kind,
                evidence.mechanism,
                evidence.file.display(),
                evidence.line,
                evidence.strength
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn same_peer_group(route: &Route, candidate: &Route) -> bool {
    if route.scope_prefix != candidate.scope_prefix
        || route.method != candidate.method
        || route_segment_count(route) != route_segment_count(candidate)
        || dynamic_segment_shape(route) != dynamic_segment_shape(candidate)
    {
        return false;
    }

    if is_authentication_route(route) || is_authentication_route(candidate) {
        return route.path == candidate.path;
    }

    true
}

fn route_segment_count(route: &Route) -> usize {
    route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
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

fn unique_routes<'a, I>(routes: I) -> Vec<&'a Route>
where
    I: IntoIterator<Item = &'a Route>,
{
    let mut unique: Vec<&'a Route> = Vec::new();
    for route in routes {
        if !unique
            .iter()
            .any(|candidate| route_identity(candidate) == route_identity(route))
        {
            unique.push(route);
        }
    }
    unique
}

fn route_identity(route: &Route) -> (&str, &str, &str, Option<&str>) {
    (
        &route.method,
        &route.path,
        &route.scope_prefix,
        route.handler.as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(method: &str, path: &str, scope_prefix: &str, authorization: &str) -> Route {
        let authorization = if authorization == "PRESENT" {
            vec![AuthEvidence {
                kind: AuthEvidenceKind::RoleCheck,
                mechanism: "test_authorization".into(),
                symbol: Some("test_authorization".into()),
                file: PathBuf::from("fixture.rs"),
                line: 1,
                handler: None,
                strength: AuthStrength::Strong,
            }]
        } else {
            Vec::new()
        };
        Route {
            method: method.into(),
            path: path.into(),
            scope_prefix: scope_prefix.into(),
            handler: None,
            authorization,
            line: 1,
            file: PathBuf::from("fixture.rs"),
        }
    }

    fn route_with_handler(
        method: &str,
        path: &str,
        scope_prefix: &str,
        handler: &str,
        authorization: &str,
    ) -> Route {
        let mut route = route(method, path, scope_prefix, authorization);
        route.handler = Some(handler.into());
        route
    }

    #[test]
    fn peer_groups_require_matching_scope_method_and_shape() {
        let suspicious = route("GET", "/admin/payments", "/admin", "NONE");
        let same_group = route("GET", "/admin/users", "/admin", "PRESENT");
        let different_method = route("POST", "/admin/orders", "/admin", "PRESENT");
        let different_shape = route("GET", "/admin/reports/daily", "/admin", "PRESENT");
        let different_scope = route("GET", "/public/users", "/public", "PRESENT");

        assert!(same_peer_group(&suspicious, &same_group));
        assert!(!same_peer_group(&suspicious, &different_method));
        assert!(!same_peer_group(&suspicious, &different_shape));
        assert!(!same_peer_group(&suspicious, &different_scope));
    }

    #[test]
    fn authentication_login_and_logout_are_not_peers() {
        let login = route("POST", "/api/auth/login", "/api/auth", "NONE");
        let logout = route("POST", "/api/auth/logout", "/api/auth", "PRESENT");

        assert!(is_authentication_route(&login));
        assert!(is_authentication_route(&logout));
        assert!(!same_peer_group(&login, &logout));
    }

    #[test]
    fn authentication_register_and_logout_are_not_peers() {
        let register = route("POST", "/api/auth/register", "/api/auth", "NONE");
        let logout = route("POST", "/api/auth/logout", "/api/auth", "PRESENT");

        assert!(!same_peer_group(&register, &logout));
    }

    #[test]
    fn structurally_similar_protected_routes_remain_peers() {
        let users = route("GET", "/api/admin/users", "/api/admin", "PRESENT");
        let orders = route("GET", "/api/admin/orders", "/api/admin", "PRESENT");
        let payments = route("GET", "/api/admin/payments", "/api/admin", "NONE");

        assert!(same_peer_group(&users, &orders));
        assert!(same_peer_group(&payments, &users));
    }

    #[test]
    fn public_routes_under_broad_api_prefix_are_not_flagged() {
        let routes = vec![
            route("POST", "/api/auth/login", "/api/auth", "NONE"),
            route("POST", "/api/auth/register", "/api/auth", "NONE"),
            route("POST", "/api/auth/logout", "/api/auth", "PRESENT"),
        ];

        let findings = infer_prototype_drift(&routes);

        assert!(findings.is_empty());
    }

    #[test]
    fn duplicate_route_observations_do_not_dominate_peer_inference() {
        let public = route_with_handler("GET", "/api/admin/public", "/api/admin", "public", "NONE");
        let protected =
            route_with_handler("GET", "/api/admin/users", "/api/admin", "users", "PRESENT");
        let duplicate_protected = protected.clone();

        let protected_orders = route_with_handler(
            "GET",
            "/api/admin/orders",
            "/api/admin",
            "orders",
            "PRESENT",
        );
        let findings =
            infer_prototype_drift(&[public, protected, protected_orders, duplicate_protected]);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("/api/admin/public"));
        assert_eq!(findings[0].matches("/api/admin/users").count(), 1);
    }

    #[test]
    fn analysis_layers_expose_group_invariant_and_finding_relationship() {
        let routes = vec![
            route("GET", "/admin/users", "/admin", "PRESENT"),
            route("GET", "/admin/orders", "/admin", "PRESENT"),
            route("GET", "/admin/reports", "/admin", "PRESENT"),
            route("GET", "/admin/payments", "/admin", "NONE"),
        ];

        let (groups, invariants, details, findings) = build_analysis_layers(&routes);

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].routes.len(), 4);
        assert_eq!(invariants.len(), 1);
        assert_eq!(invariants[0].peer_group_id, groups[0].id);
        assert_eq!(invariants[0].total_routes, 4);
        assert_eq!(invariants[0].routes_with_authorization, 3);
        assert_eq!(invariants[0].routes_without_authorization, 1);
        assert_eq!(invariants[0].evidence_patterns, vec!["test_authorization"]);
        assert_eq!(invariants[0].strength, AuthStrength::Strong);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].peer_group_id, groups[0].id);
        assert_eq!(details[0].invariant.routes_without_authorization, 1);
        assert_eq!(details[0].suspicious_route.path, "/admin/payments");
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn authentication_routes_do_not_create_report_layers() {
        let routes = vec![
            route("POST", "/api/auth/login", "/api/auth", "NONE"),
            route("POST", "/api/auth/register", "/api/auth", "NONE"),
            route("POST", "/api/auth/logout", "/api/auth", "PRESENT"),
        ];

        let (groups, invariants, details, findings) = build_analysis_layers(&routes);

        assert!(groups.is_empty());
        assert!(invariants.is_empty());
        assert!(details.is_empty());
        assert!(findings.is_empty());
    }

    #[test]
    fn drift_finding_excludes_structural_non_peers() {
        let routes = vec![
            route("GET", "/admin/payments", "/admin", "NONE"),
            route("GET", "/admin/users", "/admin", "PRESENT"),
            route("GET", "/admin/orders", "/admin", "PRESENT"),
            route("GET", "/admin/reports", "/admin", "PRESENT"),
            route("POST", "/admin/audit", "/admin", "NONE"),
        ];

        let findings = infer_prototype_drift(&routes);

        assert_eq!(findings.len(), 1);
        assert!(findings[0].contains("/admin/payments"));
        assert!(!findings[0].contains("/admin/audit"));
    }

    #[test]
    fn nested_scopes_keep_combined_prefix() {
        let syntax: syn::File = syn::parse_str(
            "fn configure(cfg: &mut web::ServiceConfig) {
                cfg.service(web::scope(\"/api\").service(
                    web::scope(\"/admin\").route(\"/users\", web::get())
                ));
            }",
        )
        .unwrap();
        let handlers = HashMap::new();
        let mut visitor = RouteVisitor::new(PathBuf::from("nested.rs"), &handlers);
        visitor.visit_file(&syntax);

        assert_eq!(visitor.routes[0].path, "/api/admin/users");
        assert_eq!(visitor.routes[0].scope_prefix, "/api/admin");
    }

    #[test]
    fn sibling_nested_scopes_extract_routes_and_preserve_admin_drift_evidence() {
        let syntax: syn::File = syn::parse_str(
            r#"
            fn require_admin() {}
            async fn admin_users() { require_admin(); }
            async fn admin_orders() { require_admin(); }
            async fn admin_reports() { require_admin(); }
            async fn admin_payments() {}
            async fn admin_audit() { require_admin(); }
            async fn manager_audit() {}
            async fn manager_exports() {}
            async fn finance_summary() {}
            async fn finance_transactions() {}
            async fn get_document() {}
            async fn get_document_history() {}
            async fn health() {}
            async fn readiness() {}

            #[get("/api/profile")]
            async fn profile() {}
            #[get("/api/public-info")]
            async fn public_info() {}
            #[post("/api/session")]
            async fn create_session() {}

            fn configure(cfg: &mut web::ServiceConfig) {
                cfg.service(
                    web::scope("/api")
                        .service(web::scope("/admin")
                            .route("/users", web::get().to(admin_users))
                            .route("/orders", web::get().to(admin_orders))
                            .route("/reports", web::get().to(admin_reports))
                            .route("/payments", web::get().to(admin_payments))
                            .route("/audit", web::post().to(admin_audit)))
                        .service(web::scope("/manager")
                            .route("/audit", web::get().to(manager_audit))
                            .route("/exports", web::get().to(manager_exports)))
                        .service(web::scope("/finance")
                            .route("/summary", web::get().to(finance_summary))
                            .route("/transactions", web::get().to(finance_transactions)))
                        .service(web::scope("/documents")
                            .route("/{id}", web::get().to(get_document))
                            .route("/{id}/history", web::get().to(get_document_history)))
                        .service(web::scope("/public")
                            .route("/health", web::get().to(health))
                            .route("/ready", web::get().to(readiness)))
                );
            }
            "#,
        )
        .unwrap();
        let file = Path::new("siblings.rs");
        let handlers = collect_authorized_handlers(file, &syntax);
        let mut visitor = RouteVisitor::new(file.to_path_buf(), &handlers);
        visitor.visit_file(&syntax);

        assert_eq!(visitor.routes.len(), 16);
        for (method, path) in [
            ("GET", "/api/admin/users"),
            ("GET", "/api/admin/orders"),
            ("GET", "/api/admin/reports"),
            ("GET", "/api/admin/payments"),
            ("POST", "/api/admin/audit"),
            ("GET", "/api/manager/audit"),
            ("GET", "/api/manager/exports"),
            ("GET", "/api/finance/summary"),
            ("GET", "/api/finance/transactions"),
            ("GET", "/api/documents/{id}"),
            ("GET", "/api/documents/{id}/history"),
            ("GET", "/api/public/health"),
            ("GET", "/api/public/ready"),
            ("GET", "/api/profile"),
            ("GET", "/api/public-info"),
            ("POST", "/api/session"),
        ] {
            assert!(visitor.routes.iter().any(|route| route.method == method && route.path == path), "missing {method} {path}");
        }

        for route in &visitor.routes {
            let expected_scope = ["admin", "manager", "finance", "documents", "public"]
                .iter()
                .find(|scope| route.path.starts_with(&format!("/api/{scope}/")))
                .map(|scope| format!("/api/{scope}"))
                .unwrap_or_default();
            assert_eq!(route.scope_prefix, expected_scope, "wrong scope for {} {}", route.method, route.path);
        }

        for handler in ["admin_users", "admin_orders", "admin_reports"] {
            let route = visitor.routes.iter().find(|route| route.handler.as_deref() == Some(handler)).unwrap();
            assert_eq!(route.authorization.len(), 1);
            assert_eq!(route.authorization[0].mechanism, "require_admin");
            assert_eq!(route.authorization[0].handler.as_deref(), Some(handler));
        }
        let audit = visitor.routes.iter().find(|route| route.path == "/api/admin/audit").unwrap();
        assert_eq!(audit.method, "POST");

        let (groups, invariants, details, findings) = build_analysis_layers(&visitor.routes);
        let admin_group = groups.iter().find(|group| {
            group.routes.iter().any(|route| route.path == "/api/admin/payments")
        }).unwrap();
        assert_eq!(admin_group.routes.len(), 4);
        assert!(admin_group.routes.iter().all(|route| route.method == "GET"));
        assert_eq!(invariants.len(), 1);
        assert_eq!(invariants[0].total_routes, 4);
        assert_eq!(invariants[0].routes_with_authorization, 3);
        assert_eq!(details.len(), 1);
        assert_eq!(details[0].suspicious_route.path, "/api/admin/payments");
        assert_eq!(details[0].authorized_peer_routes.len(), 3);
        assert_eq!(findings.len(), 1);
    }

    #[test]
    fn malformed_rust_file_is_reported_and_skipped() {
        let root = std::env::temp_dir().join(format!("archer-malformed-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("broken.rs"), "fn broken( {").unwrap();
        fs::write(
            root.join("valid.rs"),
            "fn configure(cfg: &mut web::ServiceConfig) { cfg.service(web::scope(\"/admin\").route(\"/users\", web::get())); }",
        )
        .unwrap();

        let report = analyze_repository(&root).unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.parse_errors.len(), 1);
        assert!(report.parse_errors[0].contains("broken.rs"));
        assert_eq!(report.routes.len(), 1);
    }

    #[test]
    fn recognizes_authorization_guards_and_middleware_but_not_generic_guards() {
        let handlers = HashMap::new();
        let guard: ExprMethodCall =
            syn::parse_str("web::scope(\"/admin\").route(\"/x\", web::get().guard(AdminGuard))")
                .unwrap();
        let middleware: ExprMethodCall = syn::parse_str(
            "web::scope(\"/admin\").route(\"/x\", web::get().wrap(AuthorizationMiddleware))",
        )
        .unwrap();
        let generic_guard: ExprMethodCall =
            syn::parse_str("web::scope(\"/admin\").route(\"/x\", web::get().guard(MethodGuard))")
                .unwrap();

        let guard_evidence =
            classify_authorization(&guard, None, &handlers, Path::new("fixture.rs"));
        assert_eq!(guard_evidence[0].kind, AuthEvidenceKind::AuthorizationGuard);
        assert_eq!(guard_evidence[0].symbol.as_deref(), Some("AdminGuard"));
        assert_eq!(guard_evidence[0].line, 1);
        assert_eq!(guard_evidence[0].strength, AuthStrength::Strong);

        let middleware_evidence =
            classify_authorization(&middleware, None, &handlers, Path::new("fixture.rs"));
        assert_eq!(
            middleware_evidence[0].kind,
            AuthEvidenceKind::AuthorizationMiddleware
        );
        assert_eq!(
            middleware_evidence[0].symbol.as_deref(),
            Some("AuthorizationMiddleware")
        );
        assert_eq!(middleware_evidence[0].line, 1);

        let generic_evidence =
            classify_authorization(&generic_guard, None, &handlers, Path::new("fixture.rs"));
        assert!(generic_evidence.is_empty());
    }

    #[test]
    fn extracts_attribute_routes_and_associates_handlers() {
        let syntax: syn::File = syn::parse_str(
            r#"
            fn require_admin() {}

            #[get("/admin")]
            fn admin() {
                require_admin();
            }

            #[post("/token")]
            fn token() {}
            "#,
        )
        .unwrap();
        let handlers = collect_authorized_handlers(Path::new("attributes.rs"), &syntax);
        let mut visitor = RouteVisitor::new(PathBuf::from("attributes.rs"), &handlers);
        visitor.visit_file(&syntax);

        assert_eq!(visitor.routes.len(), 2);
        assert_eq!(visitor.routes[0].method, "GET");
        assert_eq!(visitor.routes[0].path, "/admin");
        assert!(visitor.routes[0].is_authorized());
        assert_eq!(visitor.routes[0].handler.as_deref(), Some("admin"));
        assert_eq!(
            visitor.routes[0].authorization[0].kind,
            AuthEvidenceKind::RoleCheck
        );
        assert_eq!(
            visitor.routes[0].authorization[0].symbol.as_deref(),
            Some("require_admin")
        );
        assert_eq!(visitor.routes[0].authorization[0].line, 6);
        assert_eq!(visitor.routes[1].method, "POST");
        assert_eq!(visitor.routes[1].path, "/token");
        assert!(!visitor.routes[1].is_authorized());
    }

    #[test]
    fn role_check_records_symbol_line_and_handler() {
        let syntax: syn::File = syn::parse_str("fn admin() { require_admin(); }").unwrap();
        let handlers = collect_authorized_handlers(Path::new("roles.rs"), &syntax);
        let evidence = &handlers["admin"][0];

        assert_eq!(evidence.kind, AuthEvidenceKind::RoleCheck);
        assert_eq!(evidence.mechanism, "require_admin");
        assert_eq!(evidence.symbol.as_deref(), Some("require_admin"));
        assert_eq!(evidence.file, PathBuf::from("roles.rs"));
        assert_eq!(evidence.line, 1);
        assert_eq!(evidence.handler.as_deref(), Some("admin"));
        assert_eq!(evidence.strength, AuthStrength::Strong);
    }

    #[test]
    fn function_call_evidence_recognizes_checks_without_promoting_identity_or_names() {
        let syntax: syn::File = syn::parse_str(
            "fn protected() {
                check_permission();
                verify_finance_permission();
                require_manager();
                check_resource_owner();
                require_authenticated_user();
                admin_dashboard_title();
                let _ = AuthError::Unauthorized;
            }",
        )
        .unwrap();
        let handlers = collect_authorized_handlers(Path::new("calls.rs"), &syntax);
        let evidence = &handlers["protected"];

        assert_eq!(evidence.len(), 5);
        assert_eq!(evidence[0].kind, AuthEvidenceKind::PermissionCheck);
        assert_eq!(evidence[0].mechanism, "check_permission");
        assert_eq!(evidence[0].symbol.as_deref(), Some("check_permission"));
        assert_eq!(evidence[1].kind, AuthEvidenceKind::PermissionCheck);
        assert_eq!(evidence[1].mechanism, "verify_finance_permission");
        assert_eq!(evidence[2].kind, AuthEvidenceKind::RoleCheck);
        assert_eq!(evidence[2].mechanism, "require_manager");
        assert_eq!(evidence[3].kind, AuthEvidenceKind::OwnershipCheck);
        assert_eq!(evidence[3].mechanism, "check_resource_owner");
        assert_eq!(evidence[4].kind, AuthEvidenceKind::IdentityExtraction);
        assert_eq!(evidence[4].mechanism, "require_authenticated_user");
        assert!(evidence.iter().all(|item| item.handler.as_deref() == Some("protected")));
        assert!(!evidence.iter().any(|item| item.mechanism == "admin_dashboard_title"));
        assert!(!evidence.iter().any(|item| item.kind == AuthEvidenceKind::IdentityExtraction && item.is_authorization()));

        let error_syntax: syn::File = syn::parse_str(
            "fn error_only() -> Result<(), AuthError> { Err(AuthError::Forbidden) }
             fn matches_error(error: AuthError) { match error { AuthError::Forbidden => (), _ => () } }",
        )
        .unwrap();
        let error_handlers = collect_authorized_handlers(Path::new("errors.rs"), &error_syntax);
        assert!(!error_handlers.contains_key("error_only"));
        assert!(!error_handlers.contains_key("matches_error"));
    }

    #[test]
    fn identity_extraction_is_not_authorization() {
        let syntax: syn::File =
            syn::parse_str("fn profile() { let claims = Claims::from_request(); }").unwrap();
        let handlers = collect_authorized_handlers(Path::new("identity.rs"), &syntax);
        let evidence = &handlers["profile"][0];
        assert_eq!(evidence.kind, AuthEvidenceKind::IdentityExtraction);

        let route = Route {
            method: "GET".into(),
            path: "/profile".into(),
            scope_prefix: String::new(),
            handler: Some("profile".into()),
            authorization: handlers["profile"].clone(),
            line: 1,
            file: PathBuf::from("identity.rs"),
        };
        assert!(!route.is_authorized());
        assert!(route.strongest_evidence().is_none());
    }

    #[test]
    fn logger_and_compress_are_not_authorization_middleware() {
        let handlers = HashMap::new();
        for middleware in ["Logger", "Compress"] {
            let route: ExprMethodCall = syn::parse_str(&format!(
                "web::scope(\"/admin\").route(\"/x\", web::get().wrap({middleware}))"
            ))
            .unwrap();
            assert!(
                classify_authorization(&route, None, &handlers, Path::new("fixture.rs")).is_empty()
            );
        }
    }

    #[test]
    fn empty_route_has_no_authorization_evidence() {
        let route = route("GET", "/admin/payments", "/admin", "NONE");
        assert!(route.authorization.is_empty());
        assert!(!route.is_authorized());
        assert_eq!(
            route.evidence_summary(),
            "No recognized authorization evidence"
        );
    }
}
