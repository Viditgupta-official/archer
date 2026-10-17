use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};
use syn::{
    spanned::Spanned,
    visit::{self, Visit},
    Expr, ExprLit, ExprMethodCall, ExprPath, ItemFn, Lit,
};
use walkdir::WalkDir;

#[derive(Debug)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub scope_prefix: String,
    pub authorization: String,
    pub authorization_evidence: String,
    pub line: usize,
    pub file: PathBuf,
}

#[derive(Debug)]
pub struct Report {
    pub files_scanned: usize,
    pub parse_errors: Vec<String>,
    pub routes: Vec<Route>,
    pub findings: Vec<String>,
}

struct RouteVisitor<'a> {
    file: PathBuf,
    authorized_handlers: &'a HashMap<String, String>,
    scope_context: String,
    routes: Vec<Route>,
}

impl<'a> RouteVisitor<'a> {
    fn new(file: PathBuf, authorized_handlers: &'a HashMap<String, String>) -> Self {
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
        let (authorization, authorization_evidence) =
            classify_authorization(node, handler.as_deref(), self.authorized_handlers);

        let line = first_string_arg_line(&node.args).unwrap_or_else(|| node.span().start().line);

        self.routes.push(Route {
            method: extract_http_method(node),
            path,
            scope_prefix: prefix,
            authorization,
            authorization_evidence,
            line,
            file: self.file.clone(),
        });
    }
}

impl<'ast> Visit<'ast> for RouteVisitor<'_> {
    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        if node.method == "service" {
            let previous_context = self.scope_context.clone();
            self.scope_context = join_paths(&previous_context, &scope_prefix(&node.receiver));
            for arg in &node.args {
                self.visit_expr(arg);
            }
            self.scope_context = previous_context;
            return;
        }

        self.add_route(node);
        visit::visit_expr_method_call(self, node);
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

const HTTP_METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "trace", "connect",
];

fn extract_http_method(expr: &ExprMethodCall) -> String {
    for arg in &expr.args {
        if let Some(method) = find_http_method_in_expr(arg) {
            return method;
        }
    }
    "UNKNOWN".into()
}

fn find_http_method_in_expr(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Call(call) => {
            if let Expr::Path(ref path) = *call.func {
                if let Some(last_seg) = path.path.segments.last() {
                    let ident = last_seg.ident.to_string().to_lowercase();
                    if HTTP_METHODS.contains(&ident.as_str()) {
                        let is_recognized_path = match path.path.segments.len() {
                            1 => true,
                            2 => path.path.segments[0].ident == "web",
                            3 => {
                                path.path.segments[0].ident == "actix_web"
                                    && path.path.segments[1].ident == "web"
                            }
                            _ => false,
                        };
                        if is_recognized_path {
                            return Some(ident.to_uppercase());
                        }
                    } else if ident == "method" {
                        if let Some(Expr::Path(arg_path)) = call.args.first() {
                            if let Some(method_seg) = arg_path.path.segments.last() {
                                let method_name = method_seg.ident.to_string().to_lowercase();
                                if HTTP_METHODS.contains(&method_name.as_str()) {
                                    return Some(method_name.to_uppercase());
                                }
                            }
                        }
                    }
                }
            }
            for arg in &call.args {
                if let Some(m) = find_http_method_in_expr(arg) {
                    return Some(m);
                }
            }
            None
        }
        Expr::MethodCall(method) => {
            let method_name = method.method.to_string().to_lowercase();
            if HTTP_METHODS.contains(&method_name.as_str()) {
                return Some(method_name.to_uppercase());
            }
            if let Some(m) = find_http_method_in_expr(&method.receiver) {
                return Some(m);
            }
            for arg in &method.args {
                if let Some(m) = find_http_method_in_expr(arg) {
                    return Some(m);
                }
            }
            None
        }
        Expr::Paren(paren) => find_http_method_in_expr(&paren.expr),
        Expr::Group(group) => find_http_method_in_expr(&group.expr),
        _ => None,
    }
}

fn classify_authorization(
    route_expr: &ExprMethodCall,
    handler: Option<&str>,
    authorized_handlers: &HashMap<String, String>,
) -> (String, String) {
    let evidence = route_configuration_evidence(route_expr);

    if evidence.found {
        return (
            "PRESENT".into(),
            evidence
                .description
                .unwrap_or_else(|| "authorization evidence in route configuration".into()),
        );
    }

    if let Some(name) = handler {
        if let Some(handler_evidence) = authorized_handlers.get(name) {
            return ("PRESENT".into(), handler_evidence.clone());
        }
    }

    fn route_configuration_evidence(route_expr: &ExprMethodCall) -> AuthEvidenceVisitor {
        let mut evidence = AuthEvidenceVisitor::default();
        for arg in &route_expr.args {
            visit_route_configuration(arg, &mut evidence);
        }
        visit_scope_configuration(&route_expr.receiver, &mut evidence);
        evidence
    }

    fn visit_route_configuration(expr: &Expr, evidence: &mut AuthEvidenceVisitor) {
        match expr {
            Expr::MethodCall(method) => {
                if method.method == "guard" || method.method == "wrap" {
                    for arg in &method.args {
                        let identifier = authorization_identifier_in_expr(arg);
                        if let Some(identifier) = identifier {
                            let kind = if method.method == "guard" {
                                "guard"
                            } else {
                                "middleware"
                            };
                            evidence.record(format!("authorization {kind} `{identifier}`"));
                        }
                    }
                }
                visit_route_configuration(&method.receiver, evidence);
                for arg in &method.args {
                    visit_route_configuration(arg, evidence);
                }
            }
            Expr::Paren(paren) => visit_route_configuration(&paren.expr, evidence),
            Expr::Group(group) => visit_route_configuration(&group.expr, evidence),
            _ => {}
        }
    }

    fn visit_scope_configuration(expr: &Expr, evidence: &mut AuthEvidenceVisitor) {
        let Expr::MethodCall(method) = expr else {
            return;
        };

        if method.method == "route" || method.method == "resource" {
            return;
        }

        if method.method == "guard" || method.method == "wrap" {
            for arg in &method.args {
                let identifier = authorization_identifier_in_expr(arg);
                if let Some(identifier) = identifier {
                    let kind = if method.method == "guard" {
                        "guard"
                    } else {
                        "middleware"
                    };
                    evidence.record(format!("authorization {kind} `{identifier}`"));
                }
            }
        }

        visit_scope_configuration(&method.receiver, evidence);
    }

    ("NONE".into(), "no recognized authorization evidence".into())
}

fn collect_authorized_handlers(file: &syn::File) -> HashMap<String, String> {
    let mut visitor = FunctionVisitor::default();
    visitor.visit_file(file);
    visitor.authorized_handlers
}

#[derive(Default)]
struct FunctionVisitor {
    authorized_handlers: HashMap<String, String>,
}

impl<'ast> Visit<'ast> for FunctionVisitor {
    fn visit_item_fn(&mut self, item: &'ast ItemFn) {
        let mut evidence = AuthEvidenceVisitor::default();
        evidence.visit_block(&item.block);
        if evidence.found {
            self.authorized_handlers.insert(
                item.sig.ident.to_string(),
                evidence
                    .description
                    .unwrap_or_else(|| "authorization evidence in handler".into()),
            );
        }
        visit::visit_item_fn(self, item);
    }
}

#[derive(Default)]
struct AuthEvidenceVisitor {
    found: bool,
    description: Option<String>,
}

impl<'ast> Visit<'ast> for AuthEvidenceVisitor {
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(ref path) = *node.func {
            if let Some(last_seg) = path.path.segments.last() {
                let name = last_seg.ident.to_string();
                if is_authorization_enforcement_call(&name) {
                    self.record(format!("call to {name}"));
                }
            }
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast ExprMethodCall) {
        let method = node.method.to_string();
        if is_authorization_enforcement_call(&method) {
            self.record(format!("call to {}", node.method));
        } else if method == "guard" {
            if let Some(identifier) = authorization_identifier_in_args(&node.args) {
                self.record(format!("authorization guard `{identifier}`"));
            }
        } else if method == "wrap" {
            if let Some(identifier) = authorization_identifier_in_args(&node.args) {
                self.record(format!("authorization middleware `{identifier}`"));
            }
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        if let Some(last_seg) = node.mac.path.segments.last() {
            let name = last_seg.ident.to_string();
            if is_authorization_enforcement_call(&name) {
                self.record(format!("macro `{name}`"));
            }
        }
        visit::visit_expr_macro(self, node);
    }
}

impl AuthEvidenceVisitor {
    fn record(&mut self, description: String) {
        self.found = true;
        if self.description.is_none() {
            self.description = Some(description);
        }
    }
}

fn is_error_identifier(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("error")
        || lower.contains("exception")
        || lower.contains("fault")
        || name.ends_with("Err")
        || name.starts_with("Err")
}

fn is_unrelated_author_name(lower: &str) -> bool {
    (lower.starts_with("author")
        && !lower.starts_with("authoriz")
        && !lower.starts_with("authoris"))
        || lower.starts_with("authority")
}

fn is_authorization_guard_or_middleware_name(name: &str) -> bool {
    if is_error_identifier(name) {
        return false;
    }
    let lower = name.to_lowercase();
    if is_unrelated_author_name(&lower) {
        return false;
    }

    // Exclude ordinary variable or description naming patterns
    if lower.ends_with("_title")
        || lower.ends_with("_name")
        || lower.ends_with("_status")
        || lower.ends_with("_id")
        || lower.ends_with("_count")
        || lower.ends_with("_description")
    {
        return false;
    }

    let has_auth_stem = lower.contains("admin")
        || lower.contains("auth")
        || lower.contains("permission")
        || lower.contains("role");

    if !has_auth_stem {
        return false;
    }

    name.ends_with("Guard")
        || name.ends_with("Middleware")
        || name.ends_with("Filter")
        || name.ends_with("Auth")
        || name.ends_with("Authentication")
        || name.ends_with("Authorization")
        || name.starts_with("Require")
        || name.starts_with("require_")
        || name.starts_with("Check")
        || name.starts_with("check_")
        || name.starts_with("Verify")
        || name.starts_with("verify_")
        || name.starts_with("HttpAuth")
        || name == "Authorization"
        || name == "Authentication"
}

fn is_authorization_enforcement_call(name: &str) -> bool {
    if is_error_identifier(name) {
        return false;
    }
    let lower = name.to_lowercase();
    if is_unrelated_author_name(&lower) {
        return false;
    }

    if lower.ends_with("_title")
        || lower.ends_with("_name")
        || lower.ends_with("_status")
        || lower.ends_with("_id")
    {
        return false;
    }

    let is_enforcement_name = lower == "authorize"
        || lower == "authorise"
        || lower == "has_role"
        || lower == "has_any_role"
        || lower == "has_permission"
        || lower == "is_admin"
        || lower == "is_authorized"
        || lower == "is_authenticated"
        || lower == "require_admin"
        || lower == "require_auth"
        || lower == "permit";

    if is_enforcement_name {
        return true;
    }

    let is_enforcement_prefix = lower.starts_with("require_")
        || lower.starts_with("check_")
        || lower.starts_with("verify_")
        || lower.starts_with("assert_")
        || lower.starts_with("ensure_");

    if is_enforcement_prefix {
        return lower.contains("admin")
            || lower.contains("auth")
            || lower.contains("permission")
            || lower.contains("role")
            || lower.contains("user")
            || lower.contains("access");
    }

    false
}

fn authorization_identifier_in_args(
    args: &syn::punctuated::Punctuated<Expr, syn::token::Comma>,
) -> Option<String> {
    let mut visitor = AuthorizationNameVisitor::default();
    for arg in args {
        visitor.visit_expr(arg);
        if visitor.identifier.is_some() {
            break;
        }
    }
    visitor.identifier
}

fn authorization_identifier_in_expr(expr: &Expr) -> Option<String> {
    let mut visitor = AuthorizationNameVisitor::default();
    visitor.visit_expr(expr);
    visitor.identifier
}

#[derive(Default)]
struct AuthorizationNameVisitor {
    identifier: Option<String>,
}

impl<'ast> Visit<'ast> for AuthorizationNameVisitor {
    fn visit_expr_path(&mut self, node: &'ast ExprPath) {
        if self.identifier.is_none() {
            self.identifier = node
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .find(|identifier| is_authorization_guard_or_middleware_name(identifier));
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

        let authorized_handlers = collect_authorized_handlers(&syntax);
        let mut visitor = RouteVisitor::new(file_path, &authorized_handlers);
        visitor.visit_file(&syntax);
        routes.extend(visitor.routes);
    }

    let findings = infer_prototype_drift(&routes);

    Ok(Report {
        files_scanned,
        parse_errors,
        routes,
        findings,
    })
}

fn infer_prototype_drift(routes: &[Route]) -> Vec<String> {
    // Very small first-pass invariant:
    // if several routes share a first path segment and most show auth evidence,
    // report an unauthenticated route as a candidate.
    let mut findings = Vec::new();

    for route in routes.iter().filter(|r| r.authorization == "NONE") {
        let prefix = route
            .scope_prefix
            .split('/')
            .filter(|s| !s.is_empty())
            .next()
            .unwrap_or("");
        if prefix.is_empty() {
            continue;
        }

        let peers: Vec<&Route> = routes
            .iter()
            .filter(|candidate| same_peer_group(route, candidate))
            .collect();

        let authorized = peers
            .iter()
            .filter(|r| r.authorization == "PRESENT")
            .count();

        if authorized >= 2 {
            let peer_lines = peers
                .iter()
                .filter(|peer| peer.authorization == "PRESENT")
                .map(|peer| {
                    format!(
                        "    - {} {} ({}:{}) — {}",
                        peer.method,
                        peer.path,
                        peer.file.display(),
                        peer.line,
                        peer.authorization_evidence
                    )
                })
                .collect::<Vec<_>>()
                .join("\n");

            findings.push(format!(
                "  Suspicious route: {} {} ({}:{})\n\
  Inferred invariant: peer routes under /{} consistently contain authorization evidence.\n\
  Authorized peer evidence ({} route(s)):\n{}\n\
  Suspicious route evidence: {}.",
                route.method,
                route.path,
                route.file.display(),
                route.line,
                prefix,
                authorized,
                peer_lines,
                route.authorization_evidence
            ));
        }
    }

    findings
}

fn same_peer_group(route: &Route, candidate: &Route) -> bool {
    route.scope_prefix == candidate.scope_prefix
        && route.method == candidate.method
        && route_segment_count(route) == route_segment_count(candidate)
}

fn route_segment_count(route: &Route) -> usize {
    route
        .path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(method: &str, path: &str, scope_prefix: &str, authorization: &str) -> Route {
        Route {
            method: method.into(),
            path: path.into(),
            scope_prefix: scope_prefix.into(),
            authorization: authorization.into(),
            authorization_evidence: authorization.into(),
            line: 1,
            file: PathBuf::from("fixture.rs"),
        }
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

        assert_eq!(
            classify_authorization(&guard, None, &handlers),
            ("PRESENT".into(), "authorization guard `AdminGuard`".into())
        );
        assert_eq!(
            classify_authorization(&middleware, None, &handlers),
            (
                "PRESENT".into(),
                "authorization middleware `AuthorizationMiddleware`".into()
            )
        );
        assert_eq!(
            classify_authorization(&generic_guard, None, &handlers),
            ("NONE".into(), "no recognized authorization evidence".into())
        );
    }

    #[test]
    fn analyze_demo_fixture_end_to_end() {
        let repo_path = Path::new("tests/fixtures");
        let report =
            analyze_repository(repo_path).expect("analysis of demo fixture should succeed");

        assert_eq!(report.files_scanned, 1);
        assert!(report.parse_errors.is_empty(), "expected no parse errors");
        assert_eq!(report.routes.len(), 5, "expected 5 routes in demo fixture");

        let route_paths: Vec<&str> = report.routes.iter().map(|r| r.path.as_str()).collect();
        assert!(route_paths.contains(&"/admin/users"));
        assert!(route_paths.contains(&"/admin/orders"));
        assert!(route_paths.contains(&"/admin/reports"));
        assert!(route_paths.contains(&"/admin/payments"));
        assert!(route_paths.contains(&"/admin/audit"));

        let users_route = report
            .routes
            .iter()
            .find(|r| r.path == "/admin/users")
            .unwrap();
        assert_eq!(users_route.method, "GET");
        assert_eq!(users_route.authorization, "PRESENT");

        let orders_route = report
            .routes
            .iter()
            .find(|r| r.path == "/admin/orders")
            .unwrap();
        assert_eq!(orders_route.method, "GET");
        assert_eq!(orders_route.authorization, "PRESENT");

        let reports_route = report
            .routes
            .iter()
            .find(|r| r.path == "/admin/reports")
            .unwrap();
        assert_eq!(reports_route.method, "GET");
        assert_eq!(reports_route.authorization, "PRESENT");

        let payments_route = report
            .routes
            .iter()
            .find(|r| r.path == "/admin/payments")
            .unwrap();
        assert_eq!(payments_route.method, "GET");
        assert_eq!(payments_route.authorization, "NONE");

        let audit_route = report
            .routes
            .iter()
            .find(|r| r.path == "/admin/audit")
            .unwrap();
        assert_eq!(audit_route.method, "POST");
        assert_eq!(audit_route.authorization, "NONE");

        assert_eq!(report.findings.len(), 1, "expected exactly 1 drift finding");
        let finding = &report.findings[0];
        assert!(
            finding.contains("/admin/payments"),
            "finding should flag /admin/payments"
        );
        assert!(finding.contains("Authorized peer evidence (3 route(s))"));
        assert!(finding.contains("/admin/users"));
        assert!(finding.contains("/admin/orders"));
        assert!(finding.contains("/admin/reports"));
        assert!(
            !finding.contains("/admin/audit"),
            "POST audit route should not be flagged"
        );
    }

    #[test]
    fn http_method_extraction_ast_based() {
        let route_get: ExprMethodCall =
            syn::parse_str("web::scope(\"/api\").route(\"/users\", web::get().to(h))").unwrap();
        let route_post: ExprMethodCall = syn::parse_str(
            "web::scope(\"/api\").route(\"/users\", web::post().guard(AdminGuard).to(h))",
        )
        .unwrap();
        let route_direct: ExprMethodCall =
            syn::parse_str("web::scope(\"/api\").route(\"/users\", get().to(h))").unwrap();
        let route_qualified: ExprMethodCall = syn::parse_str(
            "web::scope(\"/api\").route(\"/users\", actix_web::web::delete().to(h))",
        )
        .unwrap();
        let route_resource_method: ExprMethodCall =
            syn::parse_str("web::resource(\"/users\").route(web::put().to(h))").unwrap();
        let route_with_string_method: ExprMethodCall = syn::parse_str(
            "web::scope(\"/api\").route(\"/web/get_users\", custom_helper(\"web::get\"))",
        )
        .unwrap();

        assert_eq!(extract_http_method(&route_get), "GET");
        assert_eq!(extract_http_method(&route_post), "POST");
        assert_eq!(extract_http_method(&route_direct), "GET");
        assert_eq!(extract_http_method(&route_qualified), "DELETE");
        assert_eq!(extract_http_method(&route_resource_method), "PUT");
        assert_eq!(extract_http_method(&route_with_string_method), "UNKNOWN");
    }

    #[test]
    fn ordinary_identifiers_and_strings_do_not_count_as_authorization() {
        let syntax: syn::File = syn::parse_str(
            "fn benign_handler() {
                let role_name = \"guest\";
                let admin_dashboard_title = \"Dashboard\";
                let authentication_status = false;
                let author = \"Alice\";
                let authority = 42;
                println!(\"{} {} {} {} {}\", role_name, admin_dashboard_title, authentication_status, author, authority);
            }",
        )
        .unwrap();

        let handlers = collect_authorized_handlers(&syntax);
        assert!(
            !handlers.contains_key("benign_handler"),
            "benign variable names must not be classified as authorization evidence"
        );

        let route_var_guard: ExprMethodCall = syn::parse_str(
            "web::scope(\"/admin\").route(\"/x\", web::get().guard(admin_dashboard_title))",
        )
        .unwrap();
        assert_eq!(
            classify_authorization(&route_var_guard, None, &handlers),
            ("NONE".into(), "no recognized authorization evidence".into())
        );
    }

    #[test]
    fn error_handling_expressions_do_not_count_as_authorization() {
        let syntax: syn::File = syn::parse_str(
            "fn error_returning_handler() -> Result<(), AuthError> {
                let err = AuthError::Unauthorized;
                Err(err)
            }
            fn match_error_handler(res: Result<(), MyError>) {
                match res {
                    Ok(_) => (),
                    Err(AuthError::Forbidden) => (),
                    Err(_) => (),
                }
            }",
        )
        .unwrap();

        let handlers = collect_authorized_handlers(&syntax);
        assert!(
            !handlers.contains_key("error_returning_handler"),
            "returning AuthError without check must not count as authorization"
        );
        assert!(
            !handlers.contains_key("match_error_handler"),
            "matching on AuthError must not count as authorization"
        );
    }

    #[test]
    fn genuine_permission_check_returning_error_is_recognized() {
        let syntax: syn::File = syn::parse_str(
            "fn protected_handler(user: User) -> Result<(), AuthError> {
                if !check_permission(&user, \"admin\") {
                    return Err(AuthError::Forbidden);
                }
                Ok(())
            }",
        )
        .unwrap();

        let handlers = collect_authorized_handlers(&syntax);
        assert!(
            handlers.contains_key("protected_handler"),
            "genuine check_permission call should be detected even when it guards an error return"
        );
        assert!(handlers["protected_handler"].contains("call to check_permission"));
    }
}
