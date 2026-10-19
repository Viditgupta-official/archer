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

/// One lexical scope: a block, or the binding region of a function, closure,
/// loop, match arm, or `if let`/`while let`.
#[derive(Default)]
struct BlockScope {
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
            locals,
            items: HashMap::new(),
        }
    }
}

struct RouteVisitor<'a> {
    file: PathBuf,
    index: &'a HandlerIndex,
    crate_key: PathBuf,
    module: Vec<String>,
    block_scopes: Vec<BlockScope>,
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
            file,
            index,
            crate_key,
            module,
            block_scopes: Vec::new(),
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
            return;
        };

        let local_prefix = scope_prefix(&node.receiver);
        let prefix = join_paths(&self.scope_context, &local_prefix);
        let path = join_paths(&prefix, &path);
        let target = find_handler(&node.args);
        let (handler_evidence, handler_resolution) = match &target {
            None => (Vec::new(), None),
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
        let authorization =
            classify_authorization(node, handler.as_deref(), &handler_evidence, &self.file);

        let line = first_string_arg_line(&node.args).unwrap_or_else(|| node.span().start().line);

        self.routes.push(Route {
            method: extract_http_method(node),
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
        self.with_locals(signature_bindings(&node.sig), |visitor| {
            visit::visit_item_fn(visitor, node)
        });
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
            }
        }
        self.block_scopes.pop();
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
            let authorization = handler_evidence(&self.file, node);

            self.routes.push(Route {
                method: method.into(),
                path,
                scope_prefix: prefix,
                authorization,
                handler_path: Some(handler.clone()),
                handler_resolution: Some(HandlerResolution::Definition),
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

#[derive(Debug, Clone)]
struct HandlerDefinition {
    crate_key: PathBuf,
    module: Vec<String>,
    name: String,
    evidence: Vec<AuthEvidence>,
}

impl HandlerDefinition {
    fn rust_path(&self) -> String {
        std::iter::once("crate")
            .chain(self.module.iter().map(String::as_str))
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
#[derive(Debug, Default)]
struct HandlerIndex {
    definitions: Vec<HandlerDefinition>,
    by_name: HashMap<String, Vec<usize>>,
    scopes: HashMap<ModuleKey, ModuleScope>,
    modules: HashSet<ModuleKey>,
    file_modules: HashMap<PathBuf, ModuleKey>,
}

impl HandlerIndex {
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
        index
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
                        crate_key: crate_key.to_path_buf(),
                        module: module.clone(),
                        name,
                        evidence: handler_evidence(file, function),
                    });
                }
                Item::Mod(item_mod) => {
                    module.push(item_mod.ident.to_string());
                    self.modules
                        .insert((crate_key.to_path_buf(), module.clone()));
                    if let Some((_, items)) = &item_mod.content {
                        self.add_items(file, crate_key, module, items);
                    }
                    module.pop();
                }
                Item::Use(item_use) => {
                    let scope = self
                        .scopes
                        .entry((crate_key.to_path_buf(), module.clone()))
                        .or_default();
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
        let HandlerTarget::Path {
            segments,
            leading_colon,
        } = target
        else {
            return (None, HandlerResolution::Unresolved);
        };
        if *leading_colon {
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
            let lookup =
                match self.resolve_item(crate_key, &qualifier_module, name, &mut visited, 0) {
                    Lookup::Found(index, _) => Lookup::Found(index, HandlerResolution::Qualified),
                    other => other,
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
                    .filter(|&index| {
                        qualifier_module.as_ref().is_none_or(|qualifier| {
                            self.definitions[index].module.starts_with(qualifier)
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
        visited: &mut HashSet<(Vec<String>, String)>,
        depth: usize,
    ) -> Lookup {
        if depth > MAX_RESOLUTION_DEPTH || !visited.insert((module.to_vec(), name.to_owned())) {
            return Lookup::NotFound { explicit: true };
        }

        let local: Vec<usize> = self
            .definitions_named(crate_key, name)
            .filter(|&index| self.definitions[index].module == module)
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

        let lookups = scope
            .globs
            .iter()
            .filter_map(|glob| self.resolve_module(crate_key, module, glob, depth + 1))
            .map(|glob_module| self.resolve_item(crate_key, &glob_module, name, visited, depth + 1))
            .collect();
        combine_lookups(lookups, HandlerResolution::GlobImported)
            .unwrap_or(Lookup::NotFound { explicit: false })
    }

    fn resolve_use_item(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        visited: &mut HashSet<(Vec<String>, String)>,
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
            Some(target) => match self.resolve_item(crate_key, &target, name, visited, depth) {
                Lookup::NotFound { .. } => Lookup::NotFound { explicit: true },
                lookup => lookup,
            },
            None => Lookup::NotFound { explicit: true },
        }
    }

    /// Resolves a module path written in `module` to an absolute module path
    /// within the crate. Paths into other crates return `None`.
    fn resolve_module(
        &self,
        crate_key: &Path,
        module: &[String],
        path: &UsePath,
        depth: usize,
    ) -> Option<Vec<String>> {
        if path.leading_colon || depth > MAX_RESOLUTION_DEPTH {
            return None;
        }
        let segments = &path.segments;
        let (mut resolved, rest): (Vec<String>, &[String]) =
            match segments.first().map(String::as_str) {
                None => return Some(module.to_vec()),
                Some("crate") => (Vec::new(), &segments[1..]),
                Some("self") => (module.to_vec(), &segments[1..]),
                Some("super") => {
                    let supers = segments
                        .iter()
                        .take_while(|segment| *segment == "super")
                        .count();
                    if supers > module.len() {
                        return None;
                    }
                    (
                        module[..module.len() - supers].to_vec(),
                        &segments[supers..],
                    )
                }
                Some(first) => {
                    let mut child = module.to_vec();
                    child.push(first.to_owned());
                    if self.is_module(crate_key, &child) {
                        (child, &segments[1..])
                    } else {
                        let imports = self.scope(crate_key, module)?.imports.get(first)?;
                        let [import] = imports.as_slice() else {
                            return None;
                        };
                        (
                            self.resolve_module(crate_key, module, import, depth + 1)?,
                            &segments[1..],
                        )
                    }
                }
            };
        resolved.extend(rest.iter().cloned());
        self.is_module(crate_key, &resolved).then_some(resolved)
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
    // `access` is an authorization subject only as the final noun (`check_access`,
    // `verify_resource_access`); as a modifier it names authentication artifacts
    // such as `verify_access_token` or logging helpers such as `check_access_log`.
    let ends_with_access = tokens.last() == Some(&"access");
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
        || (uses_check_prefix && (has_token(&["permission"]) || ends_with_access))
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

/// The argument of a route's `.to(...)` call.
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
) -> Option<HandlerTarget> {
    exprs.iter().find_map(find_handler_in_expr)
}

fn find_handler_in_expr(expr: &Expr) -> Option<HandlerTarget> {
    match expr {
        Expr::MethodCall(method) if method.method == "to" => Some(match method.args.first()? {
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
        }),
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

    let mut parsed_files = Vec::new();
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
        parsed_files.push((module_location(root, &file_path), file_path, syntax));
    }

    // Index every handler definition before extracting routes so that route
    // registrations can resolve handlers defined in other files.
    let index = HandlerIndex::build(
        parsed_files
            .iter()
            .map(|(location, file_path, syntax)| (file_path.as_path(), location.clone(), syntax)),
    );
    for (_, file_path, syntax) in &parsed_files {
        let mut visitor = RouteVisitor::new(file_path.clone(), &index);
        visitor.visit_file(syntax);
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
            handler_path: None,
            handler_resolution: None,
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
        let index = HandlerIndex::default();
        let mut visitor = RouteVisitor::new(PathBuf::from("nested.rs"), &index);
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
        let index = HandlerIndex::single_file(file, &syntax);
        let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
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

        let guard_evidence = classify_authorization(&guard, None, &[], Path::new("fixture.rs"));
        assert_eq!(guard_evidence[0].kind, AuthEvidenceKind::AuthorizationGuard);
        assert_eq!(guard_evidence[0].symbol.as_deref(), Some("AdminGuard"));
        assert_eq!(guard_evidence[0].line, 1);
        assert_eq!(guard_evidence[0].strength, AuthStrength::Strong);

        let middleware_evidence =
            classify_authorization(&middleware, None, &[], Path::new("fixture.rs"));
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
            classify_authorization(&generic_guard, None, &[], Path::new("fixture.rs"));
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
        let index = HandlerIndex::single_file(Path::new("attributes.rs"), &syntax);
        let mut visitor = RouteVisitor::new(PathBuf::from("attributes.rs"), &index);
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
    fn access_token_and_access_log_helpers_are_not_authorization() {
        let syntax: syn::File = syn::parse_str(
            "fn token_only() { verify_access_token(); }
             fn log_only() { check_access_log(); }
             fn permission() { check_permission(); }
             fn access() { check_access(); }
             fn resource_access() { verify_resource_access(); }",
        )
        .unwrap();
        let handlers = collect_authorized_handlers(Path::new("access.rs"), &syntax);

        assert!(!handlers.contains_key("token_only"));
        assert!(!handlers.contains_key("log_only"));
        for (handler, mechanism) in [
            ("permission", "check_permission"),
            ("access", "check_access"),
            ("resource_access", "verify_resource_access"),
        ] {
            let evidence = &handlers[handler];
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[0].kind, AuthEvidenceKind::PermissionCheck);
            assert_eq!(evidence[0].mechanism, mechanism);
            assert_eq!(evidence[0].strength, AuthStrength::Strong);
        }

        let token_route = Route {
            method: "GET".into(),
            path: "/token-only".into(),
            scope_prefix: String::new(),
            handler: Some("token_only".into()),
            handler_path: None,
            handler_resolution: None,
            authorization: handlers.get("token_only").cloned().unwrap_or_default(),
            line: 1,
            file: PathBuf::from("access.rs"),
        };
        assert!(!token_route.is_authorized());
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
            handler_path: None,
            handler_resolution: None,
            authorization: handlers["profile"].clone(),
            line: 1,
            file: PathBuf::from("identity.rs"),
        };
        assert!(!route.is_authorized());
        assert!(route.strongest_evidence().is_none());
    }

    #[test]
    fn logger_and_compress_are_not_authorization_middleware() {
        for middleware in ["Logger", "Compress"] {
            let route: ExprMethodCall = syn::parse_str(&format!(
                "web::scope(\"/admin\").route(\"/x\", web::get().wrap({middleware}))"
            ))
            .unwrap();
            assert!(classify_authorization(&route, None, &[], Path::new("fixture.rs")).is_empty());
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

    #[test]
    fn nested_handlers_resolve_in_their_lexical_block_only() {
        let syntax: syn::File = syn::parse_str(
            "fn require_admin() {}
async fn health() { require_admin(); }
fn configure_admin(cfg: &mut web::ServiceConfig) {
    async fn list() { require_admin(); }
    cfg.route(\"/admin/list\", web::get().to(list));
    cfg.route(\"/admin/late\", web::get().to(late));
    async fn late() { require_admin(); }
}
fn configure_public(cfg: &mut web::ServiceConfig) {
    async fn list() {}
    async fn health() {}
    cfg.route(\"/public/list\", web::get().to(list));
    cfg.route(\"/public/health\", web::get().to(health));
    cfg.route(\"/public/module-health\", web::get().to(self::health));
    App::new().route(\"/public/closure\", web::get().to(list));
    {
        async fn list() { require_admin(); }
        cfg.route(\"/public/inner-block\", web::get().to(list));
    }
}
fn configure_duplicate(cfg: &mut web::ServiceConfig) {
    async fn health() {}
    async fn health() { require_admin(); }
    cfg.route(\"/duplicate/health\", web::get().to(health));
}
fn configure_top(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/top/health\", web::get().to(health));
    cfg.route(\"/top/late\", web::get().to(late));
}",
        )
        .unwrap();
        let file = Path::new("nested.rs");
        let index = HandlerIndex::single_file(file, &syntax);
        let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
        visitor.visit_file(&syntax);
        let route = |path: &str| {
            visitor
                .routes
                .iter()
                .find(|route| route.path == path)
                .unwrap_or_else(|| panic!("missing route {path}"))
        };

        // Protected nested handlers, including one declared after its route,
        // and an inner block's `list` shadowing its enclosing block's `list`.
        for (path, line) in [
            ("/admin/list", 4),
            ("/admin/late", 7),
            ("/public/inner-block", 17),
        ] {
            let route = route(path);
            assert_eq!(
                route.handler_resolution,
                Some(HandlerResolution::Local),
                "{path}"
            );
            assert_eq!(route.authorization.len(), 1, "{path}");
            assert_eq!(route.authorization[0].line, line, "{path}");
        }

        // A sibling's nested `list`, and a nested `health` that shadows the
        // protected module-level `health`, lend no evidence; closures inside
        // the block see the block's own `list`.
        for path in ["/public/list", "/public/health", "/public/closure"] {
            assert_eq!(
                route(path).handler_resolution,
                Some(HandlerResolution::Local),
                "{path}"
            );
            assert!(route(path).authorization.is_empty(), "{path}");
        }

        // Qualified paths bypass block scopes and reach the module-level definition.
        let module_health = route("/public/module-health");
        assert_eq!(
            module_health.handler_resolution,
            Some(HandlerResolution::Qualified)
        );
        assert_eq!(module_health.authorization[0].line, 2);

        // A duplicate declaration fails safely instead of borrowing either
        // candidate or the module-level `health`.
        let duplicate = route("/duplicate/health");
        assert_eq!(
            duplicate.handler_resolution,
            Some(HandlerResolution::Unresolved)
        );
        assert!(duplicate.authorization.is_empty());

        // Outside those blocks, `health` is the module-level definition, and
        // another function's nested `late` is not reachable even by fallback.
        let top_health = route("/top/health");
        assert_eq!(
            top_health.handler_resolution,
            Some(HandlerResolution::Local)
        );
        assert_eq!(top_health.authorization[0].line, 2);
        let top_late = route("/top/late");
        assert_eq!(
            top_late.handler_resolution,
            Some(HandlerResolution::Unresolved)
        );
        assert!(top_late.authorization.is_empty());
    }

    #[test]
    fn nested_function_bodies_do_not_lend_evidence_to_the_enclosing_handler() {
        let syntax: syn::File = syn::parse_str(
            "fn require_admin() {}
async fn report() {
    fn report_helper() { require_admin(); }
}
async fn audited() {
    require_admin();
    fn audited_helper() { check_permission(); }
}
async fn with_methods() {
    struct Helper;
    impl Helper { fn check(&self) { require_admin(); } }
    trait Guarded { fn guarded(&self) { require_admin(); } }
}
async fn branchy(flag: bool) {
    if flag { let _ = { require_admin(); }; }
    let check = || require_admin();
    check();
}
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/report\", web::get().to(report))
        .route(\"/audited\", web::get().to(audited))
        .route(\"/with-methods\", web::get().to(with_methods))
        .route(\"/branchy\", web::get().to(branchy));
}",
        )
        .unwrap();
        let file = Path::new("nested-evidence.rs");
        let handlers = collect_authorized_handlers(file, &syntax);

        // An uncalled nested helper, or nested impl/trait methods, lend nothing.
        assert!(!handlers.contains_key("report"));
        assert!(!handlers.contains_key("with_methods"));
        // The nested helper still owns its evidence.
        let helper = &handlers["report_helper"];
        assert_eq!(helper.len(), 1);
        assert_eq!(helper[0].line, 3);
        assert_eq!(helper[0].handler.as_deref(), Some("report_helper"));
        // Positive control: the outer handler's direct call is still recognized,
        // without the nested helper's permission check.
        let audited = &handlers["audited"];
        assert_eq!(audited.len(), 1);
        assert_eq!(audited[0].kind, AuthEvidenceKind::RoleCheck);
        assert_eq!(audited[0].mechanism, "require_admin");
        assert_eq!(audited[0].line, 6);
        // Nested blocks, branches, and closures in the handler are still traversed.
        let branchy_lines: Vec<usize> = handlers["branchy"].iter().map(|item| item.line).collect();
        assert_eq!(branchy_lines, vec![15, 16]);

        let index = HandlerIndex::single_file(file, &syntax);
        let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
        visitor.visit_file(&syntax);
        let route = |path: &str| {
            visitor
                .routes
                .iter()
                .find(|route| route.path == path)
                .unwrap_or_else(|| panic!("missing route {path}"))
        };
        for path in ["/report", "/with-methods"] {
            assert!(route(path).authorization.is_empty(), "{path}");
            assert!(!route(path).is_authorized(), "{path}");
        }
        assert_eq!(route("/audited").authorization.len(), 1);
        assert!(route("/audited").is_authorized());
        assert_eq!(route("/branchy").authorization.len(), 2);
    }

    #[test]
    fn inline_modules_do_not_see_enclosing_block_handlers() {
        // `list` is not in scope inside `mod inner` (rustc rejects it); the
        // analyzer must fail safely rather than borrow the block's evidence.
        let syntax: syn::File = syn::parse_str(
            "fn require_admin() {}
fn configure(cfg: &mut web::ServiceConfig) {
    async fn list() { require_admin(); }
    mod inner {
        fn configure(cfg: &mut web::ServiceConfig) {
            async fn own() { require_admin(); }
            cfg.route(\"/inner/list\", web::get().to(list));
            cfg.route(\"/inner/own\", web::get().to(own));
        }
    }
    cfg.route(\"/outer/list\", web::get().to(list));
}",
        )
        .unwrap();
        let file = Path::new("inline-module.rs");
        let index = HandlerIndex::single_file(file, &syntax);
        let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
        visitor.visit_file(&syntax);
        let route = |path: &str| {
            visitor
                .routes
                .iter()
                .find(|route| route.path == path)
                .unwrap_or_else(|| panic!("missing route {path}"))
        };

        let inner_list = route("/inner/list");
        assert_eq!(
            inner_list.handler_resolution,
            Some(HandlerResolution::Unresolved)
        );
        assert!(inner_list.authorization.is_empty());

        // The module's own blocks still resolve, and the enclosing block's
        // scope is restored after the module.
        for (path, line) in [("/inner/own", 6), ("/outer/list", 3)] {
            let route = route(path);
            assert_eq!(
                route.handler_resolution,
                Some(HandlerResolution::Local),
                "{path}"
            );
            assert_eq!(route.authorization.len(), 1, "{path}");
            assert_eq!(route.authorization[0].line, line, "{path}");
        }
    }

    #[test]
    fn local_bindings_shadow_handler_names_in_lexical_order() {
        let source = "fn require_admin() {}
async fn health() { require_admin(); }
async fn public_health() {}
struct Wrapper<T> { inner: T }
struct Routes;
impl Routes {
    fn register(cfg: &mut web::ServiceConfig, health: u8) {
        cfg.route(\"/method-param\", web::get().to(health));
    }
}
fn register<H>(cfg: &mut web::ServiceConfig, health: H) {
    cfg.route(\"/param\", web::get().to(health));
}
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/unshadowed\", web::get().to(health));
    {
        let health = || async {};
        cfg.route(\"/closure\", web::get().to(health));
    }
    {
        let health = public_health;
        cfg.route(\"/variable\", web::get().to(health));
    }
    {
        cfg.route(\"/before-let\", web::get().to(health));
        let health = {
            cfg.route(\"/own-initializer\", web::get().to(health));
            public_health
        };
        cfg.route(\"/after-let\", web::get().to(health));
        cfg.route(\"/qualified\", web::get().to(self::health));
        cfg.route(\"/crate-qualified\", web::get().to(crate::health));
    }
    {
        let (health, _) = (public_health, 1);
        cfg.route(\"/destructured\", web::get().to(health));
    }
    {
        let Wrapper { inner: health } = Wrapper { inner: public_health };
        cfg.route(\"/struct-pattern\", web::get().to(health));
    }
    for health in [public_health] {
        cfg.route(\"/for\", web::get().to(health));
    }
    cfg.route(\"/after-for\", web::get().to(health));
    match Some(public_health) {
        Some(health) if true => { cfg.route(\"/match\", web::get().to(health)); }
        _ => { cfg.route(\"/other-arm\", web::get().to(health)); }
    }
    cfg.route(\"/after-match\", web::get().to(health));
    if let Some(health) = Some(public_health) {
        cfg.route(\"/if-let\", web::get().to(health));
    } else {
        cfg.route(\"/if-let-else\", web::get().to(health));
    }
    cfg.route(\"/after-if\", web::get().to(health));
    while let Some(health) = None::<fn()> {
        cfg.route(\"/while-let\", web::get().to(health));
    }
    cfg.route(\"/after-while\", web::get().to(health));
    if let Some(health) = Some(cfg.route(\"/first-scrutinee\", web::get().to(health)))
        && let Some(_) = Some(cfg.route(\"/chain-scrutinee\", web::get().to(health)))
    {
        cfg.route(\"/let-chain\", web::get().to(health));
    }
    [public_health].into_iter().for_each(|health| {
        cfg.route(\"/closure-param\", web::get().to(health));
    });
    cfg.route(\"/after-closure\", web::get().to(health));
    {
        const health: u8 = 5;
        cfg.route(\"/const\", web::get().to(health));
    }
    {
        static health: u8 = 5;
        cfg.route(\"/static\", web::get().to(health));
    }
    {
        async fn health() { require_admin(); }
        let health = public_health;
        cfg.route(\"/let-over-item\", web::get().to(health));
    }
    let health = public_health;
    let mut later = || cfg.route(\"/captured\", web::get().to(health));
    {
        async fn health() { require_admin(); }
        cfg.route(\"/inner-item\", web::get().to(health));
    }
    cfg.route(\"/outer-let\", web::get().to(health));
}";
        let syntax: syn::File = syn::parse_str(source).unwrap();
        let line_of = |needle: &str| {
            source
                .lines()
                .position(|line| line.contains(needle))
                .map(|index| index + 1)
                .unwrap()
        };
        let module_health = line_of("async fn health() { require_admin(); }");
        let inner_item = source
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains("async fn health() { require_admin(); }"))
            .map(|(index, _)| index + 1)
            .last()
            .unwrap();
        assert!(inner_item > module_health);
        assert!(inner_item < line_of("\"/inner-item\""));

        let file = Path::new("shadowing.rs");
        let index = HandlerIndex::single_file(file, &syntax);
        let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
        visitor.visit_file(&syntax);
        let route = |path: &str| {
            visitor
                .routes
                .iter()
                .find(|route| route.path == path)
                .unwrap_or_else(|| panic!("missing route {path}"))
        };

        // Every binding form shadows the protected module-level `health`.
        for path in [
            "/method-param",
            "/param",
            "/closure",
            "/variable",
            "/after-let",
            "/destructured",
            "/struct-pattern",
            "/for",
            "/match",
            "/if-let",
            "/while-let",
            "/chain-scrutinee",
            "/let-chain",
            "/closure-param",
            "/const",
            "/static",
            "/let-over-item",
            "/captured",
            "/outer-let",
        ] {
            let route = route(path);
            assert_eq!(
                route.handler_resolution,
                Some(HandlerResolution::Unresolved),
                "{path}"
            );
            assert!(route.authorization.is_empty(), "{path}");
            assert!(!route.is_authorized(), "{path}");
        }

        // Before a binding, inside its own initializer, in sibling branches, and
        // after its scope ends, `health` is still the module-level handler.
        for path in [
            "/unshadowed",
            "/before-let",
            "/own-initializer",
            "/after-for",
            "/other-arm",
            "/after-match",
            "/if-let-else",
            "/after-if",
            "/after-while",
            "/first-scrutinee",
            "/after-closure",
        ] {
            let route = route(path);
            assert_eq!(
                route.handler_resolution,
                Some(HandlerResolution::Local),
                "{path}"
            );
            assert_eq!(route.authorization.len(), 1, "{path}");
            assert_eq!(route.authorization[0].line, module_health, "{path}");
        }

        // Qualified paths bypass local bindings.
        for path in ["/qualified", "/crate-qualified"] {
            let route = route(path);
            assert_eq!(
                route.handler_resolution,
                Some(HandlerResolution::Qualified),
                "{path}"
            );
            assert_eq!(route.authorization[0].line, module_health, "{path}");
        }

        // An inner block's item shadows the outer `let`.
        let inner = route("/inner-item");
        assert_eq!(inner.handler_resolution, Some(HandlerResolution::Local));
        assert_eq!(inner.authorization.len(), 1);
        assert_eq!(inner.authorization[0].line, inner_item);
    }

    #[test]
    fn shadowed_handler_names_never_use_the_unique_name_fallback() {
        let repo = TempRepo::new(
            "shadowed-fallback",
            &[
                ("Cargo.toml", CARGO_TOML),
                (
                    "src/handlers.rs",
                    "fn require_admin() {}
pub async fn health() { require_admin(); }
",
                ),
                (
                    "src/main.rs",
                    "mod handlers;
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/fallback\", web::get().to(health));
    let health = || async {};
    cfg.route(\"/closure\", web::get().to(health));
    cfg.route(\"/qualified\", web::get().to(handlers::health));
}
fn register<H>(cfg: &mut web::ServiceConfig, health: H) {
    cfg.route(\"/param\", web::get().to(health));
}
fn configure_loop(cfg: &mut web::ServiceConfig) {
    for health in [handlers::health] {
        cfg.route(\"/for\", web::get().to(health));
    }
}
",
                ),
            ],
        );
        let report = repo.analyze();

        assert_resolved_evidence(
            route_at(&report, "/fallback"),
            HandlerResolution::UniqueName,
            "src/handlers.rs",
        );
        assert_resolved_evidence(
            route_at(&report, "/qualified"),
            HandlerResolution::Qualified,
            "src/handlers.rs",
        );
        for path in ["/closure", "/param", "/for"] {
            let route = route_at(&report, path);
            assert_eq!(resolution(route), &HandlerResolution::Unresolved, "{path}");
            assert!(route.authorization.is_empty(), "{path}");
        }
    }

    struct TempRepo(PathBuf);

    impl TempRepo {
        fn new(name: &str, files: &[(&str, &str)]) -> Self {
            let root = std::env::temp_dir().join(format!("archer-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            for (path, contents) in files {
                let path = root.join(path);
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, contents).unwrap();
            }
            Self(root)
        }

        fn analyze(&self) -> Report {
            analyze_repository(&self.0).unwrap()
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    const CARGO_TOML: &str = "[package]\nname = \"fixture\"\nversion = \"0.1.0\"\n";

    fn route_at<'a>(report: &'a Report, path: &str) -> &'a Route {
        report
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap_or_else(|| panic!("missing route {path}"))
    }

    fn resolution(route: &Route) -> &HandlerResolution {
        route.handler_resolution.as_ref().unwrap()
    }

    fn assert_resolved_evidence(route: &Route, expected: HandlerResolution, file_suffix: &str) {
        assert_eq!(
            resolution(route),
            &expected,
            "resolution for {}",
            route.path
        );
        assert_eq!(route.authorization.len(), 1, "evidence for {}", route.path);
        assert_eq!(route.authorization[0].mechanism, "require_admin");
        assert!(
            route.authorization[0].file.ends_with(file_suffix),
            "evidence for {} came from {}",
            route.path,
            route.authorization[0].file.display()
        );
        assert!(route.is_authorized());
    }

    #[test]
    fn cross_file_glob_imported_handlers_carry_definition_evidence() {
        let repo = TempRepo::new(
            "cross-file",
            &[
                ("Cargo.toml", CARGO_TOML),
                (
                    "src/handlers.rs",
                    "pub fn require_admin() {}
pub async fn users() { require_admin(); }
pub async fn orders() { require_admin(); }
pub async fn reports() { require_admin(); }
pub async fn payments() {}
",
                ),
                (
                    "src/main.rs",
                    "mod handlers;
use crate::handlers::*;
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope(\"/admin\")
        .route(\"/users\", web::get().to(users))
        .route(\"/orders\", web::get().to(orders))
        .route(\"/reports\", web::get().to(reports))
        .route(\"/payments\", web::get().to(payments)));
}
",
                ),
            ],
        );
        let report = repo.analyze();

        assert_eq!(report.routes.len(), 4);
        for path in ["/admin/users", "/admin/orders", "/admin/reports"] {
            let route = route_at(&report, path);
            assert_resolved_evidence(route, HandlerResolution::GlobImported, "src/handlers.rs");
            assert!(route.file.ends_with("src/main.rs"));
        }
        let users = route_at(&report, "/admin/users");
        assert_eq!(users.authorization[0].line, 2);
        assert_eq!(users.authorization[0].handler.as_deref(), Some("users"));

        let payments = route_at(&report, "/admin/payments");
        assert_eq!(resolution(payments), &HandlerResolution::GlobImported);
        assert!(payments.authorization.is_empty());

        assert_eq!(report.finding_details.len(), 1);
        assert_eq!(
            report.finding_details[0].suspicious_route.path,
            "/admin/payments"
        );
        assert_eq!(report.finding_details[0].authorized_peer_routes.len(), 3);
    }

    #[test]
    fn module_qualified_handlers_resolve_through_file_and_inline_modules() {
        let repo = TempRepo::new(
            "qualified",
            &[
                ("Cargo.toml", CARGO_TOML),
                ("src/handlers/mod.rs", "pub mod admin;\n"),
                (
                    "src/handlers/admin.rs",
                    "fn require_admin() {}
pub async fn users() { require_admin(); }
pub async fn orders() { require_admin(); }
",
                ),
                (
                    "src/main.rs",
                    "mod handlers;
mod routes;
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/root-relative\", web::get().to(handlers::admin::users));
}
",
                ),
                (
                    "src/routes.rs",
                    "use crate::handlers::admin;
async fn health() {}
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/crate\", web::get().to(crate::handlers::admin::users))
        .route(\"/super\", web::get().to(super::handlers::admin::orders))
        .route(\"/module-alias\", web::get().to(admin::orders))
        .route(\"/self\", web::get().to(self::health));
}
mod nested {
    fn configure(cfg: &mut web::ServiceConfig) {
        cfg.route(\"/nested-super\", web::get().to(super::super::handlers::admin::users));
    }
}
",
                ),
            ],
        );
        let report = repo.analyze();

        for path in [
            "/root-relative",
            "/crate",
            "/super",
            "/module-alias",
            "/nested-super",
        ] {
            assert_resolved_evidence(
                route_at(&report, path),
                HandlerResolution::Qualified,
                "src/handlers/admin.rs",
            );
        }
        let crate_route = route_at(&report, "/crate");
        assert_eq!(crate_route.handler.as_deref(), Some("users"));
        assert_eq!(
            crate_route.handler_path.as_deref(),
            Some("crate::handlers::admin::users")
        );

        let health = route_at(&report, "/self");
        assert_eq!(resolution(health), &HandlerResolution::Qualified);
        assert!(health.authorization.is_empty());
    }

    #[test]
    fn explicit_imports_renames_and_reexports_resolve_to_the_named_definition() {
        let repo = TempRepo::new(
            "imports",
            &[
                ("Cargo.toml", CARGO_TOML),
                (
                    "src/handlers/mod.rs",
                    "pub mod admin;
pub mod public;
pub use public::list as public_list;
",
                ),
                (
                    "src/handlers/admin.rs",
                    "fn require_admin() {}
pub async fn list() { require_admin(); }
",
                ),
                ("src/handlers/public.rs", "pub async fn list() {}\n"),
                (
                    "src/main.rs",
                    "mod handlers;
use crate::handlers::admin::list as admin_list;
use crate::handlers::public::{self, list};
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/renamed\", web::get().to(admin_list))
        .route(\"/grouped\", web::get().to(list))
        .route(\"/self-import\", web::get().to(public::list))
        .route(\"/reexport\", web::get().to(handlers::public_list));
}
",
                ),
            ],
        );
        let report = repo.analyze();

        let renamed = route_at(&report, "/renamed");
        assert_resolved_evidence(
            renamed,
            HandlerResolution::Imported,
            "src/handlers/admin.rs",
        );
        assert_eq!(renamed.handler.as_deref(), Some("admin_list"));
        assert_eq!(renamed.authorization[0].handler.as_deref(), Some("list"));

        let grouped = route_at(&report, "/grouped");
        assert_eq!(resolution(grouped), &HandlerResolution::Imported);
        assert!(grouped.authorization.is_empty());

        for path in ["/self-import", "/reexport"] {
            let route = route_at(&report, path);
            assert_eq!(resolution(route), &HandlerResolution::Qualified, "{path}");
            assert!(route.authorization.is_empty(), "{path}");
        }
    }

    #[test]
    fn duplicate_handler_names_never_share_evidence() {
        let repo = TempRepo::new(
            "duplicates",
            &[
                ("Cargo.toml", CARGO_TOML),
                ("src/handlers/mod.rs", "pub mod admin;\npub mod public;\n"),
                (
                    "src/handlers/admin.rs",
                    "fn require_admin() {}
pub async fn list() { require_admin(); }
",
                ),
                ("src/handlers/public.rs", "pub async fn list() {}\n"),
                (
                    "src/main.rs",
                    "mod handlers;
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/admin/list\", web::get().to(handlers::admin::list))
        .route(\"/public/list\", web::get().to(handlers::public::list));
}
",
                ),
            ],
        );
        let report = repo.analyze();

        assert_resolved_evidence(
            route_at(&report, "/admin/list"),
            HandlerResolution::Qualified,
            "src/handlers/admin.rs",
        );
        let public = route_at(&report, "/public/list");
        assert_eq!(resolution(public), &HandlerResolution::Qualified);
        assert!(public.authorization.is_empty());
        assert!(!public.is_authorized());
    }

    #[test]
    fn same_file_inline_modules_with_duplicate_names_do_not_create_false_drift() {
        let repo = TempRepo::new(
            "inline-duplicates",
            &[(
                "src/main.rs",
                "fn require_admin() {}
mod admin { pub async fn list() { super::require_admin(); } }
mod public { pub async fn list() {} }
async fn users() { require_admin(); }
async fn orders() { require_admin(); }
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope(\"/admin\")
        .route(\"/users\", web::get().to(users))
        .route(\"/orders\", web::get().to(orders))
        .route(\"/list\", web::get().to(admin::list)));
    cfg.service(web::scope(\"/public\").route(\"/list\", web::get().to(public::list)));
}
",
            )],
        );
        let report = repo.analyze();

        assert_resolved_evidence(
            route_at(&report, "/admin/list"),
            HandlerResolution::Qualified,
            "src/main.rs",
        );
        assert_eq!(
            resolution(route_at(&report, "/admin/users")),
            &HandlerResolution::Local
        );
        assert!(route_at(&report, "/public/list").authorization.is_empty());
        assert!(report.finding_details.is_empty());
    }

    #[test]
    fn ambiguous_handlers_attach_no_evidence_and_list_sorted_candidates() {
        let repo = TempRepo::new(
            "ambiguous",
            &[
                ("Cargo.toml", CARGO_TOML),
                ("src/handlers/mod.rs", "pub mod admin;\npub mod public;\n"),
                (
                    "src/handlers/admin.rs",
                    "fn require_admin() {}
pub async fn list() { require_admin(); }
pub async fn audit() { require_admin(); }
",
                ),
                ("src/handlers/public.rs", "pub async fn list() {}\n"),
                (
                    "src/main.rs",
                    "mod handlers;
mod routes;
use crate::handlers::public::*;
use crate::handlers::admin::*;
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/glob-ambiguous\", web::get().to(list));
}
",
                ),
                (
                    "src/routes.rs",
                    "fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/fallback-ambiguous\", web::get().to(list))
        .route(\"/unique\", web::get().to(audit))
        .route(\"/compatible-qualifier\", web::get().to(crate::handlers::audit))
        .route(\"/incompatible-qualifier\", web::get().to(crate::handlers::public::audit));
}
",
                ),
            ],
        );
        let report = repo.analyze();

        let expected = HandlerResolution::Ambiguous {
            candidates: vec![
                "crate::handlers::admin::list".into(),
                "crate::handlers::public::list".into(),
            ],
        };
        for path in ["/glob-ambiguous", "/fallback-ambiguous"] {
            let route = route_at(&report, path);
            assert_eq!(resolution(route), &expected, "{path}");
            assert!(route.authorization.is_empty(), "{path}");
            assert!(!route.is_authorized(), "{path}");
        }

        for path in ["/unique", "/compatible-qualifier"] {
            assert_resolved_evidence(
                route_at(&report, path),
                HandlerResolution::UniqueName,
                "src/handlers/admin.rs",
            );
        }
        let incompatible = route_at(&report, "/incompatible-qualifier");
        assert_eq!(resolution(incompatible), &HandlerResolution::Unresolved);
        assert!(incompatible.authorization.is_empty());

        let first = serde_json::to_string(&report).unwrap();
        let second = serde_json::to_string(&repo.analyze()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn unresolved_handlers_stay_in_inventory_without_evidence() {
        let repo = TempRepo::new(
            "unresolved",
            &[
                ("Cargo.toml", CARGO_TOML),
                (
                    "src/other.rs",
                    "fn require_admin() {}
pub async fn h() { require_admin(); }
pub async fn imported() { require_admin(); }
",
                ),
                (
                    "src/main.rs",
                    "mod other;
use other_crate::imported;
struct Handlers;
impl Handlers { async fn list() { require_admin(); } }
async fn list() { require_admin(); }
fn configure(cfg: &mut web::ServiceConfig) {
    cfg.route(\"/external\", web::get().to(other_crate::h))
        .route(\"/absolute\", web::get().to(::other_crate::h))
        .route(\"/explicit-external-import\", web::get().to(imported))
        .route(\"/method\", web::get().to(Handlers::list))
        .route(\"/closure\", web::get().to(|| async { \"ok\" }))
        .route(\"/missing\", web::get().to(missing_handler))
        .route(\"/no-handler\", web::get());
}
",
                ),
            ],
        );
        let report = repo.analyze();

        assert_eq!(report.routes.len(), 7);
        for path in [
            "/external",
            "/absolute",
            "/explicit-external-import",
            "/method",
            "/closure",
            "/missing",
        ] {
            let route = route_at(&report, path);
            assert_eq!(resolution(route), &HandlerResolution::Unresolved, "{path}");
            assert!(route.authorization.is_empty(), "{path}");
            assert!(!route.is_authorized(), "{path}");
        }

        let method = route_at(&report, "/method");
        assert_eq!(method.handler.as_deref(), Some("list"));
        assert_eq!(method.handler_path.as_deref(), Some("Handlers::list"));
        assert_eq!(
            route_at(&report, "/absolute").handler_path.as_deref(),
            Some("::other_crate::h")
        );

        let closure = route_at(&report, "/closure");
        assert!(closure.handler.is_none());
        assert!(closure.handler_path.is_none());

        let no_handler = route_at(&report, "/no-handler");
        assert!(no_handler.handler.is_none());
        assert!(no_handler.handler_resolution.is_none());
    }

    #[test]
    fn attribute_routes_use_their_own_definition_evidence() {
        let repo = TempRepo::new(
            "attributes",
            &[(
                "src/main.rs",
                "fn require_admin() {}
mod admin { pub async fn users() { super::require_admin(); } }
#[get(\"/users\")]
async fn users() {}
mod secure {
    #[get(\"/secure\")]
    async fn users() { crate::require_admin(); }
}
",
            )],
        );
        let report = repo.analyze();

        let open = route_at(&report, "/users");
        assert_eq!(resolution(open), &HandlerResolution::Definition);
        assert!(open.authorization.is_empty());

        let secure = route_at(&report, "/secure");
        assert_eq!(resolution(secure), &HandlerResolution::Definition);
        assert_eq!(secure.authorization.len(), 1);
        assert_eq!(secure.authorization[0].mechanism, "require_admin");
        assert_eq!(secure.authorization[0].line, 7);
    }

    #[test]
    fn handler_resolution_serializes_as_tagged_kind() {
        assert_eq!(
            serde_json::to_value(HandlerResolution::Local).unwrap(),
            serde_json::json!({"kind": "Local"})
        );
        assert_eq!(
            serde_json::to_value(HandlerResolution::Ambiguous {
                candidates: vec!["crate::a::list".into()]
            })
            .unwrap(),
            serde_json::json!({"kind": "Ambiguous", "candidates": ["crate::a::list"]})
        );
    }

    #[test]
    fn module_location_follows_cargo_layout() {
        let repo = TempRepo::new(
            "layout",
            &[
                ("Cargo.toml", CARGO_TOML),
                ("src/main.rs", ""),
                ("src/lib.rs", ""),
                ("src/handlers/mod.rs", ""),
                ("src/handlers/admin.rs", ""),
                ("src/bin/tool.rs", ""),
                ("tests/integration.rs", ""),
                ("build.rs", ""),
            ],
        );
        let root = &repo.0;
        let module = |path: &str| module_location(root, &root.join(path));

        assert_eq!(module("src/main.rs"), (root.clone(), vec![]));
        assert_eq!(module("src/lib.rs"), (root.clone(), vec![]));
        assert_eq!(
            module("src/handlers/mod.rs"),
            (root.clone(), vec!["handlers".into()])
        );
        assert_eq!(
            module("src/handlers/admin.rs"),
            (root.clone(), vec!["handlers".into(), "admin".into()])
        );
        for isolated in ["src/bin/tool.rs", "tests/integration.rs", "build.rs"] {
            assert_eq!(
                module(isolated),
                (root.join(isolated), vec![]),
                "{isolated}"
            );
        }
    }
}
