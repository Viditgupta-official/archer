//! Actix registration expansion. Mount context is separate from handler identity.
use super::*;

pub(super) fn is_app_builder(mut expr: &Expr) -> bool {
    while let Expr::MethodCall(call) = expr {
        expr = &call.receiver;
    }
    matches!(expr, Expr::Call(c) if matches!(&*c.func, Expr::Path(p) if p.path.segments.iter().map(|s| s.ident.to_string()).collect::<Vec<_>>().ends_with(&["App".into(), "new".into()])))
}

// Strip explicit test-only items before indexing and route traversal.
pub(super) fn strip_test_items(items: &mut Vec<Item>) {
    items.retain(|item| {
        let attrs = match item {
            Item::Fn(f) => &f.attrs,
            Item::Mod(m) => &m.attrs,
            _ => return true,
        };
        !attrs.iter().any(|a| {
            a.path().segments.last().is_some_and(|s| s.ident == "test")
                || (a.path().is_ident("cfg")
                    && a.parse_args::<syn::Path>()
                        .is_ok_and(|p| p.is_ident("test")))
        })
    });
    for item in items {
        if let Item::Mod(m) = item {
            if let Some((_, items)) = &mut m.content {
                strip_test_items(items);
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Diagnostic {
    pub code: String,
    pub file: PathBuf,
    pub line: usize,
    pub message: String,
}

// Normalize only the builder's root API path, never paths inside handler/guard
// arguments. Local lookalikes and unresolved imports cannot prove this contract.
pub(super) fn resolved_route_builder(
    index: &HandlerIndex,
    context: &ModuleKey,
    expr: &Expr,
) -> Option<Expr> {
    let mut builder = expr.clone();
    let mut root = &mut builder;
    loop {
        match root {
            Expr::MethodCall(c) => root = &mut c.receiver,
            Expr::Paren(p) => root = &mut p.expr,
            Expr::Group(p) => root = &mut p.expr,
            Expr::Call(c) => {
                let Expr::Path(p) = &mut *c.func else {
                    return None;
                };
                let canonical = security::external_path(index, context, &p.path, 0)?;
                let supported = canonical
                    .strip_prefix("actix_web::web::")
                    .is_some_and(|name| {
                        ROUTE_METHOD_CONSTRUCTORS.contains(&name)
                            || ["route", "method"].contains(&name)
                    })
                    || canonical == "actix_web::Route::new";
                if !supported {
                    return None;
                }
                p.path = syn::parse_str(&canonical).ok()?;
                return Some(builder);
            }
            _ => return None,
        }
    }
}

impl RouteVisitor<'_> {
    pub(super) fn diagnostic(&mut self, code: &str, line: usize, message: impl Into<String>) {
        self.diagnostics.push(Diagnostic {
            code: code.into(),
            file: self.file.clone(),
            line,
            message: message.into(),
        });
    }

    pub(super) fn expand_configuration(&mut self, node: &ExprMethodCall) {
        let prefix = join_paths(&self.scope_context, &scope_prefix(&node.receiver));
        let Some(arg) = node.args.first() else { return };
        let target = match arg {
            Expr::Closure(c) => {
                let body = match &*c.body {
                    Expr::Block(b) if b.block.stmts.len() == 1 => match &b.block.stmts[0] {
                        Stmt::Expr(e, _) => e,
                        _ => &*c.body,
                    },
                    body => body,
                };
                match (c.inputs.first(), body) {
                    (Some(Pat::Ident(param)), Expr::Call(call))
                        if c.inputs.len() == 1
                            && !call.args.is_empty()
                            && matches!(call.args.first(),Some(Expr::Path(p)) if p.path.is_ident(&param.ident)) =>
                    {
                        Some(&*call.func)
                    }
                    _ => None,
                }
            }
            Expr::Path(_) => Some(arg),
            _ => None,
        };
        if let Some(target) = target {
            if self.expand_function(target, &prefix, false) {
                return;
            }
        } else if let Expr::Closure(c) = arg {
            let previous = self.scope_context.clone();
            self.scope_context = prefix;
            self.visit_expr(&c.body);
            self.scope_context = previous;
            return;
        }
        self.diagnostic("unresolved_callback", node.span().start().line,
            "Cannot resolve configuration callback; mounted endpoints and security may be incomplete");
    }

    pub(super) fn expand_service(&mut self, expr: &Expr) -> bool {
        let target = match expr {
            Expr::Path(_) => expr,
            Expr::Call(c) => &*c.func,
            Expr::MethodCall(_) => {
                let mut root = expr;
                while let Expr::MethodCall(call) = root {
                    root = &call.receiver;
                }
                let supported = matches!(root, Expr::Call(call) if matches!(&*call.func, Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "scope" || s.ident == "resource")));
                if !supported {
                    self.diagnostic("unsupported_service_builder", expr.span().start().line, "Service builder is not a supported scope/resource; generated endpoints may be missing");
                }
                return false;
            }
            _ => return false,
        };
        let expanded = self.expand_function(target, &self.scope_context.clone(), true);
        if !expanded {
            self.diagnostic("unresolved_service", expr.span().start().line, "Service factory or attribute service could not be resolved; generated endpoints may be missing");
        }
        expanded
    }

    fn expand_function(&mut self, expr: &Expr, prefix: &str, service: bool) -> bool {
        let Expr::Path(path) = expr else { return false };
        let target = HandlerTarget::Path {
            segments: path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect(),
            leading_colon: path.path.leading_colon.is_some(),
        };
        let (definition, _) = self
            .index
            .resolve_handler(&self.crate_key, &self.module, &target);
        let Some(definition) = definition else {
            return false;
        };
        if self.expansion_depth >= 16 {
            self.diagnostic(
                "expansion_limit",
                expr.span().start().line,
                "Registration expansion depth exceeded",
            );
            return true;
        }
        let mut child = RouteVisitor::new(definition.file.clone(), self.index);
        child.application = self.application.clone();
        child.conservative_security = self.conservative_security;
        child.module = definition.module.clone();
        child.scope_context = prefix.into();
        child.expansion_depth = self.expansion_depth + 1;
        child.chain_scopes = self.chain_scopes.clone();
        if service
            && definition
                .function
                .attrs
                .iter()
                .any(|a| attribute_route_name(a).is_some())
        {
            child.add_attribute_routes(&definition.function);
            for route in &mut child.routes {
                for (_, evidence) in &child.chain_scopes {
                    route.authorization.extend(evidence.clone());
                }
            }
        } else {
            child.with_locals(signature_bindings(&definition.function.sig), |v| {
                v.visit_block(&definition.function.block)
            });
        }
        self.mounted_routes.extend(child.routes);
        self.mounted_routes.extend(child.mounted_routes);
        self.diagnostics.extend(child.diagnostics);
        true
    }

    pub(super) fn visit_resource_registration(&mut self, node: &ExprMethodCall) -> bool {
        let mut calls = Vec::new();
        let mut current = node;
        let root = loop {
            calls.push(current);
            match &*current.receiver {
                Expr::MethodCall(next) => current = next,
                Expr::Call(call) => break call,
                _ => return false,
            }
        };
        let Expr::Path(path) = &*root.func else {
            return false;
        };
        if path
            .path
            .segments
            .last()
            .is_none_or(|s| s.ident != "resource")
        {
            return false;
        }
        let Some(Expr::Lit(ExprLit {
            lit: Lit::Str(resource),
            ..
        })) = root.args.first()
        else {
            self.diagnostic(
                "unsupported_registration",
                root.span().start().line,
                "Resource path is not a string literal",
            );
            return true;
        };
        let mut inherited = chain_configuration_evidence(node, &self.file);
        if self.conservative_security {
            inherited.extend(security::unknown_middleware(node, &self.file));
        }
        let mut emitted = false;
        for call in calls.iter().rev() {
            let name = call.method.to_string();
            let builder: Option<Expr> = if ROUTE_METHOD_CONSTRUCTORS.contains(&name.as_str()) {
                call.args.first().map(|handler| {
                    let method = &call.method;
                    syn::parse_quote!(web::#method().to(#handler))
                })
            } else if name == "route" {
                call.args.first().cloned()
            } else {
                None
            };
            if let Some(builder) = builder {
                let registration: ExprMethodCall =
                    syn::parse_quote!(cfg.route(#resource, #builder));
                let start = self.routes.len();
                self.add_route(&registration);
                for route in &mut self.routes[start..] {
                    route.authorization.extend(inherited.clone());
                }
                emitted = true;
            }
        }
        if !emitted {
            self.diagnostic(
                "unsupported_registration",
                node.span().start().line,
                "Resource has no supported method/handler registration",
            );
        }
        true
    }
}

pub(super) fn merge_mounts(routes: &mut Vec<Route>, mounted: Vec<Route>) {
    routes.retain(|r| {
        !mounted.iter().any(|m| {
            m.file == r.file && m.line == r.line && m.handler == r.handler && m.method == r.method
        })
    });
    routes.extend(mounted);
    // A configuration declaration is also visited on its own. Once its source
    // registration is observed in a concrete App, keep the actual mounts and
    // discard the declaration-only expansion, including nested callbacks.
    let concrete: HashSet<_> = routes
        .iter()
        .filter(|r| {
            r.application
                .as_ref()
                .is_some_and(|a| !a.starts_with("declaration:"))
        })
        .map(|r| (r.file.clone(), r.line, r.method.clone(), r.handler.clone()))
        .collect();
    routes.retain(|r| {
        !r.application
            .as_ref()
            .is_some_and(|a| a.starts_with("declaration:"))
            || !concrete.contains(&(r.file.clone(), r.line, r.method.clone(), r.handler.clone()))
    });
    let mut seen = HashSet::new();
    routes.retain(|r| {
        seen.insert((
            r.application.clone(),
            r.file.clone(),
            r.method.clone(),
            r.path.clone(),
            r.handler_path.clone(),
            format!("{:?}", r.authorization),
        ))
    });
}

pub(super) fn missing_context(
    routes: &[Route],
    mounted: &[Route],
    index: &HandlerIndex,
) -> Vec<Diagnostic> {
    routes.iter().filter(|route| {
        !mounted.iter().any(|m| m.file == route.file && m.line == route.line && m.handler == route.handler)
        && (matches!(route.handler_resolution,Some(HandlerResolution::Definition)) || index.definitions.iter().any(|d| d.file == route.file
            && d.function.sig.to_token_stream().to_string().contains("ServiceConfig")
            && d.function.span().start().line <= route.line && d.function.span().end().line >= route.line))
    }).map(|route| Diagnostic {
        code: "missing_route_context".into(), file: route.file.clone(), line: route.line,
        message: "Route declaration has no verified application mount; effective scope and middleware context may be incomplete".into(),
    }).collect()
}

#[cfg(test)]
#[allow(dead_code)] // Retained for legacy diagnostic regression compatibility.
pub(super) fn coverage_diagnostics(routes: &[Route]) -> Vec<Diagnostic> {
    routes
        .iter()
        .filter_map(|route| {
            let (code, message) =
                if is_authentication_route(route) || is_operational_public_route(route) {
                    (
                        "peer_excluded",
                        "Authentication or operational endpoint excluded by existing peer rules",
                    )
                } else if routes.iter().filter(|r| same_peer_group(route, r)).count() < 2 {
                    (
                        "peer_rejected",
                        "No second route matches existing scope, method and path-shape rules",
                    )
                } else if !route.is_authorized() {
                    (
                        "insufficient_security_evidence",
                        "No recognized authorization evidence; authentication is not authorization",
                    )
                } else {
                    return None;
                };
            Some(Diagnostic {
                code: code.into(),
                file: route.file.clone(),
                line: route.line,
                message: message.into(),
            })
        })
        .collect()
}
