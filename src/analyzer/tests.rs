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
        application: None,
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
    let protected = route_with_handler("GET", "/api/admin/users", "/api/admin", "users", "PRESENT");
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
        assert!(
            visitor
                .routes
                .iter()
                .any(|route| route.method == method && route.path == path),
            "missing {method} {path}"
        );
    }

    for route in &visitor.routes {
        let expected_scope = ["admin", "manager", "finance", "documents", "public"]
            .iter()
            .find(|scope| route.path.starts_with(&format!("/api/{scope}/")))
            .map(|scope| format!("/api/{scope}"))
            .unwrap_or_default();
        assert_eq!(
            route.scope_prefix, expected_scope,
            "wrong scope for {} {}",
            route.method, route.path
        );
    }

    for handler in ["admin_users", "admin_orders", "admin_reports"] {
        let route = visitor
            .routes
            .iter()
            .find(|route| route.handler.as_deref() == Some(handler))
            .unwrap();
        assert_eq!(route.authorization.len(), 1);
        assert_eq!(route.authorization[0].mechanism, "require_admin");
        assert_eq!(route.authorization[0].handler.as_deref(), Some(handler));
    }
    let audit = visitor
        .routes
        .iter()
        .find(|route| route.path == "/api/admin/audit")
        .unwrap();
    assert_eq!(audit.method, "POST");

    let (groups, invariants, details, findings) = build_analysis_layers(&visitor.routes);
    let admin_group = groups
        .iter()
        .find(|group| {
            group
                .routes
                .iter()
                .any(|route| route.path == "/api/admin/payments")
        })
        .unwrap();
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
fn http_method_extraction_follows_the_route_builder_chain() {
    // Fixtures are route registrations parsed with `syn`. Constructors and
    // method constants follow actix-web 4: `web::{get, post, put, patch,
    // delete, head, trace}`, `web::method(Method::X)`, `web::route()`, and
    // `Route::method(Method::X)`, which adds a method guard. OPTIONS and
    // CONNECT have no `web::` constructor and are written with `Method::`.
    for (route, expected) in [
        // Cases from the reviewed branch commit 05561a3.
        (
            r#"web::scope("/api").route("/users", web::get().to(h))"#,
            "GET",
        ),
        (
            r#"web::scope("/api").route("/users", web::post().guard(AdminGuard).to(h))"#,
            "POST",
        ),
        (r#"web::scope("/api").route("/users", get().to(h))"#, "GET"),
        (
            r#"web::scope("/api").route("/users", actix_web::web::delete().to(h))"#,
            "DELETE",
        ),
        (r#"web::resource("/users").route(web::put().to(h))"#, "PUT"),
        (
            r#"web::scope("/api").route("/web/get_users", custom_helper("web::get"))"#,
            "UNKNOWN",
        ),
        // Calls nested in guard, configuration, or handler arguments are ignored.
        (
            r#"cfg.route("/mode", web::route().guard(guard::Header("x-mode", config.get("mode"))).to(h))"#,
            "UNKNOWN",
        ),
        (
            r#"cfg.route("/flag", web::post().guard(guard::fn_guard(|ctx| config.get("flag").is_some())).to(h))"#,
            "POST",
        ),
        (
            r#"cfg.route("/users", web::post().to(web::get_users))"#,
            "POST",
        ),
        (r#"cfg.route("/users", my_routes::get().to(h))"#, "UNKNOWN"),
        // Remaining constructors.
        (r#"cfg.route("/x", web::patch().to(h))"#, "PATCH"),
        (r#"cfg.route("/x", web::head().to(h))"#, "HEAD"),
        (r#"cfg.route("/x", web::trace().to(h))"#, "TRACE"),
        (r#"cfg.route("/x", web::options().to(h))"#, "UNKNOWN"),
        // `web::method(...)` with qualified constants.
        (r#"cfg.route("/x", web::method(Method::PUT).to(h))"#, "PUT"),
        (
            r#"cfg.route("/x", web::method(http::Method::PUT).to(h))"#,
            "PUT",
        ),
        (
            r#"cfg.route("/x", actix_web::web::method(actix_web::http::Method::PUT).to(h))"#,
            "PUT",
        ),
        (
            r#"cfg.route("/x", web::method(Method::OPTIONS).to(h))"#,
            "OPTIONS",
        ),
        (
            r#"cfg.route("/x", web::method(Method::from_bytes(b"PUT").unwrap()).to(h))"#,
            "UNKNOWN",
        ),
        // `Route::method(...)` on an any-method route.
        (
            r#"cfg.route("/x", web::route().method(Method::PUT).to(h))"#,
            "PUT",
        ),
        (
            r#"cfg.route("/x", web::route().method(http::Method::CONNECT).guard(g).to(h))"#,
            "CONNECT",
        ),
        (
            r#"cfg.route("/x", Route::new().method(Method::DELETE).to(h))"#,
            "DELETE",
        ),
        (r#"cfg.route("/x", web::route().to(h))"#, "UNKNOWN"),
        // Method guards that agree keep the method; conflicting ones do not.
        (
            r#"cfg.route("/x", web::get().method(Method::GET).to(h))"#,
            "GET",
        ),
        (
            r#"cfg.route("/x", web::get().method(Method::POST).to(h))"#,
            "UNKNOWN",
        ),
    ] {
        let call: ExprMethodCall = syn::parse_str(route).unwrap();
        assert_eq!(extract_http_method(&call), expected, "{route}");
    }
}

#[test]
fn extracted_routes_carry_builder_methods_without_changing_handler_resolution() {
    let syntax: syn::File = syn::parse_str(
        r#"
        fn require_admin() {}
        async fn get_users() { require_admin(); }
        async fn h() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/api")
                .route("/users", web::post().to(get_users))
                .route("/mode", web::route().guard(guard::Header("x-mode", config.get("mode"))).to(h))
                .route("/web/get_users", custom_helper("web::get"))
                .route("/put", web::route().method(Method::PUT).to(h)));
        }
        "#,
    )
    .unwrap();
    let file = Path::new("methods.rs");
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

    assert_eq!(visitor.routes.len(), 4);
    assert_eq!(route("/api/users").method, "POST");
    assert_eq!(route("/api/mode").method, "UNKNOWN");
    assert_eq!(route("/api/web/get_users").method, "UNKNOWN");
    assert_eq!(route("/api/put").method, "PUT");

    let users = route("/api/users");
    assert_eq!(users.handler_resolution, Some(HandlerResolution::Local));
    assert_eq!(users.authorization.len(), 1);
    assert_eq!(users.authorization[0].mechanism, "require_admin");
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
    assert!(
        evidence
            .iter()
            .all(|item| item.handler.as_deref() == Some("protected"))
    );
    assert!(
        !evidence
            .iter()
            .any(|item| item.mechanism == "admin_dashboard_title")
    );
    assert!(
        !evidence.iter().any(
            |item| item.kind == AuthEvidenceKind::IdentityExtraction && item.is_authorization()
        )
    );

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
        application: None,
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
fn helper_names_separate_enforcement_from_lookups_and_authentication() {
    use AuthEvidenceKind::*;
    for (name, expected) in [
        // Plausible enforcement helpers.
        ("require_admin", Some(RoleCheck)),
        ("has_role", Some(RoleCheck)),
        ("check_roles", Some(RoleCheck)),
        ("is_admin", Some(RoleCheck)),
        ("check_permission", Some(PermissionCheck)),
        ("verify_finance_permission", Some(PermissionCheck)),
        ("verify_resource_access", Some(PermissionCheck)),
        ("check_resource_owner", Some(OwnershipCheck)),
        ("is_owned_by", Some(OwnershipCheck)),
        ("authorize", Some(ManualAuthorizationCheck)),
        ("authorize_request", Some(ManualAuthorizationCheck)),
        // Authentication is identity, never authorization.
        ("require_auth", Some(IdentityExtraction)),
        ("require_authenticated_user", Some(IdentityExtraction)),
        // Misleading names: token validation, lookups, logging, and data.
        ("verify_access_token", None),
        ("check_username", None),
        ("ensure_user_exists", None),
        ("verify_oauth_state", None),
        ("check_access_log", None),
        ("ensure_admin_exists", None),
        ("check_admin_token", None),
        ("role_name", None),
        ("permissions_list", None),
        ("authorized_user", None),
        ("downstream", None),
        ("author_name", None),
        ("handle_auth_error", None),
    ] {
        assert_eq!(
            classify_check_name(name).map(|(kind, _)| kind),
            expected,
            "{name}"
        );
    }
}

#[test]
fn method_calls_use_word_rules_instead_of_substrings() {
    let syntax: syn::File = syn::parse_str(
        "fn is_admin_method(user: User) { user.is_admin(); }
         fn has_role_method(user: User) { user.has_role(\"admin\"); }
         fn owns_method(user: User) { user.owns(&doc); }
         fn authorize_method(policy: Policy) { policy.authorize(&user); }
         fn claims_method(req: Req) { req.extract_claims(); }
         fn misleading_methods(user: User, stream: Stream, req: Req) {
             user.role_name();
             user.permissions_list();
             req.authorized_user();
             stream.downstream();
         }",
    )
    .unwrap();
    let handlers = collect_authorized_handlers(Path::new("methods.rs"), &syntax);

    for (handler, kind) in [
        ("is_admin_method", AuthEvidenceKind::RoleCheck),
        ("has_role_method", AuthEvidenceKind::RoleCheck),
        ("owns_method", AuthEvidenceKind::OwnershipCheck),
        (
            "authorize_method",
            AuthEvidenceKind::ManualAuthorizationCheck,
        ),
        ("claims_method", AuthEvidenceKind::IdentityExtraction),
    ] {
        let evidence = &handlers[handler];
        assert_eq!(evidence.len(), 1, "{handler}");
        assert_eq!(evidence[0].kind, kind, "{handler}");
    }
    assert!(!handlers["claims_method"][0].is_authorization());
    assert!(!handlers.contains_key("misleading_methods"));
}

#[test]
fn route_configuration_names_separate_authorization_from_authentication() {
    assert_eq!(
        camel_case_words("AdminAuthMiddleware"),
        ["admin", "auth", "middleware"]
    );
    assert_eq!(camel_case_words("JWTGuard"), ["jwt", "guard"]);
    assert_eq!(
        camel_case_words("HttpAuthentication"),
        ["http", "authentication"]
    );

    let evidence = |route: &str| {
        let call: ExprMethodCall = syn::parse_str(route).unwrap();
        classify_authorization(&call, None, &[], Path::new("fixture.rs"))
            .into_iter()
            .map(|item| (item.kind, item.mechanism, item.strength))
            .collect::<Vec<_>>()
    };
    use AuthEvidenceKind::*;
    use AuthStrength::*;
    for (route, expected) in [
        (
            r#"web::scope("/a").route("/x", web::get().guard(AdminGuard).to(h))"#,
            vec![(AuthorizationGuard, "AdminGuard", Strong)],
        ),
        (
            r#"web::scope("/a").route("/x", web::get().guard(guard::fn_guard(check_admin)).to(h))"#,
            vec![(AuthorizationGuard, "check_admin", Strong)],
        ),
        (
            r#"web::scope("/a").wrap(RequireAdmin).route("/x", web::get().to(h))"#,
            vec![(AuthorizationMiddleware, "RequireAdmin", Medium)],
        ),
        (
            r#"web::scope("/a").wrap(AdminAuthMiddleware).route("/x", web::get().to(h))"#,
            vec![(AuthorizationMiddleware, "AdminAuthMiddleware", Medium)],
        ),
        (
            r#"web::scope("/a").wrap(AuthMiddleware).route("/x", web::get().to(h))"#,
            vec![(IdentityExtraction, "AuthMiddleware", Weak)],
        ),
        (
            r#"web::scope("/a").route("/x", web::get().guard(AuthGuard).to(h))"#,
            vec![(IdentityExtraction, "AuthGuard", Weak)],
        ),
        (
            r#"web::scope("/a").wrap(HttpAuthentication::bearer(validator)).route("/x", web::get().to(h))"#,
            vec![(IdentityExtraction, "HttpAuthentication", Weak)],
        ),
        (
            r#"web::scope("/a").wrap(UnauthorizedHandler).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").wrap(PermissionsPolicy::default()).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").wrap(RoleLogger).route("/x", web::get().to(h))"#,
            vec![],
        ),
        // Authorization and guard words, but an error-mapping or logging type.
        (
            r#"web::scope("/a").wrap(AuthorizationErrorMiddleware).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").wrap(RoleCheckLogger).route("/x", web::get().to(h))"#,
            vec![],
        ),
        (
            r#"web::scope("/a").route("/x", web::get().guard(guard::Header("x-role", "admin")).to(h))"#,
            vec![],
        ),
    ] {
        let expected: Vec<_> = expected
            .into_iter()
            .map(|(kind, mechanism, strength)| (kind, mechanism.to_owned(), strength))
            .collect();
        assert_eq!(evidence(route), expected, "{route}");
    }
}

#[test]
fn guard_and_middleware_evidence_keeps_handler_evidence() {
    let syntax: syn::File = syn::parse_str(
        r#"
        fn require_admin() {}
        async fn guarded() { check_permission(); }
        async fn authenticated_admin() { require_admin(); }
        async fn authenticated_only() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.route("/guarded", web::get().guard(AdminGuard).to(guarded));
            cfg.service(web::scope("/session")
                .wrap(AuthMiddleware)
                .route("/admin", web::get().to(authenticated_admin)));
            cfg.service(web::scope("/session")
                .wrap(AuthMiddleware)
                .route("/plain", web::get().to(authenticated_only)));
        }
        "#,
    )
    .unwrap();
    let file = Path::new("mixed.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let kinds = |path: &str| {
        let route = visitor
            .routes
            .iter()
            .find(|route| route.path == path)
            .unwrap();
        (
            route.is_authorized(),
            route
                .authorization
                .iter()
                .map(|item| item.kind.clone())
                .collect::<Vec<_>>(),
        )
    };
    use AuthEvidenceKind::*;

    assert_eq!(
        kinds("/guarded"),
        (true, vec![AuthorizationGuard, PermissionCheck])
    );
    assert_eq!(
        kinds("/session/admin"),
        (true, vec![IdentityExtraction, RoleCheck])
    );
    assert_eq!(kinds("/session/plain"), (false, vec![IdentityExtraction]));
}

fn route_evidence(source: &str) -> HashMap<String, Vec<(AuthEvidenceKind, String)>> {
    let syntax: syn::File = syn::parse_str(source).unwrap();
    let file = Path::new("scopes.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    visitor
        .routes
        .into_iter()
        .map(|route| {
            let evidence = route
                .authorization
                .into_iter()
                .map(|item| (item.kind, item.mechanism))
                .collect();
            (route.path, evidence)
        })
        .collect()
}

#[test]
fn scope_middleware_applies_to_every_route_in_its_chain() {
    // Actix applies a scope's `.wrap(...)` to all of the scope's routes,
    // wherever the call appears in the builder chain.
    let evidence = route_evidence(
        r#"
        async fn h() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/before").wrap(AdminMiddleware)
                .route("/a", web::get().to(h))
                .route("/b", web::get().to(h)));
            cfg.service(web::scope("/between")
                .route("/a", web::get().to(h))
                .wrap(AdminMiddleware)
                .route("/b", web::get().to(h)));
            cfg.service(web::scope("/after")
                .route("/a", web::get().to(h))
                .route("/b", web::get().to(h))
                .wrap(AdminMiddleware));
            cfg.service(web::scope("/leak")
                .route("/a", web::get().guard(AdminGuard).to(h))
                .wrap(Logger::default())
                .route("/b", web::get().to(h)));
        }
        "#,
    );
    let middleware = vec![(
        AuthEvidenceKind::AuthorizationMiddleware,
        "AdminMiddleware".to_owned(),
    )];
    for scope in ["/before", "/between", "/after"] {
        for route in ["a", "b"] {
            let path = format!("{scope}/{route}");
            assert_eq!(evidence[&path], middleware, "{path}");
        }
    }
    // A sibling route's own guard is not scope configuration.
    assert_eq!(
        evidence["/leak/a"],
        vec![(
            AuthEvidenceKind::AuthorizationGuard,
            "AdminGuard".to_owned()
        )]
    );
    assert!(evidence["/leak/b"].is_empty());
}

#[test]
fn nested_scopes_inherit_middleware_without_leaking_to_siblings() {
    let evidence = route_evidence(
        r#"
        async fn h() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/api").wrap(AuthMiddleware)
                .service(web::scope("/admin").wrap(AdminMiddleware)
                    .route("/x", web::get().to(h))
                    .service(web::scope("/deep").guard(RoleGuard)
                        .route("/z", web::get().to(h))))
                .service(web::scope("/public")
                    .route("/y", web::get().to(h)))
                .route("/direct", web::get().to(h)));
            cfg.service(web::scope("/other").route("/w", web::get().to(h)));
        }
        "#,
    );
    use AuthEvidenceKind::*;
    let kinds = |path: &str| {
        let mut found: Vec<(AuthEvidenceKind, &str)> = evidence[path]
            .iter()
            .map(|(kind, mechanism)| (kind.clone(), mechanism.as_str()))
            .collect();
        found.sort_by_key(|(_, mechanism)| mechanism.to_owned());
        found
    };

    assert_eq!(
        kinds("/api/admin/x"),
        vec![
            (AuthorizationMiddleware, "AdminMiddleware"),
            (IdentityExtraction, "AuthMiddleware"),
        ]
    );
    assert_eq!(
        kinds("/api/admin/deep/z"),
        vec![
            (AuthorizationMiddleware, "AdminMiddleware"),
            (IdentityExtraction, "AuthMiddleware"),
            (AuthorizationGuard, "RoleGuard"),
        ]
    );
    // Siblings receive the shared parent's middleware but not each other's.
    assert_eq!(
        kinds("/api/public/y"),
        vec![(IdentityExtraction, "AuthMiddleware")]
    );
    assert_eq!(
        kinds("/api/direct"),
        vec![(IdentityExtraction, "AuthMiddleware")]
    );
    // An unrelated top-level scope receives nothing.
    assert!(evidence["/other/w"].is_empty());
}

#[test]
fn scope_middleware_is_kept_alongside_handler_evidence() {
    let source = r#"
        fn require_admin() {}
        async fn users() { require_admin(); }
        async fn orders() { require_admin(); }
        async fn payments() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin").wrap(AdminMiddleware)
                .route("/users", web::get().to(users))
                .route("/orders", web::get().to(orders))
                .route("/payments", web::get().to(payments)));
        }
    "#;
    let evidence = route_evidence(source);
    use AuthEvidenceKind::*;
    for path in ["/admin/users", "/admin/orders"] {
        assert_eq!(
            evidence[path],
            vec![
                (AuthorizationMiddleware, "AdminMiddleware".to_owned()),
                (RoleCheck, "require_admin".to_owned()),
            ],
            "{path}"
        );
    }
    assert_eq!(
        evidence["/admin/payments"],
        vec![(AuthorizationMiddleware, "AdminMiddleware".to_owned())]
    );

    // Every route is authorized by the scope middleware, so no drift remains.
    let syntax: syn::File = syn::parse_str(source).unwrap();
    let file = Path::new("scopes.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let (_, _, details, _) = build_analysis_layers(&visitor.routes);
    assert!(details.is_empty());
}

#[test]
fn route_and_handler_names_alone_do_not_count_as_protection() {
    let syntax: syn::File = syn::parse_str(
        r#"
        async fn require_admin_panel() {}
        async fn admin_only() {}
        #[get("/admin/attribute")]
        async fn check_permission() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin")
                .route("/panel", web::get().to(require_admin_panel))
                .route("/secure", web::get().to(admin_only)));
        }
        "#,
    )
    .unwrap();
    let file = Path::new("names.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);

    assert_eq!(visitor.routes.len(), 3);
    for route in &visitor.routes {
        assert!(route.authorization.is_empty(), "{}", route.path);
        assert!(!route.is_authorized(), "{}", route.path);
    }
}

#[test]
fn identity_extraction_is_not_authorization() {
    let syntax: syn::File =
        syn::parse_str("fn profile() { let claims = Claims::from_request(); }").unwrap();
    let handlers = collect_authorized_handlers(Path::new("identity.rs"), &syntax);
    let evidence = &handlers["profile"][0];
    assert_eq!(evidence.kind, AuthEvidenceKind::IdentityExtraction);

    let route = Route {
        application: None,
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

pub(super) struct TempRepo(PathBuf);

impl TempRepo {
    pub(super) fn path(&self) -> &Path { &self.0 }
    pub(super) fn new(name: &str, files: &[(&str, &str)]) -> Self {
        let root = std::env::temp_dir().join(format!("archer-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for (path, contents) in files {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, contents).unwrap();
        }
        Self(root)
    }

    pub(super) fn analyze(&self) -> Report {
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
    // Resolution preserves lexical evidence, but an unresolved/no-op helper
    // is not proven enforcement under the P2 security model.
    assert!(matches!(
        route.security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
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

    // These helpers have no available implementation. Resolution alone
    // must not manufacture an authorization contract or a drift finding.
    assert!(report.finding_details.is_empty());
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
            "fn require_admin() { if !allowed() { return Err(denied()); } }
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

fn macro_evidence(
    source: &str,
) -> HashMap<String, Vec<(AuthEvidenceKind, String, String, AuthStrength)>> {
    let syntax: syn::File = syn::parse_str(source).unwrap();
    collect_authorized_handlers(Path::new("macros.rs"), &syntax)
        .into_iter()
        .map(|(handler, evidence)| {
            let evidence = evidence
                .into_iter()
                .map(|item| {
                    assert_eq!(item.handler.as_deref(), Some(handler.as_str()));
                    (
                        item.kind,
                        item.mechanism,
                        item.symbol.unwrap(),
                        item.strength,
                    )
                })
                .collect();
            (handler, evidence)
        })
        .collect()
}

#[test]
fn statement_and_expression_macros_use_the_helper_name_rules() {
    let evidence = macro_evidence(
        r#"
        fn statement() { require_admin!(user); }
        fn braced() { check_admin! { user } }
        fn expression() { let allowed = check_permission!(user, "reports:read"); if allowed {} }
        fn tail() -> bool { has_role!(user, "manager") }
        fn condition() { if !is_owner!(user, document) { return; } }
        fn ownership() { ensure_owner!(user, document); }
        fn authentication() { require_auth!(request); }
        "#,
    );
    use AuthEvidenceKind::*;
    use AuthStrength::*;
    let single = |handler: &str| {
        assert_eq!(evidence[handler].len(), 1, "{handler}");
        evidence[handler][0].clone()
    };

    assert_eq!(
        single("statement"),
        (
            RoleCheck,
            "require_admin".into(),
            "require_admin!".into(),
            Strong
        )
    );
    assert_eq!(
        single("braced"),
        (
            RoleCheck,
            "check_admin".into(),
            "check_admin!".into(),
            Strong
        )
    );
    assert_eq!(
        single("expression"),
        (
            PermissionCheck,
            "check_permission".into(),
            "check_permission!".into(),
            Strong
        )
    );
    assert_eq!(
        single("tail"),
        (RoleCheck, "has_role".into(), "has_role!".into(), Strong)
    );
    assert_eq!(
        single("condition"),
        (
            OwnershipCheck,
            "is_owner".into(),
            "is_owner!".into(),
            Medium
        )
    );
    assert_eq!(
        single("ownership"),
        (
            OwnershipCheck,
            "ensure_owner".into(),
            "ensure_owner!".into(),
            Medium
        )
    );
    assert_eq!(
        single("authentication"),
        (
            IdentityExtraction,
            "require_auth".into(),
            "require_auth!".into(),
            Weak
        )
    );

    let syntax: syn::File =
        syn::parse_str("fn admin() {\n    log::info!(\"start\");\n    require_admin!(user);\n}")
            .unwrap();
    let line = collect_authorized_handlers(Path::new("macros.rs"), &syntax)["admin"][0].line;
    assert_eq!(line, 3);
}

#[test]
fn logging_formatting_and_unrelated_macros_are_not_evidence() {
    let evidence = macro_evidence(
        r#"
        fn output(user: &str) {
            println!("admin {}", user);
            let message = format!("role: {}", user);
            info!("permission check for {}", user);
            log::warn!("admin access denied");
            tracing::debug!(role = "admin");
            eprintln!("{}", message);
        }
        fn assertions(user: &User) {
            assert!(is_admin(user));
            debug_assert!(has_role(user, "admin"));
            assert_eq!(user.role, "admin");
            let roles = vec![require_admin()];
        }
        fn names() {
            check_admin_log!(user);
            ensure_admin_exists!(user);
            role_name!(user);
            log_permission_check!(user);
            admin_dashboard!();
            verify_access_token!(token);
        }
        fn definitions() {
            macro_rules! require_admin { () => { require_admin() }; }
        }
        "#,
    );
    assert!(evidence.is_empty(), "{evidence:?}");
}

#[test]
fn qualified_macro_paths_use_their_last_segment() {
    let evidence = macro_evidence(
        r#"
        fn module() { auth::require_admin!(user); }
        fn crate_path() { crate::guards::check_permission!(user, "write"); }
        fn absolute() { ::authz::authorize!(user, action); }
        fn logging() { guards::admin::info!("checked"); }
        "#,
    );
    use AuthEvidenceKind::*;
    use AuthStrength::*;
    assert_eq!(
        evidence["module"],
        vec![(
            RoleCheck,
            "require_admin".into(),
            "auth::require_admin!".into(),
            Strong
        )]
    );
    assert_eq!(
        evidence["crate_path"],
        vec![(
            PermissionCheck,
            "check_permission".into(),
            "crate::guards::check_permission!".into(),
            Strong
        )]
    );
    assert_eq!(
        evidence["absolute"],
        vec![(
            ManualAuthorizationCheck,
            "authorize".into(),
            "::authz::authorize!".into(),
            Strong
        )]
    );
    assert!(!evidence.contains_key("logging"));
}

#[test]
fn macro_evidence_stays_with_its_own_handler() {
    let evidence = route_evidence(
        r#"
        async fn outer() {
            fn nested() { require_admin!(user); }
            struct Helper;
            impl Helper { fn check(&self) { check_permission!(user); } }
            trait Policy { fn verify(&self) { authorize!(user); } }
            macro_rules! hidden { () => { require_admin!(user) }; }
        }
        async fn protected() { require_admin!(user); }
        async fn sibling() {}
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin")
                .route("/outer", web::get().to(outer))
                .route("/protected", web::get().to(protected))
                .route("/sibling", web::get().to(sibling)));
        }
        "#,
    );
    assert!(
        evidence["/admin/outer"].is_empty(),
        "{:?}",
        evidence["/admin/outer"]
    );
    assert_eq!(
        evidence["/admin/protected"],
        vec![(AuthEvidenceKind::RoleCheck, "require_admin".to_owned())]
    );
    assert!(evidence["/admin/sibling"].is_empty());
}

#[test]
fn macro_handler_and_middleware_evidence_are_kept_once_each() {
    let source = r#"
        fn check_permission() {}
        async fn users() {
            require_admin!(user);
            check_permission();
            log::info!("users");
        }
        async fn orders() { require_admin!(user); }
        async fn reports() { require_admin!(user); }
        async fn payments() { log::info!("payments"); }
        fn configure(cfg: &mut web::ServiceConfig) {
            cfg.service(web::scope("/admin")
                .route("/users", web::get().guard(RoleGuard).to(users))
                .route("/orders", web::get().to(orders))
                .route("/reports", web::get().to(reports))
                .route("/payments", web::get().to(payments))
                .wrap(AuthMiddleware));
        }
    "#;
    let evidence = route_evidence(source);
    use AuthEvidenceKind::*;
    let identity = (IdentityExtraction, "AuthMiddleware".to_owned());
    let role_macro = (RoleCheck, "require_admin".to_owned());
    assert_eq!(
        evidence["/admin/users"],
        vec![
            (AuthorizationGuard, "RoleGuard".to_owned()),
            role_macro.clone(),
            (PermissionCheck, "check_permission".to_owned()),
            identity.clone(),
        ]
    );
    for path in ["/admin/orders", "/admin/reports"] {
        assert_eq!(
            evidence[path],
            vec![role_macro.clone(), identity.clone()],
            "{path}"
        );
    }
    assert_eq!(evidence["/admin/payments"], vec![identity]);

    // Macro evidence feeds drift inference like any other handler evidence.
    let syntax: syn::File = syn::parse_str(source).unwrap();
    let file = Path::new("scopes.rs");
    let index = HandlerIndex::single_file(file, &syntax);
    let mut visitor = RouteVisitor::new(file.to_path_buf(), &index);
    visitor.visit_file(&syntax);
    let (_, _, details, _) = build_analysis_layers(&visitor.routes);
    assert_eq!(details.len(), 1);
    assert_eq!(details[0].suspicious_route.path, "/admin/payments");
    assert_eq!(details[0].authorized_peer_routes.len(), 3);
}

#[test]
fn three_state_security_status_distinguishes_unprotected_from_unknown() {
    let protected_route = route("GET", "/admin/users", "/admin", "PRESENT");
    assert_eq!(
        protected_route.security_status(),
        RouteSecurityStatus::Protected
    );

    let mut unprotected_route = route("GET", "/admin/payments", "/admin", "NONE");
    unprotected_route.handler_resolution = Some(HandlerResolution::Local);
    assert_eq!(
        unprotected_route.security_status(),
        RouteSecurityStatus::Unprotected
    );

    let mut unresolved_route = route("GET", "/admin/external", "/admin", "NONE");
    unresolved_route.handler_resolution = Some(HandlerResolution::Unresolved);
    assert!(matches!(
        unresolved_route.security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));

    let mut ambiguous_route = route("GET", "/admin/duplicate", "/admin", "NONE");
    ambiguous_route.handler_resolution = Some(HandlerResolution::Ambiguous {
        candidates: vec!["a::duplicate".into(), "b::duplicate".into()],
    });
    assert!(matches!(
        ambiguous_route.security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn drift_categories_classify_auth_only_and_ownership() {
    let auth_only_route = Route {
        application: None,
        method: "GET".into(),
        path: "/admin/profile".into(),
        scope_prefix: "/admin".into(),
        handler: Some("profile".into()),
        handler_path: Some("profile".into()),
        handler_resolution: Some(HandlerResolution::Local),
        authorization: vec![AuthEvidence {
            kind: AuthEvidenceKind::IdentityExtraction,
            mechanism: "AuthenticatedUser".into(),
            symbol: Some("AuthenticatedUser".into()),
            file: PathBuf::from("test.rs"),
            line: 10,
            handler: Some("profile".into()),
            strength: AuthStrength::Weak,
        }],
        line: 10,
        file: PathBuf::from("test.rs"),
    };

    let peer1 = route("GET", "/admin/users", "/admin", "PRESENT");
    let peer2 = route("GET", "/admin/orders", "/admin", "PRESENT");

    let routes = vec![auth_only_route, peer1, peer2];
    let (_, _, details, _) = build_analysis_layers(&routes);
    assert_eq!(details.len(), 1);
    assert_eq!(
        details[0].category,
        DriftCategory::AuthenticationOnlyWithoutAuthorization
    );
    assert!(details[0].explanation.contains("authentication"));
}

#[test]
fn operational_routes_do_not_produce_false_positive_drift() {
    let health_route = route("GET", "/admin/health", "/admin", "NONE");
    let user_route = route("GET", "/admin/users", "/admin", "PRESENT");
    let order_route = route("GET", "/admin/orders", "/admin", "PRESENT");

    let routes = vec![health_route, user_route, order_route];
    let (_, _, details, _) = build_analysis_layers(&routes);
    // /admin/health must be excluded as an operational route and not flagged as drift
    assert!(details.is_empty());
}

#[test]
fn parameterized_route_scope_fallback_detects_drift() {
    let mut order_param = route("GET", "/admin/orders/{id}", "/admin", "PRESENT");
    order_param.authorization = vec![AuthEvidence {
        kind: AuthEvidenceKind::OwnershipCheck,
        mechanism: "is_owner".into(),
        symbol: Some("is_owner".into()),
        file: PathBuf::from("test.rs"),
        line: 5,
        handler: Some("order_detail".into()),
        strength: AuthStrength::Medium,
    }];

    let payment_param = route("GET", "/admin/payments/{id}", "/admin", "NONE");

    let scope_peer1 = route("GET", "/admin/users", "/admin", "PRESENT");
    let scope_peer2 = route("GET", "/admin/reports", "/admin", "PRESENT");

    let routes = vec![order_param, payment_param, scope_peer1, scope_peer2];
    let (_, _, details, _) = build_analysis_layers(&routes);

    let param_finding = details
        .iter()
        .find(|f| f.suspicious_route.path == "/admin/payments/{id}");
    assert!(
        param_finding.is_some(),
        "Parameterized drift should be caught via scope fallback"
    );
    assert_eq!(
        param_finding.unwrap().category,
        DriftCategory::MissingOwnershipValidation
    );
}

#[test]
fn authorization_relationship_graph_generates_nodes_and_edges() {
    let routes = vec![
        route("GET", "/admin/users", "/admin", "PRESENT"),
        route("GET", "/admin/payments", "/admin", "NONE"),
    ];
    let (_, _, details, _) = build_analysis_layers(&routes);
    let graph = build_authorization_graph(&routes, &details);

    assert!(!graph.nodes.is_empty());
    assert!(!graph.edges.is_empty());
    let dot = graph.to_dot();
    assert!(dot.contains("digraph ARCHER_Authorization_Graph"));
    assert!(dot.contains("Scope: /admin"));
}

#[test]
fn workspace_resolution_labels_check_definitions_and_reject_decoys() {
    let repo = TempRepo::new(
        "workspace-resolution-labels",
        &[
            (
                "Cargo.toml",
                "[workspace]\nmembers=[\"app\",\"service\",\"guard\"]\nresolver=\"2\"\n[workspace.dependencies]\nservice_alias={package=\"domain-service\",path=\"service\"}\n",
            ),
            (
                "app/Cargo.toml",
                "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nservice_alias={workspace=true}\n",
            ),
            (
                "service/Cargo.toml",
                "[package]\nname=\"domain-service\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nguard={path=\"../guard\"}\n",
            ),
            (
                "guard/Cargo.toml",
                "[package]\nname=\"guard\"\nversion=\"0.1.0\"\nedition=\"2021\"\n",
            ),
            (
                "app/src/lib.rs",
                r#"
use service_alias::api::handler as renamed;
use service_alias::api as module_alias;
mod local { pub fn handler() {} }
fn handler() {}
mod globs { use service_alias::api::*; use service_alias::other::*; }
mod cycle { use self::looped as looped; }
mod unknown_glob { use not_indexed::*; use service_alias::api::*; }
"#,
            ),
            (
                "service/src/lib.rs",
                r#"
pub mod api { pub fn handler() {} pub use guard::check_role as authorize; fn secret() {} }
pub mod other { pub fn handler() {} }
mod private { pub fn handler() {} }
use api::handler as hidden;
pub use api::handler as exported;
pub mod facade { pub use crate::api::*; }
pub mod hidden_facade { use crate::api::*; }
"#,
            ),
            (
                "guard/src/lib.rs",
                "pub fn check_role(role: &str) -> Result<(), Error> { if !allowed(role) { return Err(denied()); } Ok(()) }",
            ),
        ],
    );
    let mut files = Vec::new();
    for file in WalkDir::new(&repo.0)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().is_some_and(|x| x == "rs"))
    {
        let path = file.path().to_path_buf();
        files.push((
            path.clone(),
            module_location(&repo.0, &path),
            syn::parse_file(&fs::read_to_string(path).unwrap()).unwrap(),
        ));
    }
    let mut index = HandlerIndex::build(files.iter().map(|(p, k, a)| (p.as_path(), k.clone(), a)));
    assert!(index.load_workspace(&repo.0).is_none());
    let app = repo.0.join("app");
    for (path, module, expected_file, expected_module) in [
        ("renamed", "", Some("service/src/lib.rs"), "api"),
        (
            "module_alias::handler",
            "",
            Some("service/src/lib.rs"),
            "api",
        ),
        (
            "service_alias::api::handler",
            "",
            Some("service/src/lib.rs"),
            "api",
        ),
        (
            "::service_alias::api::handler",
            "",
            Some("service/src/lib.rs"),
            "api",
        ),
        (
            "service_alias::exported",
            "",
            Some("service/src/lib.rs"),
            "api",
        ),
        (
            "service_alias::facade::handler",
            "",
            Some("service/src/lib.rs"),
            "api",
        ),
        ("service_alias::hidden_facade::handler", "", None, ""),
        (
            "service_alias::api::authorize",
            "",
            Some("guard/src/lib.rs"),
            "",
        ),
        ("handler", "", Some("app/src/lib.rs"), ""),
        ("local::handler", "", Some("app/src/lib.rs"), "local"),
        ("handler", "globs", None, ""),
        ("service_alias::private::handler", "", None, ""),
        ("service_alias::api::secret", "", None, ""),
        ("service_alias::hidden", "", None, ""),
        ("missing_dependency::handler", "", None, ""),
        ("guard::check_role", "", None, ""),
        ("looped", "cycle", None, ""),
        ("handler", "unknown_glob", None, ""),
    ] {
        let target = HandlerTarget::Path {
            segments: path
                .trim_start_matches("::")
                .split("::")
                .map(str::to_owned)
                .collect(),
            leading_colon: path.starts_with("::"),
        };
        let module = if module.is_empty() {
            vec![]
        } else {
            vec![module.into()]
        };
        let (found, _) = index.resolve_handler(&app, &module, &target);
        if let Some(file) = expected_file {
            let found = found.unwrap_or_else(|| panic!("missed labeled resolution {path}"));
            assert!(
                found.file.ends_with(file),
                "wrong target for {path}: {:?}",
                found.file
            );
            assert_eq!(
                found.module.join("::"),
                expected_module,
                "wrong module for {path}"
            );
        } else {
            assert!(found.is_none(), "incorrectly resolved {path}: {found:?}");
        }
    }
}
