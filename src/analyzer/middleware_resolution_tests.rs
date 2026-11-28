//! Regression tests for middleware and extractor resolution. In-crate middleware is treated as
//! non-security only when its `call` provably forwards to the inner service; library middleware
//! only through an explicit import. Anything else stays unresolved evidence, and a custom
//! `FromRequest` extractor that cannot be modeled keeps the route unverified instead of absent.
use super::tests::TempRepo;
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

// TempRepo directories are keyed by name and process id, so parallel tests need distinct names.
fn unique(prefix: &str) -> String {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    format!("{prefix}-{}", NEXT.fetch_add(1, Ordering::Relaxed))
}

const MIDDLEWARE: &str = r#"
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
pub struct Layer;
impl Layer { pub fn new() -> Self { Layer } }
impl<S, B> Transform<S, ServiceRequest> for Layer {
    type Transform = LayerService<S>;
    fn new_transform(&self, service: S) -> Self::Future { ready(Ok(LayerService { service })) }
}
pub struct LayerService<S> { service: S }
impl<S, B> Service<ServiceRequest> for LayerService<S> {
    fn call(&self, req: ServiceRequest) -> Self::Future { CALL }
}
async fn list() {}
fn app() { App::new().wrap(Layer::new()).route("/items", web::get().to(list)); }
"#;

fn unresolved_middleware(source: &str) -> bool {
    let report = TempRepo::new(&unique("middleware-resolution"), &[("main.rs", source)]).analyze();
    assert_eq!(report.routes.len(), 1, "{source}");
    report.routes[0].authorization.iter().any(|e| e.mechanism == "UnresolvedMiddleware")
}

fn with_call(body: &str) -> String {
    MIDDLEWARE.replace("CALL", body)
}

#[test]
fn forwarding_only_middleware_is_not_unresolved_evidence() {
    for body in [
        "let fut = self.service.call(req); Box::pin(async move { let res = fut.await?; record(res.status().as_u16()); Ok(res) })",
        "self.service.call(req)",
        "let started = now(); let fut = self.service.call(req); Box::pin(async move { let res = fut.await?; info!(\"done\"); Ok(res) })",
    ] {
        assert!(!unresolved_middleware(&with_call(body)), "{body}");
    }
}

#[test]
fn middleware_that_may_reject_or_answer_itself_stays_unresolved() {
    for body in [
        // Early return of its own response.
        "if blocked(&req) { return Box::pin(async move { Ok(req.into_response(HttpResponse::Forbidden())) }); } self.service.call(req)",
        // Constructs an error response.
        "let fut = self.service.call(req); Box::pin(async move { let _ = fut.await?; Err(ErrorUnauthorized(\"no\")) })",
        // Authorization-looking helper, even without an explicit rejection.
        "check_token(&req); self.service.call(req)",
        // `?` on something other than an awaited inner future can reject on its own.
        "verify(&req)?; self.service.call(req)",
        // Never forwards to the inner service, so it answers every request itself.
        "Box::pin(async move { Ok(respond()) })",
        // An unknown macro may expand to a rejection.
        "bail_unless_ok!(req); self.service.call(req)",
    ] {
        assert!(unresolved_middleware(&with_call(body)), "{body}");
    }
}

#[test]
fn middleware_with_ambiguous_impls_stays_unresolved() {
    let duplicated = format!(
        "{}\nimpl<S, B> Transform<S, ServiceRequest> for Layer {{ type Transform = LayerService<S>; fn new_transform(&self, s: S) -> Self::Future {{ ready(Ok(LayerService {{ service: s }})) }} }}",
        with_call("self.service.call(req)")
    );
    assert!(unresolved_middleware(&duplicated));
}

#[test]
fn library_session_middleware_is_recognised_only_through_its_import() {
    let wrapped = |imports: &str, definitions: &str| {
        format!("{imports}\n{definitions}\nasync fn list() {{}}\nfn app() {{ App::new().wrap(SessionMiddleware::builder(store(), key()).build()).route(\"/items\", web::get().to(list)); }}")
    };
    assert!(!unresolved_middleware(&wrapped("use actix_session::SessionMiddleware;", "")));
    // No import, so nothing says this is the library type.
    assert!(unresolved_middleware(&wrapped("", "")));
    // A different crate's type of the same name is not the library middleware.
    assert!(unresolved_middleware(&wrapped("use my_auth::SessionMiddleware;", "")));
    // A local definition of the same name may reject and must stay unresolved.
    assert!(unresolved_middleware(&wrapped(
        "",
        "struct SessionMiddleware; impl SessionMiddleware { fn builder(a: A, b: B) -> Self { SessionMiddleware } fn build(self) -> Self { self } }"
    )));
}

const EXTRACTOR: &str = r#"
use actix_web::FromRequest;
struct Actor;
impl FromRequest for Actor {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;
    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        Box::pin(async move { let t = bearer(&req)?; Ok(Actor) })
    }
}
HANDLER
fn app() { App::new().route("/items", web::get().to(list)); }
"#;

fn extractor_report(handler: &str) -> Report {
    TempRepo::new(&unique("custom-extractor"), &[("main.rs", &EXTRACTOR.replace("HANDLER", handler))]).analyze()
}

#[test]
fn custom_extractor_keeps_the_route_unverified_not_unprotected() {
    let report = extractor_report("async fn list(actor: Actor) {}");
    let route = &report.routes[0];
    assert!(route.authorization.iter().any(|e| e.mechanism == "UnmodeledExtractor"));
    assert!(matches!(route.security_status(), RouteSecurityStatus::Unknown { .. }), "{:?}", route.security_status());
    let requirements = &report.security_assessments[0].requirements;
    assert!(requirements.iter().any(|r| r.mechanism == "custom extractor" && r.enforcement == security::Enforcement::Unresolved));
    // The engine says it could not model the extractor; it never claims protection or its absence.
    assert!(requirements.iter().all(|r| r.enforcement != security::Enforcement::Observed));
}

#[test]
fn optional_or_standard_extractors_do_not_add_unmodeled_evidence() {
    for handler in ["async fn list(actor: Option<Actor>) {}", "async fn list(query: web::Query<Filter>) {}"] {
        let report = extractor_report(handler);
        let route = &report.routes[0];
        assert!(!route.authorization.iter().any(|e| e.mechanism == "UnmodeledExtractor"), "{handler}");
        assert!(matches!(route.security_status(), RouteSecurityStatus::Unprotected), "{handler}");
    }
}

const SESSION_EXTRACTOR: &str = r#"
use actix_web::FromRequest;
struct Principal;
impl FromRequest for Principal {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;
    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();
        Box::pin(async move { BODY })
    }
}
async fn list(who: Principal) {}
fn app() { App::new().route("/items", web::get().to(list)); }
"#;

fn session_report(body: &str) -> Report {
    TempRepo::new(&unique("session-extractor"), &[("main.rs", &SESSION_EXTRACTOR.replace("BODY", body))]).analyze()
}

fn authentication_requirements(report: &Report) -> Vec<&security::Requirement> {
    report.security_assessments[0].requirements.iter().filter(|r| r.dimension == "authentication").collect()
}

#[test]
fn async_extractor_that_rejects_before_every_success_is_required_authentication() {
    for body in [
        // Each fallible step rejects with an Unauthorized error; only the tail succeeds.
        r#"let id = session(&req).ok_or_else(|| AppError::Unauthorized("no session".into()))?; let user = load(id).await.map_err(|_| AppError::Unauthorized("gone".into()))?; Ok(Principal)"#,
        r#"let token = bearer(&req).ok_or(ErrorUnauthorized("no token"))?; Ok(Principal)"#,
        r#"if !logged_in(&req) { return Err(AppError::Unauthorized("no".into())); } Ok(Principal)"#,
        r#"let Some(id) = session(&req) else { return Err(AppError::Unauthorized("no".into())) }; Ok(Principal)"#,
    ] {
        let report = session_report(body);
        let requirements = authentication_requirements(&report);
        assert_eq!(requirements.len(), 1, "{body}: {requirements:?}");
        assert_eq!(requirements[0].enforcement, security::Enforcement::Observed, "{body}");
        assert!(matches!(report.routes[0].security_status(), RouteSecurityStatus::Protected), "{body}");
    }
}

#[test]
fn async_extractor_that_can_succeed_without_its_gate_is_only_potential() {
    for body in [
        // An early success exit skips the rejection.
        r#"if has_token(&req) { return Ok(Principal); } let id = session(&req).ok_or_else(|| AppError::Unauthorized("no".into()))?; Ok(Principal)"#,
        // The rejection is conditional, so it is not on every path.
        r#"if flag() { let id = session(&req).ok_or_else(|| AppError::Unauthorized("no".into()))?; } Ok(Principal)"#,
        // The success value is not the block's tail.
        r#"let id = session(&req).ok_or_else(|| AppError::Forbidden("no".into()))?; match id { 1 => Ok(Principal), _ => Ok(Principal) }"#,
        // An unknown macro may expand to an early success.
        r#"let id = session(&req).ok_or_else(|| AppError::Unauthorized("no".into()))?; allow_if!(id); Ok(Principal)"#,
    ] {
        let report = session_report(body);
        let requirements = authentication_requirements(&report);
        assert_eq!(requirements.len(), 1, "{body}: {requirements:?}");
        assert_eq!(requirements[0].enforcement, security::Enforcement::Potential, "{body}");
        assert!(!matches!(report.routes[0].security_status(), RouteSecurityStatus::Protected), "{body}");
    }
}

#[test]
fn async_extractor_without_any_rejection_is_not_credited() {
    for body in [
        // Errors that are not authentication or authorization failures prove nothing about identity.
        r#"let id = session(&req).ok_or_else(|| AppError::Internal("x".into()))?; Ok(Principal)"#,
        r#"Ok(Principal)"#,
    ] {
        let report = session_report(body);
        assert!(authentication_requirements(&report).is_empty(), "{body}");
        assert!(report.security_assessments[0].requirements.iter().any(|r| r.mechanism == "custom extractor"), "{body}");
        assert!(matches!(report.routes[0].security_status(), RouteSecurityStatus::Unknown { .. }), "{body}");
    }
}

#[test]
fn optional_async_extractor_never_counts_as_required() {
    let source = SESSION_EXTRACTOR
        .replace("BODY", r#"let id = session(&req).ok_or_else(|| AppError::Unauthorized("no".into()))?; Ok(Principal)"#)
        .replace("who: Principal", "who: Option<Principal>");
    let report = TempRepo::new(&unique("optional-session-extractor"), &[("main.rs", &source)]).analyze();
    assert!(authentication_requirements(&report).iter().all(|r| r.enforcement != security::Enforcement::Observed));
    assert!(!matches!(report.routes[0].security_status(), RouteSecurityStatus::Protected));
}

#[test]
fn proven_extractor_supersedes_the_name_based_requirement_for_the_same_parameter() {
    // `AuthenticatedUser` is a security-looking type name, which already yields a weak,
    // name-only Potential requirement. A proven gate replaces it rather than sitting beside it.
    let source = SESSION_EXTRACTOR
        .replace("Principal", "AuthenticatedUser")
        .replace("BODY", r#"let id = session(&req).ok_or_else(|| AppError::Unauthorized("no".into()))?; Ok(AuthenticatedUser)"#);
    let report = TempRepo::new(&unique("supersede-extractor"), &[("main.rs", &source)]).analyze();
    let requirements = authentication_requirements(&report);
    assert_eq!(requirements.len(), 1, "{requirements:?}");
    assert_eq!(requirements[0].enforcement, security::Enforcement::Observed);
}
