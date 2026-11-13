use super::tests::TempRepo;
use super::*;

#[test]
fn required_extension_helpers_preserve_the_producer_proof_boundary() {
    for (name, body, expected) in [
        ("bound", "let value = lookup(&req)?; Ok(())", true),
        ("discarded-success", "lookup(&req)?; Ok(())", true),
        ("ignored", "let value = lookup(&req); Ok(())", false),
        ("optional", "let value = lookup(&req).ok(); Ok(())", false),
        ("fallback", "let value = lookup(&req).unwrap_or_else(|_| Value{}); Ok(())", false),
        ("conditional", "if condition() {lookup(&req)?;} Ok(())", false),
        ("bypass", "if condition() {return Ok(());} let value=lookup(&req)?; Ok(())", false),
        ("closure", "let work=|| {lookup(&req)?; Ok(())}; Ok(())", false),
        ("deferred", "let work=async {lookup(&req)?; Ok(())}; Ok(())", false),
        ("different-request", "let other=make_request(); let value=lookup(&other)?; Ok(())", false),
        ("shadowed", "let req=make_request(); let value=lookup(&req)?; Ok(())", false),
        ("reassigned", "req=make_request(); let value=lookup(&req)?; Ok(())", false),
    ] {
        let source=format!(r#"
use actix_web::HttpRequest;
struct Value {{}}
fn lookup(request:&HttpRequest)->Result<Value,Error> {{request.extensions().get::<Value>().map(|v|v.to_owned()).ok_or_else(||denied())}}
async fn endpoint(mut req:HttpRequest)->Result<(),Error> {{{body}}}
fn app() {{App::new().route("/item",web::get().to(endpoint));}}
"#);
        let report=TempRepo::new(&format!("extension-consumption-{name}"),&[("main.rs",&source)]).analyze();
        let requirements=&report.security_assessments[0].requirements;
        let facts:Vec<_>=requirements.iter().filter(|r|r.mechanism=="required_request_extension").collect();
        assert_eq!(facts.len(),usize::from(expected),"{name}: {requirements:?}");
        assert!(facts.iter().all(|r|r.enforcement==security::Enforcement::Unresolved && r.explanation.contains("extension production")));
        assert!(!requirements.iter().any(|r|r.dimension=="authentication" && r.enforcement==security::Enforcement::Observed),"{name}");
        assert!(report.invariants.is_empty());
        assert!(report.findings.is_empty());
    }
}

#[test]
fn required_extension_summary_requires_source_types_and_success_preservation() {
    for (name, imports, helper, expected) in [
        ("renamed", "use actix_web::HttpRequest as Incoming;", "fn lookup(r:&Incoming)->Result<Value,Error>{r.extensions().get::<Value>().map(|x|x.clone()).ok_or_else(||denied())}", true),
        ("wrong-type", "struct Incoming;", "fn lookup(r:&Incoming)->Result<Value,Error>{r.extensions().get::<Value>().map(|x|x.clone()).ok_or_else(||denied())}", false),
        ("replaced-value", "use actix_web::HttpRequest as Incoming;", "fn lookup(r:&Incoming)->Result<Value,Error>{r.extensions().get::<Value>().map(|x|Value{}).ok_or_else(||denied())}", false),
        ("optional-return", "use actix_web::HttpRequest as Incoming;", "fn lookup(r:&Incoming)->Option<Value>{r.extensions().get::<Value>().map(|x|x.clone())}", false),
        ("fake-result", "use actix_web::HttpRequest as Incoming; struct Result<T,E>(T,E);", "fn lookup(r:&Incoming)->Result<Value,Error>{r.extensions().get::<Value>().map(|x|x.clone()).ok_or_else(||denied())}", false),
    ] {
        let source=format!(r#"{imports}
struct Value{{}}
{helper}
async fn endpoint(req:Incoming)->Result<(),Error>{{let value=lookup(&req)?;Ok(())}}
fn app(){{App::new().route("/item",web::get().to(endpoint));}}
"#);
        let report=TempRepo::new(&format!("extension-source-{name}"),&[("main.rs",&source)]).analyze();
        assert_eq!(report.security_assessments[0].requirements.iter().filter(|r|r.mechanism=="required_request_extension").count(),usize::from(expected),"{name}");
    }
}

#[test]
fn required_extension_helper_alias_retains_definition_provenance() {
    let report=TempRepo::new("extension-definition-provenance",&[
        ("main.rs", r#"
mod values;
use actix_web::HttpRequest;
use crate::values::obtain as renamed;
async fn endpoint(req:HttpRequest)->Result<(),Error>{let value=renamed(&req)?;Ok(())}
fn app(){App::new().route("/item",web::get().to(endpoint));}
"#),
        ("values.rs", r#"
use actix_web::HttpRequest;
pub struct Value{}
pub fn obtain(r:&HttpRequest)->Result<Value,Error>{r.extensions().get::<Value>().map(|v|v.clone()).ok_or_else(||denied())}
"#),
    ]).analyze();
    let facts:Vec<_>=report.security_assessments[0].requirements.iter().filter(|r|r.mechanism=="required_request_extension").collect();
    assert_eq!(facts.len(),1);
    assert!(facts[0].explanation.contains("values.rs:4"));
    assert!(facts[0].explanation.contains("values::obtain"));
    assert!(facts[0].symbol.contains("renamed"));
    assert_eq!(facts[0].enforcement,security::Enforcement::Unresolved);
}

#[test]
fn conditional_result_aliases_and_renamed_field_guards_are_configuration_invariant() {
    for (name, macro_name, definition, extra, supported) in [
        (
            "conditional",
            "cfg_select",
            "feature=\"server\"=>{pub type Outcome<T>=Result<T,Error>;} _=>{}",
            "",
            true,
        ),
        (
            "same-alternatives",
            "std::cfg_select",
            "unix=>{pub type Outcome<T>=Result<T,Error>;} _=>{pub type Outcome<T>=Result<T,Error>;}",
            "",
            true,
        ),
        (
            "conflict",
            "cfg_select",
            "unix=>{pub type Outcome<T>=Result<T,Error>;} _=>{pub type Outcome<T>=Option<T>;}",
            "",
            false,
        ),
        (
            "shadow-type",
            "cfg_select",
            "unix=>{use fake::Result;pub type Outcome<T>=Result<T,Error>;} _=>{}",
            "",
            false,
        ),
        (
            "fake-macro",
            "cfg_select",
            "unix=>{pub type Outcome<T>=Result<T,Error>;} _=>{}",
            "macro_rules! cfg_select {($($t:tt)*)=>{}}",
            false,
        ),
        (
            "generic-shadow",
            "cfg_select",
            "unix=>{pub type Outcome<Result>=Result;} _=>{}",
            "",
            false,
        ),
    ] {
        let source = format!(
            r#"
{extra}
{macro_name}!{{{definition}}}
pub struct Flags{{pub permitted:bool}}pub struct Principal{{pub flags:Flags}}
fn check_role(user:&Principal)->Outcome<()>{{if !user.flags.permitted{{Err(denied())}}else{{Ok(())}}}}
fn ensure_role(subject:&Principal)->Outcome<()>{{if subject.flags.permitted{{Ok(())}}else{{Err(denied())}}}}
async fn one(p:Principal)->Result<(),Error>{{check_role(&p)?;sqlx::query("SELECT * FROM records");Ok(())}}
async fn two(p:Principal)->Result<(),Error>{{ensure_role(&p)?;sqlx::query("SELECT * FROM records");Ok(())}}
fn app(){{App::new().route("/one",web::get().to(one)).route("/two",web::get().to(two));}}
"#
        );
        let report = TempRepo::new(
            &format!("conditional-field-{name}"),
            &[("main.rs", &source)],
        )
        .analyze();
        assert_eq!(
            report.invariants.len(),
            usize::from(supported),
            "{name}: {:?}",
            report.security_assessments
        );
        assert!(report.finding_details.is_empty());
    }
}

#[test]
fn conditional_result_kind_does_not_guess_success_payload() {
    let syntax = syn::parse_file(
        r#"
cfg_select!{unix=>{pub type Result<T,E>=std::result::Result<E,T>;} _=>{}}
struct Identity;struct Failure;
fn make()->Result<Identity,Failure>{Err(Identity)}
"#,
    )
    .unwrap();
    let mut index =
        HandlerIndex::build([(Path::new("main.rs"), (PathBuf::from("."), vec![]), &syntax)]);
    index.attach_conditional_result_aliases();
    let helper = index.definitions.iter().find(|d| d.name == "make").unwrap();
    let syn::ReturnType::Type(_, ty) = &helper.function.sig.output else {
        panic!()
    };
    assert!(policy_drift::record_type(&index, helper, ty).is_none());
}

#[test]
fn typed_field_policies_require_mandatory_rejection_and_preserve_differences() {
    for (name, body, call, third, expected_invariants, expected_findings) in [
        (
            "escaping-error",
            "if !p.flags.allowed {Err({return Ok(());denied()})}else{Ok(())}",
            "check_role(&p)?;",
            "",
            0,
            0,
        ),
        (
            "escaping-argument",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role({return Ok(());&p})?;",
            "",
            0,
            0,
        ),
        (
            "tail",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "check_role(&p)?;",
            1,
            0,
        ),
        (
            "early-error",
            "if !p.flags.allowed {return Err(denied());} Ok(())",
            "check_role(&p)?;",
            "check_role(&p)?;",
            1,
            0,
        ),
        (
            "missing",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "",
            1,
            1,
        ),
        (
            "ignored",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "check_role(&p);",
            1,
            0,
        ),
        (
            "conditional",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "if choose(){check_role(&p)?;}",
            "",
            0,
            0,
        ),
        (
            "opaque-prefix",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "bypass!();check_role(&p)?;",
            "",
            0,
            0,
        ),
        (
            "early-success",
            "if choose(){return Ok(());} if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "",
            0,
            0,
        ),
        (
            "compound",
            "if !p.flags.allowed || bypass(){Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "",
            0,
            0,
        ),
        (
            "logging",
            "if !p.flags.allowed {log_denial();} Ok(())",
            "check_role(&p)?;",
            "",
            0,
            0,
        ),
        (
            "different-policy",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "check_permission(&p)?;",
            1,
            0,
        ),
        (
            "same-dimension-different-field",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "ensure_role(&p)?;",
            1,
            0,
        ),
        (
            "inline-equivalent",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "if !p.flags.allowed {return Err(denied());}",
            1,
            0,
        ),
        (
            "inline-comparison",
            "if !p.flags.allowed {Err(denied())}else{Ok(())}",
            "check_role(&p)?;",
            "if p.flags.allowed==false {return Err(denied());}",
            1,
            0,
        ),
    ] {
        let source = format!(
            r#"
struct Flags {{allowed:bool,alternative:bool}} struct Principal{{flags:Flags}}
macro_rules! bypass {{()=>{{return Ok(())}};}}
fn check_role(p:&Principal)->Result<(),Error>{{{body}}}
fn check_permission(p:&Principal)->Result<(),Error>{{if p.flags.alternative{{Ok(())}}else{{Err(denied())}}}}
fn ensure_role(p:&Principal)->Result<(),Error>{{if p.flags.alternative{{Ok(())}}else{{Err(denied())}}}}
async fn one(p:Principal)->Result<(),Error>{{{call} sqlx::query("SELECT * FROM documents");Ok(())}}
async fn two(p:Principal)->Result<(),Error>{{{call} sqlx::query("SELECT * FROM documents");Ok(())}}
async fn three(p:Principal)->Result<(),Error>{{{third} sqlx::query("SELECT * FROM documents");Ok(())}}
fn app(){{App::new().route("/one",web::get().to(one)).route("/two",web::get().to(two)).route("/three",web::get().to(three));}}
"#
        );
        let report =
            TempRepo::new(&format!("field-policy-{name}"), &[("main.rs", &source)]).analyze();
        assert_eq!(
            report.invariants.len(),
            expected_invariants,
            "{name}: {:?}",
            report.invariants
        );
        assert_eq!(
            report.finding_details.len(),
            expected_findings,
            "{name}: {:?}",
            report.finding_details
        );
        assert!(
            !report
                .security_assessments
                .iter()
                .flat_map(|a| &a.requirements)
                .any(|r| r.dimension == "authentication"
                    && r.enforcement == security::Enforcement::Observed)
        );
        if expected_invariants > 0 {
            assert!(report.invariants.iter().all(|i| {
                i.evidence_patterns
                    .iter()
                    .all(|p| p.contains("flags.allowed == true"))
            }));
        }
    }
}

#[test]
fn legacy_and_current_targets_keep_configuration_and_mount_context() {
    for (version, adapter) in [("1", "to_async"), ("2", "to"), ("4", "to")] {
        let main = format!(
            r#"
use actix_web::{{App,web}};
mod handlers {{pub async fn read() {{}}}}
use handlers::read as renamed;
fn routes(cfg:&mut web::ServiceConfig, context:Context) {{
 cfg.service(web::resource("/record").route(web::get().{adapter}(renamed)));
 cfg.route("/missing",web::get().{adapter}(absent));
 cfg.route("/callback",web::get().{adapter}(|| async {{ "public" }}));
 cfg.route("/unsupported",web::get().opaque());
}}
fn app() {{
 App::new().service(web::scope("/first").wrap(opaque_layer()).configure(|cfg|routes(cfg,context)));
 App::new().service(web::scope("/second").configure(|cfg| {{routes(cfg,context);}}));
}}
"#
        );
        let cargo = format!(
            "[package]\nname=\"registration\"\nversion=\"0.1.0\"\nedition=\"2018\"\n[dependencies]\nactix-web=\"{version}\"\n"
        );
        let report = TempRepo::new(
            "registration-adapters",
            &[("Cargo.toml", &cargo), ("src/main.rs", &main)],
        )
        .analyze();
        assert_eq!(report.routes.len(), 8, "{version}: {:?}", report.routes);
        for prefix in ["/first", "/second"] {
            let route = report
                .routes
                .iter()
                .find(|r| r.path == format!("{prefix}/record"))
                .unwrap();
            assert_eq!(route.handler.as_deref(), Some("renamed"));
            assert!(matches!(
                route.handler_resolution,
                Some(HandlerResolution::Imported)
            ));
            assert!(
                route
                    .application
                    .as_ref()
                    .is_some_and(|a| !a.starts_with("declaration:"))
            );
            assert_eq!(route.scope_prefix, prefix);
            assert_eq!(
                matches!(route.security_status(), RouteSecurityStatus::Unknown { .. }),
                prefix == "/first"
            );
            for suffix in ["missing", "callback", "unsupported"] {
                let route = report
                    .routes
                    .iter()
                    .find(|r| r.path == format!("{prefix}/{suffix}"))
                    .unwrap();
                assert!(
                    matches!(route.security_status(), RouteSecurityStatus::Unknown { .. }),
                    "{route:?}"
                );
            }
        }
        assert!(report.finding_details.is_empty());
    }
    let report = TempRepo::new(
        "ambiguous-legacy",
        &[(
            "main.rs",
            r#"
mod left {pub fn same(){}} mod right {pub fn same(){}}
use actix_web::web;
use left::same; use right::same;
fn app(){App::new().route("/x",web::get().to_async(same));}
"#,
        )],
    )
    .analyze();
    assert!(matches!(
        report.routes[0].handler_resolution,
        Some(HandlerResolution::Ambiguous { .. })
    ));
    assert!(matches!(
        report.routes[0].security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
    let report = TempRepo::new(
        "legacy-api-alias",
        &[(
            "main.rs",
            r#"
use actix_web::web as endpoints;
async fn good(){}
fn configure(cfg:&mut Config){
 cfg.route("/alias",endpoints::post().to_async(good));
 cfg.route("/fake",unrelated::get().to_async(good));
 cfg.route("/nested",endpoints::get().guard(unrelated::get().to(good)));
}
"#,
        )],
    )
    .analyze();
    let alias = report.routes.iter().find(|r| r.path == "/alias").unwrap();
    assert_eq!(alias.method, "POST");
    assert!(matches!(
        alias.handler_resolution,
        Some(HandlerResolution::Local)
    ));
    for path in ["/fake", "/nested"] {
        let route = report.routes.iter().find(|r| r.path == path).unwrap();
        assert!(route.handler.is_none());
        assert!(matches!(
            route.security_status(),
            RouteSecurityStatus::Unknown { .. }
        ));
    }
}

#[test]
fn unmounted_attribute_services_preserve_context_uncertainty() {
    let routes = r#"
use actix_identity::Identity;
#[actix_web::post("/chpass_request")]
pub async fn chpass_request(id: Identity) { match id.identity() { None => "Invalid session", Some(user) => { change_password(user); "Changed" } } }
#[actix_web::post("/confirm_delacc")]
pub async fn confirm_delacc(id: Identity) { match id.identity() { None => "Invalid session", Some(user) => { delete_account(user); "Deleted" } } }
#[actix_web::get("/public")]
pub async fn public() { "Public" }
"#;
    for (name, imports, app, expected_mounted) in [
        (
            "ambiguous-attribute-mount",
            "use actions::*; use unavailable::prelude::*;",
            "App::new().wrap(opaque_layer()).service(chpass_request).service(confirm_delacc).service(public);",
            false,
        ),
        (
            "explicit-attribute-mount",
            "use actions::{chpass_request,confirm_delacc,public}; use unavailable::prelude::*;",
            "App::new().wrap(opaque_layer()).service(chpass_request).service(confirm_delacc).service(public);",
            true,
        ),
        ("missing-attribute-mount", "", "", false),
    ] {
        let main = format!("mod actions; {imports} fn main() {{ {app} }}");
        let repo = TempRepo::new(
            name,
            &[
                (
                    "Cargo.toml",
                    "[package]\nname=\"mounts\"\nversion=\"0.1.0\"\nedition=\"2021\"",
                ),
                ("src/main.rs", &main),
                ("src/actions.rs", routes),
            ],
        );
        let report = repo.analyze();
        assert_eq!(report.routes.len(), 3);
        assert_eq!(report.summary.as_ref().unwrap().unknown_routes, 3);
        assert_eq!(report.summary.as_ref().unwrap().unprotected_routes, 0);
        for route in &report.routes {
            assert!(
                matches!(route.security_status(), RouteSecurityStatus::Unknown { .. }),
                "{name}: {route:?}"
            );
            assert_eq!(
                route
                    .application
                    .as_ref()
                    .is_some_and(|a| !a.starts_with("declaration:")),
                expected_mounted
            );
            assert!(!route.is_authorized());
        }
        assert!(report.finding_details.is_empty());
    }
    let repo = TempRepo::new(
        "mounted-public-attribute",
        &[(
            "main.rs",
            r#"
#[actix_web::get("/public")] async fn public() { "Public" }
fn main() { App::new().service(public); }
"#,
        )],
    );
    let report = repo.analyze();
    assert_eq!(
        report.routes[0].security_status(),
        RouteSecurityStatus::Unprotected
    );
}

#[test]
fn workspace_extractors_require_validated_values_on_the_same_app_mount() {
    let identity = r#"
use actix_web::FromRequest as Extract;
use std::future::ready;
use jsonwebtoken::{decode as unpack, Validation as Rules};
pub struct Principal(pub String);
impl Extract for Principal {
 type Error=Error; type Future=Ready<Result<Self,Error>>;
 fn from_request(req: &HttpRequest, payload: &mut Payload) -> Self::Future {
  ready(match req.extensions().get::<Self>() { Some(p)=>Ok(p.clone()), None=>Err(denied()) })
 }
}
pub fn acquire(raw: &str, key: &Key) -> Result<Principal,Error> {
 let decoded=unpack::<Payload>(raw,key,&Rules::default())?;
 Ok(Principal(decoded.claims.sub))
}
"#;
    let mut measurements = Vec::new();
    for (name, app, producer, insertion, parameter, expected) in [
        (
            "bound",
            "let app=App::new().wrap(Gate::new()); app.configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            true,
        ),
        (
            "direct",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            true,
        ),
        (
            "missing",
            "App::new().configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "conditional",
            "App::new().wrap(Condition::new(enabled,Gate::new())).configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "other-app",
            "let secured=App::new().wrap(Gate::new()); let public=App::new(); public.configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "optional",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Option<Actor>",
            false,
        ),
        (
            "unchecked",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.replace(
                "let decoded=unpack::<Payload>(raw,key,&Rules::default())?;",
                "let decoded=untrusted(raw);",
            ),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "ignored",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.replace(
                "let decoded=unpack::<Payload>(raw,key,&Rules::default())?;",
                "unpack::<Payload>(raw,key,&Rules::default()); let decoded=untrusted(raw);",
            ),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "unrelated",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(settings);",
            "Actor",
            false,
        ),
        (
            "shadowed",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; let person=untrusted(raw); req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "removed",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person); req.extensions_mut().remove::<Actor>();",
            "Actor",
            false,
        ),
        (
            "conditional-insert",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; if enabled { req.extensions_mut().insert(person); }",
            "Actor",
            false,
        ),
        (
            "ambiguous-decode",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.replace(
                "pub struct Principal",
                "use other::decode as unpack; pub struct Principal",
            ),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "validation-unverified",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.replace("&Rules::default()", "&custom_validation"),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "extractor-allows-missing",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.replace("None=>Err(denied())", "None=>Ok(default_user())"),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "two-mounts",
            "let secured=App::new().wrap(Gate::new()); let public=App::new(); secured.configure(config); public.configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            true,
        ),
        (
            "builder-shadow",
            "let app=App::new().wrap(Gate::new()); let app=unknown_builder(); app.configure(config);",
            identity.to_string(),
            "let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),
        (
            "unrelated-token",
            "App::new().wrap(Gate::new()).configure(config);",
            identity.to_string(),
            "let raw=service_token; let person=acquire(raw,key)?; req.extensions_mut().insert(person);",
            "Actor",
            false,
        ),

        ("wrapper-default", "App::new().wrap(Gate::new()).configure(config);", identity.replace("let decoded=unpack::<Payload>(raw,key,&Rules::default())?;", "let validation=Rules::default(); let decoded=unpack::<Payload>(raw,key,&validation)?;"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("wrapper-map-error", "App::new().wrap(Gate::new()).configure(config);", identity.replace("&Rules::default())?", "&Rules::default()).map_err(translate)?"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("wrapper-option", "App::new().wrap(Gate::new()).configure(config);", identity.replace("&Rules::default())?", "&Rules::default()).ok().ok_or(denied())?"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("wrapper-from", "App::new().wrap(Gate::new()).configure(config);", format!("{} impl std::convert::From<Payload> for Principal {{fn from(p:Payload)->Self {{Self(p.sub)}}}}",identity.replace("Principal(decoded.claims.sub)","Principal::from(decoded.claims)")), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("wrapper-struct", "App::new().wrap(Gate::new()).configure(config);", identity.replace("pub struct Principal(pub String);","pub struct Principal { pub subject:String }").replace("Principal(decoded.claims.sub)","Principal { subject:decoded.claims.sub }"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("wrapper-alias", "App::new().wrap(Gate::new()).configure(config);", format!("pub type Verdict<T> = Result<T,Error>; {}",identity.replace("Result<Principal,Error>","Verdict<Principal>")), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("wrapper-chain", "App::new().wrap(Gate::new()).configure(config);", format!("{} pub fn acquire(raw:&str,key:&Key)->Result<Principal,Error> {{ decode_person(raw,key) }}", identity.replace("pub fn acquire", "fn decode_person")), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("wrapper-adapter", "App::new().wrap(Gate::new()).configure(config);", format!("{} trait Retag<T> {{fn retag(self)->Result<T,Error>;}} impl<T,E> Retag<T> for Result<T,E> {{fn retag(self)->Result<T,Error> {{self.map_err(translate)}}}}", identity.replace("&Rules::default())?", "&Rules::default()).retag()?")), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("service-future", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("forged-after-validation", "App::new().wrap(Gate::new()).configure(config);", identity.replace("Principal(decoded.claims.sub)","Principal(forged())"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("wrong-request-context", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; other.extensions_mut().insert(person);", "Actor", false),
        ("wrong-forward-context", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("missing-extractor", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "()", false),
        ("ambiguous-conversion", "App::new().wrap(Gate::new()).configure(config);", format!("{} impl std::convert::From<Payload> for Principal {{fn from(p:Payload)->Self {{Self(p.sub)}}}} impl std::convert::From<Other> for Principal {{fn from(p:Other)->Self {{Self(p.sub)}}}}",identity.replace("Principal(decoded.claims.sub)","Principal::from(decoded.claims)")), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("ambiguous-adapters", "App::new().wrap(Gate::new()).configure(config);", format!("{} trait A<T> {{fn retag(self)->Result<T,Error>;}} trait B<T> {{fn retag(self)->Result<T,Error>;}} impl<T,E> A<T> for Result<T,E> {{fn retag(self)->Result<T,Error> {{self.map_err(translate)}}}} impl<T,E> B<T> for Result<T,E> {{fn retag(self)->Result<T,Error> {{self.map_err(translate)}}}}",identity.replace("&Rules::default())?","&Rules::default()).retag()?")), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("mutated-default", "App::new().wrap(Gate::new()).configure(config);", identity.replace("let decoded=unpack::<Payload>(raw,key,&Rules::default())?;", "let mut validation=Rules::default(); let ignored=validation.insecure_disable_signature_validation(); let decoded=unpack::<Payload>(raw,key,&validation)?;"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("ignored-validation-adapter", "App::new().wrap(Gate::new()).configure(config);", identity.replace("let decoded=unpack::<Payload>(raw,key,&Rules::default())?;", "unpack::<Payload>(raw,key,&Rules::default()).map_err(translate); let decoded=forged();"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("opaque-request-effect", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let side=spawn_override(req.request().clone()); let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("middleware-wrapper", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key).map_err(translate)?; req.extensions_mut().insert(person);", "Actor", true),
        ("generic-result-shadow", "App::new().wrap(Gate::new()).configure(config);", format!("{} pub type Verdict<Result> = Result; pub fn raw_principal(raw:&str,key:&Key)->Verdict<Principal> {{ let decoded=unpack::<Payload>(raw,key,&Rules::default())?; Principal(decoded.claims.sub) }} impl Principal {{pub fn map_err(self, f:Mapper)->Self {{Principal(forged())}}}} pub fn acquire(raw:&str,key:&Key)->Result<Principal,Error> {{Ok(raw_principal(raw,key).map_err(translate))}}", identity.replace("pub fn acquire", "fn prior")), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("shadowed-result-constructor", "App::new().wrap(Gate::new()).configure(config);", format!("{} fn Ok(p:Principal)->Result<Principal,Error> {{Result::Ok(Principal(forged()))}}", identity), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("header", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", true),
        ("header-optional", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Option<Actor>", false),
        ("header-unverified", "App::new().wrap(Gate::new()).configure(config);", identity.replace("let decoded=unpack::<Payload>(raw,key,&Rules::default())?;", "let decoded=unchecked(raw);"), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("header-refresh-fallthrough", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=match acquire(raw,key){Ok(p)=>p,Err(_)=>forged()}; req.extensions_mut().insert(person);", "Actor", false),
        ("header-exempt", "App::new().wrap(Condition::new(enabled,Gate::new())).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; req.extensions_mut().insert(person);", "Actor", false),
        ("header-wrong-type", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key)?; req.extensions_mut().insert(Other(person));", "Actor", false),
        ("header-ignored", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "let person=acquire(raw,key); req.extensions_mut().insert(person);", "Actor", false),
        ("header-permissive", "App::new().wrap(Gate::new()).configure(config);", identity.to_string(), "", "Actor", false),
    ] {
        let middleware = format!(
            r#"
use actix_web::dev::{{Service,Transform}};
use identities::{{Principal as Actor,acquire}};
pub struct Gate; pub struct Carrier<S> {{ service:S }}
impl Gate {{ pub fn new()->Self {{ Gate }} }}
impl<S> Transform<S,ServiceRequest> for Gate {{ type Transform=Carrier<S>; }}
impl<S> Service<ServiceRequest> for Carrier<S> {{
 fn call(&self,req:ServiceRequest)->Self::Future {{ Box::pin(async move {{ let raw=req.cookie("session").ok_or(denied())?.value(); {insertion} self.service.call(req).await }}) }}
}}
"#
        );
        let middleware = if name.starts_with("header") {
            middleware.replace("req.cookie(\"session\").ok_or(denied())?.value()", "req.headers().get(\"X-Credential\").ok_or(denied())?.to_str()?")
        } else { middleware };
        let middleware = if name=="service-future" {
            middleware.replace("Box::pin(async", "let svc=self.service.clone(); let context=self.context.clone(); Box::pin(async").replace("self.service.call(req).await", "let res=svc.call(req).await?; respond(res)")
        } else if name=="wrong-forward-context" {middleware.replace("self.service.call(req)","self.service.call(other)")} else {middleware};
        let source = format!(
            r#"
use identities::Principal as Actor;
use middleware::Gate;
async fn endpoint(user:{parameter}) {{ sqlx::query("SELECT * FROM documents"); }}
fn config(c:&mut Config) {{ c.route("/documents/one",web::get().to(endpoint)).route("/documents/two",web::get().to(endpoint)).route("/documents/three",web::get().to(endpoint)); }}
fn app() {{ {app} }}
"#
        );
        let repo = TempRepo::new(
            name,
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=[\"app\",\"identities\"]\nresolver=\"2\"",
                ),
                (
                    "app/Cargo.toml",
                    "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nidentities={path=\"../identities\"}",
                ),
                (
                    "identities/Cargo.toml",
                    "[package]\nname=\"identities\"\nversion=\"0.1.0\"\nedition=\"2021\"",
                ),
                ("identities/src/lib.rs", &producer),
                ("app/src/lib.rs", &format!("mod middleware; {source}")),
                ("app/src/middleware.rs", &middleware),
            ],
        );
        let report = repo.analyze();
        assert_eq!(
            report.routes.len(),
            if name == "two-mounts" { 6 } else { 3 },
            "{name}: {:?}",
            report.routes
        );
        let facts: Vec<_> = report
            .security_assessments
            .iter()
            .flat_map(|a| &a.requirements)
            .filter(|q| {
                q.dimension == "authentication" && q.enforcement == security::Enforcement::Observed
            })
            .collect();
        let before=std::env::var_os("ARCHER_PROVENANCE_EVALUATION_DIR").map(|dir| {
            let root=report.routes[0].file.parent().unwrap().parent().unwrap().parent().unwrap();
            let output=std::process::Command::new(PathBuf::from(dir).join("baseline/archer.exe")).arg(root).arg("--json").output().unwrap();
            assert!(output.status.success());
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
        });
        measurements.push(serde_json::json!({"case":name,"routes":report.routes.len(),"expected_authentication":if expected{3}else{0},"verified_authentication":facts.len(),"invariants":report.invariants.len(),"drift_comparisons":report.summary.as_ref().unwrap().peer_compared_routes,"before":before,"after":serde_json::to_value(&report).unwrap()}));
        if expected {
            assert_eq!(facts.len(), 3, "{name}: {:?}", report.security_assessments);
            assert!(
                report
                    .invariants
                    .iter()
                    .any(|i| i.description.starts_with("Supported authentication")),
                "{name}: {:?}",
                report.invariants
            );
        }
        assert_eq!(
            report.summary.as_ref().unwrap().protected_routes,
            if expected { 3 } else { 0 },
            "{name}"
        );
        if name == "optional" {
            assert!(report.security_assessments.iter().all(|a| {
                a.requirements
                    .iter()
                    .any(|q| q.explanation.starts_with("Optional identity"))
            }));
        }
        assert!(report.finding_details.is_empty());
        assert_eq!(
            !facts.is_empty(),
            expected,
            "{name}: {:?}",
            report.security_assessments
        );
    }
    if let Some(dir) = std::env::var_os("ARCHER_PROVENANCE_EVALUATION_DIR") {
        std::fs::write(
            PathBuf::from(dir).join("fixture-results.json"),
            serde_json::to_vec_pretty(&measurements).unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn async_cross_crate_checks_require_consumed_rejection() {
    for (body, observed) in [
        ("demand(\"edit\").await?;", true),
        ("(demand(\"edit\").await)?;", true),
        ("check_permission_forward(\"edit\").await?;", true),
        ("check_permission_tail(\"edit\").await?;", true),
        ("demand(\"edit\");", false),
        ("demand(\"edit\").await;", false),
        ("let _ = demand(\"edit\").await;", false),
        ("check_permission_ignored(\"edit\").await?;", false),
        ("check_permission_allowed(\"edit\").await?;", false),
        ("check_permission_cycle(\"edit\").await?;", false),
        ("check_permission_deferred(\"edit\").await?;", false),
        ("let deferred = async { demand(\"edit\").await?; };", false),
        ("let deferred = || { demand(\"edit\")?; };", false),
    ] {
        let app = format!(
            r#"
use guards::check_permission as demand;
use guards::{{check_permission_forward, check_permission_tail, check_permission_ignored,
    check_permission_allowed, check_permission_cycle, check_permission_deferred}};
async fn handler() {{ {body} }}
fn app(c: &mut Config) {{ c.route("/object", web::get().to(handler)); }}
"#
        );
        let repo = TempRepo::new(
            "async-security-controls",
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=[\"app\",\"guards\"]\nresolver=\"2\"",
                ),
                (
                    "app/Cargo.toml",
                    "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nguards={path=\"../guards\"}",
                ),
                (
                    "guards/Cargo.toml",
                    "[package]\nname=\"guards\"\nversion=\"0.1.0\"\nedition=\"2021\"",
                ),
                ("app/src/lib.rs", &app),
                (
                    "guards/src/lib.rs",
                    r#"
pub async fn check_permission(p: &str) -> Result<(), Error> { if allowed(p) { Ok(()) } else { Err(denied()) } }
pub async fn check_permission_forward(p: &str) -> Result<(), Error> { check_permission(p).await?; Ok(()) }
pub async fn check_permission_tail(p: &str) -> Result<(), Error> { (check_permission(p).await) }
pub async fn check_permission_ignored(p: &str) -> Result<(), Error> { check_permission(p).await; Ok(()) }
pub async fn check_permission_allowed(p: &str) -> Result<(), Error> { Ok(()) }
pub async fn check_permission_cycle(p: &str) -> Result<(), Error> { check_permission_cycle(p).await }
pub async fn check_permission_deferred(p: &str) -> Result<(), Error> { let unused = async { return Err(denied()); }; Ok(()) }
"#,
                ),
            ],
        );
        let report = repo.analyze();
        assert_eq!(report.security_assessments.len(), 1);
        let assessment = &report.security_assessments[0];
        assert_eq!(
            assessment
                .requirements
                .iter()
                .any(|r| r.enforcement == security::Enforcement::Observed),
            observed,
            "{body}: {assessment:?}"
        );
        if observed {
            assert!(
                assessment
                    .requirements
                    .iter()
                    .any(|r| r.dimension == "permissions" && r.values == ["edit"])
            );
        }
    }
}

#[test]
fn nested_callback_declarations_do_not_duplicate_concrete_mounts() {
    let source = r#"
async fn handler() {}
fn inner(cfg: &mut Config) { cfg.route("/item",web::get().to(handler)); }
fn outer(cfg: &mut Config) { cfg.service(web::scope("/api").configure(inner)); }
fn first() { App::new().configure(outer); }
fn second() { App::new().configure(outer); }
"#;
    let report = TempRepo::new("nested-app-context", &[("main.rs", source)]).analyze();
    assert_eq!(report.routes.len(), 2);
    assert!(
        report.routes.iter().all(|r| r.path == "/api/item"
            && !r.application.as_ref().unwrap().starts_with("declaration:"))
    );
    assert_ne!(report.routes[0].application, report.routes[1].application);
}

#[test]
fn test_apps_are_excluded_and_distinct_production_apps_are_preserved() {
    let source = r#"
async fn item() {}
fn configure(cfg: &mut Config) { cfg.route("/item", web::get().to(item)); }
fn first() { App::new().configure(configure); }
fn second() { App::new().configure(configure); }
#[cfg(test)] mod tests { fn harness() { App::new().configure(super::configure); } }
#[actix_web::test] async fn request_test() { App::new().configure(configure); }
"#;
    let report = TempRepo::new(
        "production-context",
        &[
            ("main.rs", source),
            (
                "tests/integration.rs",
                "fn test_app() { App::new().route(\"/test\", web::get().to(handler)); }",
            ),
            (
                "examples/demo.rs",
                "fn demo() { App::new().route(\"/example\", web::get().to(handler)); }",
            ),
        ],
    )
    .analyze();
    assert_eq!(report.routes.len(), 2);
    assert_ne!(report.routes[0].application, report.routes[1].application);
    assert!(report.routes.iter().all(|r| r.application.is_some()));
    assert!(report.candidate_relationships.is_empty());
}

#[test]
fn standard_middleware_binding_does_not_hide_a_shadowed_opaque_layer() {
    let repo = TempRepo::new(
        "p2-middleware-bindings",
        &[(
            "main.rs",
            r#"
async fn handler() {}
fn app() {
 let layer = Cors::default().supports_credentials();
 App::new().wrap(layer).route("/public", web::get().to(handler));
 {
   let layer = custom_layer();
   App::new().wrap(layer).route("/opaque", web::get().to(handler));
 }
}
"#,
        )],
    );
    let report = repo.analyze();
    assert_eq!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/public")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unprotected
    );
    assert!(matches!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/opaque")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn unknown_middleware_propagates_only_to_its_mount() {
    let repo = TempRepo::new(
        "p2-opaque",
        &[(
            "main.rs",
            r#"
async fn handler() {}
fn app(c: &mut Config) {
 c.service(web::scope("/opaque").wrap(custom_layer()).route("/item", web::get().to(handler)))
 .service(web::scope("/public").route("/item", web::get().to(handler)));
}
"#,
        )],
    );
    let report = repo.analyze();
    assert!(matches!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/opaque/item")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
    assert_eq!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/public/item")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unprotected
    );
}

#[test]
fn role_constructor_value_is_read_instead_of_assumed_from_its_name() {
    let repo = TempRepo::new(
        "p2-constructor",
        &[(
            "main.rs",
            r#"
struct RoleGuard { role: Role }
impl RoleGuard { pub fn admin() -> Self { Self { role: Role::Editor } } }
impl Service for RoleGuardMiddleware {
 fn call(&self, req: Request) { if req.role == self.role { self.service.call(req) } else { Err(denied()) } }
}
async fn handler() {}
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RoleGuard::admin())); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(
        report.security_assessments[0]
            .requirements
            .iter()
            .any(|r| r.dimension == "roles" && r.values == ["Role::Editor"])
    );
}

#[test]
fn ownership_predicate_controlling_rejection_is_observed() {
    let repo = TempRepo::new(
        "p2-control",
        &[(
            "main.rs",
            r#"
fn is_owner(user: User, id: Id) -> bool { user.id == id }
async fn handler(user: User, id: Id) { if !is_owner(user, id) { return Err(denied()); } serve(); }
fn app(c: &mut Config) { c.route("/item/{id}", web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(report.routes[0].is_authorized());
    assert_eq!(
        report.security_assessments[0].requirements[0].enforcement,
        security::Enforcement::Observed
    );
}

#[test]
fn fallible_permission_helper_must_propagate_result() {
    let repo = TempRepo::new(
        "p2-propagation",
        &[(
            "main.rs",
            r#"
fn check_permission(p: &str) -> Result<(), Error> { if !allowed(p) { return Err(denied()); } Ok(()) }
async fn checked() { check_permission("invoice.read")?; serve(); }
async fn ignored() { check_permission("invoice.read"); serve(); }
fn app(c: &mut Config) { c.route("/checked", web::get().to(checked)).route("/ignored", web::get().to(ignored)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/checked")
            .unwrap()
            .is_authorized()
    );
    assert!(matches!(
        report
            .routes
            .iter()
            .find(|r| r.path == "/ignored")
            .unwrap()
            .security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn cross_file_resources_repeated_mounts_keep_context() {
    let repo = TempRepo::new(
        "p1-mounts",
        &[
            ("Cargo.toml", "[package]\nname='fixture'\nversion='0.1.0'\n"),
            (
                "src/main.rs",
                r#"mod api;
fn main() { App::new()
 .service(web::scope("/one").wrap(AdminGuard).configure(api::configure))
 .service(web::scope("/two").configure(|c| api::configure(c))); }
"#,
            ),
            (
                "src/api.rs",
                r#"pub fn configure(c: &mut web::ServiceConfig) {
 c.service(web::resource("/{id}").get(read).put(update));
} async fn read() {} async fn update() {}"#,
            ),
        ],
    );
    let report = repo.analyze();
    assert_eq!(report.routes.len(), 4);
    for route in &report.routes {
        assert_eq!(
            !route.authorization.is_empty(),
            route.path.starts_with("/one/")
        );
        assert!(route.path == "/one/{id}" || route.path == "/two/{id}");
    }
}

#[test]
fn attribute_services_receive_mount_prefix() {
    let repo = TempRepo::new(
        "p1-attributes",
        &[(
            "main.rs",
            r#"
#[actix_web::get("/item")] async fn item() {}
fn app() { App::new().service(web::scope("/api").service(item)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert_eq!(report.routes.len(), 1);
    assert_eq!(report.routes[0].path, "/api/item");
}

#[test]
fn unsupported_callback_and_dynamic_path_are_diagnostic() {
    let repo = TempRepo::new(
        "p0-diagnostics",
        &[(
            "main.rs",
            r#"
fn app(c: &mut Config) { c.configure(external::configure).route(PATH, web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == "unresolved_callback")
    );
    assert!(
        report
            .diagnostics
            .iter()
            .any(|d| d.code == "unsupported_registration")
    );
}

#[test]
fn unused_local_security_predicate_is_not_protection() {
    let repo = TempRepo::new(
        "p2-unused",
        &[(
            "main.rs",
            r#"
fn is_owner() -> bool { true }
async fn handler() { is_owner(); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(!report.routes[0].is_authorized());
    assert!(matches!(
        report.routes[0].security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
    assert_eq!(
        report.security_assessments[0].requirements[0].dimension,
        "ownership"
    );
}

#[test]
fn typed_identity_and_permission_arguments_are_preserved() {
    let repo = TempRepo::new(
        "p2-values",
        &[(
            "main.rs",
            r#"
async fn handler(user: web::ReqData<Claims>) { check_permission("invoice.read"); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler)); }
"#,
        )],
    );
    let report = repo.analyze();
    let requirements = &report.security_assessments[0].requirements;
    assert!(
        requirements
            .iter()
            .any(|r| r.dimension == "authentication" && r.mechanism == "extractor")
    );
    assert!(
        requirements
            .iter()
            .any(|r| r.dimension == "permissions" && r.values == ["invoice.read"])
    );
}

#[test]
fn middleware_name_without_implementation_does_not_prove_role_policy() {
    let repo = TempRepo::new(
        "p2-model-negative",
        &[(
            "main.rs",
            r#"
async fn handler() {}
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin]))); }
"#,
        )],
    );
    let report = repo.analyze();
    assert!(!report.routes[0].is_authorized());
    assert!(matches!(
        report.routes[0].security_status(),
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn role_sets_remain_distinct_and_public_route_does_not_inherit() {
    let repo = TempRepo::new(
        "p2-roles",
        &[(
            "main.rs",
            r#"
impl Service for AuthMiddleware {
 fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } }
}
async fn handler() {}
fn app(c: &mut Config) {
 c.route("/admin", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin])))
 .route("/self", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::User, Role::Admin])))
 .route("/public", web::get().to(handler));
}
"#,
        )],
    );
    let report = repo.analyze();
    assert_eq!(
        report.routes.iter().filter(|r| r.is_authorized()).count(),
        2
    );
    let roles: Vec<_> = report
        .security_assessments
        .iter()
        .flat_map(|a| &a.requirements)
        .filter(|r| r.dimension == "roles")
        .collect();
    assert!(roles.iter().any(|r| r.values == ["Role::Admin"]));
    assert!(
        roles
            .iter()
            .any(|r| r.values == ["Role::User", "Role::Admin"])
    );
}

#[test]
fn workspace_security_aliases_and_ignored_wrapper_results() {
    for (body, observed) in [
        ("demand(\"manage\")?;", true),
        ("demand(\"manage\");", false),
        ("wrapper(\"manage\")?;", false),
        ("recursive(\"manage\")?;", false),
    ] {
        let app = format!(
            r#"
use guards::check_permission as demand;
use guards::check_permission_wrapper as wrapper;
use guards::check_permission_recursive as recursive;
async fn handler() {{ {body} }}
fn app(c: &mut Config) {{ c.route("/item", web::get().to(handler)); }}
"#
        );
        let repo = TempRepo::new(
            "workspace-security-controls",
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=[\"app\",\"guards\"]\nresolver=\"2\"",
                ),
                (
                    "app/Cargo.toml",
                    "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nguards={path=\"../guards\"}",
                ),
                (
                    "guards/Cargo.toml",
                    "[package]\nname=\"guards\"\nversion=\"0.1.0\"\nedition=\"2021\"",
                ),
                ("app/src/lib.rs", &app),
                (
                    "guards/src/lib.rs",
                    r#"
pub fn check_permission(p: &str) -> Result<(), Error> { if allowed(p) { Ok(()) } else { Err(denied()) } }
pub fn check_permission_wrapper(p: &str) -> Result<(), Error> { check_permission(p); Ok(()) }
pub fn check_permission_recursive(p: &str) -> Result<(), Error> { check_permission_recursive(p) }
"#,
                ),
            ],
        );
        let report = repo.analyze();
        let assessment = &report.security_assessments[0];
        assert_eq!(
            assessment
                .requirements
                .iter()
                .any(|r| r.enforcement == security::Enforcement::Observed),
            observed,
            "{body}: {assessment:?}"
        );
        if observed {
            assert!(
                assessment.route.authorization[0]
                    .file
                    .ends_with("app/src/lib.rs")
            );
        } else {
            assert!(matches!(
                assessment.route.status,
                RouteSecurityStatus::Unknown { .. }
            ));
        }
    }
}

#[test]
fn workspace_role_middleware_alias_and_placement_preserve_mount_boundaries() {
    for placement in ["route", "scope", "sibling"] {
        let builder = match placement {
            "route" => {
                r#"c.route("/items", web::get().to(handler).wrap(Gate::allowed_roles(vec![Role::Editor])));"#
            }
            "scope" => {
                r#"c.service(web::scope("/items").wrap(Gate::allowed_roles(vec![Role::Editor])).route("", web::get().to(handler)));"#
            }
            _ => {
                r#"c.service(web::scope("/protected").wrap(Gate::allowed_roles(vec![Role::Editor])).route("", web::get().to(handler))).route("/items", web::get().to(handler));"#
            }
        };
        let source = format!(
            "use guards::RequireAuth as Gate; async fn handler() {{ serve(); }} fn app(c: &mut Config) {{ {builder} }}"
        );
        let report = TempRepo::new("workspace-middleware-placement", &[
            ("Cargo.toml", "[workspace]\nmembers=[\"app\",\"guards\"]\nresolver=\"2\""),
            ("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nguards={path=\"../guards\"}"),
            ("guards/Cargo.toml", "[package]\nname=\"guards\"\nversion=\"0.1.0\"\nedition=\"2021\""),
            ("app/src/lib.rs", &source),
            ("guards/src/lib.rs", r#"
pub struct RequireAuth;
impl RequireAuth { pub fn allowed_roles(roles: Vec<Role>) -> Self { Self } }
impl Service for AuthMiddleware { fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } } }
"#),
        ]).analyze();
        let assessment = report
            .security_assessments
            .iter()
            .find(|a| a.route.path == "/items")
            .unwrap();
        assert_eq!(assessment.requirements.iter().any(|r| r.dimension == "roles" && r.enforcement == security::Enforcement::Observed), placement != "sibling", "{placement}: {assessment:?}");
    }
}

#[test]
fn unresolved_import_does_not_borrow_a_local_middleware_model() {
    let source = r#"
use absent_dependency::RequireAuth;
impl Service for AuthMiddleware {
 fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } }
}
async fn handler() { serve(); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin]))); }
"#;
    let report = TempRepo::new("unresolved-middleware-decoy", &[("main.rs", source)]).analyze();
    assert!(
        !report.security_assessments[0]
            .requirements
            .iter()
            .any(|r| r.enforcement == security::Enforcement::Observed)
    );
    assert!(matches!(
        report.security_assessments[0].route.status,
        RouteSecurityStatus::Unknown { .. }
    ));
}

#[test]
fn qualified_public_type_reexport_keeps_role_middleware_evidence() {
    let report = TempRepo::new("qualified-type-reexport", &[("main.rs", r#"
mod security {
 mod implementation {
  pub struct RequireAuth;
  impl RequireAuth { pub fn allowed_roles(roles: Vec<Role>) -> Self { Self } }
  impl Service for AuthMiddleware { fn call(&self, req: Request) { if self.allowed_roles.contains(&req.role) { self.service.call(req) } else { Err(denied()) } } }
 }
 pub use implementation::RequireAuth;
}
use crate::security::RequireAuth;
async fn handler() { serve(); }
fn app(c: &mut Config) { c.route("/item", web::get().to(handler).wrap(RequireAuth::allowed_roles(vec![Role::Admin]))); }
"#)]).analyze();
    assert!(
        report.security_assessments[0]
            .requirements
            .iter()
            .any(|r| r.dimension == "roles" && r.enforcement == security::Enforcement::Observed)
    );
}


#[test]
fn middleware_policy_is_bound_to_the_called_source_constructor() {
    for (name,body,expected) in [
        ("member", "Self { role: Role::Reader }",Some("Role::Reader")),
        ("unusual", "Self { role: Role::Editor }",Some("Role::Editor")),
        ("conditional", "if condition() {Self {role:Role::Reader}} else {Self {role:Role::Admin}}",None),
        ("opaque", "Self {role:choose()}",None),
        ("uncanonicalized", "Self {role:Alias::Reader}",None),
        ("early", "if condition(){return Self {role:Role::Admin};} Self {role:Role::Reader}",None),
        ("ignored", "let unused=Self {role:Role::Admin}; factory()",None),
    ] {
        let source=format!(r#"
struct RoleGuard {{role:Role}}
impl RoleGuard {{pub fn admin()->Self {{Self {{role:Role::Admin}}}} pub fn {name}()->Self {{{body}}}}}
impl Service for RoleGuardMiddleware {{fn call(&self,req:Request) {{if req.role==self.role {{self.service.call(req)}} else {{Err(denied())}}}}}}
async fn handler() {{}}
fn app(c:&mut Config) {{c.route("/other",web::get().to(handler).wrap(RoleGuard::admin())).route("/item",web::get().to(handler).wrap(RoleGuard::{name}()));}}
"#);
        let report=TempRepo::new("called-constructor-policy",&[("main.rs",&source)]).analyze();
        let assessment=report.security_assessments.iter().find(|a|a.route.path=="/item").unwrap();
        let observed:Vec<_>=assessment.requirements.iter().filter(|r|r.dimension=="roles" && r.enforcement==security::Enforcement::Observed).collect();
        if let Some(policy)=expected {assert_eq!(observed.len(),1,"{name}");assert_eq!(observed[0].values,[policy]);}
        else {assert!(observed.is_empty(),"{name}: {observed:?}");assert!(matches!(report.routes.iter().find(|r|r.path=="/item").unwrap().security_status(),RouteSecurityStatus::Unknown{..}));}
    }
}
