use super::tests::TempRepo;
use super::*;

#[test]
fn constructor_dispatch_is_per_instance_and_never_unique_implementation_guessing() {
    for name in [
        "boxed",
        "arc",
        "state-data",
        "helper",
        "alias",
        "two-instances",
        "runtime",
        "unbound",
        "unique-unbound",
        "same-handler",
        "mutable-method",
        "mutated",
        "borrowed",
        "opaque",
        "inherent-conflict",
    ] {
        let wrapper = if name == "arc" {
            "std::sync::Arc"
        } else {
            "Box"
        };
        let build = if name == "opaque" {
            "opaque_repository()"
        } else {
            "Disk"
        };
        let make = format!("let repo={wrapper}::new({build}); let state=State::new(repo);");
        let first = match name {
            "runtime" => format!(
                "let state=if choose() {{State::new({wrapper}::new(Disk))}} else {{State::new({wrapper}::new(Memory))}};"
            ),
            "unbound" | "unique-unbound" => String::new(),
            "same-handler" => format!(
                "{make} let another=State::new({wrapper}::new(Memory));let other=another.rows();response(other);"
            ),
            "mutable-method" => format!(
                "{} if choose() {{state.reset();}}",
                make.replace("let state=", "let mut state=")
            ),
            "mutated" => format!("{make} if choose() {{state.repo={wrapper}::new(Memory);}}"),
            "borrowed" => format!("{make} opaque(&mut state);"),
            "state-data" => format!("{make} let state=actix_web::web::Data::new(state);"),
            "helper" => "let state=make_state();".into(),
            _ => make.clone(),
        };
        let second = if name == "two-instances" {
            format!("let state=State::new({wrapper}::new(Memory));")
        } else {
            first.clone()
        };
        let alias = if name == "alias" {
            format!("type Repository={wrapper}<dyn Store>;")
        } else {
            String::new()
        };
        let ty = if name == "alias" {
            "Repository".to_owned()
        } else {
            format!("{wrapper}<dyn Store>")
        };
        let param = if ["unbound", "unique-unbound"].contains(&name) {
            "state:actix_web::web::Data<State>"
        } else {
            ""
        };
        let inherent = if name == "inherent-conflict" {
            r#"impl Disk {fn load(&self)->Row {sqlx::query("SELECT * FROM wrong_table");Row}}"#
        } else {
            ""
        };
        let mut source = format!(
            r#"
trait Store {{fn load(&self)->Row;}}
struct Row; struct Disk; struct Memory;
impl Store for Disk {{fn load(&self)->Row {{sqlx::query("SELECT * FROM records");Row}}}}
impl Store for Memory {{fn load(&self)->Row {{sqlx::query("SELECT * FROM cache");Row}}}}
{inherent}
{alias}
struct State {{repo:{ty}}}
impl State {{fn new(repo:{ty})->Self {{Self{{repo}}}} fn rows(&self)->Row {{self.repo.load()}} fn reset(&mut self){{self.repo={wrapper}::new(Memory);}}}}
fn make_state()->State {{let repo={wrapper}::new(Disk);State::new(repo)}}
async fn one({param}) {{{first} let rows=state.rows();response(rows);}}
async fn two({param}) {{{second} let rows=state.rows();response(rows);}}
fn app() {{App::new().route("/one",web::get().to(one)).route("/two",web::get().to(two));}}
"#
        );
        if name == "unique-unbound" {
            source=source.replace("impl Store for Memory {fn load(&self)->Row {sqlx::query(\"SELECT * FROM cache\");Row}}","").replace(&format!("fn reset(&mut self){{self.repo={wrapper}::new(Memory);}}"),"");
        }
        let report = TempRepo::new(name, &[("main.rs", &source)]).analyze();
        let positive = [
            "boxed",
            "arc",
            "state-data",
            "helper",
            "alias",
            "inherent-conflict",
            "same-handler",
        ]
        .contains(&name);
        assert_eq!(
            report.peer_groups.len(),
            usize::from(positive),
            "{name}: {:?}",
            report.resource_evidence
        );
        let facts: Vec<_> = report
            .resource_evidence
            .iter()
            .flat_map(|e| &e.resources)
            .collect();
        assert!(
            !facts.iter().any(|x| x.contains("wrong_table")),
            "{name}: {facts:?}"
        );
        if positive {
            let target_line = source
                .lines()
                .position(|line| line.starts_with("impl Store for Disk"))
                .unwrap()
                + 1;
            let target = format!("main.rs:{target_line} crate::Disk::load");
            assert!(
                report.resource_evidence.iter().all(|e| e
                    .call_chain_evidence
                    .iter()
                    .any(|x| x.contains("constructor-proven receiver"))),
                "{name}: {:?}",
                report.resource_evidence
            );
            assert!(
                report.resource_evidence.iter().all(|e| e
                    .call_chain_evidence
                    .iter()
                    .any(|line| line.ends_with(&target))),
                "{name}: {:?}",
                report.resource_evidence
            );
        }
        if name == "two-instances" {
            assert!(
                report
                    .resource_evidence
                    .iter()
                    .any(|e| e.resources.iter().any(|x| x.contains("records")))
            );
            assert!(
                report
                    .resource_evidence
                    .iter()
                    .any(|e| e.resources.iter().any(|x| x.contains("cache")))
            );
        }
        if name == "same-handler" {
            assert!(
                report.resource_evidence.iter().all(|e| e
                    .resources
                    .iter()
                    .any(|r| r.contains("cache"))
                    && e.resources.iter().any(|r| r.contains("records"))),
                "{:?}",
                report.resource_evidence
            );
        }
        assert!(report.finding_details.is_empty());
    }
}

#[test]
fn constructor_trait_values_cross_crates_without_global_type_specialization() {
    let app = r#"
use backend::{State,Disk,Store};
use std::sync::Arc as Shared;
fn make()->State {let repo=Shared::new(Disk::new());State::new(repo)}
fn erased()->Shared<dyn Store> {Shared::new(Disk::new())}
async fn one(){let state=make();let state=actix_web::web::Data::new(state);let rows=state.rows();response(rows);}
async fn two(){let state=make();let rows=state.rows();response(rows);}
async fn three(){let repo=erased();let rows=repo.load();response(rows);}
async fn unknown(state:actix_web::web::Data<State>){let rows=state.rows();response(rows);}
fn app(){App::new().route("/one",web::get().to(one)).route("/two",web::get().to(two)).route("/three",web::get().to(three)).route("/unknown",web::get().to(unknown));}
"#;
    let store = r#"
pub trait Store {fn load(&self)->Row;}
pub struct Row;pub struct Disk; pub struct Alternative;
impl Disk {pub fn new()->Self{Self} pub fn load(&self)->Row{sqlx::query("SELECT * FROM incorrect");Row}}
impl Store for Disk {fn load(&self)->Row{sqlx::query("SELECT * FROM documents");Row}}
impl Store for Alternative {fn load(&self)->Row{sqlx::query("SELECT * FROM other");Row}}
pub struct State {repo:std::sync::Arc<dyn Store>}
impl State {pub fn new(repo:std::sync::Arc<dyn Store>)->Self{Self{repo}} pub fn rows(&self)->Row{self.repo.load()}}
"#;
    let report=TempRepo::new("cross-crate-constructors",&[
        ("Cargo.toml","[workspace]\nmembers=[\"app\",\"db\"]\nresolver=\"2\""),
        ("app/Cargo.toml","[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nbackend={package=\"storage\",path=\"../db\"}"),
        ("db/Cargo.toml","[package]\nname=\"storage\"\nversion=\"0.1.0\"\nedition=\"2021\""),
        ("app/src/lib.rs",app),("db/src/lib.rs",store),
    ]).analyze();
    assert_eq!(
        report.peer_groups.len(),
        1,
        "{:?}",
        report.resource_evidence
    );
    assert_eq!(report.peer_groups[0].routes.len(), 3);
    for e in &report.resource_evidence {
        if e.route.handler.as_deref() == Some("unknown") {
            assert!(e.resources.is_empty(), "{e:?}");
        } else {
            assert!(e.resources.iter().any(|x| x.contains("documents")), "{e:?}");
            assert!(
                !e.resources
                    .iter()
                    .any(|x| x.contains("incorrect") || x.contains("other")),
                "{e:?}"
            );
        }
    }
}

#[test]
fn struct_update_preserves_static_dispatch_without_specializing_dynamic_fields() {
    let report=TempRepo::new("updated-receivers", &[("main.rs",r#"
struct Row;struct Query {limit:usize}
impl Query {fn rows(&self)->Row {sqlx::query("SELECT * FROM documents");Row}}
trait Store{fn rows(&self)->Row;}struct State{repo:Box<dyn Store>}
impl State{fn rows(&self)->Row{self.repo.rows()}}
async fn one(){let rows=Query{limit:10,..defaults()}.rows();response(rows);}
async fn two(){let mut query=Query{limit:20,..defaults()};query.limit=30;let rows=query.rows();response(rows);}
async fn unknown(){let state=State{..runtime_state()};let rows=state.rows();response(rows);}
fn app(){App::new().route("/one",web::get().to(one)).route("/two",web::get().to(two)).route("/unknown",web::get().to(unknown));}
"#)]).analyze();
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(report.peer_groups[0].routes.len(), 2);
    assert!(
        report
            .resource_evidence
            .iter()
            .find(|e| e.route.handler.as_deref() == Some("unknown"))
            .unwrap()
            .resources
            .is_empty()
    );
}

#[test]
fn canonical_state_wrappers_follow_concrete_fields_without_guessing_dispatch() {
    for (name, ty, imports, target) in [
        (
            "data",
            "StateData<State>",
            "use actix_web::web::Data as StateData;",
            true,
        ),
        (
            "arc-data",
            "StateData<std::sync::Arc<State>>",
            "use actix_web::web::Data as StateData;",
            true,
        ),
        (
            "aliased",
            "StateAlias",
            "use actix_web::web::Data as StateData; type StateAlias=StateData<State>;",
            true,
        ),
        (
            "fake-data",
            "StateData<State>",
            "struct StateData<T> { value:T }",
            false,
        ),
        ("collection", "Vec<State>", "", false),
        (
            "dynamic",
            "StateData<dyn Store>",
            "use actix_web::web::Data as StateData; trait Store {fn one(&self);fn two(&self);}",
            false,
        ),
    ] {
        let source = format!(
            r#"
{imports}
mod schema {{pub mod documents {{}} pub mod unrelated {{}}}}
pub struct Item;
pub struct Repository;
impl Repository {{
 pub fn one(&self)->Item {{schema::documents::table.first(conn); Item}}
 pub fn two(&self)->Vec<Item> {{schema::documents::table.load(conn); vec![]}}
}}
pub struct Services {{pub repository:std::sync::Arc<Repository>}}
pub struct State {{pub services:Services}}
async fn one(state:{ty}) {{let row=state.services.repository.one(); response(row);}}
async fn two(state:{ty}) {{let rows=state.services.repository.two(); response(rows);}}
async fn unrelated() {{schema::unrelated::table.load(conn);}}
fn app(c:&mut Config) {{c.route("/single/{{id}}",web::get().to(one)).route("/catalog",web::get().to(two)).route("/other",web::get().to(unrelated));}}
"#
        );
        let report = TempRepo::new(name, &[("main.rs", &source)]).analyze();
        let calls: Vec<_> = report
            .resource_evidence
            .iter()
            .flat_map(|r| &r.call_chain_evidence)
            .collect();
        assert_eq!(
            calls.iter().any(|r| r.contains("Repository::one")),
            target,
            "{name}: {calls:?}"
        );
        assert_eq!(
            calls.iter().any(|r| r.contains("Repository::two")),
            target,
            "{name}: {calls:?}"
        );
        assert_eq!(
            report.peer_groups.len(),
            usize::from(target),
            "{name}: {:?}",
            report.peer_groups
        );
        if target {
            assert_eq!(report.peer_groups[0].routes.len(), 2);
        }
        assert!(report.finding_details.is_empty());
    }
}

#[test]
fn declared_table_aliases_require_unambiguous_executed_query_sources() {
    for name in [
        "qualified",
        "bare",
        "aliased-macro",
        "callback",
        "fake-macro",
        "duplicate",
        "shadowed-query",
        "two-tables",
        "unused-closure",
        "opaque-callback",
        "unknown-glob",
        "shared-scalar-utility",
    ] {
        let setup = match name {
            "bare" => "#[macro_use] extern crate diesel;",
            "fake-macro" => {
                "#[macro_use] extern crate diesel; macro_rules! table {($($t:tt)*)=>{}}"
            }
            _ => "",
        };
        let macro_name = match name {
            "bare" | "fake-macro" => "table",
            "aliased-macro" => "define",
            _ => "diesel::table",
        };
        let schema_import = if name == "aliased-macro" {
            "use diesel::table as define;"
        } else {
            ""
        };
        let duplicate = if name == "duplicate" {
            "diesel::table! {records (id) {id->Integer,}}"
        } else {
            ""
        };
        let imports = if name == "callback" {
            "use storage::{collection,other};"
        } else if name == "unknown-glob" {
            "use storage::*; use unavailable::*;"
        } else {
            "use storage::*;"
        };
        let query = match name {
            "unused-closure" => "let deferred=||collection.load::<Row>(conn);",
            "opaque-callback" => "store_for_later(||collection.load::<Row>(conn));",
            "callback" => {
                "let rows=actix_web::web::block(move||collection.load::<Row>(conn)).await; response(rows);"
            }
            _ => "let rows=collection.load::<Row>(conn); response(rows);",
        };
        let second = if ["two-tables", "shared-scalar-utility"].contains(&name) {
            "let rows=other.load::<Row>(conn); response(rows);"
        } else {
            query
        };
        let param = if name == "shadowed-query" {
            "collection:FakeSource"
        } else {
            ""
        };
        let cache = if name == "shared-scalar-utility" {
            "let cfg=cache_metric(); use_metric(cfg);"
        } else {
            ""
        };
        let source = format!(
            r#"
{setup}
mod mapping {{ {schema_import}
 {macro_name}! {{records (id) {{id->Integer,}}}}
 {macro_name}! {{elsewhere (id) {{id->Integer,}}}}
 {duplicate}
}}
mod storage {{pub use crate::mapping::records::dsl::records as collection; pub use crate::mapping::elsewhere::dsl::elsewhere as other;}}
{imports}
struct Row {{id:i32}}
struct FakeSource;
fn cache_metric()->usize {{collection.load::<Row>(conn).len()}}
async fn first({param}) {{{cache} {query}}}
async fn second({param}) {{{cache} {second}}}
fn app(c:&mut Config) {{c.route("/first",web::get().to(first)).route("/second",web::get().to(second));}}
"#
        );
        let report = TempRepo::new(name, &[("main.rs", &source)]).analyze();
        let expected = ["qualified", "bare", "aliased-macro", "callback"].contains(&name);
        assert_eq!(
            report.peer_groups.len(),
            usize::from(expected),
            "{name}: {:?}",
            report.resource_evidence
        );
        if expected {
            assert!(
                report
                    .resource_evidence
                    .iter()
                    .all(|e| e.resources.iter().any(|r| r.ends_with("mapping::records"))),
                "{name}: {:?}",
                report.resource_evidence
            );
        }
        assert!(report.finding_details.is_empty());
    }
}

#[test]
fn layered_cross_crate_resources_support_conservative_drift_comparisons() {
    for (name, last, scope, findings) in [
        ("clean", "check_role(\"Admin\")?;", false, 0),
        ("missing", "", false, 1),
        ("weakened", "check_role(\"Reader\")?;", false, 1),
        ("ignored", "check_role(\"Admin\");", false, 0),
        ("legitimate", "check_role(\"Reader\")?;", true, 0),
    ] {
        let third = if scope {
            ".service(web::scope(\"/self\").route(\"/three/{id}\",web::get().to(three)))"
        } else {
            ".route(\"/three/{id}\",web::get().to(three))"
        };
        let app = format!(
            r#"
use actix_web::{{App,web::Data as StateData}};
use storage::Repository as Store;
pub struct Services {{pub repository:std::sync::Arc<Store>}}
pub struct State {{pub services:Services}}
fn check_role(r:&str)->Result<(),Error> {{if allowed(r) {{Ok(())}} else {{Err(denied())}}}}
async fn one(state:StateData<State>) {{check_role("Admin")?;let row=state.services.repository.load();response(row);}}
async fn two(state:StateData<State>) {{check_role("Admin")?;let row=state.services.repository.load();response(row);}}
async fn three(state:StateData<State>) {{{last}let row=state.services.repository.load();response(row);}}
fn app() {{App::new().route("/one/{{id}}",web::get().to(one)).route("/two/{{id}}",web::get().to(two)){third};}}
"#
        );
        let repo = TempRepo::new(
            name,
            &[
                (
                    "Cargo.toml",
                    "[workspace]\nmembers=[\"app\",\"store\"]\nresolver=\"2\"",
                ),
                (
                    "app/Cargo.toml",
                    "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nstorage={package=\"records\",path=\"../store\"}",
                ),
                (
                    "store/Cargo.toml",
                    "[package]\nname=\"records\"\nversion=\"0.1.0\"\nedition=\"2021\"",
                ),
                ("app/src/lib.rs", &app),
                (
                    "store/src/lib.rs",
                    "mod internal;pub use internal::Repository;",
                ),
                (
                    "store/src/internal.rs",
                    r#"pub struct Entry;pub struct Repository;impl Repository {pub fn load(&self)->Entry {sqlx::query("SELECT * FROM documents");Entry}}"#,
                ),
            ],
        );
        let report = repo.analyze();
        assert_eq!(
            report.peer_groups.len(),
            1,
            "{name}: {:?}",
            report.resource_evidence
        );
        assert_eq!(
            report.peer_groups[0].routes.len(),
            if scope { 2 } else { 3 }
        );
        assert_eq!(
            report.finding_details.len(),
            findings,
            "{name}: {:?}",
            report.finding_details
        );
        assert!(!report.invariants.is_empty(), "{name}");
        assert!(report.resource_evidence.iter().all(|e| {
            e.call_chain_evidence
                .iter()
                .any(|c| c.contains("internal::Repository::load"))
        }));
        if findings == 1 {
            assert_eq!(
                report.finding_details[0]
                    .suspicious_route
                    .handler
                    .as_deref(),
                Some("three")
            );
        }
    }
}

#[test]
fn awaited_permissions_preserve_peer_membership_and_drift_safety() {
    let mut peer_count = None;
    for (last, expected_findings) in [
        ("check_permission(\"edit\").await?;", 0),
        ("check_permission(\"read\").await?;", 1),
        ("", 1),
        // An ignored check remains unresolved; do not manufacture a missing-policy finding.
        ("check_permission(\"edit\").await;", 0),
        ("check_permission(required).await?;", 0),
    ] {
        let source = format!(
            r#"
async fn check_permission(p: &str) -> Result<(), Error> {{ if !allowed(p) {{ return Err(denied()); }} Ok(()) }}
async fn one() {{ check_permission("edit").await?; sqlx::query("SELECT * FROM records"); }}
async fn two() {{ check_permission("edit").await?; sqlx::query("SELECT * FROM records"); }}
async fn three() {{ {last} sqlx::query("SELECT * FROM records"); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records")
 .route("/one/{{id}}", web::get().to(one))
 .route("/two/{{id}}", web::get().to(two))
 .route("/three/{{id}}", web::get().to(three))); }}
"#
        );
        let report = TempRepo::new("async-permission-drift", &[("main.rs", &source)]).analyze();
        assert_eq!(
            *peer_count.get_or_insert(report.peer_groups.len()),
            report.peer_groups.len()
        );
        assert_eq!(report.peer_groups.len(), 1);
        assert_eq!(report.peer_groups[0].routes.len(), 3);
        assert_eq!(
            report.finding_details.len(),
            expected_findings,
            "{last}: {:?}",
            report.finding_details
        );
        if expected_findings > 0 {
            assert_eq!(
                report.finding_details[0]
                    .suspicious_route
                    .handler
                    .as_deref(),
                Some("three")
            );
        }
    }
}

#[test]
fn conflicting_overlapping_contracts_abstain_instead_of_choosing_first() {
    let report = analyze_bodies(
        "conflicting-contracts",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"Editor\")?;",
        ],
    );
    let mut assessments = report.security_assessments.clone();
    let target = assessments
        .iter()
        .find(|a| a.route.handler.as_deref() == Some("three"))
        .unwrap()
        .clone();
    let admin: Vec<_> = assessments
        .iter()
        .filter(|a| a.route.handler.as_deref() != Some("three"))
        .cloned()
        .collect();
    let mut other = admin.clone();
    for (i, a) in other.iter_mut().enumerate() {
        a.route.path = format!("/other/{i}");
        a.requirements
            .iter_mut()
            .find(|r| r.dimension == "roles")
            .unwrap()
            .values = vec!["User".into()];
    }
    let first = PeerGroup {
        id: "first".into(),
        description: "test".into(),
        routes: admin
            .iter()
            .map(|a| a.route.clone())
            .chain([target.route.clone()])
            .collect(),
    };
    let second = PeerGroup {
        id: "second".into(),
        description: "test".into(),
        routes: other
            .iter()
            .map(|a| a.route.clone())
            .chain([target.route.clone()])
            .collect(),
    };
    assessments.extend(other);
    let mut details = Vec::new();
    let mut findings = Vec::new();
    policy_drift::extend(&[first.clone()], &assessments, &mut details, &mut findings);
    assert_eq!(details.len(), 1);
    details.clear();
    findings.clear();
    policy_drift::extend(&[second, first], &assessments, &mut details, &mut findings);
    assert!(details.is_empty());
}

#[test]
fn database_operations_and_security_helpers_do_not_create_spurious_contracts() {
    let source = r#"
fn check_role() { sqlx::query("SELECT * FROM identities"); }
async fn read() { check_role(); sqlx::query("SELECT * FROM objects"); }
async fn write() { check_role(); sqlx::query("DELETE FROM objects"); }
async fn unrelated() { check_role(); sqlx::query("SELECT * FROM invoices"); }
fn app(cfg: &mut Config) { cfg.route("/read",web::get().to(read)).route("/write",web::get().to(write)).route("/invoice",web::get().to(unrelated)); }
"#;
    let report = TempRepo::new("resource-conflicts", &[("main.rs", source)]).analyze();
    assert_eq!(report.candidate_relationships.len(), 1);
    assert!(!report.candidate_relationships[0].contract_eligible);
    assert!(
        report.candidate_relationships[0]
            .conflicts
            .iter()
            .any(|c| c.contains("database operations"))
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn overlapping_families_do_not_merge_transitively_or_duplicate_findings() {
    let report = analyze_bodies(
        "overlap-base",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"User\")?;",
        ],
    );
    let group = report.peer_groups[0].clone();
    let mut details = Vec::new();
    let mut findings = Vec::new();
    policy_drift::extend(
        &[group.clone(), group],
        &report.security_assessments,
        &mut details,
        &mut findings,
    );
    assert_eq!(details.len(), 1);
    let edge = |a, b| policy_drift::Relationship {
        left: a,
        right: b,
        kind: "test".into(),
        evidence: vec![],
        conflicts: vec![],
        evidence_score: 0,
        confidence: "test".into(),
        contract_eligible: true,
    };
    let families = policy_drift::families(&report.routes, &[edge(0, 1), edge(1, 2)]);
    assert_eq!(families.len(), 2);
    assert!(families.iter().all(|g| g.routes.len() == 2));
}

#[test]
fn candidates_survive_removal_of_all_authorization() {
    let source = r#"
fn check_role(role: &str) -> Result<(), Error> { if !allowed(role) { return Err(denied()); } Ok(()) }
async fn item() { check_role("Admin")?; }
async fn collection() { check_role("Admin")?; }
fn app(c: &mut Config) { c.service(web::scope("/objects")
 .route("", web::get().to(collection)).route("/{id}", web::get().to(item))); }
"#;
    let baseline = TempRepo::new("candidate-before", &[("main.rs", source)]).analyze();
    let mutation = source.replace("check_role(\"Admin\")?;", "");
    let after = TempRepo::new("candidate-after", &[("main.rs", &mutation)]).analyze();
    assert_eq!(baseline.candidate_relationships.len(), 1);
    assert_eq!(after.candidate_relationships.len(), 1);
    assert_eq!(after.candidate_relationships[0].kind, "collection_item");
    assert!(!after.candidate_relationships[0].contract_eligible);
    assert!(after.finding_details.is_empty());
}

#[test]
fn generic_shared_utilities_do_not_establish_peer_membership() {
    let source = r#"
mod storage { pub fn load() {} pub fn list() {} }
async fn a() { storage::load(); }
async fn b() { storage::list(); }
fn app(c: &mut Config) { c.route("/single/{id}", web::get().to(a))
 .route("/catalog", web::get().to(b)); }
"#;
    let report = TempRepo::new("candidate-dependency", &[("main.rs", source)]).analyze();
    assert!(report.candidate_relationships.is_empty());
}

// Source-level mutations: each case changes exactly one handler, in every
// route position, and checks the exact target/category (not just a count).
#[test]
fn source_mutation_matrix() {
    let base = "check_role(\"Admin\")?; check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }";
    let cases = [
        (
            "wrong-role",
            "check_role(\"User\")?; check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "wrong-permission",
            "check_role(\"Admin\")?; check_permission(\"read\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "missing-role",
            "check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "missing-permission",
            "check_role(\"Admin\")?; if !is_owner(user, id) { return Err(denied()); }",
            Some(DriftCategory::InconsistentRoleOrPermission),
        ),
        (
            "missing-owner",
            "check_role(\"Admin\")?; check_permission(\"write\")?;",
            Some(DriftCategory::MissingOwnershipValidation),
        ),
        (
            "missing-all",
            "serve();",
            Some(DriftCategory::MissingOwnershipValidation),
        ),
        (
            "ignored",
            "check_role(\"Admin\"); check_permission(\"write\"); is_owner(user, id);",
            None,
        ),
        (
            "equivalent-predicate",
            "if !check_role(\"Admin\").is_ok() { return Err(denied()); } check_permission(\"write\")?; if !is_owner(user, id) { return Err(denied()); }",
            None,
        ),
        (
            "reordered",
            "if !is_owner(user, id) { return Err(denied()); } check_permission(\"write\")?; check_role(\"Admin\")?;",
            None,
        ),
        ("unchanged", base, None),
    ];
    for (name, mutation, expected) in cases {
        for position in 0..3 {
            let mut bodies = [base; 3];
            bodies[position] = mutation;
            let report = analyze_bodies(&format!("mutation-{name}-{position}"), bodies);
            assert!(report.parse_errors.is_empty());
            assert_eq!(report.routes.len(), 3);
            assert_eq!(report.peer_groups.len(), 1);
            assert_eq!(
                report.finding_details.len(),
                if name == "missing-all" {
                    3
                } else {
                    usize::from(expected.is_some())
                },
                "{name}, position {position}: {:?}",
                report.finding_details
            );
            if let Some(category) = &expected {
                let finding = &report.finding_details[0];
                if name != "missing-all" {
                    assert_eq!(&finding.category, category, "{name}");
                }
                assert_eq!(
                    finding.suspicious_route.handler.as_deref(),
                    Some(["one", "two", "three"][position])
                );
            }
            if name == "ignored" {
                assert_eq!(report.summary.unwrap().unknown_routes, 1);
            }
        }
    }
}

#[test]
fn mounted_allowlist_mutations() {
    for (name, baseline, mutated, count) in [
        ("broaden", "Role::Admin", "Role::Admin, Role::User", 1),
        ("replace", "Role::Admin", "Role::User", 1),
        ("narrow", "Role::Admin, Role::User", "Role::Admin", 0),
        (
            "reorder",
            "Role::Admin, Role::User",
            "Role::User, Role::Admin",
            0,
        ),
        ("duplicate", "Role::Admin", "Role::Admin, Role::Admin", 0),
    ] {
        for position in 0..3 {
            let mut policies = [baseline; 3];
            policies[position] = mutated;
            let source = format!(
                r#"
impl Service for AuthMiddleware {{
 fn call(&self, req: Request) {{ if self.allowed_roles.contains(&req.role) {{ self.service.call(req) }} else {{ Err(denied()) }} }}
}}
async fn one() {{ sqlx::query("SELECT * FROM records"); }} async fn two() {{ sqlx::query("SELECT * FROM records"); }} async fn three() {{ sqlx::query("SELECT * FROM records"); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records")
 .route("/one", web::get().to(one).wrap(RequireAuth::allowed_roles(vec![{}])))
 .route("/two", web::get().to(two).wrap(RequireAuth::allowed_roles(vec![{}])))
 .route("/three", web::get().to(three).wrap(RequireAuth::allowed_roles(vec![{}])))); }}
"#,
                policies[0], policies[1], policies[2]
            );
            let report = TempRepo::new(
                &format!("allowlist-{name}-{position}"),
                &[("main.rs", &source)],
            )
            .analyze();
            assert_eq!(report.summary.as_ref().unwrap().protected_routes, 3);
            assert_eq!(
                report.finding_details.len(),
                count,
                "{name}: {:?}",
                report.finding_details
            );
            if count == 1 {
                assert_eq!(
                    report.finding_details[0]
                        .suspicious_route
                        .handler
                        .as_deref(),
                    Some(["one", "two", "three"][position])
                );
            }
        }
    }
}

#[test]
fn multiple_omissions_produce_distinct_requirement_findings() {
    let report = analyze_bodies(
        "mutation-two-omissions",
        [
            "check_role(\"Admin\")?; check_permission(\"write\")?; if !is_owner(user,id) { return Err(denied()); }",
            "check_role(\"Admin\")?; check_permission(\"write\")?; if !is_owner(user,id) { return Err(denied()); }",
            "check_role(\"Admin\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 2);
    assert!(
        report
            .finding_details
            .iter()
            .any(|f| f.category == DriftCategory::MissingOwnershipValidation)
    );
    assert!(
        report
            .finding_details
            .iter()
            .any(|f| f.category == DriftCategory::InconsistentRoleOrPermission)
    );
    assert!(
        report
            .finding_details
            .iter()
            .all(|f| f.suspicious_route.handler.as_deref() == Some("three"))
    );
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["summary"]["drift_findings_count"], 2);
    assert_eq!(json["finding_details"].as_array().unwrap().len(), 2);
}

#[test]
fn unsupported_values_and_insufficient_support_abstain() {
    let cases = [
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(required_role)?;",
        ],
        ["check_role(\"Admin\")?;", "serve();", "serve();"],
        ["serve();", "serve();", "serve();"],
        [
            "check_role(\"Admin\")?;",
            "check_role(required_role)?;",
            "check_role(\"User\")?;",
        ],
    ];
    for (i, bodies) in cases.into_iter().enumerate() {
        let report = analyze_bodies(&format!("mutation-abstain-{i}"), bodies);
        assert!(report.finding_details.is_empty(), "case {i}");
    }
}

#[test]
fn unknown_members_count_against_policy_consensus() {
    let source = r#"
fn check_role(role: &str) -> Result<(), Error> { if !allowed(role) { return Err(denied()); } Ok(()) }
async fn a() { sqlx::query("SELECT * FROM records"); check_role("Admin")?; }
async fn b() { sqlx::query("SELECT * FROM records"); check_role("Admin")?; }
async fn c() { sqlx::query("SELECT * FROM records"); check_role("User")?; }
async fn d() { sqlx::query("SELECT * FROM records"); check_role(dynamic_role)?; }
async fn e() { sqlx::query("SELECT * FROM records"); check_role(dynamic_role)?; }
fn app(cfg: &mut Config) { cfg.service(web::scope("/records")
 .route("/a", web::get().to(a)).route("/b", web::get().to(b))
 .route("/c", web::get().to(c)).route("/d", web::get().to(d))
 .route("/e", web::get().to(e))); }
"#;
    let report = TempRepo::new("mutation-unknown-consensus", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(
        report.peer_groups[0].routes.len(),
        5,
        "{:?} {:?}",
        report.routes,
        report.candidate_relationships
    );
    assert!(report.finding_details.is_empty());
}

fn analyze_bodies(name: &str, bodies: [&str; 3]) -> Report {
    let source = format!(
        r#"
fn check_role(role: &str) -> Result<(), Error> {{ if !allowed(role) {{ return Err(denied()); }} Ok(()) }}
fn check_permission(p: &str) -> Result<(), Error> {{ if !allowed(p) {{ return Err(denied()); }} Ok(()) }}
fn is_owner(user: User, id: Id) -> bool {{ user.id == id }}
async fn one() {{ {} sqlx::query("SELECT * FROM records"); }}
async fn two() {{ {} sqlx::query("SELECT * FROM records"); }}
async fn three() {{ {} sqlx::query("SELECT * FROM records"); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records")
 .route("/one/{{id}}", web::get().to(one))
 .route("/two/{{id}}", web::get().to(two))
 .route("/three/{{id}}", web::get().to(three))); }}
"#,
        bodies[0], bodies[1], bodies[2]
    );
    TempRepo::new(name, &[("main.rs", &source)]).analyze()
}

#[test]
fn protected_wrong_role_is_reported_with_requirement_evidence() {
    let report = analyze_bodies(
        "p3-role",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"User\")?;",
        ],
    );
    assert_eq!(report.summary.as_ref().unwrap().protected_routes, 3);
    assert_eq!(report.finding_details.len(), 1);
    let finding = &report.finding_details[0];
    assert_eq!(
        finding.category,
        DriftCategory::InconsistentRoleOrPermission
    );
    assert_eq!(finding.suspicious_route.handler.as_deref(), Some("three"));
    assert_eq!(finding.authorized_peer_routes.len(), 2);
    assert!(finding.explanation.contains("Admin"));
    assert!(finding.explanation.contains("User"));
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.summary.as_ref().unwrap().drift_findings_count, 1);
    assert_eq!(report.summary.as_ref().unwrap().peer_compared_routes, 1);
    assert!(
        report
            .graph
            .unwrap()
            .nodes
            .iter()
            .any(|n| n.kind == NodeKind::Finding)
    );
}

#[test]
fn permission_drift_is_checked_independently_of_role_protection() {
    let report = analyze_bodies(
        "p3-permission",
        [
            "check_permission(\"record.write\")?;",
            "check_permission(\"record.write\")?;",
            "check_role(\"Admin\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert_eq!(
        report.finding_details[0].category,
        DriftCategory::InconsistentRoleOrPermission
    );
    assert!(
        report.finding_details[0]
            .explanation
            .contains("permissions")
    );
}

#[test]
fn protected_route_can_lack_peer_ownership_requirement() {
    let report = analyze_bodies(
        "p3-ownership",
        [
            "check_role(\"User\")?; if !is_owner(user, id) { return Err(denied()); }",
            "check_role(\"User\")?; if !is_owner(other, key) { return Err(denied()); }",
            "check_role(\"User\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert_eq!(
        report.finding_details[0].category,
        DriftCategory::MissingOwnershipValidation
    );
}

#[test]
fn matching_policies_do_not_create_drift() {
    let report = analyze_bodies(
        "p3-match",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn different_permission_value_is_reported() {
    let report = analyze_bodies(
        "p3-wrong-permission",
        [
            "check_permission(\"record.write\")?;",
            "check_permission(\"record.write\")?;",
            "check_permission(\"record.read\")?;",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert!(
        report.finding_details[0]
            .explanation
            .contains("record.read")
    );
}

#[test]
fn narrower_role_allowlist_does_not_weaken_peer_policy() {
    let mut report = analyze_bodies(
        "p3-narrower",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
        ],
    );
    for assessment in &mut report.security_assessments {
        if assessment.route.handler.as_deref() != Some("three") {
            assessment
                .requirements
                .iter_mut()
                .find(|r| r.dimension == "roles")
                .unwrap()
                .values
                .push("Editor".into());
        }
    }
    let mut details = Vec::new();
    let mut findings = Vec::new();
    policy_drift::extend(
        &report.peer_groups,
        &report.security_assessments,
        &mut details,
        &mut findings,
    );
    assert!(details.is_empty());
}

#[test]
fn multiple_role_checks_are_not_flattened_into_an_allowlist() {
    let report = analyze_bodies(
        "p3-multiple",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"User\")?; check_role(\"Editor\")?;",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn operation_policy_difference_outside_peer_family_is_not_flagged() {
    let source = r#"
fn check_role(role: &str) -> Result<(), Error> { if !allowed(role) { return Err(denied()); } Ok(()) }
async fn one() { check_role("Admin")?; }
async fn two() { check_role("Admin")?; }
async fn self_profile() { check_role("User")?; }
fn app(c: &mut Config) { c.service(web::scope("/users")
 .route("/one", web::get().to(one)).route("/two", web::get().to(two)))
 .service(web::scope("/self").route("/profile", web::get().to(self_profile))); }
"#;
    let report = TempRepo::new("p3-exception", &[("main.rs", source)]).analyze();
    assert!(report.finding_details.is_empty());
    let summary = report.summary.unwrap();
    assert_eq!(summary.peer_compared_routes, 0);
    assert_eq!(summary.routes_without_peer_comparison, 3);
}

#[test]
fn mixed_policies_without_two_supporters_do_not_invent_a_contract() {
    let report = analyze_bodies(
        "p3-mixed",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Editor\")?;",
            "check_role(\"User\")?;",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn ignored_check_is_uncertain_rather_than_missing_policy() {
    let report = analyze_bodies(
        "p3-ignored",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_permission(\"record.read\")?; check_role(\"Admin\");",
        ],
    );
    assert!(report.finding_details.is_empty());
}

#[test]
fn missing_all_enforcement_still_uses_existing_finding_without_duplicates() {
    let report = analyze_bodies(
        "p3-missing",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "serve();",
        ],
    );
    assert_eq!(report.finding_details.len(), 1);
    assert_eq!(
        report.finding_details[0].category,
        DriftCategory::InconsistentRoleOrPermission
    );
}

#[test]
fn cross_operation_resources_keep_membership_under_policy_mutation() {
    for resource in ["invoices", "projects", "messages"] {
        for mutation in [
            "check_role(\"Admin\")?;",
            "check_role(\"Visitor\")?;",
            "serve();",
        ] {
            let source = format!(
                r#"
fn check_role(role: &str) -> Result<(), Error> {{ if !allowed(role) {{ return Err(denied()); }} Ok(()) }}
async fn read() {{ check_role("Admin")?; }}
async fn update() {{ check_role("Admin")?; }}
async fn delete() {{ {mutation} }}
fn app(cfg: &mut Config) {{ cfg.route("/{resource}/{{id}}",web::get().to(read))
.route("/{resource}/{{id}}",web::put().to(update))
.route("/{resource}/{{id}}",web::delete().to(delete)); }}
"#
            );
            let report = TempRepo::new("cross-operation", &[("main.rs", &source)]).analyze();
            assert_eq!(report.peer_groups.len(), 1);
            assert_eq!(report.peer_groups[0].routes.len(), 3);
            assert!(!report.invariants.is_empty());
            assert_eq!(
                report.finding_details.len(),
                usize::from(mutation != "check_role(\"Admin\")?;")
            );
        }
    }
}

#[test]
fn two_peers_establish_an_invariant_without_inventing_a_drift() {
    let source = r#"
fn check_permission(value: &str) -> Result<(), Error> { if !allowed(value) { return Err(denied()); } Ok(()) }
async fn archive() { check_permission("manage")?; }
async fn restore() { check_permission("manage")?; }
fn app(cfg: &mut Config) { cfg.route("/records/{id}/archive",web::post().to(archive))
.route("/records/{id}/restore",web::patch().to(restore)); }
"#;
    let report = TempRepo::new("two-member-invariant", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(report.invariants.len(), 1);
    assert!(report.finding_details.is_empty());
}

#[test]
fn unrelated_siblings_do_not_inherit_policy_from_mount_alone() {
    let source = r#"
async fn one() { check_role("Admin")?; }
async fn two() { check_role("Admin")?; }
async fn three() { serve(); }
fn app(cfg: &mut Config) { cfg.route("/api/invoices",web::get().to(one))
.route("/api/messages",web::get().to(two)).route("/api/weather",web::get().to(three)); }
"#;
    let report = TempRepo::new("unrelated-siblings", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
    assert!(report.invariants.is_empty());
    assert!(report.finding_details.is_empty());
}

#[test]
fn resolved_data_models_support_collection_item_and_self_without_named_paths() {
    for endpoint in ["current", "owned", "selected"] {
        for missing_auth in [false, true] {
            let auth = if missing_auth {
                ""
            } else {
                "require_auth(\"session\")?;"
            };
            let source = format!(
                r#"
struct Record {{ id: u64 }}
struct View {{ id: u64 }}
impl View {{
 pub fn one(record: &Record) -> Self {{ View {{ id: record.id }} }}
 pub fn many(records: &[Record]) -> Vec<View> {{ records.iter().map(View::one).collect() }}
}}
fn require_auth(kind: &str) -> Result<(), Error> {{ if allowed(kind) {{ Ok(()) }} else {{ Err(denied()) }} }}
fn check_role(role: &str) -> Result<(), Error> {{ if allowed(role) {{ Ok(()) }} else {{ Err(denied()) }} }}
async fn collection() {{ require_auth("session")?; check_role("Admin")?; HttpResponse::Ok().json(View::many(&records)); }}
async fn item() {{ require_auth("session")?; check_role("Member")?; HttpResponse::Ok().json(View::one(&record)); }}
async fn selected() {{ {auth} check_role("Member")?; HttpResponse::Ok().json(View::one(&record)); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records")
 .route("",web::get().to(collection)).route("/{{id}}",web::get().to(item)).route("/{endpoint}",web::get().to(selected))); }}
"#
            );
            let report =
                TempRepo::new("resource-selector-controls", &[("main.rs", &source)]).analyze();
            assert_eq!(report.peer_groups.len(), 1, "{endpoint}");
            assert_eq!(report.peer_groups[0].routes.len(), 3);
            assert!(
                report
                    .invariants
                    .iter()
                    .any(|i| i.description.starts_with("Supported authentication"))
            );
            assert!(
                !report
                    .invariants
                    .iter()
                    .any(|i| i.description.starts_with("Supported roles"))
            );
            assert_eq!(report.finding_details.len(), usize::from(missing_auth));
            if missing_auth {
                assert_eq!(
                    report.finding_details[0]
                        .suspicious_route
                        .handler
                        .as_deref(),
                    Some("selected")
                );
            }
            assert!(
                report
                    .analysis_evidence
                    .iter()
                    .any(|e| e.stage == "invariant"
                        && e.dimension.as_deref() == Some("roles")
                        && !e.abstention_reasons.is_empty())
            );
        }
    }
}

#[test]
fn shared_unit_returning_utilities_are_not_data_models() {
    let source = r#"
struct Context { id: u64 }
struct Logger;
impl Logger { pub fn event(ctx: &Context) { log(ctx.id); } }
async fn one() { Logger::event(&ctx); }
async fn two() { Logger::event(&ctx); }
fn app(c: &mut Config) { c.route("/inventory", web::get().to(one)).route("/forecast", web::get().to(two)); }
"#;
    let report = TempRepo::new("typed-utility-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
    assert!(report.finding_details.is_empty());
}

#[test]
fn concrete_cross_crate_methods_trait_defaults_and_alias_returns_share_resources() {
    for resource in ["invoices", "tickets", "assets"] {
        let storage = format!(
            r#"
pub mod schema {{ pub mod {resource} {{}} }}
pub mod models {{
 use crate::schema::{resource};
 #[diesel(table_name = {resource})] pub struct Entry {{ pub id: u64 }}
}}
pub type StoreResult<T> = Result<T, Error>;
pub mod repository {{
 use crate::models::Entry;
 use crate::schema::{resource};
 pub trait ReadStore {{ fn load(&self) -> Entry {{ {resource}::table.first(conn); Entry {{ id: 1 }} }} }}
 impl ReadStore for Entry {{}}
 impl Entry {{ pub fn fetch() -> Self {{ {resource}::table.first(conn); Entry {{ id: 1 }} }} }}
 pub struct Query;
 impl Query {{ pub fn list(&self) -> Vec<Entry> {{ {resource}::table.load(conn); vec![] }} }}
}}
"#
        );
        let app = format!(
            r#"
use storage::{{models::Entry, repository::{{Query, ReadStore}}, StoreResult}};
fn service() -> StoreResult<Entry> {{ Ok(Entry::fetch()) }}
async fn collection() {{ let rows = Query {{}}.list(); respond(rows); }}
async fn item(repo: Entry) {{ let row = repo.load(); respond(row); }}
async fn selected() {{ let row = service()?; respond(row); }}
fn app(c: &mut Config) {{ c.route("/{resource}", web::get().to(collection))
.service(web::scope("/{resource}").route("/{{id}}", web::get().to(item)).route("/selected", web::get().to(selected))); }}
"#
        );
        let report = TempRepo::new("typed-resource-workspace", &[
            ("Cargo.toml", "[workspace]\nmembers=[\"app\",\"storage\"]\nresolver=\"2\""),
            ("app/Cargo.toml", "[package]\nname=\"app\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[dependencies]\nstorage={path=\"../storage\"}"),
            ("storage/Cargo.toml", "[package]\nname=\"storage\"\nversion=\"0.1.0\"\nedition=\"2021\""),
            ("app/src/lib.rs", &app), ("storage/src/lib.rs", &storage),
        ]).analyze();
        assert_eq!(
            report.peer_groups.len(),
            1,
            "{resource}: {:?}",
            report.peer_groups
        );
        assert_eq!(report.peer_groups[0].routes.len(), 3);
        assert!(report.finding_details.is_empty());
        assert!(report.resource_evidence.iter().any(|r| {
            r.call_chain_evidence
                .iter()
                .any(|call| call.contains("::Query::list"))
        }));
        assert!(report.resource_evidence.iter().any(|r| {
            r.call_chain_evidence
                .iter()
                .any(|call| call.contains("::Entry::load"))
        }));
    }
}

#[test]
fn competing_traits_unknown_receivers_and_shadowing_never_guess_a_method() {
    for body in [
        "let value = receiver.load();",
        "let receiver = opaque(); let value = receiver.load();",
        "{ let receiver = opaque(); let value = receiver.load(); }",
    ] {
        let source = format!(
            r#"
mod schema {{ pub mod invoices {{}} pub mod weather {{}} }}
struct Row;
trait A {{ fn load(&self) -> Row {{ schema::invoices::table.first(conn); Row }} }}
trait B {{ fn load(&self) -> Row {{ schema::weather::table.first(conn); Row }} }}
impl A for Row {{}} impl B for Row {{}}
async fn one(receiver: Row) {{ {body} }}
async fn two() {{ let row = schema::invoices::table.first(conn); }}
fn app(c: &mut Config) {{ c.route("/a",web::get().to(one)).route("/b",web::get().to(two)); }}
"#
        );
        let report =
            TempRepo::new("ambiguous-receiver-negative", &[("main.rs", &source)]).analyze();
        assert!(report.peer_groups.is_empty(), "{body}");
    }
}

#[test]
fn generic_auxiliary_helpers_do_not_independently_make_peers() {
    let source = r#"
struct Settings;
impl Settings { pub fn read() -> Self { sqlx::query("SELECT * FROM settings"); Self } }
fn log_request() { sqlx::query("INSERT INTO audit_log VALUES (1)"); }
struct Audit;
impl Audit { pub fn record(&self) -> Result<(), Error> { sqlx::query("INSERT INTO audit_log VALUES (1)"); Ok(()) } }
async fn one() { Settings::read(); let _ = Settings::read(); log_request(); Audit {}.record(); respond(); }
async fn two() { Settings::read(); let _ = Settings::read(); log_request(); Audit {}.record(); respond(); }
fn app(c: &mut Config) { c.route("/inventory",web::get().to(one)).route("/forecast",web::get().to(two)); }
"#;
    let report = TempRepo::new("auxiliary-data-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
}

#[test]
fn resource_overlap_is_not_transitive_and_method_names_do_not_identify_resources() {
    let source = r#"
struct Invoices; struct Weather;
impl Invoices { pub fn load() -> Self { sqlx::query("SELECT * FROM invoices"); Self } }
impl Weather { pub fn load() -> Self { sqlx::query("SELECT * FROM weather"); Self } }
async fn one() { let row = Invoices::load(); respond(row); }
async fn bridge() { let a = Invoices::load(); let b = Weather::load(); respond((a,b)); }
async fn three() { let row = Weather::load(); respond(row); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/bridge",web::get().to(bridge)).route("/three",web::get().to(three)); }
"#;
    let report = TempRepo::new("typed-overlap-not-transitive", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 2);
    assert!(report.peer_groups.iter().all(|g| g.routes.len() == 2));
    assert!(!report.peer_groups.iter().any(|g| {
        g.routes.iter().any(|r| r.handler.as_deref() == Some("one"))
            && g.routes
                .iter()
                .any(|r| r.handler.as_deref() == Some("three"))
    }));
}

#[test]
fn nested_resource_mount_membership_does_not_transfer_public_creation_policy() {
    let source = r#"
mod schema { pub mod invoices {} }
use crate::schema::invoices;
#[diesel(table_name = invoices)] struct Entry;
impl Entry { pub fn fetch() -> Self { invoices::table.first(conn); Self } }
fn check_role(role: &str) -> Result<(), Error> { if allowed(role) { Ok(()) } else { Err(denied()) } }
async fn public() { let row = Entry::fetch(); respond(row); }
async fn one() { check_role("Admin")?; let row = Entry::fetch(); respond(row); }
async fn two() { check_role("Admin")?; let row = Entry::fetch(); respond(row); }
async fn three() { check_role("Admin")?; let row = Entry::fetch(); respond(row); }
fn app(c: &mut Config) { c.service(web::scope("/api")
 .route("/invoices",web::post().to(public))
 .service(web::scope("/invoices")
  .route("/{id}/one",web::get().to(one)).route("/{id}/two",web::get().to(two)).route("/{id}/three",web::get().to(three)))); }
"#;
    let report = TempRepo::new("nested-resource-policy-contexts", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.iter().any(|g| g.routes.len() == 4));
    assert!(report.finding_details.is_empty());
    assert!(
        report
            .analysis_evidence
            .iter()
            .filter(|e| e.stage == "drift"
                && e.route
                    .as_ref()
                    .is_some_and(|r| r.handler.as_deref() == Some("public")))
            .all(|e| !e.abstention_reasons.is_empty())
    );
}

#[test]
fn shadowed_pattern_and_shared_cache_reads_cannot_create_resource_peers() {
    for branch in [
        "if let Some(receiver) = opaque() { let row = receiver.load(); }",
        "match opaque() { Some(receiver) => { let row = receiver.load(); }, _ => {} }",
        "while let Some(receiver) = opaque() { let row = receiver.load(); }",
    ] {
        let source = format!(
            r#"
struct Invoices;
impl Invoices {{ pub fn load(&self) -> Self {{ sqlx::query("SELECT * FROM invoices"); Self }} }}
async fn one(receiver: Invoices) {{ {branch} }}
async fn two() {{ let row = sqlx::query("SELECT * FROM invoices"); respond(row); }}
fn app(c: &mut Config) {{ c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }}
"#
        );
        let report =
            TempRepo::new("pattern-shadow-resource-negative", &[("main.rs", &source)]).analyze();
        assert!(report.peer_groups.is_empty());
    }
}

#[test]
fn consumed_opaque_record_wrappers_and_private_query_factories_keep_resource_evidence() {
    let source = r#"
mod schema { pub mod invoices {} }
struct View;
impl View {
 fn query() -> OpaqueQuery { schema::invoices::table.select(columns) }
 pub fn read() -> Self { let row = Self::query().first(conn); Self }
}
fn service() -> ExternalResult<View> { Ok(View::read()) }
async fn one() { let result = service(); respond(result); }
async fn two() { let result = View::read(); respond(result); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }
"#;
    let report = TempRepo::new("private-query-factory", &[("main.rs", source)]).analyze();
    assert_eq!(report.peer_groups.len(), 1);
    assert_eq!(report.peer_groups[0].routes.len(), 2);
}

#[test]
fn containers_are_not_their_payload_receivers() {
    for parameter in ["Option<Row>", "Vec<Row>", "Result<Row, Error>"] {
        let source = format!(
            r#"
struct Row;
impl Row {{ pub fn load(&self) -> Self {{ sqlx::query("SELECT * FROM records"); Self }} }}
async fn one(receiver: {parameter}) {{ let value = receiver.load(); respond(value); }}
async fn two() {{ let value = sqlx::query("SELECT * FROM records"); respond(value); }}
fn app(c: &mut Config) {{ c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }}
"#
        );
        let report = TempRepo::new("container-payload-negative", &[("main.rs", &source)]).analyze();
        assert!(report.peer_groups.is_empty(), "{parameter}");
    }
}

#[test]
fn global_unique_name_fallback_does_not_supply_resource_proof() {
    let source = r#"
struct Row;
mod not_imported { pub fn fetch() -> super::Row { sqlx::query("SELECT * FROM records"); super::Row } }
async fn one() { let row = fetch(); respond(row); }
async fn two() { let row = sqlx::query("SELECT * FROM records"); respond(row); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }
"#;
    let report = TempRepo::new("unique-name-resource-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
}

#[test]
fn same_line_trait_implementations_have_distinct_resource_cache_entries() {
    let source = r#"
struct Row; trait A { fn load(&self) -> Row { sqlx::query("SELECT * FROM alpha"); Row } } trait B { fn load(&self) -> Row { sqlx::query("SELECT * FROM beta"); Row } } impl A for Row {} impl B for Row {}
mod one { use crate::{Row,A}; pub fn read(row: Row) -> Row { row.load() } }
mod two { use crate::{Row,B}; pub fn read(row: Row) -> Row { row.load() } }
async fn handler() { let a = one::read(Row); let b = two::read(Row); respond((a,b)); }
fn app(c: &mut Config) { c.route("/records",web::get().to(handler)); }
"#;
    let report = TempRepo::new("distinct-trait-resource-cache", &[("main.rs", source)]).analyze();
    assert!(
        report.resource_evidence[0]
            .resources
            .iter()
            .any(|r| r == "sql:alpha")
    );
    assert!(
        report.resource_evidence[0]
            .resources
            .iter()
            .any(|r| r == "sql:beta")
    );
}

#[test]
fn receiver_autoref_conflicts_abstain_instead_of_preferring_an_inherent_guess() {
    let source = r#"
struct Row;
impl Row { pub fn load(&mut self) -> Self { sqlx::query("SELECT * FROM invoices"); Self } }
trait Alternate { fn load(&self) -> Row { sqlx::query("SELECT * FROM weather"); Row } }
impl Alternate for Row {}
async fn one(receiver: Row) { let row = receiver.load(); respond(row); }
async fn two() { let row = sqlx::query("SELECT * FROM invoices"); respond(row); }
fn app(c: &mut Config) { c.route("/one",web::get().to(one)).route("/two",web::get().to(two)); }
"#;
    let report = TempRepo::new("receiver-autoref-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
    assert!(
        report
            .resource_evidence
            .iter()
            .find(|r| r.route.handler.as_deref() == Some("one"))
            .unwrap()
            .abstention_reasons
            .iter()
            .any(|r| r.contains("No unique applicable implementation"))
    );
}

#[test]
fn root_routes_without_shared_resources_never_form_peer_groups() {
    let source = r#"
async fn landing() { respond("welcome to landing page"); }
async fn upload() { respond("file uploaded"); }
async fn check() { respond("ok"); }
fn app(c: &mut Config) {
    c.route("/", web::get().to(landing))
     .route("/", web::post().to(upload))
     .route("/", web::head().to(check));
}
"#;
    let report = TempRepo::new("root-routes-unrelated", &[("main.rs", source)]).analyze();
    assert_eq!(report.routes.len(), 3);
    assert!(
        report.peer_groups.is_empty(),
        "Unrelated root routes with no shared resources must not form peer groups: {:?}",
        report.peer_groups
    );
}

#[test]
fn root_routes_with_shared_database_resource_form_corroborated_peer_group() {
    let source = r#"
async fn list_root() { let _ = sqlx::query("SELECT * FROM items"); }
async fn create_root() { let _ = sqlx::query("INSERT INTO items VALUES (1)"); }
fn app(c: &mut Config) {
    c.route("/", web::get().to(list_root))
     .route("/", web::post().to(create_root));
}
"#;
    let report = TempRepo::new("root-routes-related", &[("main.rs", source)]).analyze();
    assert_eq!(report.routes.len(), 2);
    assert_eq!(
        report.peer_groups.len(),
        1,
        "Genuinely related root routes sharing a database table must form a peer group"
    );
    assert_eq!(report.peer_groups[0].routes.len(), 2);
    assert!(report.peer_groups[0]
        .routes
        .iter()
        .any(|r| r.handler.as_deref() == Some("list_root")));
    assert!(report.peer_groups[0]
        .routes
        .iter()
        .any(|r| r.handler.as_deref() == Some("create_root")));
}

#[test]
fn multi_method_attribute_routes_register_each_operation() {
    let source = r#"
#[route("/files/{id}", method = "GET", method = "HEAD")]
async fn serve_file() { respond("data"); }

#[get("/items")]
#[head("/items")]
async fn get_and_head_items() { respond("items"); }

#[get("/wrapped", wrap = "Logger::default()")]
async fn wrapped_handler() { respond("wrapped"); }

fn app(c: &mut Config) {
    c.service(serve_file)
     .service(get_and_head_items)
     .service(wrapped_handler);
}
"#;
    let report = TempRepo::new("multi-method-attrs", &[("main.rs", source)]).analyze();
    assert!(report
        .routes
        .iter()
        .any(|r| r.method == "GET" && r.path == "/files/{id}"));
    assert!(report
        .routes
        .iter()
        .any(|r| r.method == "HEAD" && r.path == "/files/{id}"));
    assert!(report
        .routes
        .iter()
        .any(|r| r.method == "GET" && r.path == "/items"));
    assert!(report
        .routes
        .iter()
        .any(|r| r.method == "HEAD" && r.path == "/items"));
    assert!(report
        .routes
        .iter()
        .any(|r| r.method == "GET" && r.path == "/wrapped"));
}

#[test]
fn unresolved_middleware_produces_dimension_aware_diagnostic_uncertainty() {
    let source = r#"
async fn one() { check_role("Admin")?; sqlx::query("SELECT * FROM docs"); }
async fn two() { check_role("Admin")?; sqlx::query("SELECT * FROM docs"); }
async fn three() { sqlx::query("SELECT * FROM docs"); }
fn app(c: &mut Config) {
    c.service(
        web::scope("/docs")
            .wrap(SessionMiddleware::builder())
            .route("/one", web::get().to(one))
            .route("/two", web::get().to(two))
            .route("/three", web::get().to(three))
    );
}
"#;
    let report = TempRepo::new("unresolved-middleware-diag", &[("main.rs", source)]).analyze();
    let three_evidence: Vec<_> = report
        .analysis_evidence
        .iter()
        .filter(|e| {
            e.route.as_ref().and_then(|r| r.handler.as_deref()) == Some("three")
                && e.stage == "drift"
        })
        .collect();
    assert!(!three_evidence.is_empty());
    assert!(
        three_evidence.iter().any(|e| {
            e.dimension.as_deref() == Some("authentication")
                && e.abstention_reasons
                    .iter()
                    .any(|r| r.contains("names do not prove behavior"))
        }),
        "Expected authentication-specific middleware diagnostic, found: {:?}",
        three_evidence
    );
    assert_eq!(report.finding_details.len(), 0);
}

#[test]
fn trait_parameters_need_values_even_with_one_visible_implementation() {
    for ty in ["&dyn Store", "Box<dyn Store>", "std::sync::Arc<dyn Store>"] {
        let source = format!(
            r#"
trait Store {{fn load(&self)->Row;}}
struct Row; struct Disk;
impl Store for Disk {{fn load(&self)->Row {{sqlx::query("SELECT * FROM records"); Row}}}}
async fn one(repo:{ty}) {{let row=repo.load(); response(row);}}
async fn two(repo:{ty}) {{let row=repo.load(); response(row);}}
fn app(c:&mut Config) {{c.route("/alpha",web::get().to(one)).route("/beta",web::get().to(two));}}
"#
        );
        let report = TempRepo::new("unproven-single-trait", &[("main.rs", &source)]).analyze();
        assert!(
            report.peer_groups.is_empty(),
            "{ty}: {:?}",
            report.resource_evidence
        );
        assert!(
            report
                .resource_evidence
                .iter()
                .all(|e| !e.resources.iter().any(|r| r.contains("records"))),
            "{ty}"
        );
    }
}

#[test]
fn attribute_methods_and_arguments_are_not_guessed() {
    for text in [
        "#[route(\"/x\")]",
        "#[route(\"/x\", method=method())]",
        "#[route(\"/x\", method=\"get\")]",
        "#[route(\"/x\", method=\"BAD METHOD\")]",
        "#[get(path())]",
        "#[get(\"/x\", method=\"POST\")]",
        "#[get(\"/x\", unknown=\"setting\")]",
        "#[get(\"/x\", wrap=unchecked())]",
        "#[foreign::get(\"/x\")]",
        "#[actix_web::foreign::get(\"/x\")]",
    ] {
        let syntax: syn::ItemFn =
            syn::parse_str(&format!("{text} async fn handler() {{}} ")).unwrap();
        assert!(parse_attribute_route(&syntax.attrs[0]).is_none(), "{text}");
    }
    let source = r#"
#[route("/invalid")] async fn invalid() {}
#[actix_web::route("/valid",method="GET",method="HEAD",method="GET")]
async fn valid() {}
fn app(c:&mut Config) {c.service(invalid).service(valid);}
"#;
    let report = TempRepo::new("invalid-attribute-evidence", &[("main.rs", source)]).analyze();
    assert!(!report.routes.iter().any(|r| r.path == "/invalid"));
    assert!(report
        .diagnostics
        .iter()
        .any(|d| d.code == "unsupported_attribute"));
    for method in ["GET", "HEAD"] {
        assert_eq!(
            report
                .routes
                .iter()
                .filter(|r| r.path == "/valid" && r.method == method)
                .count(),
            1
        );
    }
}

#[test]
fn attribute_wrappers_and_guards_preserve_uncertainty_at_mounts() {
    for key in ["wrap", "guard"] {
        let source = format!(
            r#"
#[get("/x",{key}="SomeAdapter::new()")]
async fn handler() {{}}
fn app(c:&mut Config) {{c.service(web::scope("/api").service(handler));}}
"#
        );
        let report =
            TempRepo::new("attribute-config-uncertainty", &[("main.rs", &source)]).analyze();
        let route = report.routes.iter().find(|r| r.path == "/api/x").unwrap();
        assert!(route
            .authorization
            .iter()
            .any(|e| e.kind == AuthEvidenceKind::Unknown
                && e.mechanism == "UnresolvedAttributeConfiguration"));
        assert!(matches!(
            route.security_status(),
            RouteSecurityStatus::Unknown { .. }
        ));
        assert!(report.finding_details.is_empty());
    }
}

#[test]
fn root_routes_shared_auxiliary_access_does_not_prove_resource_identity() {
    let source = r#"
struct Settings;
impl Settings {pub fn read()->Self {sqlx::query("SELECT * FROM settings");Self}}
async fn one() {Settings::read(); response("landing");}
async fn two() {Settings::read(); response("upload");}
fn app(c:&mut Config) {c.route("/",web::get().to(one)).route("/",web::post().to(two));}
"#;
    let report = TempRepo::new("root-auxiliary-negative", &[("main.rs", source)]).analyze();
    assert!(report.peer_groups.is_empty());
}

#[test]
fn explicit_foreign_or_conflicting_attribute_imports_do_not_create_routes() {
    for imports in [
        "use other_framework::get;",
        "use actix_web::get; use other_framework::get;",
        "use other_framework::post as get;",
    ] {
        let source = format!(
            r#"{imports}
#[get("/decoy")] async fn handler() {{}}
fn app(c:&mut Config) {{c.service(handler);}}
"#
        );
        let report = TempRepo::new("foreign-attribute-import", &[("main.rs", &source)]).analyze();
        assert!(report.routes.is_empty(), "{imports}");
        assert!(report
            .diagnostics
            .iter()
            .any(|d| d.code == "unsupported_attribute"));
    }
}

#[test]
fn typed_uncertainty_preserves_independently_satisfied_comparisons() {
    let checks = [
        ("authentication", "require_auth(\"session\")?;"),
        ("roles", "check_role(\"Admin\")?;"),
        ("permissions", "check_permission(\"manage\")?;"),
        (
            "ownership",
            "if !is_owner(user, id) { return Err(denied()); }",
        ),
    ];
    // Source fixtures, including unresolved helpers which are converted to
    // Unknown evidence by assessment, exercise the complete reporting pipeline.
    for (dimension, check) in checks {
        let unknown = if dimension == "roles" {
            "check_permission_unknown();"
        } else {
            "check_role_unknown();"
        };
        let target = format!("{check} {unknown}");
        let mut source = format!(
            r#"
fn require_auth(kind: &str) -> Result<(), Error> {{ if allowed(kind) {{ Ok(()) }} else {{ Err(denied()) }} }}
fn check_role(role: &str) -> Result<(), Error> {{ if !allowed(role) {{ return Err(denied()); }} Ok(()) }}
fn check_permission(p: &str) -> Result<(), Error> {{ if !allowed(p) {{ return Err(denied()); }} Ok(()) }}
fn is_owner(user: User, id: Id) -> bool {{ user.id == id }}
async fn one() {{ {check} sqlx::query("SELECT * FROM records"); }}
async fn two() {{ {check} sqlx::query("SELECT * FROM records"); }}
async fn three() {{ {target} sqlx::query("SELECT * FROM records"); }}
fn app(c: &mut Config) {{ c.route("/one/{{id}}",web::get().to(one)).route("/two/{{id}}",web::get().to(two)).route("/three/{{id}}",web::get().to(three)); }}
"#
        );
        // Use canonical recognized helper names with no rejection path.
        source = source
            .replace("check_permission_unknown", "require_permission")
            .replace("check_role_unknown", "require_role");
        let report = TempRepo::new("dimension-isolation", &[("main.rs", &source)]).analyze();
        assert!(
            report.analysis_evidence.iter().any(|e| e.stage == "drift"
                && e.route.as_ref().and_then(|r| r.handler.as_deref()) == Some("three")
                && e.dimension.as_deref() == Some(dimension)
                && e.abstention_reasons.is_empty()),
            "{dimension}: {:?}",
            report.analysis_evidence
        );
        assert!(report.finding_details.is_empty());
        let target = report
            .security_assessments
            .iter()
            .find(|a| a.route.handler.as_deref() == Some("three"))
            .unwrap();
        assert!(
            target
                .requirements
                .iter()
                .any(|r| r.enforcement == security::Enforcement::Unresolved)
        );
    }
}

#[test]
fn uncertainty_blocks_missing_mismatched_and_same_dimension_policies() {
    for body in [
        "require_permission();",
        "check_role(\"User\")?; require_permission();",
        "check_role(\"Admin\")?; require_role();",
    ] {
        let report = analyze_bodies(
            "dependent-uncertainty",
            ["check_role(\"Admin\")?;", "check_role(\"Admin\")?;", body],
        );
        assert!(report.finding_details.is_empty(), "{body}");
        assert!(
            !report.analysis_evidence.iter().any(|e| e.stage == "drift"
                && e.route.as_ref().and_then(|r| r.handler.as_deref()) == Some("three")
                && e.dimension.as_deref() == Some("roles")
                && e.abstention_reasons.is_empty()),
            "{body}"
        );
    }
}

#[test]
fn dependent_uncertainty_and_provenance_fail_closed() {
    let report = analyze_bodies(
        "uncertainty-provenance",
        [
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?;",
            "check_role(\"Admin\")?; require_permission();",
        ],
    );
    for variant in [
        "identity",
        "unclassified",
        "wrong-file",
        "wrong-line",
        "wrong-symbol",
        "mount",
        "handler",
        "one-supporter",
    ] {
        let mut assessments = report.security_assessments.clone();
        let target = assessments
            .iter_mut()
            .find(|a| a.route.handler.as_deref() == Some("three"))
            .unwrap();
        let unresolved = target
            .requirements
            .iter_mut()
            .find(|r| r.enforcement == security::Enforcement::Unresolved)
            .unwrap();
        match variant {
            "identity" => unresolved.dimension = "authentication".into(),
            "unclassified" => unresolved.dimension = "unresolved".into(),
            "wrong-file" => unresolved.file = PathBuf::from("other.rs"),
            "wrong-line" => unresolved.line += 1,
            "wrong-symbol" => unresolved.symbol = "different".into(),
            "mount" => {
                target.route.status = RouteSecurityStatus::Unknown {
                    reason:
                        "Attribute service has no verified application/middleware mount context"
                            .into(),
                }
            }
            "handler" => {
                target.route.status = RouteSecurityStatus::Unknown {
                    reason: "Handler symbol could not be uniquely resolved in repository AST"
                        .into(),
                }
            }
            "one-supporter" => {}
            _ => unreachable!(),
        }
        if variant == "one-supporter" {
            assessments
                .iter_mut()
                .find(|a| a.route.handler.as_deref() == Some("one"))
                .unwrap()
                .requirements
                .clear();
        }
        let mut evidence = Vec::new();
        let mut findings = Vec::new();
        policy_drift::infer(
            &report.peer_groups,
            &assessments,
            &mut findings,
            &mut Vec::new(),
            &mut Vec::new(),
            &mut HashSet::new(),
            &mut evidence,
        );
        assert!(
            !findings
                .iter()
                .any(|f| f.suspicious_route.handler.as_deref() == Some("three")),
            "{variant}"
        );
        assert!(
            !evidence.iter().any(|e| e.stage == "drift"
                && e.route.as_ref().and_then(|r| r.handler.as_deref()) == Some("three")
                && e.dimension.as_deref() == Some("roles")
                && e.abstention_reasons.is_empty()),
            "{variant}"
        );
    }
}


#[test]
fn resolved_ignored_predicate_is_retained_without_claiming_enforcement() {
    for check in ["require_role(&user);", "let ignored = require_role(&user);", "require_role(&user)?;"] {
        let source = format!(r#"
struct User {{ privileged: bool }}
fn require_role(user: &User) -> Result<(), Error> {{
    if !user.privileged {{ Err(denied()) }} else {{ Ok(()) }}
}}
async fn one(user: User) {{ {check} sqlx::query("SELECT * FROM records"); }}
fn app(c: &mut Config) {{ c.route("/records",web::get().to(one)); }}
"#);
        let report = TempRepo::new("ignored-predicate-provenance", &[("main.rs", &source)]).analyze();
        let requirement = report.security_assessments[0].requirements.iter().find(|r| r.dimension == "roles").unwrap();
        assert!(requirement.values.iter().any(|v| v.contains("User.privileged == true")));
        assert_eq!(requirement.enforcement, if check.contains('?') { security::Enforcement::Observed } else { security::Enforcement::Unresolved });
        assert!(report.finding_details.is_empty());
    }
}


#[test]
fn alternative_enforcement_does_not_turn_ignored_predicate_into_verified_drift() {
    for alternative in [
        "if !user.privileged { return Err(denied()); }",
        "alternate(&user)?;",
        "let permitted = records.filter(privileged.eq(true)).first(conn)?;",
    ] {
        let source = format!(r#"
struct User {{ privileged: bool }}
fn require_role(user: &User) -> Result<(), Error> {{ if !user.privileged {{ Err(denied()) }} else {{ Ok(()) }} }}
fn alternate(user: &User) -> Result<(), Error> {{ if !user.privileged {{ Err(denied()) }} else {{ Ok(()) }} }}
async fn one(user: User) {{ require_role(&user)?; sqlx::query("SELECT * FROM records"); }}
async fn two(user: User) {{ require_role(&user)?; sqlx::query("SELECT * FROM records"); }}
async fn three(user: User) {{ require_role(&user); {alternative} sqlx::query("SELECT * FROM records"); }}
async fn public() {{ sqlx::query("SELECT * FROM catalog"); }}
fn app(c: &mut Config) {{ c.service(web::scope("/records").wrap(PolicyMiddleware::new()).route("/one",web::get().to(one)).route("/two",web::get().to(two)).route("/three",web::get().to(three))); c.route("/catalog",web::get().to(public)); }}
"#);
        let report = TempRepo::new("alternative-enforcement", &[("main.rs", &source)]).analyze();
        assert!(report.finding_details.is_empty());
        assert!(!report.peer_groups.iter().any(|g| g.routes.iter().any(|r|r.handler.as_deref()==Some("public")) && g.routes.iter().any(|r|r.handler.as_deref()==Some("three"))));
    }
}


#[test]
fn exploratory_reviews_are_separate_and_preserve_alternative_policies() {
    for variant in ["missing", "ignored", "alternative", "public"] {
        let alternative = variant == "alternative" || variant == "public";
        let body = match variant { "alternative" => "check_permission(\"other\")?;", "ignored" => "require_role(&u);", _ => "" };
        let method = if variant == "public" { "get" } else { "post" };
        let source = format!(r#"
struct User {{ allowed: bool }}
fn require_role(u:&User)->Result<(),Error>{{if !u.allowed{{Err(denied())}}else{{Ok(())}}}}
fn check_permission(p:&str)->Result<(),Error>{{if allowed(p){{Ok(())}}else{{Err(denied())}}}}
async fn one(u:User){{require_role(&u)?;sqlx::query("SELECT * FROM records");}}
async fn two(u:User){{require_role(&u)?;sqlx::query("SELECT * FROM records");}}
async fn three(u:User){{{body}sqlx::query("SELECT * FROM records");}}
fn app(c:&mut Config){{c.service(web::scope("/records").wrap(UnknownPolicy::new()).route("/one",web::post().to(one)).route("/two",web::post().to(two)).route("/three",web::{method}().to(three)));}}
"#);
        let report=TempRepo::new("review-tier", &[("main.rs", &source)]).analyze();
        assert!(report.finding_details.is_empty());
        assert_eq!(report.review_observations.len(),usize::from(!alternative));
        if !alternative {
            let review=&report.review_observations[0];
            assert_eq!(review.related_routes.len(),2);
            assert!(!review.unresolved_evidence.is_empty());
            assert_eq!(review.supporting_requirements.len(),2);
        }
    }
}


#[test]
fn resource_provenance_abstains_for_ambiguous_and_utility_dependencies() {
    for setup in [
        "trait Store { fn rows(&self); } async fn one(store:Box<dyn Store>){store.rows();} async fn two(store:Box<dyn Store>){store.rows();}",
        "type First=Second; type Second=First; async fn one(store:First){store.rows();} async fn two(store:Second){store.rows();}",
        "mod a {pub struct Repo;} mod b {pub struct Repo;} use a::*; use b::*; async fn one(){Repo::rows();} async fn two(){Repo::rows();}",
        "fn utility()->usize{sqlx::query(\"SELECT * FROM settings\");1} async fn one(){let v=utility();} async fn two(){let v=utility();}",
        "mod a {pub struct Repo; impl Repo {pub fn rows()->usize{sqlx::query(\"SELECT * FROM records\");1}}} mod b {pub struct Repo; impl Repo {pub fn rows()->usize{sqlx::query(\"SELECT * FROM invoices\");1}}} async fn one(){let v=a::Repo::rows();} async fn two(){let v=b::Repo::rows();}",
    ] {
        let source=format!("{setup} fn app(c:&mut Config){{c.route(\"/alpha\",web::get().to(one)).route(\"/beta\",web::get().to(two));}}");
        let report=TempRepo::new("provenance-abstention", &[("main.rs",&source)]).analyze();
        assert!(report.peer_groups.is_empty(), "{setup}");
        assert!(report.finding_details.is_empty());
        assert!(report.review_observations.is_empty());
    }
}


#[test]
fn promotion_requires_resource_proof_beyond_namespace_or_collection_shape() {
    for source in [r#"
async fn public_registration() {} async fn manage_users() {} async fn articles() {}
fn app(c:&mut Config){c.route("/api/users",web::post().to(public_registration)).route("/api/manage",web::post().to(manage_users)).route("/api/articles",web::post().to(articles));}
"#, r#"
async fn collection() {} async fn item() {}
fn app(c:&mut Config){c.route("/objects",web::post().to(collection)).route("/objects/{id}",web::get().to(item));}
"#, r#"
async fn collection(){sqlx::query("SELECT * FROM records");} async fn item(){sqlx::query("SELECT * FROM invoices");}
fn app(c:&mut Config){c.route("/objects",web::get().to(collection)).route("/objects/{id}",web::get().to(item));}
"#] {
        let report=TempRepo::new("promotion-evidence-boundary", &[("main.rs",source)]).analyze();
        assert!(!report.candidate_relationships.is_empty());
        assert!(report.peer_groups.is_empty());
        assert!(report.finding_details.is_empty());
        assert!(report.review_observations.is_empty());
        assert_eq!(report.summary.as_ref().unwrap().peer_compared_routes,0);
    }
}


#[test]
fn metadata_tables_and_documentation_do_not_invent_macro_routes() {
    let source=r#"
use actix_web::{web,App};
#[metadata::catalog(routes("/invented" => [get(handler),post(handler)]))]
struct Catalog;
#[metadata::catalog(routes(DYNAMIC => get(handler)))]
struct Dynamic;
#[metadata::catalog(routes("/dead" => get(handler)))]
struct Dead;
/// #[routes(routes("/documented" => get(handler)))]
async fn handler(){}
fn app(){App::new().configure(Catalog::configure);}
"#;
    let report=TempRepo::new("macro-metadata-boundary", &[("main.rs",source)]).analyze();
    assert!(report.routes.is_empty());
    assert!(report.finding_details.is_empty());
    assert!(report.review_observations.is_empty());
    assert!(report.diagnostics.iter().any(|d|d.code=="unresolved_callback"));
}


#[test]
fn source_check_contrasts_are_informational_and_require_independent_related_handlers() {
    for variant in [
        "contrast",
        "same-check",
        "optional",
        "unrelated",
        "lookalike",
        "alias-handler",
        "shadowed",
    ] {
        let helper = if variant == "lookalike" {
            "struct HttpRequest;"
        } else {
            "use actix_web::HttpRequest;"
        };
        let first = if variant == "shadowed" {
            "let req=another();let user=lookup(&req)?;"
        } else {
            "let user=lookup(&req)?;"
        };
        let third = if variant == "optional" { "let user=lookup(&req).ok();" } else if variant == "same-check" {
            "let user=lookup(&req)?;"
        } else {
            ""
        };
        let route = if variant == "unrelated" {
            "/invoices"
        } else {
            "/records/{id}"
        };
        let second = if variant == "alias-handler" {
            "one"
        } else {
            "two"
        };
        let source = format!(
            r#"
{helper}
struct Principal {{id:u64}}
fn lookup(req:&HttpRequest)->Result<Principal,Error>{{req.extensions().get::<Principal>().map(|u|u.clone()).ok_or_else(||denied())}}
async fn one(req:HttpRequest)->Result<(),Error>{{{first} Ok(())}}
async fn two(req:HttpRequest)->Result<(),Error>{{let user=lookup(&req)?;Ok(())}}
async fn three(req:HttpRequest)->Result<(),Error>{{{third} Ok(())}}
fn app(c:&mut Config){{c.route("/records/{{id}}",web::post().to(one)).route("/records/{{id}}",web::put().to({second})).route("{route}",web::get().to(three));}}
"#
        );
        let report = TempRepo::new("source-check-contrast", &[("main.rs", &source)]).analyze();
        assert_eq!(
            report.check_comparisons.len(),
            usize::from(matches!(variant,"contrast"|"optional")),
            "{variant}"
        );
        assert!(report.finding_details.is_empty());
        assert!(report.review_observations.is_empty());
        if matches!(variant,"contrast"|"optional") {
            let contrast = &report.check_comparisons[0];
            assert_eq!(contrast.classification, "InformationalCheckContrast");
            assert_eq!(contrast.supporting_checks.len(), 2);
            assert!(
                contrast
                    .supporting_checks
                    .iter()
                    .all(|c| c.enforcement == security::Enforcement::Unresolved)
            );
            assert!(contrast.confidence.contains("undetermined"));
        }
    }
}


#[test]
fn future_source_contrasts_resolve_closed_aliases_and_abstain_on_ambiguity() {
    for variant in ["closed","open-glob","ambiguous-alias","cyclic-alias","lookalike-future","recovered-error","unrelated","shadowed-header","preserved-result","wrong-optional-value"] {
        let prelude=if variant=="cyclic-alias" {"pub type Outcome<T>=Other<T>;pub type Other<T>=Outcome<T>;"} else {"pub type Outcome<T>=std::result::Result<T,Error>;"};
        let extra=match variant {"open-glob"=>"use external_unknown::*;", "ambiguous-alias"=>"mod other{pub type Outcome<T>=std::result::Result<T,Error>;}use other::*;",_=>""};
        let future=if variant=="lookalike-future" {"use futures::future::result;trait Future {}"} else {"use futures::{future::result,Future};"};
        let first=if variant=="recovered-error" {"gate(&state,&req).or_else(|e|Ok(())).and_then(|a|finish(a))"} else {"gate(&state,&req).and_then(|a|finish(a))"};
        let route=if variant=="unrelated" {"/api/invoices"}else{"/api/records/{id}"};
        let third=match variant {"preserved-result"=>"gate(&state,&req).then(|a|a)","wrong-optional-value"=>"gate(&state,&req).then(|a|{let other=something();other.ok();a})",_=>"gate(&state,&req).then(|a|finish(a.ok()))"};
        let shadow=if variant=="shadowed-header" {"const AUTHORIZATION:Header=other();"}else{""};
        let source=format!(r#"
mod prelude{{{prelude}}}
mod handlers {{
use actix_web::{{HttpRequest,http::header::AUTHORIZATION}};
{future}
use crate::prelude::*;{extra}
fn preprocess(h:Option<&Header>)->Outcome<String>{{if bad(){{return Err(denied());}}Ok(text())}}
fn gate(state:&State,req:&HttpRequest)->impl Future<Item=Principal,Error=Error>{{{shadow}result(preprocess(req.headers().get(AUTHORIZATION))).and_then(|token|validate(token))}}
pub fn one(state:State,(req,): (HttpRequest,))->impl Future<Item=Response,Error=Error>{{{first}}}
pub fn two(state:State,(req,): (HttpRequest,))->impl Future<Item=Response,Error=Error>{{result(validate_input()).and_then(move |_|gate(&state,&req)).and_then(|a|finish(a))}}
pub fn three(state:State,(req,): (HttpRequest,))->impl Future<Item=Response,Error=Error>{{{third}}}
}}
use actix_web::web;
fn app(c:&mut Config){{c.route("/api/records/{{id}}",web::post().to(handlers::one)).route("/api/records/{{id}}",web::put().to(handlers::two)).route("{route}",web::get().to(handlers::three));}}
"#);
        let report=TempRepo::new("future-check-contrast", &[("main.rs",&source)]).analyze();
        assert_eq!(report.check_comparisons.len(),usize::from(variant=="closed"),"{variant}");
        assert!(report.finding_details.is_empty());assert!(report.review_observations.is_empty());
        if variant=="closed" {assert_eq!(report.check_comparisons[0].target_checks[0].mechanism,"source_optional_future_helper");}
    }
}
