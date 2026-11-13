#![cfg(feature = "api")]
use actix_web::{App, middleware::from_fn, test, web};
use archer::api::{
    self,
    config::{ApiConfig, random_id},
};
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

const TOKEN: &str = "test-token-000000000000000000000000000000";
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("archer-api-test-{}", random_id().unwrap())))
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        assert!(
            self.0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("archer-api-test-")
        );
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn config(root: &Temp) -> ApiConfig {
    let mut c = ApiConfig::new(
        TOKEN.into(),
        root.0.clone(),
        env!("CARGO_BIN_EXE_archer-api").into(),
    );
    c.cargo_bin = api::config::discover_cargo();
    c.cors_origins.insert("http://localhost:5173".into());
    c
}
fn snapshot() -> Value {
    json!({"source":{"type":"snapshot","files":[{"path":"Cargo.toml","content":"[package]\nname='fixture'\nversion='0.1.0'\nedition='2024'\n"},{"path":"src/main.rs","content":"use actix_web::{web, App};\nasync fn list() {}\nasync fn get() {}\nfn main() { App::new().route(\"/items\",web::get().to(list)).route(\"/items/{id}\",web::get().to(get)); }"},{"path":"build.rs","content":"fn main() { panic!(\"SUBMITTED_BUILD_MUST_NEVER_EXECUTE\"); }"}]}})
}

#[actix_web::test]
async fn authentication_cors_errors_and_contract_are_stable() {
    let root = Temp::new();
    let c = config(&root);
    let limit = c.limits.request_bytes;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(api::ApiState::new(c).unwrap()))
            .app_data(api::json_config(limit))
            .wrap(from_fn(api::guard))
            .configure(api::configure),
    )
    .await;
    let health: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::get().uri("/api/v1/health").to_request(),
    )
    .await;
    assert_eq!(health["capabilities"]["llm_explanations"], false);
    let spec: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/openapi.json")
            .to_request(),
    )
    .await;
    assert_eq!(spec["openapi"], "3.1.0");
    assert_eq!(spec["paths"].as_object().unwrap().len(), 6);
    assert!(spec["components"]["schemas"]["Report"]["properties"]["check_comparisons"].is_object());
    for (method, path, payload, status) in [
        ("POST", "/api/v1/analyses", snapshot(), 401),
        ("GET", "/api/v1/analyses/none", json!(null), 404),
        (
            "POST",
            "/api/v1/analyses",
            json!({"source":{"type":"snapshot","files":[{"path":"../a.rs","content":""}]}}),
            400,
        ),
        (
            "POST",
            "/api/v1/analyses",
            json!({"source":{"type":"local","path":"C:/"}}),
            400,
        ),
    ] {
        let mut req = test::TestRequest::default()
            .method(method.parse().unwrap())
            .uri(path)
            .set_json(payload);
        if status != 401 {
            req = req.insert_header(("Authorization", format!("Bearer {TOKEN}")));
        }
        let response = test::call_service(&app, req.to_request()).await;
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers().get("Cache-Control").unwrap(), "no-store");
        let body: Value = test::read_body_json(response).await;
        assert_eq!(body["schema_version"], "1.0");
        assert!(body["error"]["code"].is_string());
    }
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/analyses")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .insert_header(("Content-Type", "application/json"))
            .set_payload("{broken secret")
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 400);
    assert!(!String::from_utf8_lossy(&test::read_body(response).await).contains("secret"));
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/analyses")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .insert_header(("Content-Type", "application/json"))
            .set_payload("x".repeat(limit + 1))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 413);
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri("/api/v1/health")
            .insert_header(("Origin", "https://evil.test"))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 403);
    assert!(
        response
            .headers()
            .get("Access-Control-Allow-Origin")
            .is_none()
    );
    let response = test::call_service(
        &app,
        test::TestRequest::default()
            .method(actix_web::http::Method::OPTIONS)
            .uri("/api/v1/analyses")
            .insert_header(("Origin", "http://localhost:5173"))
            .insert_header(("Access-Control-Request-Method", "POST"))
            .insert_header((
                "Access-Control-Request-Headers",
                "authorization, content-type",
            ))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 204);
    assert_eq!(
        response
            .headers()
            .get("Access-Control-Allow-Origin")
            .unwrap(),
        "http://localhost:5173"
    );
}

#[actix_web::test]
async fn isolated_worker_matches_cli_and_retains_arg_without_running_build_scripts() {
    let root = Temp::new();
    let fixture = Temp::new();
    fs::create_dir_all(&fixture.0).unwrap();
    let payload = snapshot();
    for file in payload["source"]["files"].as_array().unwrap() {
        let path = fixture.0.join(file["path"].as_str().unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, file["content"].as_str().unwrap()).unwrap();
    }
    let c = config(&root);
    let limit = c.limits.request_bytes;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(api::ApiState::new(c).unwrap()))
            .app_data(api::json_config(limit))
            .wrap(from_fn(api::guard))
            .configure(api::configure),
    )
    .await;
    let request = test::TestRequest::post()
        .uri("/api/v1/analyses")
        .insert_header(("Authorization", format!("Bearer {TOKEN}")))
        .set_json(payload)
        .to_request();
    let response = test::call_service(&app, request).await;
    assert_eq!(response.status(), 202);
    let job: Value = test::read_body_json(response).await;
    let started = Instant::now();
    loop {
        let status: Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::get()
                .uri(job["status_url"].as_str().unwrap())
                .insert_header(("Authorization", format!("Bearer {TOKEN}")))
                .to_request(),
        )
        .await;
        if status["status"] == "succeeded" {
            break;
        }
        assert!(
            status["status"] == "queued" || status["status"] == "running",
            "{status}"
        );
        assert!(started.elapsed() < Duration::from_secs(30));
        actix_web::rt::time::sleep(Duration::from_millis(25)).await;
    }
    let result: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::get()
            .uri(job["result_url"].as_str().unwrap())
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request(),
    )
    .await;
    assert_eq!(result["schema_version"], "1.0");
    assert_eq!(result["llm_enabled"], false);
    assert_eq!(result["report"]["routes"].as_array().unwrap().len(), 2);
    assert_eq!(result["privacy"]["raw_files_available"], false);
    let cli = std::process::Command::new(env!("CARGO_BIN_EXE_archer"))
        .arg(&fixture.0)
        .arg("--json")
        .output()
        .unwrap();
    assert!(cli.status.success());
    let expected = api::project_json(
        serde_json::from_slice(&cli.stdout).unwrap(),
        &fixture.0,
        false,
    );
    assert_eq!(result["report"], expected);
    let arg = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(job["arg_url"].as_str().unwrap())
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request(),
    )
    .await;
    assert_eq!(arg.status(), 200);
    assert_eq!(
        arg.headers().get("Content-Type").unwrap(),
        "text/vnd.graphviz; charset=utf-8"
    );
    assert_eq!(
        arg.headers().get("Content-Security-Policy").unwrap(),
        "default-src 'none'; sandbox"
    );
    assert_eq!(
        arg.headers().get("X-Content-Type-Options").unwrap(),
        "nosniff"
    );
    assert_eq!(
        arg.headers().get("Content-Disposition").unwrap(),
        "attachment; filename=\"authorization-graph.dot\""
    );
    assert!(
        arg.headers()
            .get("Link")
            .unwrap()
            .to_str()
            .unwrap()
            .contains(job["result_url"].as_str().unwrap())
    );
    let dot = String::from_utf8(test::read_body(arg).await.to_vec()).unwrap();
    assert!(dot.contains("digraph"));
    let graph = &result["report"]["graph"];
    assert_eq!(
        dot.lines().filter(|line| line.contains(" -> ")).count(),
        graph["edges"].as_array().unwrap().len()
    );
    for node in graph["nodes"].as_array().unwrap() {
        assert!(dot.contains(&format!("\"{}\" [label=", node["id"].as_str().unwrap())));
    }
    for edge in graph["edges"].as_array().unwrap() {
        assert!(dot.contains(&format!(
            "\"{}\" -> \"{}\" [label=\"{}\"",
            edge["from"].as_str().unwrap(),
            edge["to"].as_str().unwrap(),
            edge["relation"].as_str().unwrap()
        )));
    }
    let unavailable_svg = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(&format!("{}/arg.svg", job["status_url"].as_str().unwrap()))
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request(),
    )
    .await;
    assert_eq!(unavailable_svg.status(), 404);
    assert_eq!(
        fs::read_dir(&root.0).unwrap().count(),
        0,
        "Source workspace must be removed after completion"
    );
    let response = test::call_service(
        &app,
        test::TestRequest::delete()
            .uri(job["status_url"].as_str().unwrap())
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 204);
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(job["status_url"].as_str().unwrap())
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 404);
}

#[actix_web::test]
async fn processing_deadline_kills_worker_and_removes_workspace() {
    let root = Temp::new();
    let mut c = config(&root);
    c.limits.wall_ms = 1;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(api::ApiState::new(c).unwrap()))
            .app_data(api::json_config(2 * 1024 * 1024))
            .wrap(from_fn(api::guard))
            .configure(api::configure),
    )
    .await;
    let job: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/analyses")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .set_json(snapshot())
            .to_request(),
    )
    .await;
    let started = Instant::now();
    loop {
        let status: Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::get()
                .uri(job["status_url"].as_str().unwrap())
                .insert_header(("Authorization", format!("Bearer {TOKEN}")))
                .to_request(),
        )
        .await;
        if status["status"] == "timed_out" {
            assert_eq!(status["error"]["code"], "analysis_timeout");
            break;
        }
        assert!(started.elapsed() < Duration::from_secs(10), "{status}");
        actix_web::rt::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}

#[actix_web::test]
async fn admission_is_bounded_and_worker_errors_are_sanitized() {
    let root = Temp::new();
    let mut c = config(&root);
    c.retained_jobs = 1;
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(api::ApiState::new(c).unwrap()))
            .app_data(api::json_config(2 * 1024 * 1024))
            .wrap(from_fn(api::guard))
            .configure(api::configure),
    )
    .await;
    let mut payload = snapshot();
    payload["source"]["files"][0]["content"] =
        json!("[package]\nname='fixture'\nversion='0.1.0'\nbuild='../private-secret-file.rs'");
    let job: Value = test::call_and_read_body_json(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/analyses")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .set_json(payload)
            .to_request(),
    )
    .await;
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/analyses")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .set_json(snapshot())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 429);
    assert!(response.headers().contains_key("Retry-After"));
    let start = Instant::now();
    loop {
        let status: Value = test::call_and_read_body_json(
            &app,
            test::TestRequest::get()
                .uri(job["status_url"].as_str().unwrap())
                .insert_header(("Authorization", format!("Bearer {TOKEN}")))
                .to_request(),
        )
        .await;
        if status["status"] == "failed" {
            assert_eq!(status["error"]["code"], "invalid_source");
            assert!(!status.to_string().contains("private-secret"));
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(10), "{status}");
        actix_web::rt::time::sleep(Duration::from_millis(20)).await;
    }
    let response = test::call_service(
        &app,
        test::TestRequest::get()
            .uri(job["result_url"].as_str().unwrap())
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 409);
    let response = test::call_service(
        &app,
        test::TestRequest::post()
            .uri("/api/v1/analyses")
            .insert_header(("Authorization", format!("Bearer {TOKEN}")))
            .set_json(snapshot())
            .to_request(),
    )
    .await;
    assert_eq!(response.status(), 429);
    assert_eq!(fs::read_dir(&root.0).unwrap().count(), 0);
}
