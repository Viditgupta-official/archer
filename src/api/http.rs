use super::{
    config::{ApiConfig, random_id},
    contracts::*,
    sources,
    worker::{self, Outcome, StoredResult},
};
use actix_web::{
    App, Error, HttpResponse, HttpServer, ResponseError,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    http::{Method, StatusCode, header},
    middleware::Next,
    web,
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Job {
    status: JobStatus,
    result: Option<StoredResult>,
    finished: Option<Instant>,
}
pub struct ApiState {
    pub config: ApiConfig,
    jobs: Mutex<HashMap<String, Job>>,
    slots: Arc<tokio::sync::Semaphore>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn active(status: &JobState) -> bool {
    matches!(status, JobState::Queued | JobState::Running)
}
impl ApiState {
    pub fn new(mut config: ApiConfig) -> anyhow::Result<Self> {
        config.validate()?;
        config.work_root = worker::prepare_root(&config.work_root)?;
        Ok(Self {
            slots: Arc::new(tokio::sync::Semaphore::new(config.concurrency)),
            config,
            jobs: Mutex::new(HashMap::new()),
        })
    }
    fn prune(&self, jobs: &mut HashMap<String, Job>) {
        jobs.retain(|_, j| {
            j.finished
                .is_none_or(|t| t.elapsed() < Duration::from_secs(self.config.retention_secs))
        });
    }
    fn finish(&self, id: &str, outcome: Outcome) {
        if let Ok(mut jobs) = self.jobs.lock() {
            if let Some(job) = jobs.get_mut(id) {
                match outcome {
                    Outcome::Succeeded(result) => {
                        job.status.status = JobState::Succeeded;
                        job.result = Some(result);
                    }
                    Outcome::Failed(error) => {
                        job.status.status = JobState::Failed;
                        job.status.error = Some(error);
                    }
                    Outcome::TimedOut => {
                        job.status.status = JobState::TimedOut;
                        job.status.error = Some(PublicError {
                            code: "analysis_timeout".into(),
                            message: "Analysis exceeded its processing deadline".into(),
                        });
                    }
                }
                job.finished = Some(Instant::now());
                job.status.completed_at = Some(now());
                job.status.expires_at = Some(now() + self.config.retention_secs);
            }
        }
    }
}
fn missing() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "The resource does not exist or has expired",
    )
}
fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn submit(
    state: web::Data<ApiState>,
    request: web::Json<AnalysisRequest>,
) -> Result<HttpResponse, ApiError> {
    sources::validate(
        &request,
        &state.config.limits,
        &state.config.allowed_repositories,
    )?;
    let permit = state.slots.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "capacity_exceeded",
            "Analysis capacity is currently full",
        )
    })?;
    let id = random_id()?;
    let status = JobStatus {
        schema_version: SCHEMA_VERSION,
        id: id.clone(),
        status: JobState::Queued,
        created_at: now(),
        completed_at: None,
        expires_at: None,
        error: None,
        status_url: format!("/api/v1/analyses/{id}"),
        result_url: format!("/api/v1/analyses/{id}/result"),
        arg_url: format!("/api/v1/analyses/{id}/arg"),
    };
    {
        let mut jobs = state.jobs.lock().map_err(|_| ApiError::internal())?;
        state.prune(&mut jobs);
        if jobs.len() >= state.config.retained_jobs {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "retention_capacity",
                "Delete a completed analysis or wait for its retention period to expire",
            ));
        }
        jobs.insert(
            id.clone(),
            Job {
                status: status.clone(),
                result: None,
                finished: None,
            },
        );
    }
    let request = request.into_inner();
    let background = state.clone();
    actix_web::rt::spawn(async move {
        if let Ok(mut jobs) = background.jobs.lock() {
            if let Some(job) = jobs.get_mut(&id) {
                job.status.status = JobState::Running;
            }
        }
        let config = background.config.clone();
        let worker_id = id.clone();
        let outcome = web::block(move || {
            let _permit = permit;
            worker::run(&config, &worker_id, request)
        })
        .await
        .unwrap_or_else(|_| Outcome::Failed(ApiError::internal().public()));
        background.finish(&id, outcome);
    });
    Ok(HttpResponse::Accepted()
        .insert_header((header::LOCATION, status.status_url.clone()))
        .json(status))
}
async fn status(
    state: web::Data<ApiState>,
    id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    if !valid_id(&id) {
        return Err(missing());
    }
    let mut jobs = state.jobs.lock().map_err(|_| ApiError::internal())?;
    state.prune(&mut jobs);
    Ok(HttpResponse::Ok().json(&jobs.get(id.as_str()).ok_or_else(missing)?.status))
}
fn result_bytes(state: &ApiState, id: &str, arg: bool) -> Result<web::Bytes, ApiError> {
    if !valid_id(id) {
        return Err(missing());
    }
    let mut jobs = state.jobs.lock().map_err(|_| ApiError::internal())?;
    state.prune(&mut jobs);
    let job = jobs.get(id).ok_or_else(missing)?;
    if active(&job.status.status) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "analysis_not_ready",
            "Analysis has not completed",
        ));
    }
    let Some(result) = &job.result else {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "analysis_failed",
            "Analysis did not produce a result; inspect its status",
        ));
    };
    Ok(if arg {
        result.dot.clone()
    } else {
        result.json.clone()
    })
}
async fn result(
    state: web::Data<ApiState>,
    id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(result_bytes(&state, &id, false)?))
}
async fn arg(state: web::Data<ApiState>, id: web::Path<String>) -> Result<HttpResponse, ApiError> {
    let dot = result_bytes(&state, &id, true)?;
    Ok(HttpResponse::Ok()
        .content_type("text/vnd.graphviz; charset=utf-8")
        .insert_header((
            header::CONTENT_DISPOSITION,
            "attachment; filename=\"authorization-graph.dot\"",
        ))
        .insert_header((
            header::CONTENT_SECURITY_POLICY,
            "default-src 'none'; sandbox",
        ))
        .insert_header((
            header::LINK,
            format!(
                "</api/v1/analyses/{id}/result>; rel=\"describedby\"; type=\"application/json\""
            ),
        ))
        .body(dot))
}
async fn delete(
    state: web::Data<ApiState>,
    id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    if !valid_id(&id) {
        return Err(missing());
    }
    let mut jobs = state.jobs.lock().map_err(|_| ApiError::internal())?;
    state.prune(&mut jobs);
    let job = jobs.get(id.as_str()).ok_or_else(missing)?;
    if active(&job.status.status) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            "analysis_running",
            "A running analysis cannot be deleted",
        ));
    }
    jobs.remove(id.as_str());
    Ok(HttpResponse::NoContent().finish())
}
async fn health(state: web::Data<ApiState>) -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({"schema_version":SCHEMA_VERSION,"status":"ok","engine_version":env!("CARGO_PKG_VERSION"),"capabilities":{"snapshot":true,"github":!state.config.allowed_repositories.is_empty(),"llm_explanations":false},"limits":state.config.limits}))
}
async fn spec() -> HttpResponse {
    HttpResponse::Ok().json(super::openapi::document())
}
async fn not_found() -> HttpResponse {
    missing().error_response()
}
async fn method_not_allowed() -> HttpResponse {
    ApiError::new(
        StatusCode::METHOD_NOT_ALLOWED,
        "method_not_allowed",
        "HTTP method is not supported for this resource",
    )
    .error_response()
}

pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/api/v1/health")
            .route(web::get().to(health))
            .default_service(web::to(method_not_allowed)),
    )
    .service(
        web::resource("/api/v1/openapi.json")
            .route(web::get().to(spec))
            .default_service(web::to(method_not_allowed)),
    )
    .service(
        web::resource("/api/v1/analyses")
            .route(web::post().to(submit))
            .default_service(web::to(method_not_allowed)),
    )
    .service(
        web::resource("/api/v1/analyses/{id}")
            .route(web::get().to(status))
            .route(web::delete().to(delete))
            .default_service(web::to(method_not_allowed)),
    )
    .service(
        web::resource("/api/v1/analyses/{id}/result")
            .route(web::get().to(result))
            .default_service(web::to(method_not_allowed)),
    )
    .service(
        web::resource("/api/v1/analyses/{id}/arg")
            .route(web::get().to(arg))
            .default_service(web::to(method_not_allowed)),
    )
    .default_service(web::to(not_found));
}

pub fn json_config(limit: usize) -> web::JsonConfig {
    web::JsonConfig::default()
        .limit(limit)
        .error_handler(|error, _| {
            let error = match error {
                actix_web::error::JsonPayloadError::Overflow { .. }
                | actix_web::error::JsonPayloadError::OverflowKnownLength { .. } => ApiError::new(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request_too_large",
                    "JSON request exceeds the configured byte limit",
                ),
                actix_web::error::JsonPayloadError::ContentType => ApiError::new(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_media_type",
                    "Content-Type must be application/json",
                ),
                _ => ApiError::new(
                    StatusCode::BAD_REQUEST,
                    "invalid_json",
                    "Request must be valid JSON matching the documented contract",
                ),
            };
            error.into()
        })
}

fn authorized(secret: &str, header: Option<&str>) -> bool {
    let value = header
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
        .as_bytes();
    let secret = secret.as_bytes();
    let mut different = secret.len() ^ value.len();
    for (i, b) in secret.iter().enumerate() {
        different |= (b ^ value.get(i).copied().unwrap_or(0)) as usize;
    }
    different == 0
}
fn headers<B>(response: &mut ServiceResponse<B>, origin: Option<&str>) {
    let h = response.headers_mut();
    h.insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        header::HeaderValue::from_static("nosniff"),
    );
    h.append(header::VARY, header::HeaderValue::from_static("Origin"));
    if let Some(origin) = origin {
        if let Ok(origin) = header::HeaderValue::from_str(origin) {
            h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
            h.insert(
                header::ACCESS_CONTROL_EXPOSE_HEADERS,
                header::HeaderValue::from_static("Content-Disposition, Link"),
            );
        }
    }
}
pub async fn guard(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> Result<ServiceResponse<EitherBody<impl MessageBody>>, Error> {
    let state = req
        .app_data::<web::Data<ApiState>>()
        .cloned()
        .ok_or_else(ApiError::internal)?;
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .map(|v| v.to_str().unwrap_or("").to_owned());
    let mut denied = None;
    if origin
        .as_ref()
        .is_some_and(|o| !state.config.cors_origins.contains(o))
        || req.headers().get_all(header::ORIGIN).count() > 1
    {
        denied = Some(ApiError::new(
            StatusCode::FORBIDDEN,
            "origin_not_allowed",
            "The request origin is not allowed",
        ));
    }
    if req.headers().get_all(header::AUTHORIZATION).count() > 1 {
        denied = Some(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "A valid Bearer token is required",
        ));
    }
    let public = matches!(req.path(), "/api/v1/health" | "/api/v1/openapi.json");
    if req.method() != Method::OPTIONS
        && !public
        && !authorized(
            &state.config.token,
            req.headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok()),
        )
    {
        denied = Some(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "A valid Bearer token is required",
        ));
    }
    if req
        .headers()
        .get(header::CONTENT_ENCODING)
        .is_some_and(|v| v != "identity")
    {
        denied = Some(ApiError::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_encoding",
            "Compressed request bodies are not accepted",
        ));
    }
    if let Some(error) = denied {
        let mut response = req
            .into_response(error.error_response())
            .map_into_right_body();
        headers(
            &mut response,
            origin
                .as_deref()
                .filter(|o| state.config.cors_origins.contains(*o)),
        );
        return Ok(response);
    }
    if req.method() == Method::OPTIONS {
        let method = req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|v| v.to_str().ok());
        let allowed = req
            .headers()
            .get(header::ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|v| v.to_str().ok())
            .is_none_or(|v| {
                v.split(',').all(|h| {
                    matches!(
                        h.trim().to_ascii_lowercase().as_str(),
                        "authorization" | "content-type"
                    )
                })
            });
        if origin.is_none() || !matches!(method, Some("GET" | "POST" | "DELETE")) || !allowed {
            return Ok(req
                .into_response(
                    ApiError::new(
                        StatusCode::FORBIDDEN,
                        "preflight_rejected",
                        "Unsupported CORS preflight",
                    )
                    .error_response(),
                )
                .map_into_right_body());
        }
        let mut response = req
            .into_response(
                HttpResponse::NoContent()
                    .insert_header((header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, DELETE"))
                    .insert_header((
                        header::ACCESS_CONTROL_ALLOW_HEADERS,
                        "Authorization, Content-Type",
                    ))
                    .insert_header((header::ACCESS_CONTROL_MAX_AGE, "300"))
                    .finish(),
            )
            .map_into_right_body();
        headers(&mut response, origin.as_deref());
        return Ok(response);
    }
    let response = actix_web::rt::time::timeout(Duration::from_secs(15), next.call(req))
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "request_timeout",
                "HTTP request processing deadline exceeded",
            )
        })??;
    let mut response = response.map_into_left_body();
    headers(&mut response, origin.as_deref());
    Ok(response)
}

pub async fn run() -> std::io::Result<()> {
    let config = ApiConfig::from_env().map_err(std::io::Error::other)?;
    let bind = config.bind;
    let request_bytes = config.limits.request_bytes;
    let state = web::Data::new(ApiState::new(config).map_err(std::io::Error::other)?);
    eprintln!("ARCHER API listening on {bind}; OpenAPI: /api/v1/openapi.json");
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .app_data(json_config(request_bytes))
            .wrap(actix_web::middleware::from_fn(guard))
            .configure(configure)
    })
    .workers(2)
    .worker_max_blocking_threads(2)
    .max_connections(16)
    .client_request_timeout(Duration::from_secs(10))
    .shutdown_timeout(5)
    .bind(bind)?
    .run()
    .await
}
