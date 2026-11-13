use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisRequest {
    pub source: Source,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Snapshot { files: Vec<SourceFile> },
    Github { url: String, commit: String },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub path: String,
    pub content: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
    TimedOut,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicError {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Serialize)]
pub struct JobStatus {
    pub schema_version: &'static str,
    pub id: String,
    pub status: JobState,
    pub created_at: u64,
    pub completed_at: Option<u64>,
    pub expires_at: Option<u64>,
    pub error: Option<PublicError>,
    pub status_url: String,
    pub result_url: String,
    pub arg_url: String,
}

#[derive(Serialize)]
pub struct AnalysisResult {
    pub schema_version: &'static str,
    pub analysis_id: String,
    pub engine_version: &'static str,
    pub privacy: Privacy,
    pub report: Value,
    pub arg_url: String,
    pub llm_enabled: bool,
}

#[derive(Serialize)]
pub struct Privacy {
    pub evidence_text: &'static str,
    pub source_paths: &'static str,
    pub raw_files_available: bool,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: &'static str,
}
impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }
    pub fn invalid(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_source", message)
    }
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "The operation could not be completed",
        )
    }
    pub fn public(&self) -> PublicError {
        PublicError {
            code: self.code.into(),
            message: self.message.into(),
        }
    }
}
impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for ApiError {}
impl ResponseError for ApiError {
    fn status_code(&self) -> StatusCode {
        self.status
    }
    fn error_response(&self) -> HttpResponse {
        let mut response = HttpResponse::build(self.status);
        response.insert_header(("Cache-Control", "no-store"));
        if self.status == StatusCode::UNAUTHORIZED {
            response.insert_header(("WWW-Authenticate", "Bearer"));
        }
        if self.status == StatusCode::TOO_MANY_REQUESTS {
            response.insert_header(("Retry-After", "1"));
        }
        response.json(serde_json::json!({"schema_version":SCHEMA_VERSION,"error":self.public()}))
    }
}
