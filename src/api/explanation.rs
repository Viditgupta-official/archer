//! Future optional LLM boundary. No provider, network call or HTTP endpoint is
//! implemented. Supplements can reference evidence but cannot replace analysis.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{future::Future, pin::Pin};

#[derive(Serialize)]
pub struct ExplanationEvidence<'a> {
    pub schema_version: &'static str,
    pub analysis_id: &'a str,
    pub deterministic_analysis_authoritative: bool,
    /// Use the API privacy projection; never add source files or credentials.
    pub report: &'a Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplanationSupplement {
    pub summary: String,
    pub evidence_references: Vec<String>,
    pub limitations: Vec<String>,
}
#[derive(Debug)]
pub enum ExplanationError {
    Unavailable,
    TimedOut,
    InvalidSupplement,
}

pub trait ExplanationProvider: Send + Sync {
    fn explain<'a>(
        &'a self,
        evidence: ExplanationEvidence<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<ExplanationSupplement, ExplanationError>> + Send + 'a>>;
}
