use super::contracts::ApiError;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::SocketAddr, path::PathBuf};

#[derive(Clone, Serialize, Deserialize)]
pub struct Limits {
    pub request_bytes: usize,
    pub source_files: usize,
    pub source_bytes: u64,
    pub file_bytes: u64,
    pub archive_bytes: u64,
    pub expanded_bytes: u64,
    pub result_bytes: u64,
    pub memory_bytes: usize,
    pub wall_ms: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            request_bytes: 2 * 1024 * 1024,
            source_files: 5000,
            source_bytes: 32 * 1024 * 1024,
            file_bytes: 1024 * 1024,
            archive_bytes: 32 * 1024 * 1024,
            expanded_bytes: 64 * 1024 * 1024,
            result_bytes: 64 * 1024 * 1024,
            memory_bytes: 1024 * 1024 * 1024,
            wall_ms: 90_000,
        }
    }
}

#[derive(Clone)]
pub struct ApiConfig {
    pub bind: SocketAddr,
    pub token: String,
    pub work_root: PathBuf,
    pub worker_exe: PathBuf,
    pub cargo_bin: Option<PathBuf>,
    pub curl_bin: PathBuf,
    pub allowed_repositories: BTreeSet<String>,
    pub cors_origins: BTreeSet<String>,
    pub concurrency: usize,
    pub retained_jobs: usize,
    pub retention_secs: u64,
    pub include_evidence_text: bool,
    pub limits: Limits,
}

pub fn random_id() -> Result<String, ApiError> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

impl ApiConfig {
    pub fn new(token: String, work_root: PathBuf, worker_exe: PathBuf) -> Self {
        Self {
            bind: "127.0.0.1:8080".parse().unwrap(),
            token,
            work_root,
            worker_exe,
            cargo_bin: None,
            curl_bin: default_curl(),
            allowed_repositories: BTreeSet::new(),
            cors_origins: BTreeSet::new(),
            concurrency: 1,
            retained_jobs: 8,
            retention_secs: 600,
            include_evidence_text: false,
            limits: Limits::default(),
        }
    }
    pub fn from_env() -> anyhow::Result<Self> {
        let token = std::env::var("ARCHER_API_TOKEN").map_err(|_| {
            anyhow::anyhow!("ARCHER_API_TOKEN must be set (at least 32 ASCII characters)")
        })?;
        let root = std::env::var_os("ARCHER_WORK_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "archer-api-{}",
                    random_id().expect("OS random generator")
                ))
            });
        let mut config = Self::new(token, root, std::env::current_exe()?);
        if let Ok(value) = std::env::var("ARCHER_BIND") {
            config.bind = value.parse()?;
        }
        config.allowed_repositories = csv("ARCHER_GITHUB_REPOSITORIES")
            .into_iter()
            .map(|s| s.to_ascii_lowercase())
            .collect();
        config.cors_origins = csv("ARCHER_CORS_ORIGINS");
        config.concurrency = number("ARCHER_CONCURRENCY", 1)?;
        config.retained_jobs = number("ARCHER_RETAINED_JOBS", 8)?;
        config.retention_secs = number("ARCHER_RETENTION_SECONDS", 600)? as u64;
        config.limits.wall_ms = (number("ARCHER_TIMEOUT_SECONDS", 90)? as u64)
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("Invalid analysis timeout"))?;
        config.limits.memory_bytes = number("ARCHER_MEMORY_MIB", 1024)?
            .checked_mul(1024 * 1024)
            .ok_or_else(|| anyhow::anyhow!("Invalid memory limit"))?;
        config.include_evidence_text = match std::env::var("ARCHER_EVIDENCE_TEXT").as_deref() {
            Ok("include") => true,
            Ok("redact") | Err(_) => false,
            _ => anyhow::bail!("ARCHER_EVIDENCE_TEXT must be redact or include"),
        };
        config.cargo_bin = std::env::var_os("ARCHER_CARGO_BIN")
            .map(PathBuf::from)
            .or_else(discover_cargo);
        if let Some(bin) = std::env::var_os("ARCHER_CURL_BIN") {
            config.curl_bin = bin.into();
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.allowed_repositories.len() <= 64 && self.cors_origins.len() <= 32,
            "Too many allowlist entries"
        );
        anyhow::ensure!(
            [
                self.limits.file_bytes,
                self.limits.source_bytes,
                self.limits.archive_bytes,
                self.limits.expanded_bytes
            ]
            .iter()
            .all(|v| *v > 0),
            "Byte limits must be positive"
        );
        anyhow::ensure!(
            (32..=256).contains(&self.token.len())
                && self.token.bytes().all(|b| b.is_ascii_graphic()),
            "Invalid API token length or characters"
        );
        anyhow::ensure!(
            (1..=4).contains(&self.concurrency)
                && (1..=32).contains(&self.retained_jobs)
                && self.concurrency <= self.retained_jobs,
            "Invalid concurrency/job retention limits"
        );
        anyhow::ensure!(
            (10..=3600).contains(&self.retention_secs),
            "Invalid retention interval"
        );
        anyhow::ensure!(
            (1..=300_000).contains(&self.limits.wall_ms),
            "Invalid analysis timeout"
        );
        anyhow::ensure!(
            (128 * 1024 * 1024..=4usize * 1024 * 1024 * 1024).contains(&self.limits.memory_bytes),
            "Invalid memory limit"
        );
        anyhow::ensure!(
            (1024..=16 * 1024 * 1024).contains(&self.limits.request_bytes)
                && (1..=10_000).contains(&self.limits.source_files),
            "Invalid input limits"
        );
        anyhow::ensure!(
            self.limits.file_bytes <= self.limits.source_bytes
                && self.limits.source_bytes <= 64 * 1024 * 1024
                && self.limits.archive_bytes <= 64 * 1024 * 1024
                && self.limits.expanded_bytes <= 128 * 1024 * 1024
                && self.limits.result_bytes <= 128 * 1024 * 1024
                && self.limits.result_bytes > 0,
            "Invalid byte limits"
        );
        for origin in &self.cors_origins {
            let url = url::Url::parse(origin)?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https")
                    && url.host_str().is_some()
                    && url.username().is_empty()
                    && url.password().is_none()
                    && url.path() == "/"
                    && url.query().is_none()
                    && url.fragment().is_none()
                    && url.origin().ascii_serialization() == *origin,
                "CORS requires exact http(s) origins without trailing slash or wildcard"
            );
        }
        for repo in &self.allowed_repositories {
            super::sources::validate_slug(repo)
                .map_err(|_| anyhow::anyhow!("Invalid GitHub repository allowlist entry"))?;
        }
        anyhow::ensure!(
            self.worker_exe.is_absolute() && self.worker_exe.is_file(),
            "Worker executable must be an existing absolute path"
        );
        if let Some(cargo) = &self.cargo_bin {
            anyhow::ensure!(
                cargo.is_absolute() && cargo.is_file(),
                "Cargo executable must be an existing absolute trusted executable"
            );
        }
        anyhow::ensure!(
            self.curl_bin.is_absolute(),
            "curl must be an absolute trusted executable path"
        );
        Ok(())
    }
}

fn csv(name: &str) -> BTreeSet<String> {
    std::env::var(name)
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}
fn number(name: &str, default: usize) -> anyhow::Result<usize> {
    match std::env::var(name) {
        Ok(value) => value
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid numeric backend configuration")),
        Err(_) => Ok(default),
    }
}
fn default_curl() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
            .join("System32/curl.exe")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/usr/bin/curl")
    }
}
pub fn discover_cargo() -> Option<PathBuf> {
    let output = std::process::Command::new("rustup")
        .args(["which", "cargo"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    (path.is_absolute() && path.is_file()).then_some(path)
}
