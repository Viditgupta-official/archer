use super::{
    config::{ApiConfig, Limits, random_id},
    contracts::*,
    limits, privacy, sources,
};
use actix_web::web::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const IPC_BYTES: u64 = 17 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
struct Input {
    id: String,
    request: AnalysisRequest,
    limits: Limits,
    allowed: BTreeSet<String>,
    curl: PathBuf,
    include_text: bool,
}

pub struct StoredResult {
    pub json: Bytes,
    pub dot: Bytes,
}
pub enum Outcome {
    Succeeded(StoredResult),
    Failed(PublicError),
    TimedOut,
}

struct Workspace {
    path: PathBuf,
    parent: PathBuf,
}
impl Drop for Workspace {
    fn drop(&mut self) {
        if let Ok(path) = self.path.canonicalize() {
            if path != self.parent && path.starts_with(&self.parent) {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
struct Running {
    child: Child,
    limits: limits::ProcessLimits,
    active: bool,
}
impl Drop for Running {
    fn drop(&mut self) {
        if self.active {
            self.limits.terminate();
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

pub fn prepare_root(path: &Path) -> anyhow::Result<PathBuf> {
    if !path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(path)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path)?;
    }
    anyhow::ensure!(
        !fs::symlink_metadata(path)?.file_type().is_symlink(),
        "Work root cannot be a symlink"
    );
    let path = path.canonicalize()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(&path)?;
        anyhow::ensure!(
            m.mode() & 0o077 == 0 && m.uid() == unsafe { libc::geteuid() },
            "Work root must be owned by the service user with mode 0700"
        );
    }
    Ok(path)
}

pub fn run(config: &ApiConfig, id: &str, request: AnalysisRequest) -> Outcome {
    match run_inner(config, id, request) {
        Ok(outcome) => outcome,
        Err(error) => Outcome::Failed(error.public()),
    }
}
fn run_inner(config: &ApiConfig, id: &str, request: AnalysisRequest) -> Result<Outcome, ApiError> {
    let path = config.work_root.join(format!("job-{}", random_id()?));
    fs::create_dir(&path).map_err(|_| ApiError::internal())?;
    let workspace = Workspace {
        path: path.clone(),
        parent: config.work_root.clone(),
    };
    for directory in ["source", "home", "cargo-home", "temp"] {
        fs::create_dir(path.join(directory)).map_err(|_| ApiError::internal())?;
    }
    let input = Input {
        id: id.into(),
        request,
        limits: config.limits.clone(),
        allowed: config.allowed_repositories.clone(),
        curl: config.curl_bin.clone(),
        include_text: config.include_evidence_text,
    };
    let bytes = serde_json::to_vec(&input).map_err(|_| ApiError::internal())?;
    if bytes.len() as u64 > IPC_BYTES {
        return Err(ApiError::invalid("Submission exceeds worker input limit"));
    }
    fs::write(path.join("request.json"), bytes).map_err(|_| ApiError::internal())?;
    let mut command = Command::new(&config.worker_exe);
    command
        .arg("--analysis-worker")
        .current_dir(&path)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
        .env("HOME", path.join("home"))
        .env("USERPROFILE", path.join("home"))
        .env("CARGO_HOME", path.join("cargo-home"))
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TARGET_DIR", path.join("metadata-target"))
        .env("TMP", path.join("temp"))
        .env("TEMP", path.join("temp"))
        .env("TMPDIR", path.join("temp"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", path.join("home/no-git-config"));
    let mut search = Vec::new();
    if let Some(cargo) = &config.cargo_bin {
        let parent = cargo.parent().ok_or_else(ApiError::internal)?;
        search.push(parent.to_owned());
        let rustc = parent.join(if cfg!(windows) { "rustc.exe" } else { "rustc" });
        if rustc.is_file() {
            command.env("RUSTC", rustc);
        }
    }
    #[cfg(windows)]
    {
        let system = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        command.env("SystemRoot", &system);
        search.push(PathBuf::from(system).join("System32"));
    }
    #[cfg(not(windows))]
    {
        search.push(PathBuf::from("/usr/bin"));
        search.push(PathBuf::from("/bin"));
    }
    command.env(
        "PATH",
        std::env::join_paths(search).map_err(|_| ApiError::internal())?,
    );
    limits::prepare(&mut command, &config.limits);
    let start = Instant::now();
    let mut child = command.spawn().map_err(|_| ApiError::internal())?;
    let scope = match limits::ProcessLimits::attach(&child, &config.limits) {
        Ok(scope) => scope,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ApiError::new(
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "isolation_unavailable",
                "Resource-limited worker setup failed",
            ));
        }
    };
    let mut running = Running {
        child,
        limits: scope,
        active: true,
    };
    // A single-byte gate cannot block on a full pipe. The larger request is in
    // a bounded private control file, outside the submitted source directory.
    running
        .child
        .stdin
        .take()
        .ok_or_else(ApiError::internal)?
        .write_all(b"1")
        .map_err(|_| ApiError::internal())?;
    let status = loop {
        if start.elapsed() >= Duration::from_millis(config.limits.wall_ms) {
            return Ok(Outcome::TimedOut);
        }
        for name in ["result.json", "result.tmp", "arg.dot"] {
            if fs::metadata(path.join(name)).is_ok_and(|m| m.len() > config.limits.result_bytes) {
                return Err(ApiError::new(
                    actix_web::http::StatusCode::UNPROCESSABLE_ENTITY,
                    "result_limit",
                    "Analysis result exceeds the configured limit",
                ));
            }
        }
        if let Some(status) = running.child.try_wait().map_err(|_| ApiError::internal())? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        let error = read_bounded(&path.join("failure.json"), 4096)
            .ok()
            .and_then(|b| serde_json::from_slice::<PublicError>(&b).ok())
            .unwrap_or(PublicError {
                code: "worker_failed".into(),
                message: "Analysis worker failed or reached an OS resource limit".into(),
            });
        return Ok(Outcome::Failed(error));
    }
    running.active = false;
    let result = StoredResult {
        json: read_bounded(&path.join("result.json"), config.limits.result_bytes)?.into(),
        dot: read_bounded(&path.join("arg.dot"), config.limits.result_bytes)?.into(),
    };
    drop(running);
    drop(workspace);
    Ok(Outcome::Succeeded(result))
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, ApiError> {
    let file = fs::File::open(path).map_err(|_| ApiError::internal())?;
    if file.metadata().map_err(|_| ApiError::internal())?.len() > limit {
        return Err(ApiError::invalid("Worker output exceeds limit"));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ApiError::internal())?;
    if bytes.len() as u64 > limit {
        return Err(ApiError::invalid("Worker output exceeds limit"));
    }
    Ok(bytes)
}
struct Output {
    file: fs::File,
    left: u64,
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.left {
            return Err(std::io::Error::other("result limit"));
        }
        let n = self.file.write(bytes)?;
        self.left -= n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}
fn write_result(path: &Path, value: &impl Serialize, limit: u64) -> Result<(), ApiError> {
    let mut output = Output {
        file: fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|_| ApiError::internal())?,
        left: limit,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| {
        ApiError::new(
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY,
            "result_limit",
            "Analysis result exceeds the configured limit",
        )
    })?;
    output.flush().map_err(|_| ApiError::internal())
}

/// Internal process entry point; not an HTTP route. No analysis occurs before
/// the parent attaches OS limits and opens the stdin gate.
pub fn worker_main() -> anyhow::Result<()> {
    let mut gate = [0];
    std::io::stdin().read_exact(&mut gate)?;
    anyhow::ensure!(gate == *b"1", "Invalid worker gate");
    let cwd = std::env::current_dir()?;
    let input: Input =
        serde_json::from_slice(&read_bounded(&cwd.join("request.json"), IPC_BYTES)?)?;
    let result = execute(&cwd, &input);
    if let Err(error) = &result {
        let _ = write_result(&cwd.join("failure.json"), &error.public(), 4096);
    }
    result.map_err(Into::into)
}
fn execute(cwd: &Path, input: &Input) -> Result<(), ApiError> {
    sources::validate(&input.request, &input.limits, &input.allowed)?;
    let root = cwd.join("source");
    match &input.request.source {
        Source::Snapshot { .. } => sources::stage_snapshot(&input.request, &root)?,
        Source::Github { url, commit } => {
            let repo = sources::repository(url, commit, &input.allowed)?;
            let archive = cwd.join("archive.tar.gz");
            sources::fetch(&repo, &input.curl, &archive, &input.limits)?;
            sources::unpack(&archive, &root, &repo, &input.limits)?;
        }
    }
    if !root.join("Cargo.toml").exists() {
        fs::write(
            root.join("Cargo.toml"),
            "[package]\nname=\"submitted\"\nversion=\"0.1.0\"\nedition=\"2024\"\n",
        )
        .map_err(|_| ApiError::internal())?;
    }
    sources::validate_manifests(&root)?;
    let report = crate::analyzer::analyze_repository(&root).map_err(|_| {
        ApiError::new(
            actix_web::http::StatusCode::UNPROCESSABLE_ENTITY,
            "analysis_failed",
            "The submitted source could not be analyzed",
        )
    })?;
    let (report, dot) = privacy::project_report(report, &root, input.include_text)?;
    if dot.len() as u64 > input.limits.result_bytes {
        return Err(ApiError::invalid("ARG output exceeds limit"));
    }
    fs::write(cwd.join("arg.dot"), dot).map_err(|_| ApiError::internal())?;
    let envelope = AnalysisResult {
        schema_version: SCHEMA_VERSION,
        analysis_id: input.id.clone(),
        engine_version: env!("CARGO_PKG_VERSION"),
        privacy: Privacy {
            evidence_text: if input.include_text {
                "included"
            } else {
                "redacted"
            },
            source_paths: "repository_relative",
            raw_files_available: false,
        },
        report,
        arg_url: format!("/api/v1/analyses/{}/arg", input.id),
        llm_enabled: false,
    };
    write_result(
        &cwd.join("result.tmp"),
        &envelope,
        input.limits.result_bytes,
    )?;
    fs::rename(cwd.join("result.tmp"), cwd.join("result.json"))
        .map_err(|_| ApiError::internal())?;
    Ok(())
}
