use super::{
    config::Limits,
    contracts::{AnalysisRequest, ApiError, Source},
};
use std::{
    collections::{BTreeSet, HashSet},
    fs,
    io::{Read, Write},
    net::{IpAddr, ToSocketAddrs},
    path::Path,
    process::{Command, Stdio},
};

#[derive(Clone)]
pub struct Repository {
    pub slug: String,
    pub commit: String,
}

pub fn validate_slug(slug: &str) -> Result<(), ApiError> {
    let parts: Vec<_> = slug.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|s| {
            s.is_empty()
                || s.len() > 100
                || !s.as_bytes()[0].is_ascii_alphanumeric()
                || s.contains("..")
                || !s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        })
    {
        return Err(ApiError::invalid(
            "Expected an ASCII owner/repository identifier",
        ));
    }
    Ok(())
}

pub fn repository(
    url: &str,
    commit: &str,
    allowed: &BTreeSet<String>,
) -> Result<Repository, ApiError> {
    if url.len() > 512 || url.contains('%') || url.contains('\\') {
        return Err(ApiError::invalid("Unsupported repository URL"));
    }
    let parsed = url::Url::parse(url).map_err(|_| ApiError::invalid("Invalid repository URL"))?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("github.com")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(ApiError::invalid(
            "Only credential-free HTTPS github.com repository URLs are supported",
        ));
    }
    let path = parsed
        .path()
        .strip_prefix('/')
        .unwrap_or("")
        .strip_suffix('/')
        .unwrap_or(parsed.path().trim_start_matches('/'));
    let slug = path
        .strip_suffix(".git")
        .unwrap_or(path)
        .to_ascii_lowercase();
    validate_slug(&slug)?;
    if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::invalid(
            "A full 40-character commit SHA is required",
        ));
    }
    if !allowed.contains(&slug) {
        return Err(ApiError::new(
            actix_web::http::StatusCode::FORBIDDEN,
            "repository_not_allowed",
            "Remote access is disabled for this repository",
        ));
    }
    Ok(Repository {
        slug,
        commit: commit.to_ascii_lowercase(),
    })
}

pub fn source_path(path: &str) -> Result<(), ApiError> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
    {
        return Err(ApiError::invalid("Unsupported source file path"));
    }
    for component in path.split('/') {
        let stem = component
            .split('.')
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        if component.is_empty()
            || component.starts_with('.')
            || component.ends_with('.')
            || component.len() > 100
            || matches!(component, "target" | "node_modules")
            || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || (stem.len() == 4
                && (stem.starts_with("COM") || stem.starts_with("LPT"))
                && matches!(stem.as_bytes()[3], b'1'..=b'9'))
        {
            return Err(ApiError::invalid("Unsupported source file path"));
        }
    }
    if !supported(path) {
        return Err(ApiError::invalid(
            "Only Rust source and Cargo manifests/lockfiles are accepted",
        ));
    }
    Ok(())
}
fn supported(path: &str) -> bool {
    path.ends_with(".rs") || matches!(path.rsplit('/').next(), Some("Cargo.toml" | "Cargo.lock"))
}

struct Budget<'a> {
    limits: &'a Limits,
    seen: HashSet<String>,
    total: u64,
    rust: bool,
}
impl<'a> Budget<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            seen: HashSet::new(),
            total: 0,
            rust: false,
        }
    }
    fn add(&mut self, path: &str, size: u64) -> Result<(), ApiError> {
        source_path(path)?;
        if !self.seen.insert(path.to_ascii_lowercase()) {
            return Err(ApiError::invalid("Duplicate source file path"));
        }
        self.total = self
            .total
            .checked_add(size)
            .ok_or_else(|| ApiError::invalid("Source budget exceeded"))?;
        if self.seen.len() > self.limits.source_files
            || size > self.limits.file_bytes
            || self.total > self.limits.source_bytes
        {
            return Err(ApiError::new(
                actix_web::http::StatusCode::PAYLOAD_TOO_LARGE,
                "source_limit",
                "Source file count or byte limit exceeded",
            ));
        }
        self.rust |= path.ends_with(".rs");
        Ok(())
    }
}

pub fn validate(
    request: &AnalysisRequest,
    limits: &Limits,
    allowed: &BTreeSet<String>,
) -> Result<(), ApiError> {
    match &request.source {
        Source::Snapshot { files } => {
            let mut budget = Budget::new(limits);
            for file in files {
                budget.add(&file.path, file.content.len() as u64)?;
            }
            if !budget.rust {
                return Err(ApiError::invalid(
                    "At least one Rust source file is required",
                ));
            }
        }
        Source::Github { url, commit } => {
            repository(url, commit, allowed)?;
        }
    }
    Ok(())
}

pub fn stage_snapshot(request: &AnalysisRequest, root: &Path) -> Result<(), ApiError> {
    if let Source::Snapshot { files } = &request.source {
        for file in files {
            let path = root.join(&file.path);
            fs::create_dir_all(path.parent().unwrap()).map_err(|_| ApiError::internal())?;
            let mut output = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .map_err(|_| ApiError::invalid("Duplicate or invalid source path"))?;
            output
                .write_all(file.content.as_bytes())
                .map_err(|_| ApiError::internal())?;
        }
    }
    Ok(())
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let n = u32::from(v);
            ![
                (0, 8),
                (0x0a000000, 8),
                (0x64400000, 10),
                (0x7f000000, 8),
                (0xa9fe0000, 16),
                (0xac100000, 12),
                (0xc0000000, 24),
                (0xc0000200, 24),
                (0xc0586300, 24),
                (0xc0a80000, 16),
                (0xc6120000, 15),
                (0xc6336400, 24),
                (0xcb007100, 24),
                (0xe0000000, 3),
            ]
            .iter()
            .any(|(base, bits)| n & (u32::MAX << (32 - bits)) == *base)
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && s[1] < 0x0200)
                && !(s[0] == 0x2001 && s[1] == 0x0db8)
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}

pub fn fetch(
    repo: &Repository,
    curl: &Path,
    archive: &Path,
    limits: &Limits,
) -> Result<(), ApiError> {
    let version = Command::new(curl)
        .args(["--disable", "--version"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ApiError::invalid("Remote retrieval tool is unavailable"))?;
    let text = String::from_utf8_lossy(&version.stdout);
    let version = text.split_whitespace().nth(1).unwrap_or("");
    let numbers: Vec<_> = version
        .split('.')
        .filter_map(|p| p.parse::<u32>().ok())
        .collect();
    if numbers.len() < 2 || (numbers[0], numbers[1]) < (8, 4) {
        return Err(ApiError::invalid(
            "Remote retrieval requires curl 8.4 or newer",
        ));
    }
    let addresses: Vec<_> = ("codeload.github.com", 443)
        .to_socket_addrs()
        .map_err(|_| ApiError::invalid("Repository provider DNS failed"))?
        .collect();
    if addresses.is_empty() || addresses.iter().any(|a| !public_ip(a.ip())) {
        return Err(ApiError::invalid(
            "Repository provider resolved to a prohibited address",
        ));
    }
    let address = addresses
        .iter()
        .find(|a| a.is_ipv4())
        .ok_or_else(|| ApiError::invalid("Repository provider requires a public IPv4 address"))?;
    let output = Command::new(curl)
        .args([
            "--disable",
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-redirs",
            "0",
            "--noproxy",
            "*",
            "--tlsv1.2",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "--max-filesize",
        ])
        .arg(limits.archive_bytes.to_string())
        .arg("--resolve")
        .arg(format!("codeload.github.com:443:{}", address.ip()))
        .arg("--output")
        .arg(archive)
        .args(["--write-out", "%{http_code}"])
        .arg(format!(
            "https://codeload.github.com/{}/tar.gz/{}",
            repo.slug, repo.commit
        ))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .map_err(|_| ApiError::invalid("Repository retrieval failed"))?;
    if !output.status.success()
        || output.stdout != b"200"
        || fs::metadata(archive)
            .map_err(|_| ApiError::invalid("Repository retrieval failed"))?
            .len()
            > limits.archive_bytes
    {
        return Err(ApiError::invalid(
            "Repository retrieval failed or exceeded its limit",
        ));
    }
    Ok(())
}

struct Bounded<R> {
    inner: R,
    left: u64,
}
impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            let mut extra = [0];
            return if self.inner.read(&mut extra)? == 0 {
                Ok(0)
            } else {
                Err(std::io::Error::other("expanded archive limit"))
            };
        }
        let n = buffer.len().min(self.left as usize);
        let got = self.inner.read(&mut buffer[..n])?;
        self.left -= got as u64;
        Ok(got)
    }
}
fn octal(bytes: &[u8]) -> Result<u64, ApiError> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| ApiError::invalid("Invalid tar header"))?
        .trim_matches(['\0', ' ']);
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| ApiError::invalid("Unsupported tar numeric format"))
}
fn tar_text(bytes: &[u8]) -> Result<String, ApiError> {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes[..end].to_vec())
        .map_err(|_| ApiError::invalid("Invalid archive path encoding"))
}
fn read_exact(reader: &mut impl Read, bytes: &mut [u8]) -> Result<(), ApiError> {
    reader
        .read_exact(bytes)
        .map_err(|_| ApiError::invalid("Malformed or oversized source archive"))
}

pub fn unpack(
    archive: &Path,
    root: &Path,
    repo: &Repository,
    limits: &Limits,
) -> Result<(), ApiError> {
    let file = fs::File::open(archive).map_err(|_| ApiError::internal())?;
    let mut reader = Bounded {
        inner: flate2::read::GzDecoder::new(file),
        left: limits.expanded_bytes,
    };
    let mut budget = Budget::new(limits);
    let mut entries = 0usize;
    let mut next_path = None;
    let expected = format!("{}-{}", repo.slug.split('/').nth(1).unwrap(), repo.commit);
    loop {
        let mut header = [0u8; 512];
        read_exact(&mut reader, &mut header)?;
        if header.iter().all(|b| *b == 0) {
            let mut end = [0; 512];
            read_exact(&mut reader, &mut end)?;
            if end.iter().any(|b| *b != 0) {
                return Err(ApiError::invalid("Invalid tar terminator"));
            }
            break;
        }
        entries += 1;
        if entries > limits.source_files.saturating_mul(4).min(20_000) {
            return Err(ApiError::invalid("Archive entry limit exceeded"));
        }
        let checksum = octal(&header[148..156])?;
        let actual: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum();
        if checksum != actual {
            return Err(ApiError::invalid("Invalid tar checksum"));
        }
        let size = octal(&header[124..136])?;
        if size > limits.expanded_bytes {
            return Err(ApiError::invalid("Archive entry size exceeded"));
        }
        let kind = header[156];
        if kind == b'x' || kind == b'g' {
            if size > 16 * 1024 {
                return Err(ApiError::invalid("Archive metadata limit exceeded"));
            }
            let mut bytes = vec![0; size as usize];
            read_exact(&mut reader, &mut bytes)?;
            let path = parse_pax(&bytes, kind == b'g')?;
            if next_path.is_some() {
                return Err(ApiError::invalid("Ambiguous archive metadata"));
            }
            next_path = path;
        } else {
            if !matches!(kind, 0 | b'0' | b'5') {
                return Err(ApiError::invalid(
                    "Links and special archive entries are prohibited",
                ));
            }
            let name = tar_text(&header[..100])?;
            let prefix = tar_text(&header[345..500])?;
            let path = next_path.take().unwrap_or_else(|| {
                if prefix.is_empty() {
                    name
                } else {
                    format!("{prefix}/{name}")
                }
            });
            if path.starts_with('/')
                || path.contains('\\')
                || path.contains(':')
                || path.split('/').any(|p| p == ".." || p == ".")
            {
                return Err(ApiError::invalid("Unsafe archive path"));
            }
            let (top, relative) = path.split_once('/').unwrap_or((&path, ""));
            if !top.eq_ignore_ascii_case(&expected) {
                return Err(ApiError::invalid("Unexpected repository archive root"));
            }
            if kind == b'5' {
                if size != 0 {
                    return Err(ApiError::invalid("Invalid archive directory"));
                }
            } else if supported(relative) {
                budget.add(relative, size)?;
                let path = root.join(relative);
                fs::create_dir_all(path.parent().unwrap()).map_err(|_| ApiError::internal())?;
                let mut target = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                    .map_err(|_| ApiError::invalid("Duplicate source path"))?;
                let copied = std::io::copy(&mut reader.by_ref().take(size), &mut target)
                    .map_err(|_| ApiError::invalid("Invalid source archive"))?;
                if copied != size {
                    return Err(ApiError::invalid("Truncated source archive"));
                }
            } else {
                let copied = std::io::copy(&mut reader.by_ref().take(size), &mut std::io::sink())
                    .map_err(|_| ApiError::invalid("Invalid archive payload"))?;
                if copied != size {
                    return Err(ApiError::invalid("Truncated source archive"));
                }
            }
        }
        let padding = (512 - size % 512) % 512;
        let mut bytes = vec![0; padding as usize];
        read_exact(&mut reader, &mut bytes)?;
    }
    let mut rest = [0; 4096];
    loop {
        let n = reader
            .read(&mut rest)
            .map_err(|_| ApiError::invalid("Invalid compressed archive"))?;
        if n == 0 {
            break;
        }
        if rest[..n].iter().any(|b| *b != 0) {
            return Err(ApiError::invalid("Trailing archive content is unsupported"));
        }
    }
    if !budget.rust {
        return Err(ApiError::invalid(
            "Archive contains no supported Rust source",
        ));
    }
    Ok(())
}

fn parse_pax(bytes: &[u8], global: bool) -> Result<Option<String>, ApiError> {
    let mut offset = 0;
    let mut path = None;
    while offset < bytes.len() {
        let space = bytes[offset..]
            .iter()
            .position(|b| *b == b' ')
            .ok_or_else(|| ApiError::invalid("Invalid archive metadata"))?;
        let length: usize = std::str::from_utf8(&bytes[offset..offset + space])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| ApiError::invalid("Invalid archive metadata"))?;
        if length <= space + 2
            || length > bytes.len() - offset
            || bytes[offset + length - 1] != b'\n'
        {
            return Err(ApiError::invalid("Invalid archive metadata length"));
        }
        let entry = std::str::from_utf8(&bytes[offset + space + 1..offset + length - 1])
            .map_err(|_| ApiError::invalid("Invalid archive metadata"))?;
        let (key, value) = entry
            .split_once('=')
            .ok_or_else(|| ApiError::invalid("Invalid archive metadata"))?;
        match key {
            "path" if !global && path.is_none() => path = Some(value.to_owned()),
            "comment" | "mtime" | "atime" | "ctime" => {}
            _ => return Err(ApiError::invalid("Unsupported archive metadata override")),
        };
        offset += length;
    }
    Ok(path)
}

// Cargo metadata is offline and never builds code. Keep every manifest-referenced
// filesystem path inside the staged tree; no .cargo config/toolchain files are staged.
pub fn validate_manifests(root: &Path) -> Result<(), ApiError> {
    fn contained(base: &Path, root: &Path, value: &str) -> bool {
        if value.contains('\\')
            || value.contains(':')
            || value.starts_with('/')
            || value.contains('\0')
        {
            return false;
        }
        let mut parts: Vec<_> = base
            .strip_prefix(root)
            .unwrap()
            .components()
            .map(|p| p.as_os_str().to_owned())
            .collect();
        for part in value.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    if parts.pop().is_none() {
                        return false;
                    }
                }
                p => parts.push(p.into()),
            }
        }
        true
    }
    fn check(value: &toml::Value, key: &str, base: &Path, root: &Path) -> bool {
        match value {
            toml::Value::String(s)
                if matches!(
                    key,
                    "path"
                        | "workspace"
                        | "build"
                        | "readme"
                        | "license-file"
                        | "members"
                        | "exclude"
                        | "default-members"
                        | "include"
                ) =>
            {
                contained(base, root, s)
            }
            toml::Value::Table(t) => t.iter().all(|(k, v)| check(v, k, base, root)),
            toml::Value::Array(a) => a.iter().all(|v| check(v, key, base, root)),
            _ => true,
        }
    }
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|_| ApiError::invalid("Invalid source tree"))?;
        if entry.file_type().is_symlink() {
            return Err(ApiError::invalid("Source links are prohibited"));
        }
        if entry.file_name() == "Cargo.toml" {
            let text = fs::read_to_string(entry.path())
                .map_err(|_| ApiError::invalid("Manifest must be UTF-8"))?;
            let value: toml::Value =
                toml::from_str(&text).map_err(|_| ApiError::invalid("Invalid Cargo manifest"))?;
            if !check(&value, "", entry.path().parent().unwrap(), root) {
                return Err(ApiError::invalid(
                    "Manifest paths must stay inside the submitted repository",
                ));
            }
        }
    }
    Ok(())
}
