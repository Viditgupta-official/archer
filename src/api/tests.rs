use super::{config::Limits, contracts::*, privacy, sources::*};
use serde_json::json;
use std::{collections::BTreeSet, fs, io::Write, path::PathBuf};

struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "archer-security-test-{}",
            super::config::random_id().unwrap()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        assert!(
            self.0
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("archer-security-test-")
        );
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn remote_urls_are_allowlisted_pinned_and_not_client_network_targets() {
    let allowed = BTreeSet::from(["owner/repo".into()]);
    let sha = "a".repeat(40);
    assert!(repository("https://github.com/owner/repo.git", &sha, &allowed).is_ok());
    for url in [
        "http://github.com/owner/repo",
        "https://127.0.0.1/owner/repo",
        "https://github.com.evil.test/owner/repo",
        "https://user@github.com/owner/repo",
        "https://github.com:8443/owner/repo",
        "https://github.com/owner/repo?q=x",
        "https://github.com/owner/%72epo",
        "file:///owner/repo",
        "https://github.com/other/repo",
    ] {
        assert!(repository(url, &sha, &allowed).is_err(), "{url}");
    }
    assert!(repository("https://github.com/owner/repo", "main", &allowed).is_err());
    assert!(repository("https://github.com/owner/repo", &sha, &BTreeSet::new()).is_err());
    for ip in [
        "127.0.0.1",
        "10.1.1.1",
        "169.254.169.254",
        "172.31.1.2",
        "192.168.1.1",
        "100.64.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "198.18.0.1",
        "::1",
        "fc00::1",
        "fe80::1",
        "::ffff:127.0.0.1",
        "2001:db8::1",
    ] {
        assert!(!public_ip(ip.parse().unwrap()), "{ip}");
    }
    assert!(public_ip("140.82.114.10".parse().unwrap()));
    assert!(public_ip("2606:4700::1111".parse().unwrap()));
}

#[test]
fn source_paths_duplicates_and_budgets_fail_closed() {
    for path in [
        "../a.rs",
        "a/../../b.rs",
        "C:/a.rs",
        "/a.rs",
        "a\\b.rs",
        ".cargo/config.toml",
        "a//b.rs",
        "CON.rs",
        "nul/x.rs",
        "a/b.rs.",
        "a.txt",
        "target/a.rs",
        "a/.env",
    ] {
        assert!(source_path(path).is_err(), "{path}");
    }
    assert!(source_path("src/routes-v1.rs").is_ok());
    let request = AnalysisRequest {
        source: Source::Snapshot {
            files: vec![
                SourceFile {
                    path: "src/A.rs".into(),
                    content: "".into(),
                },
                SourceFile {
                    path: "src/a.rs".into(),
                    content: "".into(),
                },
            ],
        },
    };
    assert!(validate(&request, &Limits::default(), &BTreeSet::new()).is_err());
    let mut limits = Limits::default();
    limits.file_bytes = 1;
    let request = AnalysisRequest {
        source: Source::Snapshot {
            files: vec![SourceFile {
                path: "a.rs".into(),
                content: "abc".into(),
            }],
        },
    };
    assert_eq!(
        validate(&request, &limits, &BTreeSet::new())
            .unwrap_err()
            .status,
        413
    );
}

#[test]
fn manifest_references_cannot_escape_the_workspace() {
    let temp = Temp::new();
    for contents in [
        "[dependencies]\nx={path='../outside'}",
        "[workspace]\nmembers=['../../outside']",
        "[package]\nname='x'\nversion='0.1.0'\nbuild='C:/outside.rs'",
        "[package]\nname='x'\nversion='0.1.0'\nworkspace='../'",
    ] {
        fs::write(temp.0.join("Cargo.toml"), contents).unwrap();
        assert!(validate_manifests(&temp.0).is_err(), "{contents}");
    }
    fs::write(
        temp.0.join("Cargo.toml"),
        "[workspace]\nmembers=['crates/*']",
    )
    .unwrap();
    assert!(validate_manifests(&temp.0).is_ok());
}

fn archive(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
    let mut tar = Vec::new();
    for (name, kind, body) in entries {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[124..136].copy_from_slice(format!("{:011o}\0", body.len()).as_bytes());
        header[156] = *kind;
        header[148..156].fill(b' ');
        let checksum: u32 = header.iter().map(|b| *b as u32).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
        tar.extend(header);
        tar.extend_from_slice(body);
        tar.extend(vec![0; (512 - body.len() % 512) % 512]);
    }
    tar.extend([0u8; 1024]);
    let mut zip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    zip.write_all(&tar).unwrap();
    zip.finish().unwrap()
}

#[test]
fn bounded_archive_extraction_rejects_links_traversal_duplicates_and_bombs() {
    let repo = Repository {
        slug: "owner/repo".into(),
        commit: "a".repeat(40),
    };
    let prefix = format!("repo-{}", repo.commit);
    let valid = format!("{prefix}/src/main.rs");
    let escape = format!("{prefix}/../escape.rs");
    let duplicate = format!("{prefix}/src/MAIN.rs");
    let temp = Temp::new();
    let archive_path = temp.0.join("input.gz");
    let output = temp.0.join("source");
    for (i, entries) in [
        vec![(valid.as_str(), b'0', b"fn main() {}".as_slice())],
        vec![(valid.as_str(), b'2', b"".as_slice())],
        vec![(escape.as_str(), b'0', b"".as_slice())],
        vec![
            (valid.as_str(), b'0', b"".as_slice()),
            (duplicate.as_str(), b'0', b"".as_slice()),
        ],
    ]
    .iter()
    .enumerate()
    {
        let destination = output.join(i.to_string());
        fs::create_dir_all(&destination).unwrap();
        fs::write(&archive_path, archive(entries)).unwrap();
        assert_eq!(
            unpack(&archive_path, &destination, &repo, &Limits::default()).is_ok(),
            i == 0
        );
    }
    let mut limits = Limits::default();
    limits.expanded_bytes = 512;
    fs::write(&archive_path, archive(&[(&valid, b'0', b"fn main() {}")])).unwrap();
    let destination = output.join("bomb");
    fs::create_dir(&destination).unwrap();
    assert!(unpack(&archive_path, &destination, &repo, &limits).is_err());
}

#[test]
fn privacy_projection_preserves_structure_without_source_secrets() {
    let temp = Temp::new();
    let secret = "private-token-super-secret";
    let input = json!({"routes":[{"method":"GET","path":"/items","file":temp.0.join("main.rs"),"authorization":[{"kind":"RoleCheck","symbol":secret,"value":secret}]}],"finding_details":[],"graph":{"nodes":[{"id":secret,"label":secret,"kind":"Route","file":temp.0.join("main.rs")}],"edges":[{"from":secret,"to":secret,"relation":"RoutesTo"}]}});
    let value = privacy::project_json(input, &temp.0, false);
    assert!(!value.to_string().contains(secret));
    assert!(
        !value
            .to_string()
            .contains(&temp.0.to_string_lossy().to_string())
    );
    assert_eq!(value["routes"][0]["file"], "main.rs");
    assert_eq!(value["routes"][0]["path"], "/items");
    assert_eq!(
        value["graph"]["nodes"][0]["id"],
        value["graph"]["edges"][0]["from"]
    );
    assert_eq!(value["graph"]["edges"][0]["relation"], "RoutesTo");
}
