use secrethunter::{
    config::{self, Config},
    detect,
    extract::safe_member,
    finding::Identity,
    report,
    scan::{Run, Scanner},
    source,
};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Command,
    sync::{Arc, atomic::AtomicBool},
};
use tempfile::TempDir;

const PASSWORD: &str = "synthetic-potato-passphrase";

fn scan_config(path: &Path, config: Config) -> report::Report {
    let target = source::parse_target(path.to_str().unwrap()).unwrap();
    let mut scanner = Scanner::new(
        config,
        Identity::from_bytes(vec![42; 32]).unwrap(),
        Run::new(60, Arc::new(AtomicBool::new(false))),
        path.to_string_lossy().into(),
        None,
    )
    .unwrap();
    source::scan(&mut scanner, &target, None);
    scanner.finish(path.to_string_lossy().into())
}

fn scan(path: &Path) -> report::Report {
    scan_config(path, Config::default())
}

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args([
            "-c",
            "user.name=Synthetic Test",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {:?}: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn repo() -> TempDir {
    let temp = TempDir::new().unwrap();
    git(temp.path(), &["init", "-b", "main"]);
    temp
}

fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", "--all"]);
    git(root, &["commit", "-m", message]);
    git(root, &["rev-parse", "HEAD"])
}

fn custom_config(extra: &str) -> Config {
    toml::from_str(&format!(
        r#"
version = 1
[ruleset]
builtins = false
[[rules]]
id = "customer-id"
description = "Synthetic customer ID"
category = "sensitive_data"
severity = "high"
confidence = "medium"
regex = '\bCUST-[0-9]{{8}}\b'
secret_group = 0
positive_examples = ["CUST-12345678"]
negative_examples = ["CUST-short"]
{extra}
"#
    ))
    .unwrap()
}

#[test]
fn scans_hidden_ignored_low_entropy_and_redacts_every_report() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join(".env.example"),
        format!("password = \"{PASSWORD}\"\npwd=cat\n"),
    )
    .unwrap();
    fs::write(temp.path().join(".gitignore"), ".env.example\n").unwrap();
    let result = scan(temp.path());
    assert!(result.coverage.complete, "{:?}", result.coverage.entries);
    assert_eq!(result.exit_code, 1);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id.starts_with("generic-secret"))
    );
    for format in ["terminal", "json", "sarif"] {
        let bytes = report::render(&result, format, true).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        // Values are now intentionally shown in the report for fast triage.
        assert!(text.contains(PASSWORD), "{format}");
        if format != "terminal" {
            serde_json::from_str::<Value>(&text).unwrap();
        }
    }
}

#[test]
fn occurrences_are_ordered_most_recent_first_and_show_the_real_value() {
    let temp = repo();
    fs::write(
        temp.path().join("app.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    commit(temp.path(), "first");
    fs::write(
        temp.path().join("app.env"),
        format!("password={PASSWORD}\nother=1\n"),
    )
    .unwrap();
    commit(temp.path(), "second");
    let result = scan(temp.path());
    let finding = result
        .findings
        .iter()
        .find(|f| f.value == PASSWORD)
        .expect("the real matched value is stored on the finding");
    assert!(
        finding.occurrences.len() >= 3,
        "expect working tree + two historical commits"
    );
    // The working-tree occurrence (always the most current state) must sort
    // before every historical commit occurrence.
    assert_eq!(finding.occurrences[0].source, "working_tree");
    let commit_times: Vec<_> = finding.occurrences[1..]
        .iter()
        .map(|o| o.commit_time.unwrap_or(i64::MIN))
        .collect();
    assert!(
        commit_times.windows(2).all(|w| w[0] >= w[1]),
        "historical occurrences must be sorted newest-first: {commit_times:?}"
    );
    for format in ["terminal", "json", "markdown", "html"] {
        let text = String::from_utf8(report::render(&result, format, true).unwrap()).unwrap();
        assert!(text.contains(PASSWORD), "{format} must show the real value");
    }
}

#[test]
fn finds_deleted_renamed_branched_and_tagged_secrets_without_running_hooks() {
    let temp = repo();
    fs::write(
        temp.path().join("removed.env"),
        format!("password={PASSWORD}"),
    )
    .unwrap();
    let first = commit(temp.path(), "initial");
    git(
        temp.path(),
        &["tag", "-a", "v1", "-m", "token=synthetic-tag-token"],
    );
    git(temp.path(), &["branch", "exposed"]);
    fs::rename(
        temp.path().join("removed.env"),
        temp.path().join("renamed.env"),
    )
    .unwrap();
    let renamed = commit(temp.path(), "rename");
    fs::remove_file(temp.path().join("renamed.env")).unwrap();
    commit(temp.path(), "token=synthetic-commit-token");
    let hook_marker = temp.path().join("HOOK_EXECUTED");
    let hook = temp.path().join(".git/hooks/post-checkout");
    fs::write(
        &hook,
        format!("#!/bin/sh\ntouch '{}'\n", hook_marker.display()),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    git(
        temp.path(),
        &["config", "core.fsmonitor", hook.to_str().unwrap()],
    );
    git(
        temp.path(),
        &["config", "filter.malicious.smudge", hook.to_str().unwrap()],
    );
    let result = scan(temp.path());
    assert!(result.coverage.complete, "{:?}", result.coverage.entries);
    assert_eq!(result.exit_code, 1);
    assert!(!hook_marker.exists());
    let f = result
        .findings
        .iter()
        .find(|f| f.occurrences.iter().any(|o| o.path == "removed.env"))
        .unwrap();
    assert_eq!(f.lifecycle, "historical_only");
    assert!(
        f.occurrences
            .iter()
            .any(|o| o.commit.as_deref() == Some(&first))
    );
    assert!(
        f.occurrences
            .iter()
            .any(|o| o.path == "renamed.env" && o.commit.as_deref() == Some(&renamed))
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.occurrences.iter().any(|o| o.source == "tag_message"))
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.occurrences.iter().any(|o| o.source == "commit_message"))
    );
    assert!(
        result
            .coverage
            .resolved_refs
            .contains_key("refs/heads/exposed")
    );
    assert!(result.coverage.resolved_refs.contains_key("refs/tags/v1"));
}

#[test]
fn subtree_never_scans_sibling_files_or_history() {
    let temp = repo();
    fs::create_dir(temp.path().join("service")).unwrap();
    fs::write(temp.path().join("service/readme"), "nothing sensitive").unwrap();
    fs::write(
        temp.path().join("sibling.env"),
        format!("password={PASSWORD}"),
    )
    .unwrap();
    commit(temp.path(), "password=synthetic-global-message");
    let result = scan(&temp.path().join("service"));
    assert!(result.coverage.complete, "{:?}", result.coverage.entries);
    assert_eq!(result.exit_code, 0);
    assert!(result.findings.is_empty());
}

#[test]
fn detached_head_and_shallow_scope_are_visible() {
    let temp = repo();
    fs::write(temp.path().join("secret"), format!("password={PASSWORD}")).unwrap();
    let first = commit(temp.path(), "initial");
    git(temp.path(), &["checkout", "--detach"]);
    git(temp.path(), &["branch", "-D", "main"]);
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 1);
    assert_eq!(result.coverage.resolved_refs.get("HEAD"), Some(&first));
    fs::write(temp.path().join(".git/shallow"), format!("{first}\n")).unwrap();
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 2);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason.contains("Shallow"))
    );
}

#[test]
fn empty_git_repository_is_a_complete_scan() {
    let temp = repo();
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 0, "{:?}", result.coverage.entries);
}

#[test]
fn malicious_alternates_and_git_extensions_are_rejected() {
    let temp = repo();
    fs::write(
        temp.path().join(".git/objects/info/alternates"),
        "/tmp/untrusted-objects\n",
    )
    .unwrap();
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 2);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason.contains("alternates"))
    );
    fs::remove_file(temp.path().join(".git/objects/info/alternates")).unwrap();
    git(temp.path(), &["config", "extensions.untrusted", "true"]);
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 2);
}

#[test]
fn local_history_off_ignores_git_metadata_and_all_requires_git() {
    let temp = repo();
    fs::write(temp.path().join("removed"), format!("password={PASSWORD}")).unwrap();
    commit(temp.path(), "initial");
    fs::remove_file(temp.path().join("removed")).unwrap();
    let mut config = Config::default();
    config.scan.history = "off".into();
    assert_eq!(scan_config(temp.path(), config).exit_code, 0);
    let plain = TempDir::new().unwrap();
    let mut config = Config::default();
    config.scan.history = "all".into();
    assert_eq!(scan_config(plain.path(), config).exit_code, 2);
}

#[test]
fn glob_semantics_are_root_relative_segment_aware_and_strict() {
    for (pattern, yes, no) in [
        ("**/*.env", ".env", "config.env/more"),
        (
            "**/node_modules/**",
            "node_modules/pkg/a",
            "node_modulesX/pkg/a",
        ),
        (
            "exports/**",
            "exports/customer.csv",
            "nested/exports/customer.csv",
        ),
        ("a/**/b", "a/b", "a/c"),
        ("*.json", ".hidden.json", "nested/file.json"),
        ("a/?.txt", "a/x.txt", "a/xy.txt"),
    ] {
        let re = config::glob(pattern).unwrap();
        assert!(re.is_match(yes), "{pattern} should match {yes}");
        assert!(!re.is_match(no), "{pattern} should not match {no}");
    }
    for invalid in [
        "../secret",
        "/tmp/**",
        "foo/../bar",
        "foo/**bar",
        "!foo",
        "a/[bc]",
    ] {
        if invalid == "!foo" {
            continue;
        }
        assert!(config::glob(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn custom_rules_context_keywords_paths_entropy_and_validators() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("exports")).unwrap();
    fs::write(
        temp.path().join("exports/customers.csv"),
        "customer\nCUST-12345678\n",
    )
    .unwrap();
    fs::write(temp.path().join("other.csv"), "customer\nCUST-87654321\n").unwrap();
    let config = custom_config(
        r#"
paths = ["exports/**"]
keywords = ["CUST"]
[rules.context]
any_of = ["customer"]
within_lines = 1
"#,
    );
    config::validate(&config, true).unwrap();
    assert_eq!(detect::test_rules(&custom_config("")).unwrap(), 2);
    let result = scan_config(temp.path(), config);
    assert_eq!(result.active_occurrences, 1);
    assert_eq!(
        result.findings[0].occurrences[0].matched_path_level,
        Some(0)
    );
    assert!(detect::luhn("4111 1111 1111 1111"));
    assert!(!detect::luhn("4111 1111 1111 1112"));
    assert!(detect::entropy("aaaa") < 1.0);
    assert!(detect::entropy("abcd") >= 2.0);
}

#[test]
fn suppression_selectors_are_and_expiry_is_enforced_and_audit_is_visible() {
    let temp = TempDir::new().unwrap();
    fs::create_dir(temp.path().join("fixtures")).unwrap();
    fs::write(
        temp.path().join("fixtures/a"),
        "CUST-12345678 CUST-87654321",
    )
    .unwrap();
    fs::write(temp.path().join("outside"), "CUST-12345678").unwrap();
    let config = custom_config(
        r#"
[[ignore.suppressions]]
id = "synthetic"
rule_ids = ["customer-id"]
paths = ["fixtures/**"]
value_regex = 'CUST-12345678'
reason = "Synthetic fixture"
owner = "security@example.invalid"
ticket = "TEST-1"
expires = "2099-12-31"
"#,
    );
    config::validate(&config, true).unwrap();
    let result = scan_config(temp.path(), config.clone());
    assert_eq!(result.active_occurrences, 2);
    assert_eq!(result.suppressed_occurrences, 1);
    let normal: Value =
        serde_json::from_slice(&report::render(&result, "json", false).unwrap()).unwrap();
    let audit: Value =
        serde_json::from_slice(&report::render(&result, "json", true).unwrap()).unwrap();
    let occurrences = |v: &Value| {
        v["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["occurrences"].as_array().unwrap().len())
            .sum::<usize>()
    };
    assert_eq!(occurrences(&normal), 2);
    assert_eq!(occurrences(&audit), 3);
    let mut expired = config;
    expired.ignore.suppressions[0].expires = "2000-01-01".into();
    assert!(config::validate(&expired, true).is_err());
    config::validate(&expired, false).unwrap();
    let result = scan_config(temp.path(), expired);
    assert_eq!(result.active_occurrences, 3);
    assert_eq!(result.suppressed_occurrences, 0);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason.contains("Expired"))
    );
}

#[test]
fn exclusions_apply_to_current_historical_and_archive_paths() {
    let temp = repo();
    fs::create_dir(temp.path().join("excluded")).unwrap();
    fs::write(temp.path().join("excluded/secret"), "CUST-12345678").unwrap();
    write_zip(
        &temp.path().join("data.zip"),
        &[("excluded/inside", b"CUST-12345678")],
    );
    commit(temp.path(), "initial");
    let mut config = custom_config("");
    config.ignore.exclude_paths = vec!["excluded/**".into()];
    let result = scan_config(temp.path(), config);
    assert!(result.coverage.complete, "{:?}", result.coverage.entries);
    assert_eq!(result.exit_code, 0);
    assert!(result.findings.is_empty());
    assert!(result.coverage.excluded_counts["excluded/**"] >= 3);
}

fn write_zip(path: &Path, files: &[(&str, &[u8])]) {
    let file = File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for (name, bytes) in files {
        zip.start_file(*name, zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(bytes).unwrap();
    }
    zip.finish().unwrap();
}

#[test]
fn decoding_utf16_and_nested_archives_keep_mapped_provenance() {
    use base64::Engine;
    let temp = TempDir::new().unwrap();
    let token = "CUST-12345678";
    let encoded = base64::engine::general_purpose::STANDARD.encode(token);
    fs::write(temp.path().join("base64"), format!("encoded: {encoded}")).unwrap();
    fs::write(temp.path().join("hex"), hex::encode(token)).unwrap();
    fs::write(temp.path().join("percent"), "CUST%2D12345678").unwrap();
    let utf16: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(token.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    fs::write(temp.path().join("utf16"), utf16).unwrap();
    let inner = temp.path().join("inner.zip");
    write_zip(&inner, &[("record.txt", token.as_bytes())]);
    write_zip(
        &temp.path().join("outer.zip"),
        &[("nested.zip", &fs::read(&inner).unwrap())],
    );
    let result = scan_config(temp.path(), custom_config(""));
    assert!(result.coverage.complete, "{:?}", result.coverage.entries);
    assert_eq!(result.findings.len(), 1);
    for kind in ["base64", "hex", "percent", "utf16", "zip"] {
        assert!(
            result.findings[0]
                .occurrences
                .iter()
                .any(|o| o.extraction_chain.contains(&kind.into())),
            "missing {kind}"
        );
    }
    let encoded_occurrence = result.findings[0]
        .occurrences
        .iter()
        .find(|o| o.path == "base64")
        .unwrap();
    assert_eq!(encoded_occurrence.byte_start, 9);
    assert_eq!(encoded_occurrence.byte_end, 9 + encoded.len());
    assert_eq!(
        encoded_occurrence.location_mapping,
        "enclosing_encoded_range"
    );
    assert_eq!(encoded_occurrence.line_start, None);
    let utf16_occurrence = result.findings[0]
        .occurrences
        .iter()
        .find(|o| o.path == "utf16")
        .unwrap();
    assert_eq!(utf16_occurrence.byte_start, 2);
    assert_eq!(utf16_occurrence.byte_end, 2 + token.len() * 2);
    assert!(
        result.findings[0]
            .occurrences
            .iter()
            .any(|o| o.member_chain.len() == 2)
    );
}

#[test]
fn tar_gzip_and_large_multiline_records_are_scanned_without_chunk_gaps() {
    let temp = TempDir::new().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    let content = "CUST-12345678";
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, "record.txt", content.as_bytes())
        .unwrap();
    let tar = builder.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&tar).unwrap();
    fs::write(temp.path().join("records.tar.gz"), gzip.finish().unwrap()).unwrap();
    let mut long = " ".repeat(65530);
    long.push_str("CUST-12345678");
    fs::write(temp.path().join("large-line"), long).unwrap();
    let result = scan_config(temp.path(), custom_config(""));
    assert!(result.coverage.complete, "{:?}", result.coverage.entries);
    assert_eq!(result.active_occurrences, 2);
    assert!(
        result.findings[0]
            .occurrences
            .iter()
            .any(|o| o.extraction_chain == ["gzip", "tar"])
    );
    let multiline = "-----BEGIN PRIVATE KEY-----\nAAAA\nAAAA\n-----END PRIVATE KEY-----";
    fs::write(temp.path().join("key"), multiline).unwrap();
    assert!(
        scan(temp.path())
            .findings
            .iter()
            .any(|f| f.rule_id == "private-key")
    );
}

#[test]
fn unsupported_binary_limits_unsafe_members_and_symlinks_are_honest() {
    let temp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(
        outside.path().join("secret"),
        format!("password={PASSWORD}"),
    )
    .unwrap();
    symlink(outside.path().join("secret"), temp.path().join("link")).unwrap();
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 0);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason.contains("Symlink"))
    );
    fs::write(
        temp.path().join("binary.pdf"),
        b"\0binary\xff CUST-12345678",
    )
    .unwrap();
    let result = scan_config(temp.path(), custom_config(""));
    assert_eq!(
        result.exit_code, 1,
        "binary strings are a limitation by default"
    );
    assert_eq!(result.active_occurrences, 1);
    assert_eq!(result.findings[0].occurrences[0].line_start, None);
    assert_eq!(
        result.findings[0].occurrences[0].location_mapping,
        "binary_string_bytes"
    );
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.status == "limitation" && e.reason == secrethunter::extract::BINARY_STRINGS)
    );
    let mut strict = custom_config("");
    strict.scan.strict_coverage = true;
    assert_eq!(scan_config(temp.path(), strict).exit_code, 2);
    let mut limits = custom_config("");
    limits.scan.max_file_bytes = 4;
    assert_eq!(
        scan_config(temp.path(), limits).exit_code,
        0,
        "oversized files are a limitation by default, not a hard failure"
    );
    let mut strict_limits = custom_config("");
    strict_limits.scan.max_file_bytes = 4;
    strict_limits.scan.strict_coverage = true;
    assert_eq!(scan_config(temp.path(), strict_limits).exit_code, 2);
    fs::remove_file(temp.path().join("binary.pdf")).unwrap();
    write_zip(
        &temp.path().join("unsafe.zip"),
        &[("../escape", b"CUST-12345678")],
    );
    let result = scan_config(temp.path(), custom_config(""));
    assert_eq!(result.exit_code, 2);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason.contains("Unsafe"))
    );
    for name in ["/etc/passwd", "../x", "a/../x", r"C:\secrets", "a/./b"] {
        assert!(!safe_member(name));
    }
}

#[test]
fn archive_member_depth_and_cumulative_budgets_return_incomplete() {
    let temp = TempDir::new().unwrap();
    write_zip(
        &temp.path().join("data.zip"),
        &[("a", b"CUST-12345678"), ("b", b"CUST-87654321")],
    );
    let mut config = custom_config("");
    config.scan.max_expanded_bytes_per_record = 20;
    let result = scan_config(temp.path(), config);
    assert_eq!(result.exit_code, 2);
    assert!(result.coverage.expanded_bytes <= 20);
    let mut config = custom_config("");
    config.scan.max_archive_depth = 0;
    assert_eq!(scan_config(temp.path(), config).exit_code, 2);
    let mut config = custom_config("");
    config.scan.max_archive_members = 1;
    assert_eq!(scan_config(temp.path(), config).exit_code, 2);
}

#[test]
fn fingerprints_survive_line_movement_but_not_new_paths() {
    let temp = TempDir::new().unwrap();
    let path = temp.path().join("one");
    fs::write(&path, "CUST-12345678").unwrap();
    let first = scan_config(temp.path(), custom_config(""));
    fs::write(&path, "\n\nCUST-12345678").unwrap();
    let moved = scan_config(temp.path(), custom_config(""));
    assert_eq!(first.findings[0].secret_id, moved.findings[0].secret_id);
    assert_eq!(
        first.findings[0].occurrences[0].fingerprint,
        moved.findings[0].occurrences[0].fingerprint
    );
    fs::rename(&path, temp.path().join("two")).unwrap();
    let renamed = scan_config(temp.path(), custom_config(""));
    assert_ne!(
        first.findings[0].occurrences[0].fingerprint,
        renamed.findings[0].occurrences[0].fingerprint
    );
}

#[test]
fn failure_thresholds_are_inclusive_and_require_both_dimensions() {
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("data"), "CUST-12345678").unwrap();
    let mut config = custom_config("");
    config.policy.fail_on_severity = "critical".into();
    assert_eq!(scan_config(temp.path(), config).exit_code, 0);
    let mut config = custom_config("");
    config.policy.fail_on_confidence = "high".into();
    assert_eq!(scan_config(temp.path(), config).exit_code, 0);
    let mut config = custom_config("");
    config.policy.fail_on_severity = "high".into();
    config.policy.fail_on_confidence = "medium".into();
    assert_eq!(scan_config(temp.path(), config).exit_code, 1);
}

#[test]
fn cancellation_preserves_partial_report_and_130_takes_precedence() {
    let temp = TempDir::new().unwrap();
    let mut scanner = Scanner::new(
        Config::default(),
        Identity::from_bytes(vec![42; 32]).unwrap(),
        Run::new(60, Arc::new(AtomicBool::new(true))),
        "test".into(),
        None,
    )
    .unwrap();
    source::scan(
        &mut scanner,
        &source::Target::Directory(temp.path().into()),
        None,
    );
    let result = scanner.finish("test".into());
    assert_eq!(result.exit_code, 130);
    assert!(result.interrupted);
    assert!(!result.coverage.complete);
}

#[test]
fn malformed_urls_and_invalid_policies_fail_before_acquisition() {
    for url in [
        "http://github.com/owner/repo",
        "https://evil.invalid/owner/repo",
        "https://user:token@github.com/owner/repo",
        "https://github.com/owner/repo?token=secret",
        "https://github.com/owner/repo#branch",
        "https://github.com/owner/repo/tree/main",
        "https://github.com/owner/repo.git/extra",
        "git@github.com:owner/repo.git",
        "https://github.com/owner/%72epo",
    ] {
        assert!(source::parse_target(url).is_err(), "{url}");
    }
    assert!(source::parse_target("https://github.com/owner/repo.git").is_ok());
    let temp = TempDir::new().unwrap();
    let policy = temp.path().join("policy.toml");
    for text in [
        "version=1\nunknown=true",
        "version=1\nversion=1",
        "[scan]\nworkers='four'",
    ] {
        fs::write(&policy, text).unwrap();
        assert!(config::load(Some(&policy)).is_err());
    }
    for mutate in [
        |c: &mut Config| c.scan.follow_symlinks = true,
        |c: &mut Config| c.scan.workers = 0,
        |c: &mut Config| c.verification.mode = "online".into(),
        |c: &mut Config| c.output.redact = false,
        |c: &mut Config| c.rules[0].regex = "(?=no)".into(),
        |c: &mut Config| c.rules[0].secret_group = 10,
        |c: &mut Config| c.rules[0].validators = vec!["execute".into()],
    ] {
        let mut config = custom_config("");
        mutate(&mut config);
        assert!(config::validate(&config, true).is_err());
    }
}

#[test]
fn private_keys_reports_and_cli_exit_codes() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("secret.env"), format!("password={PASSWORD}")).unwrap();
    let key = temp.path().join("identity.key");
    fs::write(&key, [42; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    let output = target.join("result.json");
    fs::write(&output, format!("password={PASSWORD}")).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .args([
            "scan",
            target.to_str().unwrap(),
            "--history",
            "off",
            "--format",
            "json",
            "--key-file",
            key.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let bytes = fs::read(&output).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains(PASSWORD), "value must be shown for triage");
    let report: Value = serde_json::from_str(&text).unwrap();
    assert!(report["active_occurrences"].as_u64().unwrap() >= 1);
    assert!(report["findings"].as_array().unwrap().iter().all(|f| {
        f["occurrences"]
            .as_array()
            .unwrap()
            .iter()
            .all(|o| o["path"] == "secret.env")
    }));
    assert_eq!(
        fs::metadata(&output).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(Identity::load(&key, false).is_ok());
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Identity::load(&key, false).is_err());
}

#[test]
fn quoted_passwords_keep_the_complete_exact_value() {
    let temp = TempDir::new().unwrap();
    let value = "synthetic horse's battery staple";
    fs::write(
        temp.path().join("config"),
        format!("password=\"{value}\"\nsecret='synthetic simple phrase'"),
    )
    .unwrap();
    let result = scan(temp.path());
    let identity = Identity::from_bytes(vec![42; 32]).unwrap();
    let expected = identity.fingerprint("secrethunter.secret.v1", &[value]);
    assert!(result.findings.iter().any(|f| f.secret_id == expected));
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "generic-secret-single-quoted")
    );
    assert!(
        String::from_utf8(report::render(&result, "json", true).unwrap())
            .unwrap()
            .contains(value)
    );
}

#[test]
fn provider_signatures_detect_synthetic_formats() {
    let temp = TempDir::new().unwrap();
    let fixtures = [
        ("aws-access-key", format!("AKIA{}", "0".repeat(16))),
        ("github-token", format!("ghp_{}", "a".repeat(36))),
        ("slack-token", format!("xoxb-{}", "0".repeat(20))),
        ("stripe-secret-key", format!("sk_test_{}", "0".repeat(24))),
        ("google-api-key", format!("AIza{}", "0".repeat(35))),
    ];
    fs::write(
        temp.path().join("synthetic"),
        fixtures
            .iter()
            .map(|(_, value)| value.as_str())
            .collect::<Vec<_>>()
            .join("\n"),
    )
    .unwrap();
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 1);
    for (id, value) in fixtures {
        assert!(result.findings.iter().any(|f| f.rule_id == id), "{id}");
        assert!(
            String::from_utf8(report::render(&result, "json", true).unwrap())
                .unwrap()
                .contains(&value)
        );
    }
}

#[test]
fn cached_blobs_reapply_path_and_exact_commit_suppressions() {
    let temp = repo();
    fs::create_dir(temp.path().join("fixtures")).unwrap();
    fs::write(temp.path().join("fixtures/a"), "CUST-12345678").unwrap();
    let first = commit(temp.path(), "initial");
    fs::write(temp.path().join("outside"), "CUST-12345678").unwrap();
    commit(temp.path(), "another location");
    let config = custom_config(&format!(
        r#"
[[ignore.suppressions]]
id = "first-fixture-only"
rule_ids = ["customer-id"]
paths = ["fixtures/**"]
commit_ids = ["{first}"]
reason = "Synthetic historical exception"
owner = "security@example.invalid"
ticket = "TEST-1"
expires = "2099-12-31"
"#
    ));
    let result = scan_config(temp.path(), config);
    // History records the commit that introduced each path/blob; the shared blob is
    // read once but suppression is reevaluated for each path and commit.
    assert_eq!(result.suppressed_occurrences, 1);
    assert_eq!(result.active_occurrences, 3);
    assert_eq!(result.coverage.cached_records, 1);
    assert_eq!(result.findings[0].lifecycle, "present_in_current_tree");
}

#[test]
fn nofollow_handles_reject_symlinks_in_every_component() {
    let temp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("value"), PASSWORD).unwrap();
    symlink(outside.path(), temp.path().join("link")).unwrap();
    let root = File::open(temp.path()).unwrap();
    assert!(source::open_relative(&root, Path::new("link/value"), false).is_err());
    assert!(source::open_relative(&root, Path::new("../value"), false).is_err());
}

#[test]
fn record_finding_and_decode_limits_never_return_clean_success() {
    use base64::Engine;
    let temp = TempDir::new().unwrap();
    fs::write(temp.path().join("a"), "CUST-12345678 CUST-87654321").unwrap();
    fs::write(temp.path().join("b"), "safe").unwrap();
    let mut config = custom_config("");
    config.scan.max_records = 1;
    assert_eq!(scan_config(temp.path(), config).exit_code, 2);
    let mut config = custom_config("");
    config.scan.max_findings = 1;
    assert_eq!(scan_config(temp.path(), config).exit_code, 2);
    fs::write(
        temp.path().join("a"),
        base64::engine::general_purpose::STANDARD.encode("CUST-12345678"),
    )
    .unwrap();
    let mut config = custom_config("");
    config.scan.max_decode_depth = 0;
    let result = scan_config(temp.path(), config);
    assert_eq!(result.exit_code, 2);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason.contains("Decoding nesting"))
    );
}

#[test]
fn text_documents_are_complete_and_untrusted_metadata_is_masked() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("CUST-12345678\n!.pdf"),
        "%PDF-1.7 CUST-12345678",
    )
    .unwrap();
    let mut config = custom_config("");
    config.rules[0].description = "A record for CUST-12345678".into();
    let result = scan_config(temp.path(), config);
    assert_eq!(result.exit_code, 1);
    assert!(result.findings[0].description.contains("[REDACTED]"));
    assert!(
        result.findings[0].occurrences[0]
            .path
            .contains("[REDACTED]")
    );
    assert_eq!(result.findings[0].value, "CUST-12345678");
    for format in ["terminal", "json", "sarif", "markdown", "html"] {
        let text = String::from_utf8(report::render(&result, format, true).unwrap()).unwrap();
        // The matched value is now shown (for triage), but the path/description
        // that happen to also spell it out stay masked. Markdown backslash-escapes
        // punctuation, so compare with escaping characters stripped out.
        let unescaped: String = text.chars().filter(|&c| c != '\\').collect();
        assert!(
            unescaped.contains("CUST-12345678"),
            "{format} missing value: {text}"
        );
        assert!(!text.contains('\u{1b}'), "{format} has escape byte");
        assert!(
            unescaped.contains("[REDACTED]"),
            "{format} missing redaction marker: {text}"
        );
    }
}

#[test]
fn missing_historical_objects_preserve_current_findings_but_fail_coverage() {
    let temp = repo();
    fs::write(temp.path().join("secret"), format!("password={PASSWORD}")).unwrap();
    commit(temp.path(), "initial");
    let blob = git(temp.path(), &["rev-parse", "HEAD:secret"]);
    fs::remove_file(
        temp.path()
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .unwrap();
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 2);
    assert!(!result.findings.is_empty());
}

#[test]
fn bare_repositories_and_sha256_object_formats_are_supported() {
    let temp = repo();
    fs::write(temp.path().join("secret"), format!("password={PASSWORD}")).unwrap();
    commit(temp.path(), "initial");
    let storage = TempDir::new().unwrap();
    let bare = storage.path().join("bare.git");
    git(
        storage.path(),
        &[
            "clone",
            "--bare",
            temp.path().to_str().unwrap(),
            bare.to_str().unwrap(),
        ],
    );
    assert_eq!(scan(&bare).exit_code, 1);
    let sha256 = TempDir::new().unwrap();
    git(
        sha256.path(),
        &["init", "--object-format=sha256", "-b", "main"],
    );
    fs::write(sha256.path().join("secret"), format!("password={PASSWORD}")).unwrap();
    let id = commit(sha256.path(), "initial");
    assert_eq!(id.len(), 64);
    let result = scan(sha256.path());
    assert_eq!(result.exit_code, 1, "{:?}", result.coverage.entries);
}

#[test]
fn policy_schema_is_strict_and_example_rules_pass() {
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .args(["config", "schema"])
        .output()
        .unwrap();
    assert!(result.status.success());
    let schema: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(schema["additionalProperties"], false);
    let config = config::load(Some(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/secrethunter.toml"),
    ))
    .unwrap();
    config::validate(&config, false).unwrap();
    assert_eq!(detect::test_rules(&config).unwrap(), 6);
}

fn cli_key(temp: &Path) -> std::path::PathBuf {
    let key = temp.join("identity.key");
    fs::write(&key, [42; 32]).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    key
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[test]
fn github_adapter_fetches_local_mock_branches_tags_and_default_snapshot() {
    let temp = repo();
    fs::write(temp.path().join("deleted"), format!("password={PASSWORD}")).unwrap();
    commit(temp.path(), "initial");
    git(temp.path(), &["tag", "v1"]);
    fs::remove_file(temp.path().join("deleted")).unwrap();
    commit(temp.path(), "deleted");
    let tools = TempDir::new().unwrap();
    let real_git = Command::new("/bin/sh")
        .args(["-c", "command -v git"])
        .output()
        .unwrap();
    let real_git = String::from_utf8(real_git.stdout)
        .unwrap()
        .trim()
        .to_string();
    let wrapper = tools.path().join("git");
    fs::write(&wrapper, format!(
        "#!/bin/sh\nfor arg do\n shift\n case \"$arg\" in\n https://github.com/synthetic/fixture) set -- \"$@\" {} ;;\n *) set -- \"$@\" \"$arg\" ;;\n esac\ndone\nexec {} -c protocol.file.allow=always \"$@\"\n",
        shell_quote(temp.path().to_str().unwrap()), shell_quote(&real_git)
    )).unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let key = cli_key(tools.path());
    let path = format!(
        "{}:{}",
        tools.path().display(),
        std::env::var("PATH").unwrap()
    );
    for (history, expected) in [("auto", 1), ("off", 0)] {
        let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
            .env("PATH", &path)
            .args([
                "scan",
                "https://github.com/synthetic/fixture",
                "--history",
                history,
                "--key-file",
                key.to_str().unwrap(),
                "--format",
                "json",
                "--output",
                "-",
            ])
            .output()
            .unwrap();
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(result.status.code(), Some(expected), "{report}");
        assert_eq!(report["coverage"]["complete"], true);
        if history == "auto" {
            assert!(report["findings"].as_array().unwrap().iter().any(|f| {
                f["occurrences"].as_array().unwrap().iter().any(|o| {
                    o["url"].as_str().is_some_and(|u| {
                        u.starts_with("https://github.com/synthetic/fixture/blob/")
                    })
                })
            }));
        }
        let stdout = String::from_utf8(result.stdout).unwrap();
        if history == "auto" {
            assert!(stdout.contains(PASSWORD));
        } else {
            assert!(!stdout.contains(PASSWORD));
        }
    }
}

#[test]
fn remote_authentication_failures_and_empty_repositories_are_distinct() {
    let tools = TempDir::new().unwrap();
    let key = cli_key(tools.path());
    let wrapper = tools.path().join("git");
    let path = format!(
        "{}:{}",
        tools.path().display(),
        std::env::var("PATH").unwrap()
    );
    for (body, expected) in [
        ("exit 0", 0),
        (
            "for arg do\n if [ \"$arg\" = ls-remote ]; then\n printf '%s\\n' \"Authentication failed $SECRETHUNTER_AUTH_TOKEN\" >&2\n exit 1\n fi\ndone\nexit 0",
            2,
        ),
    ] {
        fs::write(&wrapper, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
            .env("PATH", &path)
            .env("SYNTHETIC_GITHUB_TOKEN", "synthetic-private-auth-fixture")
            .args([
                "scan",
                "https://github.com/synthetic/fixture",
                "--github-token-env",
                "SYNTHETIC_GITHUB_TOKEN",
                "--key-file",
                key.to_str().unwrap(),
                "--format",
                "json",
                "--output",
                "-",
            ])
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(expected));
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["coverage"]["complete"], expected == 0);
        assert!(
            !String::from_utf8(result.stdout)
                .unwrap()
                .contains("synthetic-private-auth-fixture")
        );
        assert!(
            !String::from_utf8(result.stderr)
                .unwrap()
                .contains("synthetic-private-auth-fixture")
        );
    }
}

#[test]
fn nested_annotated_tags_retain_each_tag_object_and_ref() {
    let temp = repo();
    fs::write(temp.path().join("safe"), "safe").unwrap();
    commit(temp.path(), "initial");
    git(
        temp.path(),
        &[
            "tag",
            "-a",
            "inner",
            "-m",
            "token=synthetic-nested-tag-secret",
        ],
    );
    let inner = git(temp.path(), &["rev-parse", "refs/tags/inner"]);
    git(
        temp.path(),
        &["tag", "-a", "outer", "inner", "-m", "outer annotation"],
    );
    git(temp.path(), &["tag", "-d", "inner"]);
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 1);
    let occurrence = result
        .findings
        .iter()
        .flat_map(|f| &f.occurrences)
        .find(|o| o.tag.as_deref() == Some(&inner))
        .unwrap();
    assert_eq!(occurrence.ref_name.as_deref(), Some("refs/tags/outer"));
    assert!(occurrence.commit.is_none());
}

#[test]
fn pem_validator_uses_envelope_parsing_not_key_activity_claims() {
    let mut spec = detect::builtin_rules()
        .into_iter()
        .find(|r| r.id == "private-key")
        .unwrap();
    spec.validators = vec!["pem".into()];
    let rule = detect::CompiledRule::new(spec).unwrap();
    assert_eq!(
        rule.matches("-----BEGIN PRIVATE KEY-----\nc3ludGhldGlj\n-----END PRIVATE KEY-----")
            .len(),
        1
    );
    assert!(
        rule.matches("-----BEGIN PRIVATE KEY-----\n%%%\n-----END PRIVATE KEY-----")
            .is_empty()
    );
}

#[test]
fn cli_interruption_cancels_git_and_removes_private_workspaces() {
    let tools = TempDir::new().unwrap();
    let key = cli_key(tools.path());
    let wrapper = tools.path().join("git");
    let ready = tools.path().join("ready");
    fs::write(
        &wrapper,
        format!("#!/bin/sh\nfor arg do\n if [ \"$arg\" = ls-remote ]; then : > {}; sleep 30; fi\ndone\nexit 0\n",
            shell_quote(ready.to_str().unwrap())),
    )
    .unwrap();
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:{}",
        tools.path().display(),
        std::env::var("PATH").unwrap()
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .env("PATH", path)
        .env("TMPDIR", tools.path())
        .args([
            "scan",
            "https://github.com/synthetic/fixture",
            "--key-file",
            key.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            "-",
            "--timeout-seconds",
            "10",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !ready.exists() && std::time::Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    if child.try_wait().unwrap().is_none() {
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(child.id() as i32).unwrap(),
            rustix::process::Signal::INT,
        )
        .unwrap();
    }
    let result = child.wait_with_output().unwrap();
    assert!(ready.exists(), "Mock Git did not become ready.");
    assert_eq!(result.status.code(), Some(130));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["coverage"]["complete"], false);
    assert_eq!(report["interrupted"], true);
    assert!(!fs::read_dir(tools.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("secrethunter-")
    }));
}

#[test]
fn archive_limits_are_cumulative_across_records_and_include_directories() {
    let temp = TempDir::new().unwrap();
    write_zip(&temp.path().join("a.zip"), &[("a", b"CUST-12345678")]);
    write_zip(&temp.path().join("b.zip"), &[("b", b"CUST-87654321")]);
    let mut config = custom_config("");
    config.scan.max_archive_members = 1;
    assert_eq!(scan_config(temp.path(), config).exit_code, 2);
    let mut config = custom_config("");
    config.scan.max_expanded_bytes_total = 20;
    let result = scan_config(temp.path(), config);
    assert_eq!(result.exit_code, 2);
    assert!(result.coverage.expanded_bytes <= 20);
    let file = File::create(temp.path().join("directories.zip")).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    for name in ["first/", "second/"] {
        zip.add_directory(name, zip::write::SimpleFileOptions::default())
            .unwrap();
    }
    zip.finish().unwrap();
    fs::remove_file(temp.path().join("a.zip")).unwrap();
    fs::remove_file(temp.path().join("b.zip")).unwrap();
    let mut config = custom_config("");
    config.scan.max_archive_members = 1;
    assert_eq!(scan_config(temp.path(), config).exit_code, 2);
}

fn stable_report(report: &report::Report) -> Value {
    let mut value = serde_json::to_value(report).unwrap();
    value["scan_id"] = Value::Null;
    // Worker count is part of the effective policy digest by design.
    value["policy_digest"] = Value::Null;
    for finding in value["findings"].as_array_mut().unwrap() {
        finding["scan_id"] = Value::Null;
    }
    value
}

#[test]
fn parallel_workers_produce_identical_reports_to_single_worker() {
    let temp = repo();
    for dir in 0..6 {
        fs::create_dir_all(temp.path().join(format!("d{dir}"))).unwrap();
        for file in 0..40 {
            fs::write(
                temp.path().join(format!("d{dir}/f{file}.env")),
                format!("password=synthetic-{dir}-{file}\nCUST-{dir:04}{file:04}\n"),
            )
            .unwrap();
        }
    }
    commit(temp.path(), "initial");
    for file in 0..20 {
        fs::write(
            temp.path().join(format!("d0/f{file}.env")),
            format!("token=synthetic-rotated-{file}\n"),
        )
        .unwrap();
    }
    commit(temp.path(), "rotate");
    let mut reports = Vec::new();
    for workers in [1, 8] {
        let mut config = custom_config("");
        config.ruleset.builtins = true;
        config.scan.workers = workers;
        let result = scan_config(temp.path(), config);
        assert_eq!(result.exit_code, 1, "{:?}", result.coverage.entries);
        reports.push(stable_report(&result));
    }
    assert_eq!(reports[0], reports[1]);
}

#[test]
fn packed_and_loose_history_are_both_read_through_isolated_storage() {
    let temp = repo();
    fs::write(
        temp.path().join("packed"),
        format!("password={PASSWORD}-packed"),
    )
    .unwrap();
    commit(temp.path(), "packed");
    git(temp.path(), &["gc", "--quiet"]);
    fs::remove_file(temp.path().join("packed")).unwrap();
    fs::write(
        temp.path().join("loose"),
        format!("password={PASSWORD}-loose"),
    )
    .unwrap();
    commit(temp.path(), "loose");
    fs::remove_file(temp.path().join("loose")).unwrap();
    commit(temp.path(), "cleanup");
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 1, "{:?}", result.coverage.entries);
    for path in ["packed", "loose"] {
        assert!(
            result
                .findings
                .iter()
                .any(|f| f.lifecycle == "historical_only"
                    && f.occurrences.iter().any(|o| o.path == path)),
            "missing historical {path}"
        );
    }
}

#[test]
fn loose_object_expansion_is_bounded_by_the_run_budget() {
    let temp = repo();
    fs::write(temp.path().join("large"), "0".repeat(64 * 1024)).unwrap();
    commit(temp.path(), "compressible");
    let mut config = Config::default();
    config.scan.max_expanded_bytes_total = 16 * 1024;
    let result = scan_config(temp.path(), config);
    assert_eq!(result.exit_code, 2);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason.contains("expanded-byte budget"))
    );
}

#[test]
fn plain_progress_reports_stages_without_paths_or_values() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("target");
    fs::create_dir(&target).unwrap();
    let sensitive_name = "CUST-12345678-name.env";
    fs::write(target.join(sensitive_name), format!("password={PASSWORD}")).unwrap();
    let key = cli_key(temp.path());
    let output = temp.path().join("result.json");
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .args([
            "scan",
            target.to_str().unwrap(),
            "--progress",
            "plain",
            "--key-file",
            key.to_str().unwrap(),
            "--format",
            "json",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("Enumerating files"), "{stderr}");
    assert!(stderr.contains("scanning 1 objects"), "{stderr}");
    assert!(stderr.contains("scan complete"), "{stderr}");
    assert!(stderr.contains("report written to"), "{stderr}");
    assert!(!stderr.contains(sensitive_name));
    assert!(!stderr.contains(PASSWORD));
    let quiet = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .args([
            "scan",
            target.to_str().unwrap(),
            "--progress",
            "off",
            "--key-file",
            key.to_str().unwrap(),
            "--format",
            "json",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert!(quiet.stderr.is_empty());
}

#[test]
fn short_values_do_not_garble_scanner_text_or_unrelated_words() {
    let temp = repo();
    fs::create_dir(temp.path().join("admin")).unwrap();
    fs::write(
        temp.path().join("admin/notes"),
        "secret=synthetic-notes-value",
    )
    .unwrap();
    fs::write(
        temp.path().join("administrator.cfg"),
        "token=synthetic-unrelated-value",
    )
    .unwrap();
    fs::write(
        temp.path().join("app.env"),
        "password=admin\ntoken=:\nsecret = ::\n",
    )
    .unwrap();
    commit(temp.path(), "initial");
    let result = scan(temp.path());
    let text = String::from_utf8(report::render(&result, "terminal", true).unwrap()).unwrap();
    assert!(text.contains("administrative storage"), "{text}");
    assert!(!text.contains("[REDACTED]istrat"), "{text}");
    assert!(!text.contains("scope[REDACTED]"), "{text}");
    let json = String::from_utf8(report::render(&result, "json", true).unwrap()).unwrap();
    assert!(json.contains("administrator.cfg"));
    assert!(
        json.contains("[REDACTED]/notes"),
        "standalone short value stays masked"
    );
    let identity = Identity::from_bytes(vec![42; 32]).unwrap();
    for junk in [":", "::"] {
        let id = identity.fingerprint("secrethunter.secret.v1", &[junk]);
        assert!(
            !result.findings.iter().any(|f| f.secret_id == id),
            "{junk} detected"
        );
    }
    let admin = identity.fingerprint("secrethunter.secret.v1", &["admin"]);
    assert!(result.findings.iter().any(|f| f.secret_id == admin));
}

#[test]
fn long_values_are_masked_even_inside_file_names() {
    let temp = TempDir::new().unwrap();
    let token = format!("ghp_{}", "Z".repeat(36));
    let name = format!("dump{token}backup.txt");
    fs::write(temp.path().join(&name), &token).unwrap();
    let result = scan(temp.path());
    for format in ["terminal", "json", "sarif"] {
        let text = String::from_utf8(report::render(&result, format, true).unwrap()).unwrap();
        assert!(text.contains(&token), "{format}");
        assert!(text.contains("dump[REDACTED]backup.txt"), "{format}");
    }
}

/// Minimal class file: Utf8 constants (one using modified-UTF-8 NUL), a Long that
/// occupies two pool slots, and a Class reference, followed by class metadata.
fn class_file(secret: &str) -> (Vec<u8>, usize) {
    let mut out = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 61, 0, 6];
    let push_utf8 = |out: &mut Vec<u8>, data: &[u8]| {
        out.push(1);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    };
    push_utf8(&mut out, b"com/example/Config");
    out.push(5);
    out.extend_from_slice(&42u64.to_be_bytes());
    let mut literal = b"key\xc0\x80".to_vec();
    literal.extend_from_slice(secret.as_bytes());
    out.push(1);
    out.extend_from_slice(&(literal.len() as u16).to_be_bytes());
    let secret_offset = out.len() + 5;
    out.extend_from_slice(&literal);
    out.extend_from_slice(&[7, 0, 1]);
    out.extend_from_slice(&[0, 0x21, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    (out, secret_offset)
}

#[test]
fn java_class_constants_are_fully_inspected_inside_jars() {
    let temp = TempDir::new().unwrap();
    let secret = "CUST-12345678";
    let (class, offset) = class_file(secret);
    fs::create_dir(temp.path().join("target")).unwrap();
    write_zip(
        &temp.path().join("target/app.jar"),
        &[
            ("com/example/Config.class", &class),
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
        ],
    );
    let result = scan_config(temp.path(), custom_config(""));
    assert!(result.coverage.complete, "{:?}", result.coverage.entries);
    assert_eq!(result.exit_code, 1);
    let occurrence = &result.findings[0].occurrences[0];
    assert_eq!(occurrence.extraction_chain, ["zip", "java-class"]);
    assert_eq!(occurrence.location_mapping, "class_constant_bytes");
    assert_eq!(occurrence.byte_start, offset);
    assert_eq!(occurrence.byte_end, offset + secret.len());
    assert_eq!(occurrence.line_start, None);

    let mut universal = vec![0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2];
    universal.extend_from_slice(b"\0CUST-87654321\0");
    fs::write(temp.path().join("tool"), universal).unwrap();
    let result = scan_config(temp.path(), custom_config(""));
    assert_eq!(result.exit_code, 1, "readable strings are still inspected");
    let mut strict = custom_config("");
    strict.scan.strict_coverage = true;
    assert_eq!(
        scan_config(temp.path(), strict).exit_code,
        2,
        "Mach-O universal binaries are strings-only coverage"
    );
}

#[test]
fn terminal_report_groups_coverage_and_cli_exclusions_resolve_it() {
    let temp = TempDir::new().unwrap();
    let target = temp.path().join("target");
    fs::create_dir_all(target.join("build")).unwrap();
    for index in 0..10 {
        fs::write(
            target.join(format!("build/blob{index}.bin")),
            b"\0\x01binary",
        )
        .unwrap();
    }
    fs::write(target.join("app.env"), format!("password={PASSWORD}")).unwrap();
    let key = cli_key(temp.path());
    let run = |extra: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_secrethunter"))
            .args([
                "scan",
                target.to_str().unwrap(),
                "--progress",
                "off",
                "--format",
                "terminal",
                "--key-file",
            ])
            .arg(&key)
            .args(extra)
            .output()
            .unwrap()
    };
    let result = run(&[]);
    assert_eq!(result.status.code(), Some(1), "works without configuration");
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("cannot be. (10)"), "{text}");
    assert!(text.contains("... and 7 more"), "{text}");
    assert!(text.contains("Result: exit 1"), "{text}");
    assert!(
        text.contains("generic-secret"),
        "findings remain visible: {text}"
    );
    assert!(text.contains(PASSWORD));
    let result = run(&["--strict-coverage"]);
    assert_eq!(result.status.code(), Some(2));
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("Result: exit 2"), "{text}");
    assert!(text.contains("--exclude"), "{text}");
    let result = run(&["--exclude", "build/**"]);
    assert_eq!(result.status.code(), Some(1));
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("Result: exit 1"), "{text}");
    assert!(text.contains("excluded 10: build/**"), "{text}");
}

#[test]
fn decoded_noise_is_not_reported_as_binary() {
    use base64::Engine;
    let temp = repo();
    let noise =
        base64::engine::general_purpose::STANDARD.encode(b"\x01\x02\x03\x04\x05\x06\x07abcdefgh");
    fs::write(temp.path().join("notes.txt"), format!("branch {noise}\n")).unwrap();
    commit(temp.path(), &format!("Merge branch feature/{noise}"));
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 0, "{:?}", result.coverage.entries);
    assert!(
        !result
            .coverage
            .entries
            .iter()
            .any(|e| e.reason == secrethunter::extract::BINARY_STRINGS),
        "{:?}",
        result.coverage.entries
    );
}

#[test]
fn legacy_encoded_text_and_utf16_binary_strings_are_inspected() {
    let temp = repo();
    fs::write(
        temp.path().join("latin1.properties"),
        b"# caf\xe9 settings\npassword=synthetic-latin1-value\n",
    )
    .unwrap();
    let mut wide = vec![0u8, 1, 2, 3];
    let prefix = wide.len();
    for unit in "password=synthetic-wide-value".encode_utf16() {
        wide.extend_from_slice(&unit.to_le_bytes());
    }
    wide.extend_from_slice(&[0, 0, 0xff]);
    fs::write(temp.path().join("app.dll"), &wide).unwrap();
    git(temp.path(), &["add", "--all"]);
    git(
        temp.path(),
        &[
            "-c",
            "i18n.commitEncoding=ISO-8859-1",
            "commit",
            "-m",
            "init",
        ],
    );
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 1, "{:?}", result.coverage.entries);
    let occurrences: Vec<_> = result
        .findings
        .iter()
        .flat_map(|f| &f.occurrences)
        .collect();
    let latin = occurrences
        .iter()
        .find(|o| o.path == "latin1.properties" && o.source == "working_tree")
        .unwrap();
    assert_eq!(latin.extraction_chain, ["latin1"]);
    assert_eq!(latin.line_start, Some(2));
    let binary = occurrences
        .iter()
        .find(|o| o.path == "app.dll" && o.source == "working_tree")
        .unwrap();
    assert_eq!(binary.extraction_chain, ["binary-strings"]);
    assert_eq!(binary.byte_start, prefix + 2 * "password=".len());
    assert_eq!(binary.byte_end, wide.len() - 3);
}

#[test]
fn github_remote_urls_are_validated_and_canonicalized() {
    use secrethunter::links::github_base;
    for (remote, expected) in [
        (
            "https://github.com/acme/app.git",
            Some("https://github.com/acme/app"),
        ),
        (
            "https://user:token@github.com/acme/app",
            Some("https://github.com/acme/app"),
        ),
        (
            "git@github.com:acme/app.git",
            Some("https://github.com/acme/app"),
        ),
        (
            "ssh://git@github.com/acme/app.git",
            Some("https://github.com/acme/app"),
        ),
        ("https://github.com.evil.example/acme/app", None),
        ("https://evil.example/github.com/acme/app", None),
        ("git@github.com:acme/app/extra", None),
        ("https://github.com/acme/a%22pp", None),
        ("file:///tmp/github.com/acme/app", None),
    ] {
        assert_eq!(github_base(remote).as_deref(), expected, "{remote}");
    }
}

#[test]
fn html_and_markdown_reports_link_to_github_and_escape_target_text() {
    let temp = repo();
    git(
        temp.path(),
        &[
            "remote",
            "add",
            "origin",
            "git@github.com:example-org/example-repo.git",
        ],
    );
    fs::create_dir(temp.path().join("docs")).unwrap();
    let name = "x<b>&\"evil\".env";
    fs::write(temp.path().join(name), format!("password={PASSWORD}\n")).unwrap();
    fs::write(
        temp.path().join("docs/guide.md"),
        "token=synthetic-doc-token\n",
    )
    .unwrap();
    let first = commit(temp.path(), "add config");
    fs::write(
        temp.path().join("untracked.env"),
        "secret=synthetic-untracked\n",
    )
    .unwrap();
    let result = scan(temp.path());
    assert_eq!(result.exit_code, 1);
    let base = "https://github.com/example-org/example-repo";
    assert_eq!(result.repository_url.as_deref(), Some(base));
    let occurrences: Vec<_> = result
        .findings
        .iter()
        .flat_map(|f| &f.occurrences)
        .collect();
    let historical = occurrences
        .iter()
        .find(|o| o.path == "docs/guide.md" && o.source == "git_history")
        .unwrap();
    assert_eq!(
        historical.url.as_deref(),
        Some(format!("{base}/blob/{first}/docs/guide.md?plain=1#L1").as_str())
    );
    let message = occurrences
        .iter()
        .find(|o| o.path == name && o.source == "working_tree")
        .unwrap();
    assert_eq!(
        message.url.as_deref(),
        Some(format!("{base}/blob/{first}/x%3Cb%3E%26%22evil%22.env#L1").as_str())
    );
    assert!(message.file_url.as_deref().unwrap().starts_with("file:///"));
    let untracked = occurrences
        .iter()
        .find(|o| o.path == "untracked.env")
        .unwrap();
    assert!(
        untracked.url.is_none(),
        "untracked files have no GitHub page"
    );
    assert!(untracked.file_url.is_some());

    let html = String::from_utf8(report::render(&result, "html", false).unwrap()).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains(&format!("href=\"{base}/commit/{first}\"")));
    assert!(html.contains("x&lt;b&gt;&amp;&quot;evil&quot;.env"));
    assert!(!html.contains("x<b>"));
    assert!(html.contains(PASSWORD));
    assert!(html.contains("Content-Security-Policy"));
    let markdown = String::from_utf8(report::render(&result, "markdown", false).unwrap()).unwrap();
    assert!(markdown.contains(&format!("({base}/commit/{first})")));
    assert!(markdown.contains("x\\<b\\>\\&\"evil\"\\.env"));
    assert!(markdown.contains(PASSWORD));
}

#[test]
fn links_are_dropped_when_their_path_contains_a_redacted_value() {
    let temp = repo();
    git(
        temp.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example-org/example-repo",
        ],
    );
    fs::create_dir(temp.path().join("exports")).unwrap();
    fs::write(
        temp.path().join("exports/CUST-12345678 copy.txt"),
        "CUST-12345678",
    )
    .unwrap();
    commit(temp.path(), "export");
    let result = scan_config(temp.path(), custom_config(""));
    let occurrences: Vec<_> = result
        .findings
        .iter()
        .flat_map(|f| &f.occurrences)
        .collect();
    assert!(!occurrences.is_empty());
    for occurrence in occurrences {
        assert!(occurrence.path.contains("[REDACTED]"));
        assert!(occurrence.url.is_none() && occurrence.file_url.is_none());
    }
    for format in ["json", "html", "markdown"] {
        let text = String::from_utf8(report::render(&result, format, false).unwrap()).unwrap();
        let unescaped: String = text.chars().filter(|&c| c != '\\').collect();
        // The path stays masked (and is never linked), but the matched value is
        // now shown elsewhere in the report (e.g. the finding's value field).
        assert!(unescaped.contains("CUST-12345678"), "{format}");
        assert!(!text.contains("CUST-12345678%20"), "{format}");
    }
}

#[test]
fn commit_messages_with_legacy_encodings_or_escapes_are_text() {
    for message in [
        b"Caf\xe9 fix for d\xe9ploiement\n".as_slice(),
        b"Fix \x1b[31mcolored\x1b[0m \x02 output\n".as_slice(),
    ] {
        let temp = repo();
        fs::write(temp.path().join("README"), "readme").unwrap();
        fs::write(temp.path().join(".git/msg"), message).unwrap();
        git(temp.path(), &["add", "README"]);
        git(temp.path(), &["commit", "-F", ".git/msg"]);
        let result = scan(temp.path());
        assert_eq!(result.exit_code, 0, "{:?}", result.coverage.entries);
        assert!(
            !result
                .coverage
                .entries
                .iter()
                .any(|e| e.reason == secrethunter::extract::BINARY_STRINGS),
            "{:?}",
            result.coverage.entries
        );
    }
}

#[test]
fn sensitivity_scale_filters_low_entropy_generic_secrets_but_not_signatures() {
    use secrethunter::detect::{entropy, sensitivity_floor};
    let low_value = "aaaaaaaaaaaa";
    assert!(
        entropy(low_value) < sensitivity_floor(0),
        "fixture must be low-entropy enough to be filtered at sensitivity 0"
    );
    assert!(
        entropy(PASSWORD) >= sensitivity_floor(10),
        "fixture must still match at maximum sensitivity"
    );

    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("config.env"),
        format!("password={low_value}\n"),
    )
    .unwrap();
    fs::write(
        temp.path().join("aws.env"),
        "AWS_KEY=AKIAABCDEFGHIJKLMNOP\n",
    )
    .unwrap();

    let mut strict = Config::default();
    strict.scan.sensitivity = 0;
    let result = scan_config(temp.path(), strict);
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.rule_id.starts_with("generic-secret")),
        "low-entropy placeholder should be filtered at sensitivity 0: {:?}",
        result.findings
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id == "aws-access-key"),
        "provider signatures must be unaffected by sensitivity"
    );

    let mut lenient = Config::default();
    lenient.scan.sensitivity = 10;
    let result = scan_config(temp.path(), lenient);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.rule_id.starts_with("generic-secret")),
        "sensitivity 10 must restore full detection"
    );
}

#[test]
fn sensitivity_out_of_range_is_rejected_by_policy_validation() {
    let mut config = Config::default();
    config.scan.sensitivity = 11;
    assert!(config::validate(&config, true).is_err());
}

#[test]
fn cli_rejects_out_of_range_sensitivity() {
    let temp = TempDir::new().unwrap();
    let key = cli_key(temp.path());
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .args([
            "scan",
            temp.path().to_str().unwrap(),
            "--sensitivity",
            "11",
            "--key-file",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
}

#[test]
fn default_output_is_a_named_html_file_in_the_current_directory() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("secret.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    let key = cli_key(temp.path());
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args(["scan", ".", "--key-file", key.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("report written to"), "{stderr}");
    let produced: Vec<_> = fs::read_dir(temp.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("SecretHunter-") && name.ends_with(".html"))
        .collect();
    assert_eq!(produced.len(), 1, "{:?}", produced);
    let html = fs::read_to_string(temp.path().join(&produced[0])).unwrap();
    assert!(html.starts_with("<!doctype html>"));
    assert!(html.contains("id=\"sh-search\""));
    assert!(html.contains("class=\"finding searchable"));
    assert!(html.contains(PASSWORD));
}

#[test]
fn llm_verify_flags_are_non_interactive_and_never_block_the_scan() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("secret.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    let key = cli_key(temp.path());

    // No flags at all: without a TTY, LLM verification is never attempted
    // and the scan completes and writes a report as usual.
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--key-file",
            key.to_str().unwrap(),
            "--format",
            "json",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["findings"][0]["llm"].is_null());

    // --no-llm-verify explicitly skips, same outcome.
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--key-file",
            key.to_str().unwrap(),
            "--no-llm-verify",
            "--format",
            "json",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));

    // --llm-verify with an unreachable, explicitly-forced backend skips with
    // a warning instead of failing the scan or blocking on a prompt.
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--key-file",
            key.to_str().unwrap(),
            "--llm-verify",
            "--llm-backend",
            "ollama",
            "--llm-model",
            "fixture-model",
            "--ollama-endpoint",
            "http://127.0.0.1:1",
            "--format",
            "json",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("skipping LLM verification"), "{stderr}");
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["findings"][0]["llm"].is_null());

    // Neither backend reachable and none forced: a clear "no local LLM
    // detected" warning, still never blocking or failing the scan.
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--key-file",
            key.to_str().unwrap(),
            "--llm-verify",
            "--ollama-endpoint",
            "http://127.0.0.1:1",
            "--lmstudio-endpoint",
            "http://127.0.0.1:1",
            "--format",
            "json",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("no local LLM detected"), "{stderr}");
    assert!(
        stderr.contains("online models are not yet supported"),
        "{stderr}"
    );
}

/// Minimal mock Ollama server: answers `/api/tags` with one model and
/// `/api/generate` with a canned verdict, enough to exercise the real CLI
/// flow end-to-end without a real Ollama install.
fn mock_ollama() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                continue;
            }
            let mut content_length = 0usize;
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
                if let Some(value) = header.to_lowercase().strip_prefix("content-length:") {
                    content_length = value.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            std::io::Read::read_exact(&mut reader, &mut body).ok();
            let body = if request_line.contains("/api/tags") {
                r#"{"models":[{"name":"fixture-model"}]}"#
            } else {
                r#"{"response":"LIKELY_FALSE_POSITIVE: synthetic fixture value"}"#
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = std::io::Write::write_all(&mut stream, response.as_bytes());
        }
    });
    (addr, handle)
}

#[test]
fn llm_rule_selection_drops_unselected_categories_from_the_report() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("app.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    fs::write(temp.path().join("customer.txt"), "CUST-12345678").unwrap();
    let policy = temp.path().join("secrethunter.toml");
    fs::write(
        &policy,
        r###"version = 1
[ruleset]
builtins = true
[[rules]]
id = "customer-id"
description = "Synthetic customer ID"
category = "sensitive_data"
severity = "high"
confidence = "medium"
regex = '\bCUST-[0-9]{8}\b'
secret_group = 0
positive_examples = ["CUST-12345678"]
negative_examples = ["CUST-short"]
"###,
    )
    .unwrap();
    let key = cli_key(temp.path());
    let (addr, _server) = mock_ollama();
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--config",
            policy.to_str().unwrap(),
            "--key-file",
            key.to_str().unwrap(),
            "--llm-verify",
            "--llm-backend",
            "ollama",
            "--llm-model",
            "fixture-model",
            "--ollama-endpoint",
            &format!("http://{addr}"),
            "--llm-rule",
            "customer-id",
            "--format",
            "json",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("analyzed"), "{stderr}");
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    let findings = report["findings"].as_array().unwrap();
    assert!(
        findings.iter().all(|f| f["rule_id"] == "customer-id"),
        "categories not selected for LLM triage must be dropped from the report: {report}"
    );
    assert!(
        findings
            .iter()
            .any(|f| f["llm"]["verdict"] == "likely_false_positive"),
        "{report}"
    );
}

#[test]
fn html_report_is_filterable_by_llm_verdict() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("app.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    let key = cli_key(temp.path());
    let (addr, _server) = mock_ollama();
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--key-file",
            key.to_str().unwrap(),
            "--llm-verify",
            "--llm-backend",
            "ollama",
            "--llm-model",
            "fixture-model",
            "--ollama-endpoint",
            &format!("http://{addr}"),
            "--format",
            "html",
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    let html = String::from_utf8(result.stdout).unwrap();
    assert!(
        html.contains("data-llm=\"likely_false_positive\""),
        "the finding's verdict must be attached as a filterable attribute: {html}"
    );
    assert!(html.contains("Filter by LLM verdict"), "{html}");
    assert!(
        html.contains("class=\"sh-llm-check\" value=\"likely_false_positive\""),
        "{html}"
    );
    assert!(html.contains("LIKELY FALSE POSITIVE"), "{html}");
}

#[test]
fn output_dash_forces_stdout_regardless_of_default_format() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("secret.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    let key = cli_key(temp.path());
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--key-file",
            key.to_str().unwrap(),
            "--output",
            "-",
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    let stdout = String::from_utf8(result.stdout).unwrap();
    assert!(stdout.starts_with("<!doctype html>"));
    assert!(
        fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .all(|e| !e.file_name().to_string_lossy().starts_with("SecretHunter-"))
    );
}

#[test]
fn terminal_format_without_output_still_defaults_to_stdout() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("secret.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    let key = cli_key(temp.path());
    let result = Command::new(env!("CARGO_BIN_EXE_secrethunter"))
        .current_dir(temp.path())
        .args([
            "scan",
            ".",
            "--format",
            "terminal",
            "--progress",
            "off",
            "--key-file",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("Result: exit 1")
    );
    assert!(
        fs::read_dir(temp.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .all(|e| !e.file_name().to_string_lossy().starts_with("SecretHunter-"))
    );
}

#[test]
fn html_report_is_searchable_with_collapsed_sections_and_a_summary() {
    let temp = repo();
    fs::write(
        temp.path().join("secret.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    commit(temp.path(), "add secret");
    let result = scan(temp.path());
    let html = String::from_utf8(report::render(&result, "html", false).unwrap()).unwrap();
    assert!(html.contains("id=\"sh-search\""));
    assert!(html.contains("id=\"sh-expand\""));
    assert!(html.contains("id=\"sh-collapse\""));
    assert!(html.contains("<details class=\"section\" id=\"findings-section\">"));
    assert!(!html.contains("<details class=\"section\" id=\"findings-section\" open"));
    assert!(html.contains("class=\"finding searchable"));
    assert!(html.contains("At a glance"));
    assert!(html.contains(&format!(
        "<span class=\"n\">{}</span>",
        result.findings.len()
    )));
    assert!(html.contains("script-src 'unsafe-inline'"));
    assert!(html.contains("<script>"));
}

#[test]
fn oversized_working_tree_files_are_a_default_limitation_not_a_hard_failure() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("small.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    fs::write(temp.path().join("huge.bin"), vec![b'a'; 10_000]).unwrap();
    let mut config = Config::default();
    config.scan.max_file_bytes = 100;
    let result = scan_config(temp.path(), config);
    assert_eq!(
        result.exit_code, 1,
        "a single oversized build artifact must not force incomplete coverage by default: {:?}",
        result.coverage.entries
    );
    assert!(result.coverage.complete);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.status == "limitation" && e.reason == "Record exceeds file-byte limit.")
    );
    assert_eq!(result.max_file_bytes, 100);

    let mut strict = Config::default();
    strict.scan.max_file_bytes = 100;
    strict.scan.strict_coverage = true;
    let result = scan_config(temp.path(), strict);
    assert_eq!(result.exit_code, 2);
    assert!(!result.coverage.complete);
    assert!(
        result
            .coverage
            .entries
            .iter()
            .any(|e| e.status == "incomplete" && e.reason == "Record exceeds file-byte limit.")
    );
}

#[test]
fn oversized_historical_blobs_are_a_default_limitation_not_a_hard_failure() {
    let temp = repo();
    fs::write(
        temp.path().join("small.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    fs::write(temp.path().join("huge.bin"), vec![b'a'; 10_000]).unwrap();
    commit(temp.path(), "initial");
    let mut config = Config::default();
    config.scan.max_file_bytes = 100;
    let result = scan_config(temp.path(), config);
    assert_eq!(result.exit_code, 1, "{:?}", result.coverage.entries);
    assert!(result.coverage.complete);
    assert!(result.coverage.entries.iter().any(
        |e| e.status == "limitation" && e.reason == "Historical blob exceeds file-byte limit."
    ));
}

#[test]
fn terminal_report_hints_about_oversized_skips_with_the_configured_limit() {
    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("small.env"),
        format!("password={PASSWORD}\n"),
    )
    .unwrap();
    fs::write(temp.path().join("huge.bin"), vec![b'a'; 10_000]).unwrap();
    let mut config = Config::default();
    config.scan.max_file_bytes = 100;
    let result = scan_config(temp.path(), config);
    let text = String::from_utf8(report::render(&result, "terminal", true).unwrap()).unwrap();
    assert!(text.contains("exceed max_file_bytes"), "{text}");
    assert!(text.contains("--max-file-bytes"), "{text}");
    assert!(text.contains("100 B"), "{text}");
}
