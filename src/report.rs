use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{self, Write},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoverageEntry {
    pub status: String,
    pub source: String,
    pub path: String,
    pub reason: String,
    pub pattern: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Coverage {
    pub complete: bool,
    pub records_scanned: usize,
    pub bytes_scanned: u64,
    pub expanded_bytes: u64,
    pub cached_records: usize,
    pub excluded_counts: BTreeMap<String, usize>,
    pub entries: Vec<CoverageEntry>,
    pub resolved_refs: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Report {
    pub schema_version: u32,
    pub scanner_version: String,
    pub scan_id: String,
    pub policy_digest: String,
    pub canonicalization_version: u32,
    pub key_id: String,
    pub target: String,
    /// `https://github.com/OWNER/REPO` when links to GitHub can be built.
    pub repository_url: Option<String>,
    /// Effective `scan.max_file_bytes`; surfaced so reporters can explain
    /// oversized-content skips without needing the original policy.
    pub max_file_bytes: u64,
    pub history: String,
    pub interrupted: bool,
    pub exit_code: i32,
    pub active_occurrences: usize,
    pub suppressed_occurrences: usize,
    pub findings: Vec<Finding>,
    pub coverage: Coverage,
}

pub fn sanitize(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c.is_control() {
                c.escape_default().collect::<Vec<_>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

/// Values shorter than this are masked only when they stand alone (not inside a word),
/// so a detected password like `admin` does not garble `administrative`.
const SHORT_VALUE: usize = 8;

struct Masker {
    matcher: aho_corasick::AhoCorasick,
}

impl Masker {
    fn mask(&self, text: &str) -> String {
        let bytes = text.as_bytes();
        let word = |index: Option<usize>| {
            index
                .and_then(|i| bytes.get(i))
                .is_some_and(u8::is_ascii_alphanumeric)
        };
        let mut spans: Vec<(usize, usize)> = self
            .matcher
            .find_overlapping_iter(text)
            .map(|m| (m.start(), m.end()))
            .filter(|&(start, end)| {
                end - start >= SHORT_VALUE
                    || (bytes[start..end].iter().any(u8::is_ascii_alphanumeric)
                        && !word(start.checked_sub(1))
                        && !word(Some(end)))
            })
            .collect();
        spans.sort_unstable();
        let mut out = String::with_capacity(text.len());
        let mut cursor = 0;
        for (start, end) in spans {
            if end <= cursor {
                continue;
            }
            if start > cursor {
                out.push_str(&text[cursor..start]);
            }
            if start >= cursor {
                out.push_str("[REDACTED]");
            }
            cursor = end;
        }
        out.push_str(&text[cursor..]);
        sanitize(&out)
    }
}

/// Masks detected values in target- and policy-derived metadata. Scanner-generated
/// reasons are fixed text and are only control-character sanitized.
pub fn redact_metadata(report: &mut Report, values: &[String]) -> Result<(), String> {
    let masker = Masker {
        matcher: aho_corasick::AhoCorasick::builder()
            .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
            .build(values)
            .map_err(|_| {
                "Metadata redaction matcher exceeded implementation limits.".to_string()
            })?,
    };
    let apply = |text: &mut String, _: &[String]| *text = masker.mask(text);
    let original_target = report.target.clone();
    apply(&mut report.target, values);
    let target_masked = report.target != sanitize(&original_target);
    if report
        .repository_url
        .as_ref()
        .is_some_and(|url| masker.mask(url) != *url)
    {
        report.repository_url = None;
    }
    for entry in &mut report.coverage.entries {
        apply(&mut entry.path, values);
        entry.reason = sanitize(&entry.reason);
        if let Some(pattern) = &mut entry.pattern {
            apply(pattern, values);
        }
    }
    report.coverage.resolved_refs = std::mem::take(&mut report.coverage.resolved_refs)
        .into_iter()
        .map(|(mut name, oid)| {
            apply(&mut name, values);
            (name, oid)
        })
        .collect();
    report.coverage.excluded_counts = std::mem::take(&mut report.coverage.excluded_counts)
        .into_iter()
        .map(|(mut name, count)| {
            if name.starts_with("scope: ") {
                name = sanitize(&name);
            } else {
                apply(&mut name, values);
            }
            (name, count)
        })
        .collect();
    for finding in &mut report.findings {
        apply(&mut finding.rule_id, values);
        apply(&mut finding.description, values);
        apply(&mut finding.remediation, values);
        for occurrence in &mut finding.occurrences {
            let before = (
                occurrence.path.clone(),
                occurrence.ref_name.clone(),
                occurrence.member_chain.clone(),
            );
            apply(&mut occurrence.path, values);
            if let Some(name) = &mut occurrence.ref_name {
                apply(name, values);
            }
            for member in &mut occurrence.member_chain {
                apply(member, values);
            }
            // Links encode paths, so any masked component removes them entirely.
            let masked = occurrence.path != sanitize(&before.0)
                || occurrence.ref_name != before.1.as_deref().map(sanitize)
                || occurrence.member_chain
                    != before.2.iter().map(|m| sanitize(m)).collect::<Vec<_>>();
            for (url, local) in [
                (&mut occurrence.url, false),
                (&mut occurrence.file_url, true),
            ] {
                if masked
                    || (local && target_masked)
                    || report.repository_url.is_none() && !local
                    || url.as_ref().is_some_and(|u| masker.mask(u) != *u)
                {
                    *url = None;
                }
            }
            for sup in &mut occurrence.suppressions {
                apply(&mut sup.id, values);
                apply(&mut sup.owner, values);
                apply(&mut sup.reason, values);
                apply(&mut sup.ticket, values);
                sup.expires = sanitize(&sup.expires);
            }
        }
    }
    Ok(())
}

fn visible(report: &Report, audit: bool) -> Report {
    let mut report = report.clone();
    if !audit {
        for finding in &mut report.findings {
            finding.occurrences.retain(|o| o.suppressions.is_empty());
        }
        report.findings.retain(|f| !f.occurrences.is_empty());
    }
    report
}

pub fn render(report: &Report, format: &str, audit: bool) -> Result<Vec<u8>, String> {
    let report = visible(report, audit);
    match format {
        "json" => {
            serde_json::to_vec_pretty(&report).map_err(|_| "Cannot serialize JSON report.".into())
        }
        "sarif" => serde_json::to_vec_pretty(&sarif(&report))
            .map_err(|_| "Cannot serialize SARIF report.".into()),
        "markdown" => Ok(crate::document::markdown(&report).into_bytes()),
        "html" => Ok(crate::document::html(&report).into_bytes()),
        "terminal" => {
            let mut out = format!(
                "SecretHunter {} | {} | {}\n",
                report.scanner_version,
                if report.coverage.complete {
                    "COMPLETE"
                } else {
                    "INCOMPLETE"
                },
                report.target
            );
            out.push_str(
                "WARNING: this report contains the raw matched value of every finding. \
                 Handle and store it as sensitively as the secrets themselves.\n",
            );
            if report.findings.is_empty() {
                out.push_str("\nNo findings to display.\n");
            }
            for finding in &report.findings {
                out.push_str(&format!(
                    "\n{} / {}  {}  {}\n  {}\n",
                    finding.severity.to_uppercase(),
                    finding.confidence,
                    finding.rule_id,
                    finding.value,
                    finding.description
                ));
                let shown = finding.occurrences.iter().take(1 + TERMINAL_EXAMPLES);
                for o in shown.clone() {
                    out.push_str(&format!(
                        "  {}{}{}{}\n",
                        display_path(&o.path, &o.member_chain),
                        o.line_start.map_or_else(
                            || format!(" @ byte {}", o.byte_start),
                            |line| format!(":{line}")
                        ),
                        o.commit.as_ref().map_or_else(
                            || o.tag.as_ref().map_or(String::new(), |id| format!(
                                " (tag {} {id})",
                                o.ref_name.as_deref().unwrap_or("")
                            )),
                            |id| format!(" (commit {id})")
                        ),
                        if o.suppressions.is_empty() {
                            ""
                        } else {
                            " [SUPPRESSED]"
                        }
                    ));
                    for sup in &o.suppressions {
                        out.push_str(&format!(
                            "    {} | {} | expires {} | {}\n",
                            sup.id, sup.owner, sup.expires, sup.reason
                        ));
                    }
                }
                let hidden = finding.occurrences.len().saturating_sub(shown.count());
                if hidden > 0 {
                    out.push_str(&format!(
                        "  ... and {hidden} earlier occurrence(s) (use --format json or html for all)\n"
                    ));
                }
                if let Some(llm) = &finding.llm {
                    out.push_str(&format!(
                        "  LLM ({}): {} - {}\n",
                        llm.model, llm.verdict, llm.explanation
                    ));
                }
                out.push_str(&format!("  Remediation: {}\n", finding.remediation));
            }
            out.push_str(&format!(
                "\n{} active occurrences; {} suppressed; {} records; {} bytes; {} expanded bytes\n",
                report.active_occurrences,
                report.suppressed_occurrences,
                report.coverage.records_scanned,
                report.coverage.bytes_scanned,
                report.coverage.expanded_bytes
            ));
            terminal_coverage(&report, &mut out);
            Ok(out.into_bytes())
        }
        _ => Err("Unknown report format.".into()),
    }
}

pub fn exit_meaning(code: i32) -> &'static str {
    match code {
        0 => "complete; no active finding meets the failure threshold",
        1 => "complete; active findings meet the failure threshold",
        130 => "interrupted; partial report",
        _ => "requested coverage is INCOMPLETE; see Coverage",
    }
}

/// Coverage entries grouped by status (incomplete first) and reason.
pub fn coverage_groups(report: &Report) -> Vec<(&str, &str, Vec<&CoverageEntry>)> {
    let mut groups: BTreeMap<(u8, &str, &str), Vec<&CoverageEntry>> = BTreeMap::new();
    for entry in &report.coverage.entries {
        let rank = match entry.status.as_str() {
            "incomplete" => 0,
            "warning" => 1,
            "limitation" => 2,
            _ => 3,
        };
        groups
            .entry((rank, &entry.status, &entry.reason))
            .or_default()
            .push(entry);
    }
    groups
        .into_iter()
        .map(|((_, status, reason), entries)| (status, reason, entries))
        .collect()
}

/// Paths shown per coverage group; JSON and SARIF reports keep every entry.
const TERMINAL_EXAMPLES: usize = 3;

fn terminal_coverage(report: &Report, out: &mut String) {
    let groups = coverage_groups(report);
    if !groups.is_empty() {
        out.push_str("\nCoverage:\n");
    }
    for (status, reason, entries) in &groups {
        out.push_str(&format!("  [{status}] {reason} ({})\n", entries.len()));
        for entry in entries
            .iter()
            .filter(|e| !e.path.is_empty())
            .take(TERMINAL_EXAMPLES)
        {
            out.push_str(&format!(
                "      {}{}\n",
                entry.path,
                entry
                    .pattern
                    .as_ref()
                    .map_or(String::new(), |p| format!(" (pattern {p})"))
            ));
        }
        let shown = entries
            .iter()
            .filter(|e| !e.path.is_empty())
            .count()
            .min(TERMINAL_EXAMPLES);
        let hidden = entries.iter().filter(|e| !e.path.is_empty()).count() - shown;
        if hidden > 0 {
            out.push_str(&format!(
                "      ... and {hidden} more (use --format json for every path)\n"
            ));
        }
    }
    for (pattern, count) in &report.coverage.excluded_counts {
        // Scope exclusions are already counted in their coverage group above.
        if !pattern.starts_with("scope: ") {
            out.push_str(&format!("  excluded {count}: {pattern}\n"));
        }
    }
    if !report.coverage.resolved_refs.is_empty() {
        out.push_str(&format!(
            "  {} Git refs resolved{}\n",
            report.coverage.resolved_refs.len(),
            report
                .coverage
                .resolved_refs
                .get("HEAD")
                .map_or(String::new(), |oid| format!(" (HEAD {oid})"))
        ));
    }
    let partial_binaries = report
        .coverage
        .entries
        .iter()
        .filter(|e| e.status == "incomplete" && e.reason == crate::extract::BINARY_STRINGS)
        .count();
    let oversized = report
        .coverage
        .entries
        .iter()
        .filter(|e| {
            e.reason.contains("exceeds the file-byte limit")
                || e.reason.contains("exceeds file-byte limit")
        })
        .count();
    let meaning = exit_meaning(report.exit_code);
    out.push_str(&format!(
        "\nResult: exit {} - {meaning}. {} active and {} suppressed occurrences.\n",
        report.exit_code, report.active_occurrences, report.suppressed_occurrences
    ));
    if partial_binaries > 0 {
        out.push_str(&format!(
            "Hint: strict coverage counts {partial_binaries} strings-only binary inspections as \
             incomplete. Exclude build outputs you do not need to audit, for example \
             --exclude '**/target/**', or omit --strict-coverage.\n"
        ));
    }
    if oversized > 0 {
        out.push_str(&format!(
            "Hint: {oversized} object(s) exceed max_file_bytes ({}) and were skipped entirely \
             (not just partially inspected). Raise --max-file-bytes to cover them, or \
             --exclude the path if it is a build artifact you do not need to audit.\n",
            crate::progress::human_bytes(report.max_file_bytes)
        ));
    }
    out.push_str(&format!(
        "Policy: {} | Key: {}\n",
        report.policy_digest, report.key_id
    ));
}

pub fn display_path(path: &str, members: &[String]) -> String {
    std::iter::once(path)
        .chain(members.iter().map(String::as_str))
        .map(|p| p.replace('!', "\\!"))
        .collect::<Vec<_>>()
        .join("!")
}

fn sarif(report: &Report) -> Value {
    let mut rules = BTreeMap::new();
    let mut results = Vec::new();
    for f in &report.findings {
        rules.entry(&f.rule_id).or_insert(json!({
            "id": f.rule_id, "shortDescription": {"text": f.description},
            "help": {"text": f.remediation}, "properties": {"category": f.category}
        }));
        for o in &f.occurrences {
            // Logical locations avoid turning untrusted repository names into clickable URIs.
            let mut result = json!({
                "ruleId": f.rule_id,
                "level": if f.severity == "low" { "note" } else if f.severity == "medium" { "warning" } else { "error" },
                "message": {"text": format!("{}: {}", f.description, f.value)},
                "locations": [{"logicalLocations": [{"fullyQualifiedName": display_path(&o.path, &o.member_chain), "kind": "member"}]}],
                "partialFingerprints": {"secrethunter/v1": o.fingerprint},
                "properties": {"severity": f.severity, "confidence": f.confidence, "verification": f.verification,
                    "commit": o.commit, "tag": o.tag, "refName": o.ref_name,
                    "webUrl": o.url, "fileUrl": o.file_url,
                    "byteStart": o.byte_start, "byteEnd": o.byte_end,
                    "lineStart": o.line_start, "lineEnd": o.line_end, "extractionChain": o.extraction_chain,
                    "lifecycle": f.lifecycle, "evidenceCodes": f.evidence_codes, "llm": f.llm}
            });
            if !o.suppressions.is_empty() {
                result["suppressions"] = json!([{"kind": "external", "status": "accepted",
                    "justification": o.suppressions.iter().map(|s| s.reason.as_str()).collect::<Vec<_>>().join("; ")}]);
                result["properties"]["suppressionAudit"] = json!(o.suppressions);
            }
            results.push(result);
        }
    }
    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SecretHunter", "version": report.scanner_version,
                "rules": rules.into_values().collect::<Vec<_>>() }},
            "invocations": [{"executionSuccessful": report.coverage.complete,
                "exitCode": report.exit_code, "toolExecutionNotifications":
                    report.coverage.entries.iter().map(|e| json!({
                        "level": if e.status == "incomplete" { "error" } else { "note" },
                        "message": {"text": format!("{}: {}", e.path, e.reason)}
                    })).collect::<Vec<_>>()
            }],
            "results": results,
            "properties": {"coverage": report.coverage, "policyDigest": report.policy_digest,
                "keyId": report.key_id, "scanId": report.scan_id, "interrupted": report.interrupted,
                "activeOccurrences": report.active_occurrences, "suppressedOccurrences": report.suppressed_occurrences,
                "valuesIncluded": true, "valuesIncludedWarning": "This report contains the raw matched value of every finding; handle it as sensitively as the secrets themselves."}
        }]
    })
}

pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|_| "Cannot create private output file.")?;
    temp.write_all(bytes)
        .and_then(|_| temp.write_all(b"\n"))
        .and_then(|_| temp.as_file().sync_all())
        .map_err(|_| "Cannot write report.")?;
    temp.persist(path)
        .map_err(|_| "Cannot atomically replace output report.")?;
    Ok(())
}

pub fn write_stdout(bytes: &[u8]) -> Result<(), String> {
    let mut out = io::stdout().lock();
    out.write_all(bytes)
        .and_then(|_| out.write_all(b"\n"))
        .map_err(|_| "Cannot write report to stdout.".into())
}
