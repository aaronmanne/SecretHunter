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

pub fn redact_metadata(report: &mut Report, values: &[String]) -> Result<(), String> {
    let matcher = aho_corasick::AhoCorasick::builder()
        .kind(Some(aho_corasick::AhoCorasickKind::ContiguousNFA))
        .match_kind(aho_corasick::MatchKind::LeftmostLongest)
        .build(values)
        .map_err(|_| "Metadata redaction matcher exceeded implementation limits.".to_string())?;
    let replacements = vec!["[REDACTED]"; values.len()];
    let apply = |text: &mut String, _: &[String]| {
        *text = matcher.replace_all(text, &replacements);
        *text = sanitize(text);
    };
    apply(&mut report.target, values);
    for entry in &mut report.coverage.entries {
        apply(&mut entry.path, values);
        apply(&mut entry.reason, values);
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
            apply(&mut name, values);
            (name, count)
        })
        .collect();
    for finding in &mut report.findings {
        apply(&mut finding.rule_id, values);
        apply(&mut finding.description, values);
        apply(&mut finding.remediation, values);
        for occurrence in &mut finding.occurrences {
            apply(&mut occurrence.path, values);
            if let Some(name) = &mut occurrence.ref_name {
                apply(name, values);
            }
            for member in &mut occurrence.member_chain {
                apply(member, values);
            }
            for sup in &mut occurrence.suppressions {
                apply(&mut sup.id, values);
                apply(&mut sup.owner, values);
                apply(&mut sup.reason, values);
                apply(&mut sup.ticket, values);
                apply(&mut sup.expires, values);
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
            for finding in &report.findings {
                out.push_str(&format!(
                    "\n{} / {}  {}  [REDACTED]\n  {}\n",
                    finding.severity.to_uppercase(),
                    finding.confidence,
                    finding.rule_id,
                    finding.description
                ));
                for o in &finding.occurrences {
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
            for entry in &report.coverage.entries {
                out.push_str(&format!(
                    "  [{}] {}: {}{}\n",
                    entry.status,
                    entry.path,
                    entry.reason,
                    entry
                        .pattern
                        .as_ref()
                        .map_or(String::new(), |p| format!(" (pattern {p})"))
                ));
            }
            for (name, oid) in &report.coverage.resolved_refs {
                out.push_str(&format!("  ref {name} {oid}\n"));
            }
            for (pattern, count) in &report.coverage.excluded_counts {
                out.push_str(&format!("  excluded {count}: {pattern}\n"));
            }
            out.push_str(&format!(
                "Policy: {} | Key: {} | Exit: {}\n",
                report.policy_digest, report.key_id, report.exit_code
            ));
            Ok(out.into_bytes())
        }
        _ => Err("Unknown report format.".into()),
    }
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
                "message": {"text": format!("{}: [REDACTED]", f.description)},
                "locations": [{"logicalLocations": [{"fullyQualifiedName": display_path(&o.path, &o.member_chain), "kind": "member"}]}],
                "partialFingerprints": {"secrethunter/v1": o.fingerprint},
                "properties": {"severity": f.severity, "confidence": f.confidence, "verification": f.verification,
                    "commit": o.commit, "tag": o.tag, "refName": o.ref_name,
                    "byteStart": o.byte_start, "byteEnd": o.byte_end,
                    "lineStart": o.line_start, "lineEnd": o.line_end, "extractionChain": o.extraction_chain,
                    "lifecycle": f.lifecycle, "evidenceCodes": f.evidence_codes}
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
                "activeOccurrences": report.active_occurrences, "suppressedOccurrences": report.suppressed_occurrences}
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
