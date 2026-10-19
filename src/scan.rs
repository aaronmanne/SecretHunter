use crate::{
    config::{self, Config, confidence_rank, severity_rank},
    detect::Detector,
    extract::{self, Issue, View},
    finding::{Finding, Identity, Occurrence, SuppressionAudit},
    report::{Coverage, CoverageEntry, Report, display_path},
};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct Run {
    pub cancelled: Arc<AtomicBool>,
    deadline: Instant,
}
impl Run {
    pub fn new(seconds: u64, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            deadline: Instant::now() + Duration::from_secs(seconds),
        }
    }
    pub fn stopped(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed) || Instant::now() >= self.deadline
    }
    pub fn interrupted(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
}

pub struct Record {
    pub source: String,
    pub path: String,
    pub commit: Option<String>,
    pub tag: Option<String>,
    pub ref_name: Option<String>,
    pub blob: Option<String>,
    pub current: bool,
    pub bytes: Vec<u8>,
}

#[derive(Clone)]
struct Hit {
    rule: usize,
    secret_id: String,
    start: usize,
    end: usize,
    line_start: Option<usize>,
    line_end: Option<usize>,
    members: Vec<String>,
    chain: Vec<String>,
    mapping: String,
    evidence: Vec<String>,
    value_suppressions: HashSet<usize>,
}
#[derive(Clone)]
struct Cached {
    hits: Vec<Hit>,
    issues: Vec<(Vec<String>, &'static str, bool, Option<String>)>,
}

pub struct Scanner {
    pub(crate) config: Config,
    pub run: Run,
    pub coverage: Coverage,
    pub output: Option<PathBuf>,
    pub protected_paths: Vec<PathBuf>,
    pub runtime_excludes: HashSet<String>,
    detector: Detector,
    identity: Identity,
    repository_id: String,
    scan_id: String,
    findings: BTreeMap<(String, usize), Finding>,
    excludes: Vec<(String, Regex)>,
    value_regexes: Vec<Option<Regex>>,
    cache: HashMap<String, Cached>,
    raw_values: HashSet<String>,
    raw_value_bytes: usize,
    expanded: u64,
    archive_members: usize,
    occurrence_count: usize,
    capacity_exhausted: bool,
}

impl Scanner {
    pub fn config(&self) -> &Config {
        &self.config
    }

    pub fn new(
        config: Config,
        identity: Identity,
        run: Run,
        repository_id: String,
        output: Option<PathBuf>,
    ) -> Result<Self, String> {
        config::validate(&config, false)?;
        let detector = Detector::new(&config)?;
        let excludes = config
            .ignore
            .exclude_paths
            .iter()
            .map(|p| Ok((p.clone(), config::glob(p)?)))
            .collect::<Result<_, String>>()?;
        let value_regexes = config
            .ignore
            .suppressions
            .iter()
            .map(|s| {
                s.value_regex
                    .as_ref()
                    .map(|r| {
                        Regex::new(&format!(r"\A(?:{r})\z"))
                            .map_err(|_| "Invalid suppression regex.".to_string())
                    })
                    .transpose()
            })
            .collect::<Result<_, _>>()?;
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| "Cannot generate scan identifier.")?;
        let mut scanner = Self {
            config,
            run,
            coverage: Coverage {
                complete: true,
                ..Coverage::default()
            },
            output,
            detector,
            identity,
            repository_id,
            scan_id: hex::encode(id),
            findings: BTreeMap::new(),
            excludes,
            protected_paths: Vec::new(),
            runtime_excludes: HashSet::new(),
            value_regexes,
            cache: HashMap::new(),
            raw_values: HashSet::new(),
            raw_value_bytes: 0,
            expanded: 0,
            archive_members: 0,
            occurrence_count: 0,
            capacity_exhausted: false,
        };
        for _ in scanner
            .config
            .ignore
            .suppressions
            .iter()
            .filter(|s| config::expired(&s.expires))
        {
            scanner.coverage.entries.push(CoverageEntry {
                status: "warning".into(),
                source: "policy".into(),
                path: String::new(),
                reason: "Expired suppression is inactive.".into(),
                pattern: None,
            });
        }
        Ok(scanner)
    }

    pub fn stopped(&self) -> bool {
        self.run.stopped() || self.capacity_exhausted
    }

    pub fn issue(&mut self, source: &str, path: &str, reason: &str, incomplete: bool) {
        if incomplete {
            self.coverage.complete = false;
        }
        if self.coverage.entries.len() < self.config.scan.max_records.min(100_000) {
            self.coverage.entries.push(CoverageEntry {
                status: if incomplete {
                    "incomplete"
                } else {
                    "limitation"
                }
                .into(),
                source: source.into(),
                path: path.into(),
                reason: reason.into(),
                pattern: None,
            });
        } else {
            self.coverage.complete = false;
            self.capacity_exhausted = true;
        }
    }

    pub fn excluded(&mut self, source: &str, path: &str) -> bool {
        if self.runtime_excludes.contains(path) {
            self.scope_exclusion(source, path, "Active report or identity key excluded.");
            return true;
        }
        if let Some((pattern, _)) = self.excludes.iter().find(|(_, re)| re.is_match(path)) {
            self.record_exclusion(source, path, pattern.clone());
            true
        } else {
            false
        }
    }

    pub fn scope_exclusion(&mut self, source: &str, path: &str, reason: &str) {
        *self
            .coverage
            .excluded_counts
            .entry(format!("scope: {reason}"))
            .or_default() += 1;
        if self.coverage.entries.len() < self.config.scan.max_records.min(100_000) {
            self.coverage.entries.push(CoverageEntry {
                status: "excluded".into(),
                source: source.into(),
                path: path.into(),
                reason: reason.into(),
                pattern: None,
            });
        }
    }

    fn record_exclusion(&mut self, source: &str, path: &str, pattern: String) {
        *self
            .coverage
            .excluded_counts
            .entry(pattern.clone())
            .or_default() += 1;
        if self.coverage.entries.len() < self.config.scan.max_records.min(100_000) {
            self.coverage.entries.push(CoverageEntry {
                status: "excluded".into(),
                source: source.into(),
                path: path.into(),
                reason: "Explicit policy exclusion.".into(),
                pattern: Some(pattern),
            });
        }
    }

    pub fn record(&mut self, record: Record) {
        if self.stopped() {
            return;
        }
        if self.coverage.records_scanned >= self.config.scan.max_records {
            self.issue(
                &record.source,
                &record.path,
                "Source record budget exhausted.",
                true,
            );
            self.capacity_exhausted = true;
            return;
        }
        if self.excluded(&record.source, &record.path) {
            return;
        }
        if record.bytes.len() as u64 > self.config.scan.max_file_bytes {
            self.issue(
                &record.source,
                &record.path,
                "Record exceeds file-byte limit.",
                true,
            );
            return;
        }
        self.coverage.records_scanned += 1;
        self.coverage.bytes_scanned += record.bytes.len() as u64;
        let cache_key = record.blob.clone();
        let cached = cache_key
            .as_ref()
            .and_then(|id| self.cache.get(id))
            .cloned();
        let inspection = if let Some(cached) = cached {
            self.coverage.cached_records += 1;
            cached
        } else {
            let mut hits = Vec::new();
            let limits = self.config.scan.clone();
            let run = self.run.clone();
            let excludes = self.excludes.clone();
            let mut expanded = self.expanded;
            let mut archive_members = self.archive_members;
            let issues = extract::inspect(
                &record.bytes,
                &limits,
                &mut expanded,
                &mut archive_members,
                &run,
                &excludes,
                &mut |view| {
                    self.inspect_view(view, &mut hits);
                },
            );
            self.expanded = expanded;
            self.archive_members = archive_members;
            let cached = Cached {
                hits,
                issues: issues
                    .into_iter()
                    .map(
                        |Issue {
                             members,
                             reason,
                             exclusion,
                             pattern,
                         }| (members, reason, exclusion, pattern),
                    )
                    .collect(),
            };
            let weight = cached.hits.len() + cached.issues.len();
            if let Some(key) = cache_key.filter(|_| weight <= 4096) {
                // Only sanitized metadata is cached; no candidate plaintext or persistent cache.
                if self.cache.len() >= 64
                    || self
                        .cache
                        .values()
                        .map(|c| c.hits.len() + c.issues.len())
                        .sum::<usize>()
                        + weight
                        > 16_384
                {
                    self.cache.clear();
                }
                self.cache.insert(key, cached.clone());
            }
            cached
        };
        for (members, reason, exclusion, pattern) in inspection.issues {
            let path = display_path(&record.path, &members);
            if exclusion {
                self.record_exclusion(
                    &record.source,
                    &path,
                    pattern.expect("exclusion has pattern"),
                );
            } else {
                self.issue(&record.source, &path, reason, true);
            }
        }
        for hit in inspection.hits {
            if self.occurrence_count >= self.config.scan.max_findings {
                self.issue(
                    &record.source,
                    &record.path,
                    "Finding occurrence budget exhausted.",
                    true,
                );
                self.capacity_exhausted = true;
                break;
            }
            self.add_hit(&record, hit);
        }
    }

    fn inspect_view(&mut self, view: View, hits: &mut Vec<Hit>) {
        if self.stopped() {
            return;
        }
        let newlines: Vec<_> = view
            .text
            .match_indices('\n')
            .map(|(index, _)| index)
            .collect();
        for candidate in
            self.detector
                .candidates(&view.text, self.config.scan.max_findings + 1, &self.run)
        {
            if hits.len() >= self.config.scan.max_findings {
                self.capacity_exhausted = true;
                self.coverage.complete = false;
                break;
            }
            let secret_id = self
                .identity
                .fingerprint("secrethunter.secret.v1", &[&candidate.value]);
            let value_suppressions = self
                .value_regexes
                .iter()
                .enumerate()
                .filter(|(_, re)| re.as_ref().is_none_or(|re| re.is_match(&candidate.value)))
                .map(|(i, _)| i)
                .collect();
            if !self.raw_values.contains(&candidate.value) {
                if self.raw_values.len() >= self.config.scan.max_findings
                    || self.raw_value_bytes as u64 + candidate.value.len() as u64
                        > self
                            .config
                            .scan
                            .max_expanded_bytes_per_record
                            .min(16 * 1024 * 1024)
                {
                    self.capacity_exhausted = true;
                    self.coverage.complete = false;
                    break;
                }
                self.raw_value_bytes += candidate.value.len();
                self.raw_values.insert(candidate.value);
            }
            let (start, end, mapping) = if let Some((start, end)) = view.mapped_range {
                (start, end, "enclosing_encoded_range")
            } else if let Some(offsets) = &view.offsets {
                (
                    offsets[candidate.start],
                    offsets[candidate.end],
                    "utf16_bytes",
                )
            } else {
                (
                    candidate.start,
                    candidate.end,
                    if view.members.is_empty() {
                        "source_bytes"
                    } else {
                        "member_bytes"
                    },
                )
            };
            let lines = !view.binary && view.mapped_range.is_none();
            hits.push(Hit {
                rule: candidate.rule,
                secret_id,
                start,
                end,
                line_start: lines.then(|| 1 + newlines.partition_point(|&n| n < candidate.start)),
                line_end: lines.then(|| {
                    1 + newlines.partition_point(|&n| n < candidate.end.saturating_sub(1))
                }),
                members: view.members.clone(),
                chain: view.chain.clone(),
                mapping: mapping.into(),
                evidence: candidate.evidence,
                value_suppressions,
            });
        }
    }

    fn add_hit(&mut self, record: &Record, hit: Hit) {
        let rule = &self.detector.rules[hit.rule];
        let paths: Vec<_> = std::iter::once(record.path.as_str())
            .chain(hit.members.iter().map(String::as_str))
            .collect();
        let matched_path_level = if rule.paths.is_empty() {
            None
        } else {
            let level = paths
                .iter()
                .position(|p| rule.paths.iter().any(|re| re.is_match(p)));
            if level.is_none() {
                return;
            }
            level
        };
        let source_kind = match record.source.as_str() {
            "commit_message" => "commit_message",
            "tag_message" => "tag_message",
            _ => "file",
        };
        let provenance =
            serde_json::to_string(&(source_kind, &record.ref_name, &hit.members, &hit.chain))
                .expect("serializable provenance");
        let fingerprint = self.identity.fingerprint(
            "secrethunter.occurrence.v1",
            &[
                &hit.secret_id,
                &rule.spec.id,
                &self.repository_id,
                &record.path,
                &provenance,
            ],
        );
        let suppressions = self
            .config
            .ignore
            .suppressions
            .iter()
            .enumerate()
            .filter(|(index, sup)| {
                !config::expired(&sup.expires)
                    && sup.rule_ids.contains(&rule.spec.id)
                    && hit.value_suppressions.contains(index)
                    && (sup.paths.is_empty()
                        || sup.paths.iter().any(|pattern| {
                            paths.iter().any(|path| {
                                config::glob(pattern)
                                    .expect("validated glob")
                                    .is_match(path)
                            })
                        }))
                    && (sup.commit_ids.is_empty()
                        || record
                            .commit
                            .as_ref()
                            .is_some_and(|id| sup.commit_ids.contains(id)))
                    && (sup.occurrence_fingerprints.is_empty()
                        || sup.occurrence_fingerprints.contains(&fingerprint))
            })
            .map(|(_, sup)| SuppressionAudit {
                id: sup.id.clone(),
                owner: sup.owner.clone(),
                reason: sup.reason.clone(),
                ticket: sup.ticket.clone(),
                expires: sup.expires.clone(),
            })
            .collect();
        let occurrence = Occurrence {
            fingerprint,
            source: record.source.clone(),
            path: record.path.clone(),
            member_chain: hit.members,
            commit: record.commit.clone(),
            tag: record.tag.clone(),
            ref_name: record.ref_name.clone(),
            blob: record.blob.clone(),
            byte_start: hit.start,
            byte_end: hit.end,
            line_start: hit.line_start,
            line_end: hit.line_end,
            extraction_chain: hit.chain,
            location_mapping: hit.mapping,
            matched_path_level,
            suppressions,
        };
        let finding = self
            .findings
            .entry((hit.secret_id.clone(), hit.rule))
            .or_insert_with(|| Finding {
                schema_version: 1,
                scan_id: self.scan_id.clone(),
                secret_id: hit.secret_id,
                rule_id: rule.spec.id.clone(),
                rule_version: hex::encode(Sha256::digest(
                    serde_json::to_vec(&rule.spec).expect("serializable rule"),
                )),
                description: rule.spec.description.clone(),
                category: rule.spec.category.clone(),
                severity: rule.spec.severity.clone(),
                confidence: rule.spec.confidence.clone(),
                evidence_codes: hit.evidence,
                verification: "not_attempted".into(),
                remediation: rule.spec.remediation.clone(),
                value: "[REDACTED]".into(),
                lifecycle: "historical_only".into(),
                occurrences: Vec::new(),
            });
        if record.current {
            finding.lifecycle = "present_in_current_tree".into();
        }
        finding.occurrences.push(occurrence);
        self.occurrence_count += 1;
    }

    pub fn finish(mut self, target: String) -> Report {
        if self.run.stopped() {
            self.issue(
                "scan",
                "",
                if self.run.interrupted() {
                    "Operator interruption."
                } else {
                    "Scan time budget exhausted."
                },
                true,
            );
        }
        if self.capacity_exhausted {
            self.issue(
                "scan",
                "",
                "Resource budget exhausted; requested scope is incomplete.",
                true,
            );
        }
        let mut findings: Vec<_> = self.findings.into_values().collect();
        findings.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then(a.secret_id.cmp(&b.secret_id))
        });
        let mut active = 0;
        let mut suppressed = 0;
        let mut fail = false;
        for finding in &mut findings {
            finding.occurrences.sort_by(|a, b| {
                (
                    &a.path,
                    &a.member_chain,
                    &a.commit,
                    a.byte_start,
                    &a.extraction_chain,
                )
                    .cmp(&(
                        &b.path,
                        &b.member_chain,
                        &b.commit,
                        b.byte_start,
                        &b.extraction_chain,
                    ))
            });
            for o in &finding.occurrences {
                if o.suppressions.is_empty() {
                    active += 1;
                    fail |= severity_rank(&finding.severity)
                        >= severity_rank(&self.config.policy.fail_on_severity)
                        && confidence_rank(&finding.confidence)
                            >= confidence_rank(&self.config.policy.fail_on_confidence);
                } else {
                    suppressed += 1;
                }
            }
        }
        self.coverage.expanded_bytes = self.expanded;
        self.coverage.entries.sort_by(|a, b| {
            (&a.source, &a.path, &a.status, &a.reason)
                .cmp(&(&b.source, &b.path, &b.status, &b.reason))
        });
        let mut report = Report {
            schema_version: 1,
            scanner_version: crate::VERSION.into(),
            scan_id: self.scan_id,
            policy_digest: config::digest(&self.config),
            canonicalization_version: 1,
            key_id: self.identity.key_id,
            target,
            history: self.config.scan.history,
            interrupted: self.run.interrupted(),
            exit_code: if self.run.interrupted() {
                130
            } else if !self.coverage.complete {
                2
            } else if fail {
                1
            } else {
                0
            },
            active_occurrences: active,
            suppressed_occurrences: suppressed,
            findings,
            coverage: self.coverage,
        };
        let mut values: Vec<_> = self.raw_values.into_iter().collect();
        values.sort_by_key(|value| std::cmp::Reverse(value.len()));
        if let Err(reason) = crate::report::redact_metadata(&mut report, &values) {
            report.coverage.complete = false;
            report.exit_code = if report.interrupted { 130 } else { 2 };
            report.target = "[REDACTED: metadata unavailable]".into();
            report.findings.clear();
            report.coverage.entries.clear();
            report.coverage.resolved_refs.clear();
            report.coverage.excluded_counts.clear();
            report.coverage.entries.push(CoverageEntry {
                status: "incomplete".into(),
                source: "report".into(),
                path: String::new(),
                reason: format!("{reason} Unsafe report details were omitted."),
                pattern: None,
            });
        }
        report
    }
}
