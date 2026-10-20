use crate::{
    config::{self, Config, ScanConfig, confidence_rank, severity_rank},
    detect::Detector,
    extract::{self, Issue, View},
    finding::{Finding, Identity, Occurrence, SuppressionAudit},
    links::Links,
    progress::Progress,
    report::{Coverage, CoverageEntry, Report, display_path},
};
use crossbeam_channel::{Receiver, RecvTimeoutError, SendTimeoutError, Sender, bounded, unbounded};
use regex::Regex;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

const LFS_POINTER: &[u8] = b"version https://git-lfs.github.com/spec/v1";
const QUEUE_POLL: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct Run {
    pub cancelled: Arc<AtomicBool>,
    halted: Arc<AtomicBool>,
    deadline: Instant,
}
impl Run {
    pub fn new(seconds: u64, cancelled: Arc<AtomicBool>) -> Self {
        Self {
            cancelled,
            halted: Arc::new(AtomicBool::new(false)),
            deadline: Instant::now() + Duration::from_secs(seconds),
        }
    }
    pub fn stopped(&self) -> bool {
        self.interrupted() || self.halted.load(Ordering::Relaxed) || self.timed_out()
    }
    pub fn interrupted(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }
    pub fn timed_out(&self) -> bool {
        Instant::now() >= self.deadline
    }
    /// Stops remaining work after a resource budget makes the scope incomplete.
    pub fn halt(&self) {
        self.halted.store(true, Ordering::Relaxed);
    }
}

/// One location at which inspected content was observed.
#[derive(Clone, Debug)]
pub struct Origin {
    pub source: String,
    pub path: String,
    pub commit: Option<String>,
    pub tag: Option<String>,
    pub ref_name: Option<String>,
    pub blob: Option<String>,
    pub current: bool,
    /// Commit author/committer time (Unix seconds), when known, for recency
    /// ordering of multiple occurrences of the same secret. `None` for
    /// working-tree files (treated as "now"), tags, and library callers that
    /// do not supply one.
    pub commit_time: Option<i64>,
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

/// Content inspected once; path-dependent policy is reapplied to every origin.
pub struct Unit {
    pub origins: Vec<Origin>,
    pub bytes: Vec<u8>,
    /// Progress weight, normally the object's stored size.
    pub weight: u64,
}

/// A working-tree file that a worker opens through no-follow handles.
pub struct FileTask {
    pub path: String,
    pub size: u64,
}

pub type ProducerTask<'a> = Box<dyn FnOnce(&Feeder) -> Result<(), String> + Send + 'a>;

/// A source that feeds content into the bounded work queue from its own thread.
pub struct Producer<'a> {
    pub items: u64,
    pub bytes: u64,
    pub task: ProducerTask<'a>,
}

enum Work {
    File(FileTask),
    Unit(Unit),
}

enum Event {
    Inspected {
        origins: Vec<Origin>,
        inspection: Inspection,
        weight: u64,
        bytes: u64,
    },
    Issue {
        source: String,
        path: String,
        reason: String,
        incomplete: bool,
        items: u64,
        weight: u64,
    },
}

pub struct Feeder {
    work: Sender<Work>,
    events: Sender<Event>,
    run: Run,
}

impl Feeder {
    /// Returns false when the scan is stopping and the producer should exit.
    pub fn send(&self, unit: Unit) -> bool {
        self.push(Work::Unit(unit))
    }

    fn push(&self, mut work: Work) -> bool {
        loop {
            if self.run.stopped() {
                return false;
            }
            match self.work.send_timeout(work, QUEUE_POLL) {
                Ok(()) => return true,
                Err(SendTimeoutError::Timeout(returned)) => work = returned,
                Err(SendTimeoutError::Disconnected(_)) => return false,
            }
        }
    }

    pub fn issue(&self, source: &str, path: &str, reason: &str, incomplete: bool, weight: u64) {
        let _ = self.events.send(Event::Issue {
            source: source.into(),
            path: path.into(),
            reason: reason.into(),
            incomplete,
            items: u64::from(weight > 0),
            weight,
        });
    }
}

struct Hit {
    rule: usize,
    secret_id: String,
    value: usize,
    start: usize,
    end: usize,
    line_start: Option<usize>,
    line_end: Option<usize>,
    members: Vec<String>,
    chain: Vec<String>,
    mapping: &'static str,
    evidence: Vec<String>,
    value_suppressions: Vec<usize>,
}

struct Inspection {
    hits: Vec<Hit>,
    issues: Vec<Issue>,
    /// Exact values are kept in memory only long enough to mask report metadata.
    values: Vec<String>,
    exhausted: bool,
    lfs_pointer: bool,
}

/// Immutable, thread-shared inspection state plus run-wide atomic budgets.
struct Inspector {
    limits: ScanConfig,
    detector: Detector,
    identity: Identity,
    value_regexes: Vec<Option<Regex>>,
    excludes: Vec<(String, Regex)>,
    run: Run,
    expanded: AtomicU64,
    archive_members: AtomicUsize,
}

impl Inspector {
    fn inspect(&self, bytes: &[u8]) -> Inspection {
        let mut out = Inspection {
            hits: Vec::new(),
            issues: Vec::new(),
            values: Vec::new(),
            exhausted: false,
            lfs_pointer: bytes.starts_with(LFS_POINTER),
        };
        let mut index = HashMap::new();
        out.issues = extract::inspect(
            bytes,
            &self.limits,
            &self.expanded,
            &self.archive_members,
            &self.run,
            &self.excludes,
            &mut |view| self.view(view, &mut out, &mut index),
        );
        out
    }

    fn view(&self, view: View, out: &mut Inspection, index: &mut HashMap<String, usize>) {
        if self.run.stopped() {
            return;
        }
        let max = self.limits.max_findings;
        let candidates = self.detector.candidates(&view.text, max + 1);
        if candidates.is_empty() {
            return;
        }
        let lines = view.line_numbers && view.mapped_range.is_none();
        let newlines: Vec<_> = if lines {
            view.text.match_indices('\n').map(|(i, _)| i).collect()
        } else {
            Vec::new()
        };
        for candidate in candidates {
            if out.hits.len() >= max {
                out.exhausted = true;
                break;
            }
            let value = match index.get(&candidate.value) {
                Some(&value) => value,
                None => {
                    out.values.push(candidate.value.clone());
                    index.insert(candidate.value.clone(), out.values.len() - 1);
                    out.values.len() - 1
                }
            };
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
            let (start, end, mapping) = if let Some((start, end)) = view.mapped_range {
                (start, end, "enclosing_encoded_range")
            } else if let Some(offsets) = &view.offsets {
                (
                    offsets.map(candidate.start),
                    offsets.map(candidate.end),
                    view.offset_kind,
                )
            } else if view.members.is_empty() {
                (candidate.start, candidate.end, "source_bytes")
            } else {
                (candidate.start, candidate.end, "member_bytes")
            };
            out.hits.push(Hit {
                rule: candidate.rule,
                secret_id,
                value,
                start,
                end,
                line_start: lines.then(|| 1 + newlines.partition_point(|&n| n < candidate.start)),
                line_end: lines.then(|| {
                    1 + newlines.partition_point(|&n| n < candidate.end.saturating_sub(1))
                }),
                members: view.members.clone(),
                chain: view.chain.clone(),
                mapping,
                evidence: candidate.evidence,
                value_suppressions,
            });
        }
    }
}

fn worker(
    inspector: &Inspector,
    root: Option<&File>,
    max_file_bytes: u64,
    work: Receiver<Work>,
    events: Sender<Event>,
) {
    // Keep draining after a stop so blocked producers observe it and exit.
    for item in work.iter() {
        if inspector.run.stopped() {
            continue;
        }
        let unit = match item {
            Work::Unit(unit) => unit,
            Work::File(file) => {
                let read = root
                    .ok_or_else(|| "Working-tree root is unavailable.".to_string())
                    .and_then(|root| {
                        crate::source::open_relative(root, Path::new(&file.path), false)
                    })
                    .and_then(|handle| crate::source::read_bounded(handle, max_file_bytes));
                match read {
                    Ok(bytes) => Unit {
                        origins: vec![Origin {
                            source: "working_tree".into(),
                            path: file.path,
                            commit: None,
                            tag: None,
                            ref_name: None,
                            blob: None,
                            current: true,
                            commit_time: None,
                        }],
                        bytes,
                        weight: file.size,
                    },
                    Err(reason) => {
                        let _ = events.send(Event::Issue {
                            source: "working_tree".into(),
                            path: file.path,
                            reason,
                            incomplete: true,
                            items: 1,
                            weight: file.size,
                        });
                        continue;
                    }
                }
            }
        };
        let inspection = inspector.inspect(&unit.bytes);
        let _ = events.send(Event::Inspected {
            origins: unit.origins,
            inspection,
            weight: unit.weight,
            bytes: unit.bytes.len() as u64,
        });
    }
}

pub struct Scanner {
    pub(crate) config: Config,
    pub run: Run,
    pub coverage: Coverage,
    pub output: Option<PathBuf>,
    pub protected_paths: Vec<PathBuf>,
    pub runtime_excludes: HashSet<String>,
    pub progress: Progress,
    pub links: Links,
    inspector: Arc<Inspector>,
    suppression_paths: Vec<Vec<Regex>>,
    repository_id: String,
    scan_id: String,
    findings: BTreeMap<(String, usize), Finding>,
    raw_values: HashSet<String>,
    raw_value_bytes: usize,
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
        let suppression_paths = config
            .ignore
            .suppressions
            .iter()
            .map(|s| s.paths.iter().map(|p| config::glob(p)).collect())
            .collect::<Result<_, _>>()?;
        let mut id = [0; 16];
        getrandom::fill(&mut id).map_err(|_| "Cannot generate scan identifier.")?;
        let inspector = Arc::new(Inspector {
            limits: config.scan.clone(),
            detector,
            identity,
            value_regexes,
            excludes,
            run: run.clone(),
            expanded: AtomicU64::new(0),
            archive_members: AtomicUsize::new(0),
        });
        let mut scanner = Self {
            config,
            run,
            coverage: Coverage {
                complete: true,
                ..Coverage::default()
            },
            output,
            protected_paths: Vec::new(),
            runtime_excludes: HashSet::new(),
            progress: Progress::disabled(),
            links: Links::default(),
            inspector,
            suppression_paths,
            repository_id,
            scan_id: hex::encode(id),
            findings: BTreeMap::new(),
            raw_values: HashSet::new(),
            raw_value_bytes: 0,
            occurrence_count: 0,
            capacity_exhausted: false,
        };
        let expired = scanner
            .config
            .ignore
            .suppressions
            .iter()
            .filter(|s| config::expired(&s.expires))
            .count();
        for _ in 0..expired {
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

    fn exhaust(&mut self) {
        self.capacity_exhausted = true;
        self.coverage.complete = false;
        self.run.halt();
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
            self.exhaust();
        }
    }

    /// Records a skipped-due-to-size record or object. Oversized content is
    /// genuinely unread (unlike binary-strings-only inspection, which still reads
    /// everything), but treating every large build artifact as a hard failure
    /// would defeat "works without configuration"; `strict_coverage` opts back in.
    pub fn oversized(&mut self, source: &str, path: &str, reason: &str) {
        self.issue(source, path, reason, self.config.scan.strict_coverage);
    }

    pub fn excluded(&mut self, source: &str, path: &str) -> bool {
        if self.runtime_excludes.contains(path) {
            self.scope_exclusion(source, path, "Active report or identity key excluded.");
            return true;
        }
        let pattern = self
            .inspector
            .excludes
            .iter()
            .find(|(_, re)| re.is_match(path))
            .map(|(pattern, _)| pattern.clone());
        match pattern {
            Some(pattern) => {
                self.record_exclusion(source, path, pattern);
                true
            }
            None => false,
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

    /// Inspects one record on the calling thread (library convenience API).
    pub fn record(&mut self, record: Record) {
        if self.stopped() {
            return;
        }
        if self.excluded(&record.source, &record.path) {
            return;
        }
        if record.bytes.len() as u64 > self.config.scan.max_file_bytes {
            self.oversized(
                &record.source,
                &record.path,
                "Record exceeds file-byte limit.",
            );
            return;
        }
        let inspection = self.inspector.inspect(&record.bytes);
        let size = record.bytes.len() as u64;
        self.apply(Event::Inspected {
            origins: vec![Origin {
                source: record.source,
                path: record.path,
                commit: record.commit,
                tag: record.tag,
                ref_name: record.ref_name,
                blob: record.blob,
                current: record.current,
                commit_time: None,
            }],
            inspection,
            weight: size,
            bytes: size,
        });
    }

    /// Reads and inspects content on `workers` threads behind a bounded queue, while
    /// this thread merges results and renders progress. Budgets remain run-wide.
    pub fn execute(
        &mut self,
        root: Option<&File>,
        files: Vec<FileTask>,
        producers: Vec<Producer<'_>>,
    ) {
        let items = files.len() as u64 + producers.iter().map(|p| p.items).sum::<u64>();
        let bytes = files.iter().map(|f| f.size).sum::<u64>()
            + producers.iter().map(|p| p.bytes).sum::<u64>();
        self.progress.begin_scan(items, bytes);
        if self.stopped() || (files.is_empty() && producers.is_empty()) {
            return;
        }
        let workers = self.config.scan.workers.max(1);
        let max_file_bytes = self.config.scan.max_file_bytes;
        let inspector = Arc::clone(&self.inspector);
        let run = self.run.clone();
        let (work_tx, work_rx) = bounded::<Work>(workers);
        let (event_tx, event_rx) = unbounded::<Event>();
        std::thread::scope(|scope| {
            for _ in 0..workers {
                let work = work_rx.clone();
                let events = event_tx.clone();
                let inspector = &*inspector;
                scope.spawn(move || worker(inspector, root, max_file_bytes, work, events));
            }
            drop(work_rx);
            let feeder = || Feeder {
                work: work_tx.clone(),
                events: event_tx.clone(),
                run: run.clone(),
            };
            if !files.is_empty() {
                let feeder = feeder();
                scope.spawn(move || {
                    for file in files {
                        if !feeder.push(Work::File(file)) {
                            break;
                        }
                    }
                });
            }
            for producer in producers {
                let feeder = feeder();
                scope.spawn(move || {
                    if let Err(reason) = (producer.task)(&feeder) {
                        feeder.issue("source", "", &reason, true, 0);
                    }
                });
            }
            drop(work_tx);
            drop(event_tx);
            loop {
                match event_rx.recv_timeout(Duration::from_millis(250)) {
                    Ok(event) => self.apply(event),
                    Err(RecvTimeoutError::Timeout) => self.progress.tick(),
                    Err(RecvTimeoutError::Disconnected) => break,
                }
            }
        });
    }

    fn track(&mut self, value: &str) -> bool {
        if self.raw_values.contains(value) {
            return true;
        }
        let cap = self
            .config
            .scan
            .max_expanded_bytes_per_record
            .min(16 * 1024 * 1024);
        if self.raw_values.len() >= self.config.scan.max_findings
            || self.raw_value_bytes as u64 + value.len() as u64 > cap
        {
            self.exhaust();
            return false;
        }
        self.raw_value_bytes += value.len();
        self.raw_values.insert(value.to_owned());
        true
    }

    fn apply(&mut self, event: Event) {
        match event {
            Event::Issue {
                source,
                path,
                reason,
                incomplete,
                items,
                weight,
            } => {
                self.progress.advance(items, weight);
                self.issue(&source, &path, &reason, incomplete);
            }
            Event::Inspected {
                origins,
                inspection,
                weight,
                bytes,
            } => {
                self.progress.advance(1, weight);
                if inspection.exhausted {
                    self.exhaust();
                }
                self.coverage.bytes_scanned += bytes;
                self.coverage.cached_records += origins.len().saturating_sub(1);
                // Values that cannot be tracked for masking are never reported.
                let tracked: Vec<bool> = inspection.values.iter().map(|v| self.track(v)).collect();
                for origin in &origins {
                    if self.coverage.records_scanned >= self.config.scan.max_records {
                        self.issue(
                            &origin.source,
                            &origin.path,
                            "Source record budget exhausted.",
                            true,
                        );
                        self.exhaust();
                        break;
                    }
                    self.coverage.records_scanned += 1;
                    if inspection.lfs_pointer {
                        self.issue(
                            &origin.source,
                            &origin.path,
                            "Git LFS pointer inspected; referenced payload is outside scope.",
                            false,
                        );
                    }
                    for issue in &inspection.issues {
                        let path = display_path(&origin.path, &issue.members);
                        match &issue.pattern {
                            Some(pattern) if issue.exclusion => {
                                self.record_exclusion(&origin.source, &path, pattern.clone())
                            }
                            // Format limitations are reported but only fail strict scans.
                            _ => self.issue(
                                &origin.source,
                                &path,
                                issue.reason,
                                !issue.partial || self.config.scan.strict_coverage,
                            ),
                        }
                    }
                    for hit in &inspection.hits {
                        if !tracked[hit.value] {
                            continue;
                        }
                        if self.occurrence_count >= self.config.scan.max_findings {
                            self.issue(
                                &origin.source,
                                &origin.path,
                                "Finding occurrence budget exhausted.",
                                true,
                            );
                            self.exhaust();
                            break;
                        }
                        self.add_hit(origin, hit, &inspection.values[hit.value]);
                    }
                }
            }
        }
    }

    fn add_hit(&mut self, origin: &Origin, hit: &Hit, value: &str) {
        let rule = &self.inspector.detector.rules[hit.rule];
        let paths: Vec<_> = std::iter::once(origin.path.as_str())
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
        let source_kind = match origin.source.as_str() {
            "commit_message" => "commit_message",
            "tag_message" => "tag_message",
            _ => "file",
        };
        let provenance =
            serde_json::to_string(&(source_kind, &origin.ref_name, &hit.members, &hit.chain))
                .expect("serializable provenance");
        let fingerprint = self.inspector.identity.fingerprint(
            "secrethunter.occurrence.v1",
            &[
                &hit.secret_id,
                &rule.spec.id,
                &self.repository_id,
                &origin.path,
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
                        || self.suppression_paths[*index]
                            .iter()
                            .any(|re| paths.iter().any(|path| re.is_match(path))))
                    && (sup.commit_ids.is_empty()
                        || origin
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
        let (url, file_url) =
            self.links
                .occurrence(origin, hit.line_start, !hit.members.is_empty());
        let occurrence = Occurrence {
            fingerprint,
            source: origin.source.clone(),
            path: origin.path.clone(),
            member_chain: hit.members.clone(),
            commit: origin.commit.clone(),
            tag: origin.tag.clone(),
            ref_name: origin.ref_name.clone(),
            blob: origin.blob.clone(),
            commit_time: origin.commit_time,
            byte_start: hit.start,
            byte_end: hit.end,
            line_start: hit.line_start,
            line_end: hit.line_end,
            extraction_chain: hit.chain.clone(),
            location_mapping: hit.mapping.into(),
            matched_path_level,
            suppressions,
            url,
            file_url,
        };
        let finding = self
            .findings
            .entry((hit.secret_id.clone(), hit.rule))
            .or_insert_with(|| Finding {
                schema_version: 1,
                scan_id: self.scan_id.clone(),
                secret_id: hit.secret_id.clone(),
                rule_id: rule.spec.id.clone(),
                rule_version: hex::encode(Sha256::digest(
                    serde_json::to_vec(&rule.spec).expect("serializable rule"),
                )),
                description: rule.spec.description.clone(),
                category: rule.spec.category.clone(),
                severity: rule.spec.severity.clone(),
                confidence: rule.spec.confidence.clone(),
                evidence_codes: hit.evidence.clone(),
                verification: "not_attempted".into(),
                remediation: rule.spec.remediation.clone(),
                // The exact captured value, shown in reports for fast triage; it is
                // never masked by metadata redaction, unlike every other field here.
                value: value.to_owned(),
                lifecycle: "historical_only".into(),
                llm: None,
                occurrences: Vec::new(),
            });
        if origin.current {
            finding.lifecycle = "present_in_current_tree".into();
        }
        finding.occurrences.push(occurrence);
        self.occurrence_count += 1;
    }

    pub fn finish(mut self, target: String) -> Report {
        if self.run.interrupted() {
            self.issue("scan", "", "Operator interruption.", true);
        } else if self.run.timed_out() {
            self.issue("scan", "", "Scan time budget exhausted.", true);
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
                // Most recent first: working-tree content counts as "now"; historical
                // occurrences fall back by commit time, then deterministic tie-breakers.
                let recency = |o: &Occurrence| -> i64 {
                    if o.source == "working_tree" {
                        i64::MAX
                    } else {
                        o.commit_time.unwrap_or(i64::MIN)
                    }
                };
                recency(b).cmp(&recency(a)).then_with(|| {
                    (
                        &a.path,
                        &a.member_chain,
                        &a.commit,
                        &a.tag,
                        a.byte_start,
                        &a.extraction_chain,
                        &a.source,
                    )
                        .cmp(&(
                            &b.path,
                            &b.member_chain,
                            &b.commit,
                            &b.tag,
                            b.byte_start,
                            &b.extraction_chain,
                            &b.source,
                        ))
                })
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
        self.coverage.expanded_bytes = self.inspector.expanded.load(Ordering::Acquire);
        self.coverage.entries.sort_by(|a, b| {
            (&a.source, &a.path, &a.status, &a.reason, &a.pattern)
                .cmp(&(&b.source, &b.path, &b.status, &b.reason, &b.pattern))
        });
        let exit_code = if self.run.interrupted() {
            130
        } else if !self.coverage.complete {
            2
        } else if fail {
            1
        } else {
            0
        };
        self.progress.finish(&format!(
            "scan {} with {active} active and {suppressed} suppressed occurrences ({} records, {})",
            if self.coverage.complete {
                "complete"
            } else {
                "INCOMPLETE"
            },
            self.coverage.records_scanned,
            crate::progress::human_bytes(self.coverage.bytes_scanned),
        ));
        let mut report = Report {
            schema_version: 1,
            scanner_version: crate::VERSION.into(),
            scan_id: self.scan_id,
            policy_digest: config::digest(&self.config),
            canonicalization_version: 1,
            repository_url: self.links.github.clone(),
            max_file_bytes: self.config.scan.max_file_bytes,
            key_id: self.inspector.identity.key_id.clone(),
            target,
            history: self.config.scan.history,
            interrupted: self.run.interrupted(),
            exit_code,
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
