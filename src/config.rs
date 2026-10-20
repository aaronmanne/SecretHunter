use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs::File, io::Read, path::Path};
use time::{Date, OffsetDateTime, macros::format_description};

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    pub scan: ScanConfig,
    pub ruleset: Ruleset,
    pub rules: Vec<Rule>,
    pub verification: Verification,
    pub output: Output,
    pub policy: Policy,
    pub ignore: Ignore,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1,
            scan: ScanConfig::default(),
            ruleset: Ruleset::default(),
            rules: Vec::new(),
            verification: Verification::default(),
            output: Output::default(),
            policy: Policy::default(),
            ignore: Ignore::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct ScanConfig {
    pub history: String,
    pub respect_gitignore: bool,
    pub follow_symlinks: bool,
    pub workers: usize,
    pub max_file_bytes: u64,
    pub max_archive_depth: usize,
    pub max_decode_depth: usize,
    pub max_expanded_bytes_per_record: u64,
    pub max_expanded_bytes_total: u64,
    pub max_archive_members: usize,
    pub timeout_seconds: u64,
    pub max_records: usize,
    pub max_findings: usize,
    /// Treat format limitations (binary strings-only inspection, encrypted archive
    /// members, office containers) as incomplete coverage (exit 2).
    pub strict_coverage: bool,
    /// Detection sensitivity, 0 (fewest/highest-confidence findings) to 10 (most
    /// findings, including low-entropy or placeholder-looking values). Mainly
    /// scales a minimum-entropy requirement applied to generic assignment and
    /// connection-string rules; provider-specific signatures are unaffected.
    pub sensitivity: u8,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            history: "auto".into(),
            respect_gitignore: false,
            follow_symlinks: false,
            workers: std::thread::available_parallelism().map_or(4, |n| n.get().clamp(1, 16)),
            max_file_bytes: 100 * 1024 * 1024,
            max_archive_depth: 2,
            max_decode_depth: 2,
            max_expanded_bytes_per_record: 100 * 1024 * 1024,
            max_expanded_bytes_total: 1024 * 1024 * 1024,
            max_archive_members: 10_000,
            timeout_seconds: 600,
            max_records: 1_000_000,
            max_findings: 100_000,
            strict_coverage: false,
            sensitivity: 5,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Ruleset {
    pub builtins: bool,
    pub disabled: Vec<String>,
}
impl Default for Ruleset {
    fn default() -> Self {
        Self {
            builtins: true,
            disabled: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub confidence: String,
    pub regex: String,
    #[serde(default)]
    pub secret_group: usize,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub context: Context,
    pub entropy_min: Option<f64>,
    #[serde(default)]
    pub validators: Vec<String>,
    #[serde(default)]
    pub positive_examples: Vec<String>,
    #[serde(default)]
    pub negative_examples: Vec<String>,
    #[serde(default = "default_remediation")]
    pub remediation: String,
}

fn default_remediation() -> String {
    "Revoke exposed credentials, remove unauthorized copies, and review historical exposure.".into()
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Context {
    pub any_of: Vec<String>,
    pub within_lines: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Verification {
    pub mode: String,
}
impl Default for Verification {
    fn default() -> Self {
        Self {
            mode: "offline".into(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Output {
    pub format: String,
    pub redact: bool,
    pub include_context: bool,
}
impl Default for Output {
    fn default() -> Self {
        Self {
            format: "html".into(),
            redact: true,
            include_context: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub fail_on_severity: String,
    pub fail_on_confidence: String,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            fail_on_severity: "medium".into(),
            fail_on_confidence: "low".into(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct Ignore {
    pub exclude_paths: Vec<String>,
    pub suppressions: Vec<Suppression>,
}

#[derive(Clone, Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Suppression {
    pub id: String,
    pub rule_ids: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    pub value_regex: Option<String>,
    #[serde(default)]
    pub commit_ids: Vec<String>,
    #[serde(default)]
    pub occurrence_fingerprints: Vec<String>,
    pub reason: String,
    pub owner: String,
    pub ticket: String,
    pub expires: String,
}

pub const FORMATS: [&str; 5] = ["terminal", "json", "markdown", "html", "sarif"];

pub fn severity_rank(value: &str) -> Option<u8> {
    match value {
        "low" => Some(0),
        "medium" => Some(1),
        "high" => Some(2),
        "critical" => Some(3),
        _ => None,
    }
}
pub fn confidence_rank(value: &str) -> Option<u8> {
    match value {
        "low" => Some(0),
        "medium" => Some(1),
        "high" => Some(2),
        _ => None,
    }
}

pub fn load(path: Option<&Path>) -> Result<Config, String> {
    let Some(path) = path else {
        return Ok(Config::default());
    };
    let file = File::open(path).map_err(|_| "Cannot read selected policy file.".to_string())?;
    let mut data = Vec::new();
    file.take(2 * 1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| "Cannot read selected policy file.")?;
    if data.len() > 2 * 1024 * 1024 {
        return Err("Policy exceeds 2 MiB.".into());
    }
    let text = std::str::from_utf8(&data).map_err(|_| "Policy must be UTF-8.".to_string())?;
    // Parser diagnostics can contain secret-bearing fixture strings.
    toml::from_str(text)
        .map_err(|_| "Invalid TOML or unknown policy field; policy contents omitted.".into())
}

pub fn expiry(value: &str) -> Result<Date, String> {
    Date::parse(value, format_description!("[year]-[month]-[day]"))
        .map_err(|_| "Suppression expiry must be a valid YYYY-MM-DD date.".into())
}
pub fn expired(value: &str) -> bool {
    expiry(value).is_ok_and(|date| date < OffsetDateTime::now_utc().date())
}

pub fn validate(config: &Config, strict_expiry: bool) -> Result<(), String> {
    if config.version != 1 {
        return Err("Only policy version 1 is supported.".into());
    }
    let s = &config.scan;
    if !["auto", "off", "all"].contains(&s.history.as_str()) {
        return Err("Invalid history mode.".into());
    }
    if s.follow_symlinks || s.respect_gitignore {
        return Err("Symlink following and automatic gitignore handling are unsupported.".into());
    }
    if !(1..=64).contains(&s.workers)
        || !(1..=256 * 1024 * 1024).contains(&s.max_file_bytes)
        || s.max_archive_depth > 8
        || s.max_decode_depth > 8
        || s.max_expanded_bytes_per_record == 0
        || s.max_expanded_bytes_total == 0
        || s.max_expanded_bytes_per_record > 4 * 1024 * 1024 * 1024
        || s.max_expanded_bytes_total > 1024 * 1024 * 1024 * 1024
        || s.max_archive_members == 0
        || s.timeout_seconds == 0
        || s.timeout_seconds > 86_400
        || s.max_records == 0
        || !(1..=1_000_000).contains(&s.max_findings)
        || s.sensitivity > 10
    {
        return Err("Invalid resource limit (workers 1..64, file size 1..256 MiB, depths 0..8, timeout 1..86400, sensitivity 0..10).".into());
    }
    if config.verification.mode != "offline" {
        return Err("Only offline verification is supported.".into());
    }
    if !FORMATS.contains(&config.output.format.as_str()) {
        return Err("Invalid output format.".into());
    }
    if !config.output.redact || config.output.include_context {
        return Err("Unredacted output and source context are unsupported.".into());
    }
    if severity_rank(&config.policy.fail_on_severity).is_none()
        || confidence_rank(&config.policy.fail_on_confidence).is_none()
    {
        return Err("Invalid failure threshold.".into());
    }
    let builtins = crate::detect::builtin_rules();
    let builtin_ids: HashSet<_> = builtins.iter().map(|r| r.id.as_str()).collect();
    let mut disabled = HashSet::new();
    for id in &config.ruleset.disabled {
        if !builtin_ids.contains(id.as_str()) || !disabled.insert(id) {
            return Err("Unknown or duplicate disabled builtin ID.".into());
        }
    }
    let mut ids = HashSet::new();
    for rule in builtins.iter().chain(config.rules.iter()) {
        if !ids.insert(rule.id.as_str()) {
            return Err("Duplicate rule ID.".into());
        }
        let re = Regex::new(&rule.regex)
            .map_err(|_| "Invalid RE2-compatible rule regex.".to_string())?;
        if !valid_id(&rule.id)
            || rule.secret_group >= re.captures_len()
            || severity_rank(&rule.severity).is_none()
            || confidence_rank(&rule.confidence).is_none()
            || !["credential", "sensitive_data"].contains(&rule.category.as_str())
            || rule.description.is_empty()
            || rule.context.within_lines > 10_000
            || rule
                .entropy_min
                .is_some_and(|v| !v.is_finite() || !(0.0..=8.0).contains(&v))
        {
            return Err("Invalid rule metadata, capture group, context, or entropy.".into());
        }
        for validator in &rule.validators {
            if !["luhn", "pem"].contains(&validator.as_str()) {
                return Err("Unknown offline validator.".into());
            }
        }
        for path in &rule.paths {
            glob(path)?;
        }
    }
    let active: HashSet<_> = builtins
        .iter()
        .filter(|r| config.ruleset.builtins && !config.ruleset.disabled.contains(&r.id))
        .chain(config.rules.iter())
        .map(|r| r.id.as_str())
        .collect();
    for path in &config.ignore.exclude_paths {
        glob(path)?;
    }
    let mut suppression_ids = HashSet::new();
    for sup in &config.ignore.suppressions {
        if !valid_id(&sup.id)
            || !suppression_ids.insert(&sup.id)
            || sup.rule_ids.is_empty()
            || sup.rule_ids.iter().any(|r| !active.contains(r.as_str()))
            || [sup.reason.as_str(), sup.owner.as_str(), sup.ticket.as_str()]
                .iter()
                .any(|v| v.trim().is_empty())
            || (sup.paths.is_empty()
                && sup.value_regex.is_none()
                && sup.commit_ids.is_empty()
                && sup.occurrence_fingerprints.is_empty())
        {
            return Err(
                "Invalid suppression metadata, rule ID, or missing narrowing selector.".into(),
            );
        }
        expiry(&sup.expires)?;
        if strict_expiry && expired(&sup.expires) {
            return Err("Expired suppression; renew or remove it.".into());
        }
        for path in &sup.paths {
            glob(path)?;
        }
        if let Some(pattern) = &sup.value_regex {
            Regex::new(&format!(r"\A(?:{pattern})\z"))
                .map_err(|_| "Invalid suppression value regex.".to_string())?;
        }
        if sup
            .commit_ids
            .iter()
            .any(|id| !is_hex(id, 40) && !is_hex(id, 64))
            || sup.occurrence_fingerprints.iter().any(|id| !is_hex(id, 64))
        {
            return Err("Invalid full commit ID or occurrence fingerprint.".into());
        }
    }
    Ok(())
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
pub fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|b| b.is_ascii_hexdigit())
}
pub fn digest(config: &Config) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(&(crate::VERSION, crate::detect::builtin_rules(), config))
            .expect("serializable effective policy and detector versions"),
    ))
}

/// Root-relative, segment-aware glob. `**` must occupy a complete segment.
pub fn glob(pattern: &str) -> Result<Regex, String> {
    if pattern.is_empty()
        || pattern.starts_with('/')
        || pattern.contains('\\')
        || pattern
            .split('/')
            .any(|s| s == ".." || s == "." || s.is_empty())
    {
        return Err("Invalid root-relative POSIX glob.".into());
    }
    let parts: Vec<_> = pattern.split('/').collect();
    let mut out = String::from(r"\A");
    for (index, part) in parts.iter().enumerate() {
        if *part == "**" {
            if index + 1 == parts.len() {
                out.push_str(".*");
            } else {
                out.push_str("(?:[^/]+/)*");
            }
        } else {
            if part.contains("**") {
                return Err("** must occupy a whole path segment.".into());
            }
            for c in part.chars() {
                match c {
                    '*' => out.push_str("[^/]*"),
                    '?' => out.push_str("[^/]"),
                    '[' | ']' | '{' | '}' => {
                        return Err(
                            "Glob character classes and brace expansion are unsupported.".into(),
                        );
                    }
                    _ => out.push_str(&regex::escape(&c.to_string())),
                }
            }
            if index + 1 < parts.len() {
                out.push('/');
            }
        }
    }
    out.push_str(r"\z");
    Regex::new(&out).map_err(|_| "Invalid glob.".into())
}
