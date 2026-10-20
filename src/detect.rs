use crate::config::{Config, Rule, glob};
use regex::{Regex, RegexSet};
use std::collections::HashMap;

/// Detection is sequential per content view; the scanner parallelizes across records
/// so small views do not pay thread-dispatch overhead.
pub struct Detector {
    pub rules: Vec<CompiledRule>,
    prefilter: Option<RegexSet>,
}

pub struct CompiledRule {
    pub spec: Rule,
    regex: Regex,
    pub paths: Vec<Regex>,
    /// Built-in assignment rules ignore punctuation-only captures such as `:`.
    require_alphanumeric: bool,
    /// Extra minimum entropy (bits/char) derived from `scan.sensitivity`, applied in
    /// addition to any rule-specified `entropy_min`. `None` for precise/signature
    /// rules that should never be entropy-filtered.
    sensitivity_floor: Option<f64>,
}

pub struct Candidate {
    pub rule: usize,
    pub start: usize,
    pub end: usize,
    pub value: String,
    pub evidence: Vec<String>,
}

/// Built-in rules broad enough to match arbitrary code (any `token = ...`
/// assignment, any value after `Password=`) rather than a specific provider
/// signature. Only these are scaled by `scan.sensitivity`; AWS keys, GitHub
/// tokens, private keys, and similar fixed-format signatures are never affected.
const NOISY_RULES: [&str; 4] = [
    "generic-secret",
    "generic-secret-double-quoted",
    "generic-secret-single-quoted",
    "connection-password",
];

/// Maps a 0 (fewest findings) .. 10 (most findings) dial to a minimum required
/// Shannon entropy (bits/character) for noisy rules: 0 bits at sensitivity 10
/// (no extra filtering) up to 4.0 bits at sensitivity 0.
pub fn sensitivity_floor(sensitivity: u8) -> f64 {
    f64::from(10 - sensitivity.min(10)) * 0.4
}

impl Detector {
    pub fn new(config: &Config) -> Result<Self, String> {
        let floor = sensitivity_floor(config.scan.sensitivity);
        let builtins = builtin_rules()
            .into_iter()
            .filter(|r| config.ruleset.builtins && !config.ruleset.disabled.contains(&r.id))
            .map(|spec| {
                let noisy = NOISY_RULES.contains(&spec.id.as_str());
                CompiledRule::new(spec).map(|mut rule| {
                    rule.require_alphanumeric = true;
                    rule.sensitivity_floor = noisy.then_some(floor);
                    rule
                })
            });
        let custom = config.rules.iter().cloned().map(CompiledRule::new);
        let rules: Vec<CompiledRule> = builtins.chain(custom).collect::<Result<_, _>>()?;
        // One linear-time pass selects candidate rules. Very large custom rule sets fall
        // back to running every rule if the combined automaton exceeds regex limits.
        let prefilter = RegexSet::new(rules.iter().map(|rule| rule.spec.regex.as_str())).ok();
        Ok(Self { rules, prefilter })
    }

    pub fn candidates(&self, text: &str, limit: usize) -> Vec<Candidate> {
        let matched: Vec<usize> = match &self.prefilter {
            Some(set) => set.matches(text).into_iter().collect(),
            None => (0..self.rules.len()).collect(),
        };
        let mut out = Vec::new();
        for index in matched {
            if out.len() >= limit {
                break;
            }
            let rule = &self.rules[index];
            for (start, end, value) in rule.matches_limited(text, limit - out.len()) {
                let mut evidence = vec!["signature_match".into()];
                if !rule.spec.keywords.is_empty() {
                    evidence.push("keyword_match".into());
                }
                if !rule.spec.context.any_of.is_empty() {
                    evidence.push("context_match".into());
                }
                if rule.spec.entropy_min.is_some() {
                    evidence.push("entropy_threshold".into());
                }
                evidence.extend(
                    rule.spec
                        .validators
                        .iter()
                        .map(|v| format!("local_{v}_valid")),
                );
                out.push(Candidate {
                    rule: index,
                    start,
                    end,
                    value,
                    evidence,
                });
            }
        }
        out
    }
}

impl CompiledRule {
    pub fn new(spec: Rule) -> Result<Self, String> {
        let regex = Regex::new(&spec.regex).map_err(|_| "Invalid rule regex.".to_string())?;
        let paths = spec
            .paths
            .iter()
            .map(|p| glob(p))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            spec,
            regex,
            paths,
            require_alphanumeric: false,
            sensitivity_floor: None,
        })
    }

    pub fn matches(&self, text: &str) -> Vec<(usize, usize, String)> {
        self.matches_limited(text, 100_001)
    }

    fn matches_limited(&self, text: &str, limit: usize) -> Vec<(usize, usize, String)> {
        let needs_window = !self.spec.keywords.is_empty() || !self.spec.context.any_of.is_empty();
        let newlines: Vec<_> = if needs_window {
            text.match_indices('\n').map(|(index, _)| index).collect()
        } else {
            Vec::new()
        };
        let mut windows = HashMap::new();
        self.regex
            .captures_iter(text)
            .filter_map(|caps| {
                let whole = caps.get(0)?;
                let secret = caps.get(self.spec.secret_group)?;
                if secret.is_empty()
                    || (self.require_alphanumeric
                        && !secret.as_str().bytes().any(|b| b.is_ascii_alphanumeric()))
                {
                    return None;
                }
                if needs_window {
                    let first = newlines.partition_point(|&n| n < whole.start());
                    let last = newlines.partition_point(|&n| n < whole.end());
                    let allowed = *windows.entry((first, last)).or_insert_with(|| {
                        let start = if first == 0 {
                            0
                        } else {
                            newlines[first - 1] + 1
                        };
                        let end = newlines.get(last).copied().unwrap_or(text.len());
                        let keyword_window = text[start..end].to_lowercase();
                        let keyword_match = self.spec.keywords.is_empty()
                            || self
                                .spec
                                .keywords
                                .iter()
                                .any(|k| keyword_window.contains(&k.to_lowercase()));
                        let first = first.saturating_sub(self.spec.context.within_lines);
                        let last = last.saturating_add(self.spec.context.within_lines);
                        let start = if first == 0 {
                            0
                        } else {
                            newlines[first - 1] + 1
                        };
                        let end = newlines.get(last).copied().unwrap_or(text.len());
                        let context = text[start..end].to_lowercase();
                        keyword_match
                            && (self.spec.context.any_of.is_empty()
                                || self
                                    .spec
                                    .context
                                    .any_of
                                    .iter()
                                    .any(|term| context.contains(&term.to_lowercase())))
                    });
                    if !allowed {
                        return None;
                    }
                }
                if self
                    .spec
                    .entropy_min
                    .is_some_and(|min| entropy(secret.as_str()) < min)
                {
                    return None;
                }
                if self
                    .sensitivity_floor
                    .is_some_and(|min| entropy(secret.as_str()) < min)
                {
                    return None;
                }
                for validator in &self.spec.validators {
                    if !match validator.as_str() {
                        "luhn" => luhn(secret.as_str()),
                        "pem" => valid_pem(secret.as_str()),
                        _ => false,
                    } {
                        return None;
                    }
                }
                Some((secret.start(), secret.end(), secret.as_str().to_owned()))
            })
            .take(limit)
            .collect()
    }
}

pub fn entropy(value: &str) -> f64 {
    let mut counts = HashMap::new();
    let mut n = 0.0;
    for c in value.chars() {
        *counts.entry(c).or_insert(0.0) += 1.0;
        n += 1.0;
    }
    counts
        .values()
        .map(|count| {
            let p: f64 = count / n;
            -p * p.log2()
        })
        .sum()
}

pub fn luhn(value: &str) -> bool {
    let digits: Vec<_> = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '-')
        .map(|c| c.to_digit(10))
        .collect::<Option<_>>()
        .unwrap_or_default();
    (13..=19).contains(&digits.len())
        && digits.iter().any(|&d| d != 0)
        && digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &d)| {
                if i % 2 == 1 {
                    let v = d * 2;
                    if v > 9 { v - 9 } else { v }
                } else {
                    d
                }
            })
            .sum::<u32>()
            % 10
            == 0
}

fn valid_pem(value: &str) -> bool {
    let Ok(block) = pem::parse(value) else {
        return false;
    };
    match block.tag() {
        "OPENSSH PRIVATE KEY" => block.contents().starts_with(b"openssh-key-v1\0"),
        "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => {
            !block.contents().is_empty()
        }
        _ => false,
    }
}

pub fn builtin_rules() -> Vec<Rule> {
    let items = [
        (
            "aws-access-key",
            "AWS access key identifier",
            "high",
            "high",
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
            0,
        ),
        (
            "github-token",
            "GitHub authentication token",
            "critical",
            "high",
            r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b",
            0,
        ),
        (
            "slack-token",
            "Slack authentication token",
            "high",
            "high",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,255}\b",
            0,
        ),
        (
            "stripe-secret-key",
            "Stripe secret API key",
            "critical",
            "high",
            r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,255}\b",
            0,
        ),
        (
            "google-api-key",
            "Google API key",
            "high",
            "high",
            r"\bAIza[0-9A-Za-z_-]{35}\b",
            0,
        ),
        (
            "private-key",
            "Private key material",
            "critical",
            "high",
            r"(?s)-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
            0,
        ),
        (
            "generic-secret",
            "Secret-bearing assignment",
            "high",
            "medium",
            r#"(?im)(?:["']?(?:password|passwd|pwd|secret|client_secret|api_key|access_token|auth_token|token)["']?)[ \t]*[:=][ \t]*([^\s"'`,;}{()<>\[\]\r\n]+)"#,
            1,
        ),
        (
            "generic-secret-double-quoted",
            "Double-quoted secret-bearing assignment",
            "high",
            "medium",
            r#"(?im)["']?(?:password|passwd|pwd|secret|client_secret|api_key|access_token|auth_token|token)["']?[ \t]*[:=][ \t]*"([^"\r\n]+)""#,
            1,
        ),
        (
            "generic-secret-single-quoted",
            "Single-quoted secret-bearing assignment",
            "high",
            "medium",
            r#"(?im)["']?(?:password|passwd|pwd|secret|client_secret|api_key|access_token|auth_token|token)["']?[ \t]*[:=][ \t]*'([^'\r\n]+)'"#,
            1,
        ),
        (
            "authorization-header",
            "Authorization credential",
            "high",
            "high",
            r"(?i)\b(?:authorization|proxy-authorization)[ \t]*[:=][ \t]*['\x22]?(?:bearer|basic)[ \t]+([A-Za-z0-9+/_.=~-]+)",
            1,
        ),
        (
            "credential-uri",
            "Credential-bearing connection URI",
            "high",
            "high",
            r"(?i)\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@]+:([^\s/@]+)@",
            1,
        ),
        (
            "connection-password",
            "Connection-string password",
            "high",
            "medium",
            r#"(?i);[ \t]*(?:Password|Pwd)[ \t]*=[ \t]*([^;"'\r\n]+)"#,
            1,
        ),
        (
            "payment-card",
            "Payment card candidate with valid checksum",
            "medium",
            "low",
            r"\b(?:[0-9][ -]?){12,18}[0-9]\b",
            0,
        ),
    ];
    items.into_iter().map(|(id, description, severity, confidence, regex, secret_group)| Rule {
        id: id.into(), description: description.into(), category: if id == "payment-card" { "sensitive_data" } else { "credential" }.into(),
        // ASCII word boundaries keep built-ins on the fast DFA path for non-ASCII content.
        severity: severity.into(), confidence: confidence.into(), regex: regex.replace(r"\b", r"(?-u:\b)"), secret_group,
        paths: Vec::new(), keywords: Vec::new(), context: Default::default(), entropy_min: None,
        validators: if id == "payment-card" { vec!["luhn".into()] } else { Vec::new() },
        positive_examples: Vec::new(), negative_examples: Vec::new(),
        remediation: "Rotate credentials or contain sensitive data; deletion alone does not resolve historical exposure.".into(),
    }).collect()
}

pub fn test_rules(config: &Config) -> Result<usize, String> {
    let mut count = 0;
    for (rule_index, spec) in config.rules.iter().enumerate() {
        let rule = CompiledRule::new(spec.clone())?;
        for (examples, expected) in [
            (&spec.positive_examples, true),
            (&spec.negative_examples, false),
        ] {
            for (index, example) in examples.iter().enumerate() {
                count += 1;
                if !rule.matches(example).is_empty() != expected {
                    return Err(format!(
                        "Rule {} failed {} fixture #{} (value omitted).",
                        rule_index + 1,
                        if expected { "positive" } else { "negative" },
                        index + 1
                    ));
                }
            }
        }
    }
    Ok(count)
}
