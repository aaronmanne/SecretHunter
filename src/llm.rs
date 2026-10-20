//! Optional, local-only triage of findings through a locally running LLM
//! server: either [Ollama](https://ollama.com) or
//! [LM Studio](https://lmstudio.ai) (OpenAI-compatible API).
//!
//! This module never sends anything over the network except to a
//! user-specified local endpoint (defaults are loopback-only). It is only
//! ever invoked after an explicit, interactive opt-in (or an explicit
//! `--llm-verify` flag); scanning itself never depends on it. Online/hosted
//! models are not supported.

use crate::finding::{Finding, LlmAnalysis};
use serde::Deserialize;
use std::time::Duration;

/// Generous enough for a local model to load into memory and answer a short
/// prompt on CPU-only hardware; bounded so a hung or unreachable endpoint
/// cannot stall the whole run indefinitely.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    Ollama,
    LmStudio,
}

impl Backend {
    /// Human-readable name shown in prompts and attached to each verdict.
    pub fn display_name(self) -> &'static str {
        match self {
            Backend::Ollama => "Ollama",
            Backend::LmStudio => "LM Studio",
        }
    }

    /// CLI value for `--llm-backend`.
    pub fn id(self) -> &'static str {
        match self {
            Backend::Ollama => "ollama",
            Backend::LmStudio => "lmstudio",
        }
    }

    pub fn parse(id: &str) -> Option<Backend> {
        match id {
            "ollama" => Some(Backend::Ollama),
            "lmstudio" => Some(Backend::LmStudio),
            _ => None,
        }
    }

    pub fn default_endpoint(self) -> &'static str {
        match self {
            Backend::Ollama => "http://localhost:11434",
            Backend::LmStudio => "http://localhost:1234",
        }
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout(REQUEST_TIMEOUT)
        .build()
}

#[derive(Deserialize)]
struct OllamaTagsResponse {
    #[serde(default)]
    models: Vec<OllamaModel>,
}

#[derive(Deserialize)]
struct OllamaModel {
    name: String,
}

#[derive(Deserialize)]
struct OllamaGenerateResponse {
    #[serde(default)]
    response: String,
}

#[derive(Deserialize)]
struct OpenAiModelsResponse {
    #[serde(default)]
    data: Vec<OpenAiModel>,
}

#[derive(Deserialize)]
struct OpenAiModel {
    id: String,
}

#[derive(Deserialize)]
struct OpenAiChatResponse {
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Deserialize)]
struct OpenAiMessage {
    #[serde(default)]
    content: String,
    /// Some locally hosted "thinking" models put their output here when the
    /// token budget runs out before a final `content` is written.
    #[serde(default)]
    reasoning_content: String,
}

/// Probes whether a backend is actually running at `endpoint`: `None` means
/// unreachable (connection refused, timed out, not this kind of server);
/// `Some(models)` means it answered, with whatever models it currently has
/// installed/loaded (possibly empty).
pub fn probe(backend: Backend, endpoint: &str) -> Option<Vec<String>> {
    let base = endpoint.trim_end_matches('/');
    match backend {
        Backend::Ollama => {
            let response = agent().get(&format!("{base}/api/tags")).call().ok()?;
            let body: OllamaTagsResponse = response.into_json().ok()?;
            Some(body.models.into_iter().map(|m| m.name).collect())
        }
        Backend::LmStudio => {
            let response = agent().get(&format!("{base}/v1/models")).call().ok()?;
            let body: OpenAiModelsResponse = response.into_json().ok()?;
            Some(body.data.into_iter().map(|m| m.id).collect())
        }
    }
}

/// Convenience wrapper over [`probe`] for callers that only care about the
/// model list and are fine treating "unreachable" the same as "no models".
pub fn list_models(backend: Backend, endpoint: &str) -> Vec<String> {
    probe(backend, endpoint).unwrap_or_default()
}

fn prompt(finding: &Finding) -> String {
    format!(
        "You are a fast, terse security triage assistant reviewing one automated secret-scan \
match. Respond directly with no step-by-step reasoning, chain-of-thought, or preamble. Answer in \
exactly this format: a single verdict label on the first line, one of REAL SECRET, LIKELY FALSE \
POSITIVE, FALSE POSITIVE, or UNDETERMINED, followed by a short 2-3 sentence explanation. Do not \
ask questions or add anything else.\n\n\
Rule: {}\nDescription: {}\nMatched value: {}\n\n\
Is this a real, currently exploitable secret, or a false positive such as a placeholder, \
example, test fixture, or documentation sample?",
        finding.rule_id, finding.description, finding.value
    )
}

/// Keeps reports readable even when a model answers with far more than the
/// requested 2-3 sentences (e.g. a "thinking" model's chain-of-thought).
const MAX_EXPLANATION_CHARS: usize = 400;
const MAX_EXPLANATION_SENTENCES: usize = 3;

/// One of these four categories, in order of precedence (checked most
/// specific first, since e.g. "likely false positive" also contains "false
/// positive").
const VERDICTS: [(&str, &[&str]); 4] = [
    ("real_secret", &["real_secret", "real secret"]),
    (
        "likely_false_positive",
        &["likely_false_positive", "likely false positive"],
    ),
    ("false_positive", &["false_positive", "false positive"]),
    ("undetermined", &["undetermined"]),
];

fn parse_verdict(response: &str) -> (&'static str, String) {
    let lower = response.to_lowercase();
    let verdict = VERDICTS
        .iter()
        .find(|(_, patterns)| patterns.iter().any(|p| lower.contains(p)))
        .map_or("undetermined", |(id, _)| id);
    (verdict, summarize(response))
}

/// Strips a leading "Explanation:"/"Reason:"-style label the model adds
/// despite being asked not to, so the content after it is kept rather than
/// the whole sentence being treated as pure formatting noise.
fn strip_label(sentence: &str) -> &str {
    for label in ["explanation:", "reason:", "reasoning:"] {
        if sentence.len() >= label.len() && sentence[..label.len()].eq_ignore_ascii_case(label) {
            return sentence[label.len()..].trim();
        }
    }
    sentence
}

/// Picks a short, readable explanation out of a model's raw response. A
/// compliant reply is already just 2-3 sentences, so this is a no-op; a
/// verbose chain-of-thought instead tends to state its conclusion in its
/// final sentences, so those are kept and everything else (numbered steps,
/// markdown headers, the bare verdict label, and instructions the model
/// echoes back) is dropped.
fn summarize(response: &str) -> String {
    let sentences: Vec<&str> = response
        .split(['.', '!', '?', '\n'])
        .map(|s| strip_label(s.trim().trim_start_matches(['*', '-', '\u{2022}']).trim()))
        .filter(|s| {
            let lower = s.to_lowercase();
            s.len() >= 12
                && !s.starts_with(|c: char| c.is_ascii_digit())
                && !s.contains("**")
                && !lower.contains("thinking process")
                && !lower.contains("chain-of-thought")
                && !lower.contains("chain of thought")
                && !lower.contains("preamble")
                && !lower.contains("verdict label")
                && !lower.contains("sentence explanation")
                && !lower.contains("specified option")
                && !lower.starts_with("verdict:")
                && !lower.starts_with("line 1")
                && !lower.starts_with("line 2")
                && !lower.starts_with("line 3")
                && !VERDICTS
                    .iter()
                    .any(|(_, patterns)| patterns.iter().any(|p| lower == *p))
        })
        .collect();
    let kept = if sentences.len() > MAX_EXPLANATION_SENTENCES {
        &sentences[sentences.len() - MAX_EXPLANATION_SENTENCES..]
    } else {
        &sentences[..]
    };
    let joined = kept.join(". ");
    let trimmed = joined.trim();
    if trimmed.is_empty() {
        return "No explanation was returned.".to_string();
    }
    match trimmed.char_indices().nth(MAX_EXPLANATION_CHARS) {
        Some((cut, _)) => format!("{}\u{2026}", &trimmed[..cut]),
        None => trimmed.to_string(),
    }
}

/// Asks the model for a fast viability verdict on a single finding. Uses a low
/// temperature and a small prediction budget so it stays quick even for many
/// findings; errors are returned to the caller rather than silently attached,
/// so a failed call never fabricates a verdict.
pub fn analyze(
    backend: Backend,
    endpoint: &str,
    model: &str,
    finding: &Finding,
) -> Result<LlmAnalysis, String> {
    let base = endpoint.trim_end_matches('/');
    let text = prompt(finding);
    let explanation_source = match backend {
        Backend::Ollama => {
            let body = ureq::json!({
                "model": model,
                "prompt": text,
                "stream": false,
                "options": { "temperature": 0, "num_predict": 150 },
            });
            let response = agent()
                .post(&format!("{base}/api/generate"))
                .send_json(body)
                .map_err(|err| format!("Cannot reach Ollama: {err}"))?;
            let parsed: OllamaGenerateResponse = response
                .into_json()
                .map_err(|err| format!("Ollama returned an unexpected response: {err}"))?;
            parsed.response
        }
        Backend::LmStudio => {
            let body = ureq::json!({
                "model": model,
                "messages": [{"role": "user", "content": text}],
                "temperature": 0,
                "max_tokens": 300,
                "stream": false,
            });
            let response = agent()
                .post(&format!("{base}/v1/chat/completions"))
                .send_json(body)
                .map_err(|err| format!("Cannot reach LM Studio: {err}"))?;
            let parsed: OpenAiChatResponse = response
                .into_json()
                .map_err(|err| format!("LM Studio returned an unexpected response: {err}"))?;
            parsed
                .choices
                .into_iter()
                .next()
                .map(|c| {
                    if c.message.content.trim().is_empty() {
                        c.message.reasoning_content
                    } else {
                        c.message.content
                    }
                })
                .unwrap_or_default()
        }
    };
    let (verdict, explanation) = parse_verdict(&explanation_source);
    Ok(LlmAnalysis {
        backend: backend.display_name().to_string(),
        model: model.to_string(),
        verdict: verdict.to_string(),
        explanation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verdicts_are_parsed_case_insensitively() {
        assert_eq!(
            parse_verdict("REAL SECRET. This looks like a live AWS key with high entropy.").0,
            "real_secret"
        );
        assert_eq!(
            parse_verdict("likely false positive, this is an example value.").0,
            "likely_false_positive"
        );
        assert_eq!(
            parse_verdict("FALSE POSITIVE. This is a documentation placeholder.").0,
            "false_positive"
        );
        assert_eq!(
            parse_verdict("not enough context to decide either way").0,
            "undetermined"
        );
    }

    #[test]
    fn long_explanations_are_truncated() {
        let long = "real secret ".to_string() + &"x".repeat(1000);
        let (_, explanation) = parse_verdict(&long);
        assert!(explanation.chars().count() <= MAX_EXPLANATION_CHARS + 1);
        assert!(explanation.ends_with('\u{2026}'));
    }

    #[test]
    fn chain_of_thought_is_summarized_to_its_final_sentences() {
        let response = "Thinking Process:\n\n\
1. **Analyze the Request:** figure out what is being asked.\n\
2. **Analyze the Input Data:** the matched value is a placeholder string.\n\
The value is clearly a documentation example and not a live credential.\n\
FALSE POSITIVE";
        let (verdict, explanation) = parse_verdict(response);
        assert_eq!(verdict, "false_positive");
        assert!(!explanation.contains("Thinking Process"));
        assert!(!explanation.contains("**"));
        assert!(
            explanation.contains("documentation example"),
            "{explanation}"
        );
    }

    #[test]
    fn backend_ids_round_trip() {
        assert_eq!(Backend::parse("ollama"), Some(Backend::Ollama));
        assert_eq!(Backend::parse("lmstudio"), Some(Backend::LmStudio));
        assert_eq!(Backend::parse("other"), None);
        assert_eq!(Backend::Ollama.id(), "ollama");
        assert_eq!(Backend::LmStudio.id(), "lmstudio");
    }
}
