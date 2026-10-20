//! Optional, local-only triage of findings through an Ollama instance.
//!
//! This module never sends anything over the network except to the
//! user-specified Ollama endpoint (default `http://localhost:11434`, which is
//! loopback-only). It is only ever invoked after an explicit, interactive
//! opt-in (or an explicit `--llm-verify` flag); scanning itself never depends
//! on it.

use crate::finding::{Finding, LlmAnalysis};
use serde::Deserialize;
use std::time::Duration;

/// Generous enough for a local model to load and answer a short prompt, but
/// bounded so a hung or unreachable endpoint cannot stall the whole scan.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout(REQUEST_TIMEOUT)
        .build()
}

#[derive(Deserialize)]
struct TagsResponse {
    #[serde(default)]
    models: Vec<TagModel>,
}

#[derive(Deserialize)]
struct TagModel {
    name: String,
}

#[derive(Deserialize)]
struct GenerateResponse {
    #[serde(default)]
    response: String,
}

/// Lists locally installed Ollama models, or an empty list if the endpoint is
/// unreachable (treated as "Ollama unavailable", never a hard error).
pub fn list_models(endpoint: &str) -> Vec<String> {
    let url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
    let Ok(response) = agent().get(&url).call() else {
        return Vec::new();
    };
    response
        .into_json::<TagsResponse>()
        .map(|body| body.models.into_iter().map(|m| m.name).collect())
        .unwrap_or_default()
}

fn prompt(finding: &Finding) -> String {
    format!(
        "You are a fast, terse security triage assistant reviewing one automated secret-scan \
match. Answer in exactly this format: a single verdict word on the first line, one of \
LIKELY_REAL, LIKELY_FALSE_POSITIVE, or UNCERTAIN, followed by a one-sentence reason on the \
second line. Do not ask questions or add anything else.\n\n\
Rule: {}\nDescription: {}\nMatched value: {}\n\n\
Is this a real, currently exploitable secret, or a false positive such as a placeholder, \
example, test fixture, or documentation sample?",
        finding.rule_id, finding.description, finding.value
    )
}

fn parse_verdict(response: &str) -> (&'static str, String) {
    let lower = response.to_lowercase();
    let verdict = if lower.contains("likely_false_positive") || lower.contains("false positive") {
        "likely_false_positive"
    } else if lower.contains("likely_real") {
        "likely_real"
    } else {
        "uncertain"
    };
    let explanation = response.trim().to_string();
    (verdict, explanation)
}

/// Asks the model for a fast viability verdict on a single finding. Uses a low
/// temperature and a small prediction budget so it stays quick even for many
/// findings; errors are returned to the caller rather than silently attached,
/// so a failed call never fabricates a verdict.
pub fn analyze(endpoint: &str, model: &str, finding: &Finding) -> Result<LlmAnalysis, String> {
    let url = format!("{}/api/generate", endpoint.trim_end_matches('/'));
    let body = ureq::json!({
        "model": model,
        "prompt": prompt(finding),
        "stream": false,
        "options": { "temperature": 0, "num_predict": 80 },
    });
    let response = agent()
        .post(&url)
        .send_json(body)
        .map_err(|_| "Cannot reach the Ollama endpoint.".to_string())?;
    let parsed: GenerateResponse = response
        .into_json()
        .map_err(|_| "Ollama returned an unexpected response.".to_string())?;
    let (verdict, explanation) = parse_verdict(&parsed.response);
    Ok(LlmAnalysis {
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
            parse_verdict("LIKELY_REAL: looks like a live key").0,
            "likely_real"
        );
        assert_eq!(
            parse_verdict("likely_false_positive, this is an example").0,
            "likely_false_positive"
        );
        assert_eq!(parse_verdict("not sure either way").0, "uncertain");
    }
}
