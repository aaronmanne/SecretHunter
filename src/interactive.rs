//! Interactive prompts, used only when both stdin and stdout are a terminal.
//! In any non-interactive context (CI, pipes, redirected output) every
//! function here is skipped by its caller instead of blocking on input.

use dialoguer::{Confirm, Input, MultiSelect, Select, theme::ColorfulTheme};
use std::io::IsTerminal;

/// True only when prompts can sensibly be shown and answered: both stdin and
/// stdout must be attached to a terminal (matches the user's explicit choice
/// that interactivity is TTY-only, never attempted in CI or when piped).
pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// Asks for the scan target when it was not given on the command line.
pub fn ask_target() -> Result<String, String> {
    Input::with_theme(&ColorfulTheme::default())
        .with_prompt("Directory to scan, or a GitHub repository URL")
        .default(".".into())
        .interact_text()
        .map_err(|_| "Cannot read the scan target from the terminal.".to_string())
}

/// "Always ask the user" when running interactively, per the project's
/// explicit design choice; a `--llm-verify`/`--no-llm-verify` flag bypasses
/// this and is handled by the caller before reaching here.
pub fn ask_llm_verify() -> bool {
    Confirm::with_theme(&ColorfulTheme::default())
        .with_prompt("Verify findings with a local Ollama LLM for fast false-positive triage?")
        .default(false)
        .interact()
        .unwrap_or(false)
}

/// Lets the user pick one of the locally installed Ollama models.
pub fn ask_model(models: &[String]) -> Option<String> {
    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select an Ollama model for triage")
        .items(models)
        .default(0)
        .interact_opt()
        .ok()
        .flatten()?;
    models.get(selection).cloned()
}

/// Lets the user choose which rule categories (by `rule_id`) are sent to the
/// LLM. `counts` is `(rule_id, finding_count)`, already stable-ordered.
pub fn ask_categories(counts: &[(String, usize)]) -> Vec<String> {
    let items: Vec<String> = counts
        .iter()
        .map(|(rule, n)| format!("{rule} ({n} finding{})", if *n == 1 { "" } else { "s" }))
        .collect();
    let defaults = vec![true; items.len()];
    let Ok(selected) = MultiSelect::with_theme(&ColorfulTheme::default())
        .with_prompt("Which categories of secrets should be sent to the LLM?")
        .items(&items)
        .defaults(&defaults)
        .interact()
    else {
        return Vec::new();
    };
    selected
        .into_iter()
        .filter_map(|i| counts.get(i).map(|(rule, _)| rule.clone()))
        .collect()
}
