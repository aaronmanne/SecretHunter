use clap::{Args, Parser, Subcommand};
use secrethunter::{
    config, detect,
    finding::Identity,
    interactive, llm,
    progress::{Mode as ProgressMode, Progress},
    report,
    report::Report,
    scan::{Run, Scanner},
    source,
};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const AFTER_HELP: &str = "\
EXAMPLES:
  # Scan the current directory; writes ./SecretHunter-<timestamp>.html
  secrethunter scan .

  # Run with no arguments at all on a terminal: you are prompted for the
  # target, and asked whether to verify findings with a local LLM
  secrethunter scan

  # Scan a GitHub repository (public, or private with --github-token-env)
  secrethunter scan https://github.com/OWNER/REPO

  # Fewer, higher-confidence findings (reduce false positives)
  secrethunter scan . --sensitivity 2

  # Only the working tree, no Git history, machine-readable JSON to stdout
  secrethunter scan . --history off --format json --output -

  # Use a reviewed policy with custom rules and resource limits
  secrethunter scan . --config ./security/secrethunter.toml

  # Exclude build output without writing a policy file
  secrethunter scan . --exclude '**/target/**' --exclude '**/node_modules/**'

  # Non-interactive LLM triage via a specific backend and model
  secrethunter scan . --llm-verify --llm-backend ollama --llm-model llama3.1 \
    --llm-rule generic-secret

  # Never ask about or run LLM verification, even on a terminal
  secrethunter scan . --no-llm-verify

  # Check a policy file and its custom-rule fixtures before using it in CI
  secrethunter config validate --config ./security/secrethunter.toml
  secrethunter rules test --config ./security/secrethunter.toml

EXIT CODES:
  0    scan completed; no finding met the failure threshold
  1    scan completed; a finding met the failure threshold (--fail-on-*)
  2    invalid input/policy, acquisition failure, or incomplete coverage
  130  interrupted (Ctrl-C); a partial report is still written if possible

INTERACTIVE PROMPTS (only when both stdin and stdout are a terminal):
  - A missing TARGET is prompted for.
  - Unless --llm-verify or --no-llm-verify is given, you are always asked
    whether to send findings to a local LLM (Ollama or LM Studio) for fast,
    offline-only viability triage.
  - If you opt in and --llm-backend is omitted, both Ollama and LM Studio are
    probed: if only one is running, it is used automatically; if both are
    running, you are asked which one to use; if neither is running, LLM
    verification is skipped (online/hosted models are not supported).
  - If --llm-model is omitted, you are asked to pick a model from what the
    selected backend currently has installed.
  - If --llm-rule is omitted, you are asked which rule IDs' findings to send.
    Rule IDs you do not select are dropped from the final report entirely,
    not just skipped for LLM analysis.
  - Outside a terminal (CI, pipes, redirected output), none of the above is
    ever asked: a missing TARGET is an error, and LLM verification is off
    unless explicitly requested with --llm-verify (and, if given, every rule
    ID is included, and nothing is dropped, unless --llm-rule narrows it; if
    both backends are running, --llm-backend must choose one).
  - If no local LLM is detected, or the selected one has no models, LLM
    verification is skipped with a warning; the scan and report are never
    blocked by it.

No telemetry, no network access beyond an explicitly requested GitHub clone or
a user-opted-in local LLM call, and no credential verification: everything
else runs locally. The report includes the raw matched value of every finding
(for fast triage) and, when requested, the LLM's verdict \u{2014} handle and
store it as sensitively as the secrets themselves.";

#[derive(Parser)]
#[command(
    name = "secrethunter",
    version,
    about = "Find exposed secrets and sensitive data in a directory or GitHub repository.",
    long_about = "SecretHunter scans a local directory or a GitHub repository for exposed \
credentials, private keys, and other sensitive data \u{2014} in current files, reachable Git \
history, and inside archives/JAR files. It runs entirely offline and never uploads anything; \
the report shows each matched value for fast triage, but masks every other identifying detail \
(paths, descriptions, coverage reasons).\n\nNo configuration is required: `secrethunter scan .` \
works out of the box and writes a searchable HTML report. If run on a terminal without enough \
arguments, you are prompted interactively for what's missing.",
    after_help = AFTER_HELP
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a directory or GitHub repository and write a report (HTML by default).
    Scan(Box<ScanArgs>),
    /// Validate a policy file, or print its JSON Schema, without scanning anything.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Run a policy's custom-rule positive/negative example fixtures as a self-test.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
}

#[derive(Args)]
struct PolicyArgs {
    /// Path to a TOML policy file. If omitted, uses $SECRETHUNTER_CONFIG, or
    /// otherwise the built-in defaults (equivalent to an empty policy).
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ConfigCommand {
    /// Check a policy file's schema and semantics (duplicate IDs, bad globs/regex,
    /// invalid limits, expired suppressions, etc.) without acquiring any target.
    Validate(PolicyArgs),
    /// Print the strict structural JSON Schema for version-1 TOML policies.
    Schema,
}

#[derive(Subcommand)]
enum RulesCommand {
    /// Run every custom rule's `positive_examples`/`negative_examples` fixtures
    /// and fail if any rule matches (or fails to match) what it should.
    Test(PolicyArgs),
}

#[derive(Args)]
struct ScanArgs {
    /// Local directory to scan, or an HTTPS GitHub repository URL
    /// (https://github.com/OWNER/REPO, with or without a trailing .git).
    /// If omitted on an interactive terminal, you will be prompted for it.
    #[arg(value_name = "TARGET")]
    target: Option<String>,

    /// Path to a TOML policy file. If omitted, uses $SECRETHUNTER_CONFIG, or
    /// otherwise safe built-in defaults — no configuration is required.
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// How much Git history to inspect. "auto" (default) scans current files
    /// plus reachable branches/tags/detached HEAD for a local Git repository, or
    /// the default branch plus reachable history for a GitHub URL. "off" scans
    /// only current files (or the GitHub default-branch snapshot). "all" is the
    /// same as "auto" today, but requires a Git repository rather than a plain
    /// directory.
    #[arg(long, value_parser = ["auto", "off", "all"], value_name = "MODE")]
    history: Option<String>,

    /// Report format. "html" (default) is a single self-contained, searchable
    /// page with collapsible sections. "markdown" renders well on GitHub/GitLab.
    /// "json" and "sarif" (SARIF 2.1.0) are for tooling and code-scanning
    /// integrations. "terminal" prints a short redacted summary as plain text.
    #[arg(long, value_parser = config::FORMATS, value_name = "FORMAT")]
    format: Option<String>,

    /// Where to write the report. Defaults to
    /// ./SecretHunter-<UTC timestamp>.<ext> in the current directory, except
    /// for --format terminal, which prints to stdout by default. Pass "-" to
    /// force writing to stdout regardless of format, e.g. for piping JSON to
    /// another tool.
    #[arg(long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Include suppressed (ignored) findings in the report, with the
    /// suppression's owner, reason, ticket, and expiry — never the raw
    /// matched value. Does not change the exit code or failure threshold.
    #[arg(long)]
    audit_ignores: bool,

    /// Path to a private 32-byte random identity key file (mode 0600), used to
    /// fingerprint secrets consistently across scans so the same value always
    /// gets the same ID. Defaults to ~/.config/secrethunter/identity.key,
    /// auto-created on first use. Share the same key file across CI runs for
    /// stable fingerprints; never pass the key itself as an argument.
    #[arg(long, value_name = "FILE")]
    key_file: Option<PathBuf>,

    /// Name of an environment variable holding a GitHub access token, used only
    /// when TARGET is a private GitHub repository URL. The token is read from
    /// the environment at scan time and is never written to disk, logged, or
    /// passed as a command-line argument.
    #[arg(long, value_name = "VAR")]
    github_token_env: Option<String>,

    /// Number of parallel scanning threads. Defaults to the number of available
    /// CPU cores, capped at 16. Findings and report ordering are identical
    /// regardless of this value. Lower it on memory-constrained machines.
    #[arg(long, value_name = "N")]
    workers: Option<usize>,

    /// Progress display on stderr while scanning. "auto" (default) shows an
    /// animated bar on an interactive terminal and periodic text lines
    /// otherwise (e.g. redirected to a file, or TERM=dumb). "bar" always
    /// animates. "plain" always prints periodic lines. "off" disables it.
    /// Progress text never includes file names, refs, or matched values.
    #[arg(long, value_parser = ["auto", "bar", "plain", "off"], default_value = "auto", value_name = "MODE")]
    progress: String,

    /// Skip inspecting any single file or Git object larger than this many
    /// bytes (default: 20 MiB / 20971520). Oversized objects are listed as
    /// incomplete coverage, not silently skipped.
    #[arg(long, value_name = "BYTES")]
    max_file_bytes: Option<u64>,

    /// Stop scanning after this many seconds and return a partial, incomplete
    /// result (default: 600; must be 1–86400).
    #[arg(long, value_name = "SECONDS")]
    timeout_seconds: Option<u64>,

    /// Minimum severity (low/medium/high/critical) that causes exit code 1.
    /// Must be met together with --fail-on-confidence. Default: medium.
    #[arg(long, value_parser = ["low", "medium", "high", "critical"], value_name = "LEVEL")]
    fail_on_severity: Option<String>,

    /// Minimum confidence (low/medium/high) that causes exit code 1. Must be
    /// met together with --fail-on-severity. Default: low.
    #[arg(long, value_parser = ["low", "medium", "high"], value_name = "LEVEL")]
    fail_on_confidence: Option<String>,

    /// Detection sensitivity from 0 (fewest findings, highest-confidence only)
    /// to 10 (most findings, including low-entropy/placeholder-looking
    /// values). Default: 5. Reduces false positives from generic
    /// assignment-style and connection-string rules (for example a config
    /// key literally named "token" or "secret") by requiring more
    /// randomness in the matched value as the number goes down.
    /// Provider-specific signatures (AWS keys, GitHub tokens, private keys,
    /// etc.) always match regardless of this setting.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=10), value_name = "0-10")]
    sensitivity: Option<u8>,

    /// Treat format limitations (binary files inspected only through their
    /// readable strings, encrypted or unsupported-compression archive
    /// members, office documents) as incomplete coverage, returning exit code
    /// 2. Off by default, so a scan with no configuration still exits 0 or 1
    /// based on findings alone.
    #[arg(long)]
    strict_coverage: bool,

    /// Root-relative glob to exclude from scanning, e.g. "**/target/**" or
    /// "**/node_modules/**" (repeatable). Applied consistently to current
    /// files, Git history, and archive members; shown in the coverage report.
    #[arg(long = "exclude", value_name = "GLOB")]
    exclude: Vec<String>,

    /// Send findings to a local LLM (Ollama or LM Studio) for fast, offline
    /// viability triage after the scan completes (never a network call
    /// beyond the detected/given local endpoint; hosted/online models are
    /// not supported). On an interactive terminal you are always asked
    /// about this if neither flag is given. Conflicts with --no-llm-verify.
    #[arg(long, conflicts_with = "no_llm_verify")]
    llm_verify: bool,

    /// Skip LLM verification without being asked, even on an interactive
    /// terminal. Conflicts with --llm-verify.
    #[arg(long)]
    no_llm_verify: bool,

    /// Which local LLM backend to use. If omitted, both Ollama and LM Studio
    /// are probed: if only one is running, it is used automatically; if
    /// both are running, you are asked to pick one on an interactive
    /// terminal (an error otherwise); if neither is running, LLM
    /// verification is skipped with a warning.
    #[arg(long, value_parser = ["ollama", "lmstudio"], value_name = "BACKEND")]
    llm_backend: Option<String>,

    /// Model to use for LLM verification (e.g. "llama3.1"). If omitted on an
    /// interactive terminal, you are asked to pick one from the models
    /// currently available on the selected backend.
    #[arg(long, value_name = "MODEL")]
    llm_model: Option<String>,

    /// Base URL of the local Ollama server, used when Ollama is the selected
    /// backend.
    #[arg(long, value_name = "URL", default_value = "http://localhost:11434")]
    ollama_endpoint: String,

    /// Base URL of the local LM Studio server, used when LM Studio is the
    /// selected backend.
    #[arg(long, value_name = "URL", default_value = "http://localhost:1234")]
    lmstudio_endpoint: String,

    /// Rule ID to include in LLM verification (repeatable). If omitted on an
    /// interactive terminal, you are asked to choose from the rule IDs that
    /// actually matched. If omitted non-interactively, every rule ID is
    /// included. Rule IDs not included are dropped from the report entirely
    /// (not just skipped for LLM analysis) once LLM verification runs.
    #[arg(long = "llm-rule", value_name = "RULE_ID")]
    llm_rules: Vec<String>,
}

fn main() -> ExitCode {
    match execute(Cli::parse()) {
        Ok(code) => ExitCode::from(code as u8),
        Err(message) => {
            eprintln!("SecretHunter: {}", report::sanitize(&message));
            ExitCode::from(2)
        }
    }
}

fn selected_policy(explicit: Option<PathBuf>) -> Result<config::Config, String> {
    let path = explicit.or_else(|| std::env::var_os("SECRETHUNTER_CONFIG").map(PathBuf::from));
    config::load(path.as_deref())
}

fn absolute_output(path: &Path) -> Result<PathBuf, String> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent =
        std::fs::canonicalize(parent).map_err(|_| "Output directory must already exist.")?;
    let name = path.file_name().ok_or("Output must name a file.")?;
    Ok(parent.join(name))
}

fn format_extension(format: &str) -> &'static str {
    match format {
        "json" => "json",
        "markdown" => "md",
        "html" => "html",
        "sarif" => "sarif",
        _ => "txt",
    }
}

/// `./SecretHunter-<UTC timestamp>.<ext>` so a bare `secrethunter scan .` always
/// produces a clearly named, non-colliding report without any configuration.
fn default_report_path(format: &str) -> Result<PathBuf, String> {
    let stamp = time::OffsetDateTime::now_utc()
        .format(time::macros::format_description!(
            "[year][month][day]-[hour][minute][second]"
        ))
        .map_err(|_| "Cannot format report timestamp.".to_string())?;
    Ok(PathBuf::from(format!(
        "SecretHunter-{stamp}.{}",
        format_extension(format)
    )))
}

/// Runs optional, local-only LLM triage over the findings selected by the
/// user (interactively or via flags) and attaches each verdict to its
/// `Finding`. Never fails the scan: no local LLM detected, an empty model
/// list, or a failed individual call all just skip with a warning. Rule
/// categories the user does not select are dropped from the report
/// entirely, not just left unanalyzed.
#[allow(clippy::too_many_arguments)]
fn run_llm_verification(
    result: &mut Report,
    llm_verify: bool,
    no_llm_verify: bool,
    llm_backend: Option<String>,
    llm_model: Option<String>,
    ollama_endpoint: &str,
    lmstudio_endpoint: &str,
    llm_rules: Vec<String>,
    warn: bool,
    cancelled: &AtomicBool,
    fail_on_severity: &str,
    fail_on_confidence: &str,
) {
    if result.findings.is_empty() || no_llm_verify {
        return;
    }
    let explicit = llm_verify;
    let wants_llm = if explicit {
        true
    } else if interactive::interactive() {
        interactive::ask_llm_verify()
    } else {
        if warn {
            eprintln!(
                "SecretHunter: non-interactive session; skipping the LLM verification prompt \
                 (pass --llm-verify to run it anyway)."
            );
        }
        false
    };
    if !wants_llm {
        return;
    }

    let endpoint_for = |backend: llm::Backend| match backend {
        llm::Backend::Ollama => ollama_endpoint,
        llm::Backend::LmStudio => lmstudio_endpoint,
    };

    let (backend, endpoint, models) = match llm_backend.as_deref().map(llm::Backend::parse) {
        Some(Some(backend)) => {
            let endpoint = endpoint_for(backend);
            match llm::probe(backend, endpoint).filter(|m| !m.is_empty()) {
                Some(models) => (backend, endpoint, models),
                None => {
                    if warn {
                        eprintln!(
                            "SecretHunter: {} is not reachable (or has no models) at {endpoint}; \
                             skipping LLM verification.",
                            backend.display_name()
                        );
                    }
                    return;
                }
            }
        }
        Some(None) => {
            if warn {
                eprintln!("SecretHunter: unknown --llm-backend value; skipping LLM verification.");
            }
            return;
        }
        None => {
            let ollama = llm::probe(llm::Backend::Ollama, ollama_endpoint)
                .filter(|m| !m.is_empty())
                .map(|models| (llm::Backend::Ollama, ollama_endpoint, models));
            let lmstudio = llm::probe(llm::Backend::LmStudio, lmstudio_endpoint)
                .filter(|m| !m.is_empty())
                .map(|models| (llm::Backend::LmStudio, lmstudio_endpoint, models));
            match (ollama, lmstudio) {
                (Some(ollama), Some(lmstudio)) => {
                    let options = [
                        (ollama.0.display_name(), ollama.2.len()),
                        (lmstudio.0.display_name(), lmstudio.2.len()),
                    ];
                    if interactive::interactive() {
                        match interactive::ask_backend(&options) {
                            Some(0) => ollama,
                            Some(_) => lmstudio,
                            None => {
                                if warn {
                                    eprintln!(
                                        "SecretHunter: no backend selected; skipping LLM \
                                         verification."
                                    );
                                }
                                return;
                            }
                        }
                    } else {
                        if warn {
                            eprintln!(
                                "SecretHunter: both Ollama and LM Studio are running; pass \
                                 --llm-backend ollama or --llm-backend lmstudio to choose one \
                                 non-interactively. Skipping LLM verification."
                            );
                        }
                        return;
                    }
                }
                (Some(found), None) | (None, Some(found)) => {
                    if warn {
                        eprintln!(
                            "SecretHunter: detected {} running at {}; using it for LLM \
                             verification.",
                            found.0.display_name(),
                            found.1
                        );
                    }
                    found
                }
                (None, None) => {
                    if warn {
                        eprintln!(
                            "SecretHunter: no local LLM detected (checked Ollama at {ollama_endpoint} \
                             and LM Studio at {lmstudio_endpoint}); online models are not yet \
                             supported. Skipping LLM verification."
                        );
                    }
                    return;
                }
            }
        }
    };

    let model = match llm_model.filter(|m| models.contains(m)) {
        Some(model) => model,
        None if interactive::interactive() => match interactive::ask_model(&models) {
            Some(model) => model,
            None => {
                if warn {
                    eprintln!("SecretHunter: no model selected; skipping LLM verification.");
                }
                return;
            }
        },
        None => {
            if warn {
                eprintln!(
                    "SecretHunter: --llm-model was not given or is not installed in {}; \
                     skipping LLM verification.",
                    backend.display_name()
                );
            }
            return;
        }
    };

    // Rule IDs with their finding counts, in first-seen order, for the
    // category picker and as the non-interactive "include everything" set.
    let mut counts: Vec<(String, usize)> = Vec::new();
    for finding in &result.findings {
        match counts.iter_mut().find(|(rule, _)| *rule == finding.rule_id) {
            Some((_, count)) => *count += 1,
            None => counts.push((finding.rule_id.clone(), 1)),
        }
    }
    let selected_rules: Vec<String> = if !llm_rules.is_empty() {
        llm_rules
    } else if interactive::interactive() {
        interactive::ask_categories(&counts)
    } else {
        counts.iter().map(|(rule, _)| rule.clone()).collect()
    };

    // Categories the user did not select are dropped from the report
    // entirely, not just excluded from LLM analysis.
    let before = result.findings.len();
    result
        .findings
        .retain(|f| selected_rules.contains(&f.rule_id));
    if result.findings.len() != before {
        report::recompute_aggregates(result, fail_on_severity, fail_on_confidence);
    }
    if result.findings.is_empty() {
        if warn {
            eprintln!(
                "SecretHunter: no rule categories were selected for LLM verification; the \
                 report contains no findings."
            );
        }
        return;
    }

    let total = result.findings.len();
    if warn {
        eprintln!(
            "SecretHunter: sending {total} finding(s) to {} model {model} for triage; this can \
             take a while on CPU-only hardware...",
            backend.display_name()
        );
    }
    let mut analyzed = 0;
    let mut failed = 0;
    for (done, finding) in result.findings.iter_mut().enumerate() {
        if cancelled.load(Ordering::Relaxed) {
            if warn {
                eprintln!("SecretHunter: LLM verification interrupted; keeping what was done.");
            }
            break;
        }
        if warn {
            eprintln!(
                "SecretHunter: LLM verification {}/{total} ({})...",
                done + 1,
                finding.rule_id
            );
        }
        match llm::analyze(backend, endpoint, &model, finding) {
            Ok(analysis) => {
                finding.llm = Some(analysis);
                analyzed += 1;
            }
            Err(message) => {
                failed += 1;
                if warn {
                    eprintln!("SecretHunter: LLM verification failed for one finding: {message}");
                }
            }
        }
    }
    if warn {
        eprintln!("SecretHunter: LLM verification done: {analyzed} analyzed, {failed} failed.");
    }
}

fn execute(cli: Cli) -> Result<i32, String> {
    match cli.command {
        Command::Config {
            command: ConfigCommand::Schema,
        } => {
            let schema = schemars::schema_for!(config::Config);
            let bytes = serde_json::to_vec_pretty(&schema)
                .map_err(|_| "Cannot serialize policy schema.")?;
            report::write_stdout(&bytes)?;
            Ok(0)
        }
        Command::Config {
            command: ConfigCommand::Validate(args),
        } => {
            let config = selected_policy(args.config)?;
            config::validate(&config, true)?;
            println!(
                "Policy is valid (version 1; digest {}).",
                config::digest(&config)
            );
            Ok(0)
        }
        Command::Rules {
            command: RulesCommand::Test(args),
        } => {
            let config = selected_policy(args.config)?;
            config::validate(&config, true)?;
            let count = detect::test_rules(&config)?;
            println!("{count} custom-rule fixtures passed.");
            Ok(0)
        }
        Command::Scan(args) => {
            let target_input = match args.target {
                Some(target) => target,
                None if interactive::interactive() => interactive::ask_target()?,
                None => {
                    return Err(
                        "TARGET is required (pass a directory or GitHub URL, or run on an \
                         interactive terminal to be prompted)."
                            .into(),
                    );
                }
            };
            let mut config = selected_policy(args.config)?;
            if let Some(value) = args.history {
                config.scan.history = value;
            }
            if let Some(value) = args.format {
                config.output.format = value;
            }
            if let Some(value) = args.workers {
                config.scan.workers = value;
            }
            if let Some(value) = args.max_file_bytes {
                config.scan.max_file_bytes = value;
            }
            if let Some(value) = args.timeout_seconds {
                config.scan.timeout_seconds = value;
            }
            if let Some(value) = args.fail_on_severity {
                config.policy.fail_on_severity = value;
            }
            if let Some(value) = args.fail_on_confidence {
                config.policy.fail_on_confidence = value;
            }
            if let Some(value) = args.sensitivity {
                config.scan.sensitivity = value;
            }
            config.ignore.exclude_paths.extend(args.exclude);
            if args.strict_coverage {
                config.scan.strict_coverage = true;
            }
            config::validate(&config, false)?;
            let target = source::parse_target(&target_input)?;
            if args.github_token_env.is_some() && matches!(target, source::Target::Directory(_)) {
                return Err("--github-token-env is only valid for GitHub inputs.".into());
            }

            // "-" always means stdout; otherwise an explicit path is used as-is, and
            // an omitted path falls back to stdout for terminal (preserving the
            // original piping-friendly behavior) or a generated report file name.
            let stdout_requested = args.output.as_deref() == Some(Path::new("-"));
            let output = if stdout_requested {
                None
            } else if let Some(path) = &args.output {
                Some(absolute_output(path)?)
            } else if config.output.format == "terminal" {
                None
            } else {
                Some(absolute_output(&default_report_path(
                    &config.output.format,
                )?)?)
            };

            let default_key = args.key_file.is_none();
            let key_path = match args.key_file {
                Some(path) => path,
                None => {
                    let home =
                        std::env::var_os("HOME").ok_or("HOME is unset; provide --key-file.")?;
                    PathBuf::from(home).join(".config/secrethunter/identity.key")
                }
            };
            let key_abs = if key_path.is_absolute() {
                key_path.clone()
            } else {
                std::env::current_dir()
                    .map_err(|_| "Cannot determine current directory.")?
                    .join(&key_path)
            };
            if output.as_ref() == Some(&key_abs) {
                return Err("The report must not overwrite the identity key.".into());
            }
            let identity = Identity::load(&key_path, default_key)?;
            let key_abs = std::fs::canonicalize(&key_path)
                .map_err(|_| "Cannot resolve identity key path.")?;
            if output.as_ref() == Some(&key_abs) {
                return Err("The report must not overwrite the identity key.".into());
            }
            let cancelled = Arc::new(AtomicBool::new(false));
            let handler_flag = Arc::clone(&cancelled);
            ctrlc::set_handler(move || handler_flag.store(true, Ordering::Relaxed))
                .map_err(|_| "Cannot register cancellation handler.")?;
            let llm_cancelled = Arc::clone(&cancelled);
            let run = Run::new(config.scan.timeout_seconds, cancelled);
            let format = config.output.format.clone();
            let fail_on_severity = config.policy.fail_on_severity.clone();
            let fail_on_confidence = config.policy.fail_on_confidence.clone();
            let repository_id = match &target {
                source::Target::Directory(root) => root.to_string_lossy().into_owned(),
                source::Target::GitHub(url) => url.strip_suffix(".git").unwrap_or(url).into(),
            };
            let mut scanner =
                Scanner::new(config, identity, run, repository_id.clone(), output.clone())?;
            scanner.protected_paths.push(key_abs);
            scanner.progress = Progress::new(
                ProgressMode::parse(&args.progress).expect("clap validates progress modes"),
            );
            source::scan(&mut scanner, &target, args.github_token_env.as_deref());
            let mut result = scanner.finish(repository_id);
            run_llm_verification(
                &mut result,
                args.llm_verify,
                args.no_llm_verify,
                args.llm_backend,
                args.llm_model,
                &args.ollama_endpoint,
                &args.lmstudio_endpoint,
                args.llm_rules,
                args.progress != "off",
                &llm_cancelled,
                &fail_on_severity,
                &fail_on_confidence,
            );
            let bytes = report::render(&result, &format, args.audit_ignores)?;
            if let Some(output) = output {
                report::write_atomic(&output, &bytes)?;
                if args.progress != "off" {
                    eprintln!("SecretHunter: report written to {}", output.display());
                }
            } else {
                report::write_stdout(&bytes)?;
            }
            Ok(result.exit_code)
        }
    }
}
