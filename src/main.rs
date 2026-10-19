use clap::{Args, Parser, Subcommand};
use secrethunter::{
    config, detect,
    finding::Identity,
    report,
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

#[derive(Parser)]
#[command(
    name = "secrethunter",
    version,
    about = "Offline secret and sensitive-data exposure scanner"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a local directory or an HTTPS GitHub repository.
    Scan(Box<ScanArgs>),
    /// Validate a trusted policy without acquiring the target.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Execute synthetic positive and negative custom-rule fixtures.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
}

#[derive(Args)]
struct PolicyArgs {
    #[arg(long)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum ConfigCommand {
    Validate(PolicyArgs),
    /// Print the strict structural JSON Schema for version-1 TOML policies.
    Schema,
}
#[derive(Subcommand)]
enum RulesCommand {
    Test(PolicyArgs),
}

#[derive(Args)]
struct ScanArgs {
    target: String,
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long, value_parser = ["auto", "off", "all"])]
    history: Option<String>,
    #[arg(long, value_parser = ["terminal", "json", "sarif"])]
    format: Option<String>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    audit_ignores: bool,
    /// Protected file containing exactly 32 random bytes; never pass the key itself.
    #[arg(long)]
    key_file: Option<PathBuf>,
    /// Name of an environment variable containing the GitHub credential.
    #[arg(long)]
    github_token_env: Option<String>,
    #[arg(long)]
    workers: Option<usize>,
    #[arg(long)]
    max_file_bytes: Option<u64>,
    #[arg(long)]
    timeout_seconds: Option<u64>,
    #[arg(long, value_parser = ["low", "medium", "high", "critical"])]
    fail_on_severity: Option<String>,
    #[arg(long, value_parser = ["low", "medium", "high"])]
    fail_on_confidence: Option<String>,
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
            config::validate(&config, false)?;
            let target = source::parse_target(&args.target)?;
            if args.github_token_env.is_some() && matches!(target, source::Target::Directory(_)) {
                return Err("--github-token-env is only valid for GitHub inputs.".into());
            }
            let output = args.output.as_deref().map(absolute_output).transpose()?;
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
            let run = Run::new(config.scan.timeout_seconds, cancelled);
            let format = config.output.format.clone();
            let repository_id = match &target {
                source::Target::Directory(root) => root.to_string_lossy().into_owned(),
                source::Target::GitHub(url) => url.strip_suffix(".git").unwrap_or(url).into(),
            };
            let mut scanner =
                Scanner::new(config, identity, run, repository_id.clone(), output.clone())?;
            scanner.protected_paths.push(key_abs);
            eprintln!("SecretHunter: scanning; values remain local and reports are redacted.");
            source::scan(&mut scanner, &target, args.github_token_env.as_deref());
            let result = scanner.finish(repository_id);
            let bytes = report::render(&result, &format, args.audit_ignores)?;
            if let Some(output) = output {
                report::write_atomic(&output, &bytes)?;
            } else {
                report::write_stdout(&bytes)?;
            }
            Ok(result.exit_code)
        }
    }
}
