//! Local-first exposure scanning. No target code or online verification is executed.

#[cfg(not(unix))]
compile_error!("SecretHunter currently supports macOS and Linux only.");

pub mod config;
pub mod detect;
pub mod document;
pub mod extract;
pub mod finding;
pub mod interactive;
pub mod links;
pub mod llm;
pub mod progress;
pub mod report;
pub mod scan;
pub mod source;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
