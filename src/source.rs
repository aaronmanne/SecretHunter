use crate::{
    config,
    scan::{Record, Run, Scanner},
};
use rustix::fs::{Mode, OFlags, open, openat};
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::Read,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};
use tempfile::TempDir;

pub enum Target {
    Directory(PathBuf),
    GitHub(String),
}

pub fn parse_target(value: &str) -> Result<Target, String> {
    if value.contains("://") || value.starts_with("git@") {
        let url = url::Url::parse(value).map_err(|_| "Invalid GitHub HTTPS repository URL.")?;
        if url.scheme() != "https"
            || url.host_str() != Some("github.com")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port().is_some()
            || value.contains('%')
            || value.contains('\\')
        {
            return Err(
                "Use https://github.com/OWNER/REPO without credentials, port, query, or fragment."
                    .into(),
            );
        }
        if value.strip_prefix("https://github.com") != Some(url.path()) {
            return Err(
                "Use a canonical GitHub HTTPS repository URL without path normalization.".into(),
            );
        }
        let path = url.path().trim_start_matches('/');
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|s| {
                s.is_empty()
                    || *s == "."
                    || *s == ".."
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            })
            || parts[1].trim_end_matches(".git").is_empty()
        {
            return Err("Expected a GitHub repository URL, not a tree, issue, or file URL.".into());
        }
        return Ok(Target::GitHub(format!(
            "https://github.com/{}/{}",
            parts[0], parts[1]
        )));
    }
    let root =
        fs::canonicalize(value).map_err(|_| "Target must be an existing readable directory.")?;
    if !root.is_dir() {
        return Err("Target must be a directory.".into());
    }
    Ok(Target::Directory(root))
}

pub fn scan(scanner: &mut Scanner, target: &Target, token_env: Option<&str>) {
    let result = match target {
        Target::Directory(root) => local(scanner, root),
        Target::GitHub(url) => remote(scanner, url, token_env),
    };
    if let Err(reason) = result {
        scanner.issue("source", "", &reason, true);
    }
}

pub fn open_relative(root: &File, path: &Path, directory: bool) -> Result<File, String> {
    let mut parent = root
        .try_clone()
        .map_err(|_| "Cannot duplicate directory handle.")?;
    let components: Vec<_> = path.components().collect();
    if components.is_empty() {
        return Ok(parent);
    }
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            return Err("Unsafe relative source path.".into());
        };
        let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if index + 1 < components.len() || directory {
            flags |= OFlags::DIRECTORY;
        }
        parent = File::from(
            openat(&parent, *name, flags, Mode::empty())
                .map_err(|_| "Cannot safely open source entry.")?,
        );
    }
    Ok(parent)
}

fn root_handle(path: &Path) -> Result<File, String> {
    let root = open(
        "/",
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|_| "Cannot safely open filesystem root.")?;
    let relative = path
        .strip_prefix("/")
        .map_err(|_| "Source directory must be canonical and absolute.")?;
    open_relative(&root, relative, true)
}

fn read_bounded(mut file: File, max: u64) -> Result<Vec<u8>, String> {
    let before = file.metadata().map_err(|_| "Cannot inspect source file.")?;
    if !before.is_file() || before.len() > max {
        return Err("Non-regular file or file-byte limit exceeded.".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Source read failed.")?;
    let after = file
        .metadata()
        .map_err(|_| "Cannot recheck source identity.")?;
    if bytes.len() as u64 > max
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Err("Source changed while being read or exceeded its byte limit.".into());
    }
    Ok(bytes)
}

fn local(scanner: &mut Scanner, root: &Path) -> Result<(), String> {
    for protected in scanner.output.iter().chain(scanner.protected_paths.iter()) {
        if let Ok(relative) = protected.strip_prefix(root) {
            scanner
                .runtime_excludes
                .insert(relative.to_string_lossy().into_owned());
        }
    }
    if scanner.config.scan.history == "off" {
        if root.join("HEAD").is_file()
            && root.join("objects").is_dir()
            && root.join("config").is_file()
        {
            return Err("A local bare repository requires history=auto or all.".into());
        }
        let handle = root_handle(root)?;
        return walk_directory(scanner, root, &handle, Path::new(""));
    }
    let repo = find_repository(root)?;
    if repo.is_none() && scanner.config.scan.history == "all" {
        return Err("history=all requires a Git repository.".into());
    }
    let bare = repo.as_ref().is_some_and(|(work, git)| work == git);
    if !bare {
        let handle = root_handle(root)?;
        walk_directory(scanner, root, &handle, Path::new(""))?;
    }
    if let Some((work, git_dir)) = repo {
        if scanner.stopped() {
            return Ok(());
        }
        let isolated = isolate_local(scanner, &git_dir)?;
        let prefix = if bare {
            Path::new("")
        } else {
            root.strip_prefix(&work)
                .map_err(|_| "Cannot scope Git subtree.")?
        };
        history(scanner, &isolated, prefix, None, false)?;
    }
    Ok(())
}

fn walk_directory(
    scanner: &mut Scanner,
    root: &Path,
    handle: &File,
    relative: &Path,
) -> Result<(), String> {
    if relative.components().count() > 128 {
        scanner.issue(
            "working_tree",
            &relative.to_string_lossy(),
            "Directory nesting budget exhausted.",
            true,
        );
        return Ok(());
    }
    let entries = match fs::read_dir(root.join(relative)) {
        Ok(entries) => entries,
        Err(_) => {
            scanner.issue(
                "working_tree",
                &relative.to_string_lossy(),
                "Directory is unreadable.",
                true,
            );
            return Ok(());
        }
    };
    for entry in entries {
        if scanner.stopped() {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                scanner.issue(
                    "working_tree",
                    "",
                    "Cannot enumerate directory entry.",
                    true,
                );
                continue;
            }
        };
        if entry.file_name() == ".git" {
            scanner.scope_exclusion(
                "working_tree",
                &relative.join(".git").to_string_lossy(),
                "Git administrative storage is handled by the history adapter.",
            );
            continue;
        }
        let path = relative.join(entry.file_name());
        let Some(name) = path.to_str() else {
            scanner.issue(
                "working_tree",
                "",
                "Non-UTF-8 filename cannot be represented.",
                true,
            );
            continue;
        };
        if scanner.excluded("working_tree", name) {
            continue;
        }
        let kind = match entry.file_type() {
            Ok(kind) => kind,
            Err(_) => {
                scanner.issue("working_tree", name, "Cannot inspect entry type.", true);
                continue;
            }
        };
        if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
            scanner.scope_exclusion(
                "working_tree",
                name,
                "Symlink or special file not followed.",
            );
            continue;
        }
        if kind.is_dir() {
            match open_relative(handle, Path::new(&entry.file_name()), true) {
                Ok(child) => walk_directory(scanner, root, &child, &path)?,
                Err(reason) => scanner.issue("working_tree", name, &reason, true),
            }
        } else {
            match open_relative(handle, Path::new(&entry.file_name()), false)
                .and_then(|file| read_bounded(file, scanner.config.scan.max_file_bytes))
            {
                Ok(bytes) => {
                    if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1") {
                        scanner.issue(
                            "working_tree",
                            name,
                            "Git LFS pointer inspected; referenced payload is outside scope.",
                            false,
                        );
                    }
                    scanner.record(Record {
                        source: "working_tree".into(),
                        path: name.into(),
                        commit: None,
                        tag: None,
                        ref_name: None,
                        blob: None,
                        current: true,
                        bytes,
                    });
                }
                Err(reason) => scanner.issue("working_tree", name, &reason, true),
            }
        }
    }
    Ok(())
}

fn find_repository(root: &Path) -> Result<Option<(PathBuf, PathBuf)>, String> {
    for ancestor in root.ancestors() {
        let dot = ancestor.join(".git");
        match fs::symlink_metadata(&dot) {
            Ok(meta) if meta.is_dir() => return Ok(Some((ancestor.to_owned(), dot))),
            Ok(_) => return Err(
                "Linked worktrees, gitfiles, and symlinked Git directories are not yet supported."
                    .into(),
            ),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Cannot inspect Git administrative directory.".into()),
        }
    }
    if root.join("HEAD").is_file() && root.join("objects").is_dir() && root.join("config").is_file()
    {
        return Ok(Some((root.to_owned(), root.to_owned())));
    }
    Ok(None)
}

struct Git {
    temp: TempDir,
    token: Option<OsString>,
    storage_limit: Option<u64>,
}

impl Git {
    fn new(run: &Run, format: &str) -> Result<Self, String> {
        let temp = tempfile::Builder::new()
            .prefix("secrethunter-")
            .tempdir()
            .map_err(|_| "Cannot create private Git workspace.")?;
        let git = Self {
            temp,
            token: None,
            storage_limit: None,
        };
        git.run(
            run,
            &[
                "init",
                "--bare",
                &format!("--object-format={format}"),
                "repo",
            ],
            64 * 1024,
        )?;
        Ok(git)
    }
    fn repo(&self) -> PathBuf {
        self.temp.path().join("repo")
    }
    fn run(&self, run: &Run, args: &[&str], max: u64) -> Result<Vec<u8>, String> {
        self.run_os(
            run,
            &args.iter().map(OsString::from).collect::<Vec<_>>(),
            max,
        )
    }
    fn run_os(&self, run: &Run, args: &[OsString], max: u64) -> Result<Vec<u8>, String> {
        if run.stopped() {
            return Err("Git operation interrupted or timed out.".into());
        }
        let mut cmd = Command::new("git");
        cmd.env_clear();
        for name in ["PATH", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        cmd.env("HOME", self.temp.path())
            .env("XDG_CONFIG_HOME", self.temp.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_LITERAL_PATHSPECS", "1")
            .env("LC_ALL", "C")
            .current_dir(self.temp.path())
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "gc.auto=0",
                "-c",
                "maintenance.auto=false",
                "-c",
                "fetch.writeCommitGraph=false",
                "-c",
                "credential.helper=",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "http.followRedirects=false",
                "-c",
                "http.sslVerify=true",
                "-c",
                "fetch.fsckObjects=true",
                "-c",
                "transfer.fsckObjects=true",
            ])
            .arg(format!("--git-dir={}", self.repo().display()))
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if let Some(token) = &self.token {
            cmd.env("SECRETHUNTER_AUTH_TOKEN", token)
                .env("GIT_ASKPASS", self.temp.path().join("askpass"));
        } else {
            cmd.env("GIT_ASKPASS", "/usr/bin/false");
        }
        let mut child = cmd
            .spawn()
            .map_err(|_| "Cannot execute Git; install a supported Git release.")?;
        let stdout = child.stdout.take().ok_or("Cannot capture Git output.")?;
        let stderr = child
            .stderr
            .take()
            .ok_or("Cannot capture Git diagnostics.")?;
        let out = thread::spawn(move || {
            let mut bytes = Vec::new();
            stdout.take(max + 1).read_to_end(&mut bytes).map(|_| bytes)
        });
        let err = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr
                .take(64 * 1024)
                .read_to_end(&mut bytes)
                .map(|_| bytes)
        });
        let mut aborted = false;
        let mut storage_exceeded = false;
        let mut last_storage_check = std::time::Instant::now();
        let storage_limit = self
            .storage_limit
            .filter(|_| args.first().is_some_and(|arg| arg == "fetch"));
        let status = loop {
            if let Some(limit) = storage_limit
                && last_storage_check.elapsed() >= Duration::from_millis(100)
            {
                storage_exceeded = !storage_within_limit(&self.repo().join("objects"), limit);
                last_storage_check = std::time::Instant::now();
            }
            if run.stopped() || storage_exceeded {
                aborted = run.stopped();
                if let Some(pid) = rustix::process::Pid::from_raw(child.id() as i32) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                break child.wait();
            }
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(Duration::from_millis(10)),
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(error);
                }
            }
        };
        let stdout = out
            .join()
            .map_err(|_| "Git output reader failed.")?
            .map_err(|_| "Cannot read Git output.")?;
        let stderr = err
            .join()
            .map_err(|_| "Git diagnostic reader failed.")?
            .map_err(|_| "Cannot read Git diagnostics.")?;
        if aborted {
            return Err("Git operation interrupted or timed out.".into());
        }
        if storage_exceeded
            || storage_limit
                .is_some_and(|limit| !storage_within_limit(&self.repo().join("objects"), limit))
        {
            return Err(
                "Git acquisition storage budget exceeded or object storage could not be inspected."
                    .into(),
            );
        }
        if stdout.len() as u64 > max {
            return Err("Git output exceeds its bounded record or metadata budget.".into());
        }
        if !status.map_err(|_| "Cannot wait for Git.")?.success() {
            let text = String::from_utf8_lossy(&stderr);
            return Err(if text.contains("Authentication failed") || text.contains("could not read Username")
                || text.contains("Repository not found") || text.contains("could not read Password") {
                "GitHub authentication failed or repository is unavailable; select a credential with --github-token-env."
            } else { "Git operation failed: transport, refs, configuration, or objects unavailable (untrusted diagnostic omitted)." }.into());
        }
        Ok(stdout)
    }
}

fn isolate_local(scanner: &mut Scanner, directory: &Path) -> Result<Git, String> {
    let handle = root_handle(directory)?;
    let head = open_relative(&handle, Path::new("HEAD"), false)
        .and_then(|file| read_bounded(file, 1024))?;
    if open_relative(&handle, Path::new("commondir"), false).is_ok() {
        return Err("Linked Git worktrees are unsupported.".into());
    }
    let config_file = open_relative(&handle, Path::new("config"), false)
        .and_then(|f| read_bounded(f, 1024 * 1024))?;
    let probe = Git::new(&scanner.run, "sha1")?;
    let config_path = probe.temp.path().join("source-config");
    fs::write(&config_path, config_file).map_err(|_| "Cannot stage Git metadata.")?;
    let entries = probe.run_os(
        &scanner.run,
        &[
            "config".into(),
            "--no-includes".into(),
            "--null".into(),
            "--file".into(),
            config_path.into_os_string(),
            "--list".into(),
        ],
        2 * 1024 * 1024,
    )?;
    let mut format = "sha1";
    for item in entries.split(|&b| b == 0).filter(|v| !v.is_empty()) {
        let text =
            std::str::from_utf8(item).map_err(|_| "Unsupported Git configuration encoding.")?;
        let (key, value) = text.split_once('\n').unwrap_or((text, ""));
        if key == "extensions.objectformat" {
            format = match value {
                "sha1" => "sha1",
                "sha256" => "sha256",
                _ => return Err("Unsupported Git object format.".into()),
            };
        } else if key.starts_with("extensions.") && key != "extensions.worktreeconfig" {
            return Err("Unsupported or partial Git repository extension.".into());
        }
        if key.ends_with(".promisor") || key.ends_with(".partialclonefilter") {
            scanner.issue(
                "git_history",
                "",
                "Partial repository: requested reachable objects may be unavailable.",
                true,
            );
        }
    }
    let git = Git::new(&scanner.run, format)?;
    fs::write(git.repo().join("HEAD"), head).map_err(|_| "Cannot stage isolated Git HEAD.")?;
    let mut copied = 0;
    for relative in ["objects", "refs/heads", "refs/tags", "refs/remotes"] {
        if directory.join(relative).exists() {
            copy_metadata(
                scanner,
                &handle,
                directory,
                Path::new(relative),
                &git.repo(),
                &mut copied,
            )?;
        }
    }
    for name in ["packed-refs", "shallow"] {
        if fs::symlink_metadata(directory.join(name)).is_ok() {
            let bytes = open_relative(&handle, Path::new(name), false)
                .and_then(|f| read_bounded(f, 32 * 1024 * 1024))?;
            if name == "shallow" && !bytes.is_empty() {
                scanner.issue(
                    "git_history",
                    "",
                    "Shallow repository: requested history is incomplete.",
                    true,
                );
            }
            let bytes = if name == "packed-refs" {
                let text = std::str::from_utf8(&bytes).map_err(|_| "Invalid packed refs.")?;
                let mut output = String::new();
                let mut keep = false;
                for line in text.lines() {
                    if line.starts_with('#') {
                        output.push_str(line);
                        output.push('\n');
                        continue;
                    }
                    if !line.starts_with('^') {
                        keep = line.split_once(' ').is_some_and(|(_, name)| {
                            ["refs/heads/", "refs/tags/", "refs/remotes/"]
                                .iter()
                                .any(|prefix| name.starts_with(prefix))
                        });
                    }
                    if keep {
                        output.push_str(line);
                        output.push('\n');
                    }
                }
                output.into_bytes()
            } else {
                bytes
            };
            fs::write(git.repo().join(name), bytes)
                .map_err(|_| "Cannot stage isolated Git refs.")?;
        }
    }
    if directory.join("logs").exists() {
        scanner.issue(
            "git_history",
            "",
            "Local reflogs and dangling objects are outside reachable-history scope.",
            false,
        );
    }
    Ok(git)
}

fn copy_metadata(
    scanner: &mut Scanner,
    handle: &File,
    source: &Path,
    relative: &Path,
    destination: &Path,
    copied: &mut u64,
) -> Result<(), String> {
    if relative.components().count() > 128 {
        return Err("Git metadata directory nesting budget exceeded.".into());
    }
    if scanner.stopped() {
        return Err("Git metadata acquisition interrupted or exhausted its budget.".into());
    }
    if relative == Path::new("objects/info/alternates")
        || relative == Path::new("objects/info/http-alternates")
    {
        return Err("Git object alternates are unsupported and rejected.".into());
    }
    let meta = fs::symlink_metadata(source.join(relative))
        .map_err(|_| "Cannot inspect Git object storage.")?;
    if meta.is_symlink() || (!meta.is_file() && !meta.is_dir()) {
        return Err("Unsafe Git metadata entry rejected.".into());
    }
    if meta.is_dir() {
        let _pinned = open_relative(handle, relative, true)?;
        fs::create_dir_all(destination.join(relative))
            .map_err(|_| "Cannot stage isolated Git storage.")?;
        for entry in fs::read_dir(source.join(relative))
            .map_err(|_| "Cannot enumerate Git object storage.")?
        {
            let entry = entry.map_err(|_| "Cannot enumerate Git metadata.")?;
            copy_metadata(
                scanner,
                handle,
                source,
                &relative.join(entry.file_name()),
                destination,
                copied,
            )?;
        }
    } else {
        let remaining = scanner
            .config
            .scan
            .max_expanded_bytes_total
            .saturating_sub(*copied);
        let file = open_relative(handle, relative, false)?;
        let before = file
            .metadata()
            .map_err(|_| "Cannot inspect Git storage file.")?;
        if !before.is_file() || before.len() > remaining {
            return Err("Git acquisition byte budget exceeded or unsafe object storage.".into());
        }
        let mut output = File::create(destination.join(relative))
            .map_err(|_| "Cannot stage isolated Git storage.")?;
        let mut reader = file.take(remaining + 1);
        let bytes = std::io::copy(&mut reader, &mut output)
            .map_err(|_| "Cannot copy isolated Git storage.")?;
        let after = reader
            .get_ref()
            .metadata()
            .map_err(|_| "Cannot recheck Git storage identity.")?;
        if bytes > remaining
            || bytes != before.len()
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err(
                "Git storage changed during acquisition or exceeded its byte budget.".into(),
            );
        }
        *copied += bytes;
        if relative.extension() == Some(OsStr::new("promisor")) {
            scanner.issue(
                "git_history",
                "",
                "Promisor pack detected: partial repository history is incomplete.",
                true,
            );
        }
    }
    Ok(())
}

fn remote(scanner: &mut Scanner, url: &str, token_env: Option<&str>) -> Result<(), String> {
    let mut git = Git::new(&scanner.run, "sha1")?;
    git.storage_limit = Some(scanner.config.scan.max_expanded_bytes_total);
    if let Some(name) = token_env {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err("Invalid credential environment-variable name.".into());
        }
        let value = std::env::var_os(name)
            .filter(|v| !v.is_empty())
            .ok_or("Selected GitHub credential environment variable is unset.")?;
        let script = git.temp.path().join("askpass");
        fs::write(&script, b"#!/bin/sh\ncase \"$1\" in\n*Username*) printf '%s\\n' 'x-access-token' ;;\n*Password*) printf '%s\\n' \"$SECRETHUNTER_AUTH_TOKEN\" ;;\n*) exit 1 ;;\nesac\n")
            .map_err(|_| "Cannot create private credential adapter.")?;
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
            .map_err(|_| "Cannot protect credential adapter.")?;
        git.token = Some(value);
    }
    let advertised = git.run(
        &scanner.run,
        &["ls-remote", "--symref", "--", url],
        32 * 1024 * 1024,
    )?;
    if advertised.is_empty() {
        scanner.issue(
            "git_history",
            "",
            "Remote repository advertises no reachable refs.",
            false,
        );
        return Ok(());
    }
    let has_head = advertised
        .split(|&b| b == b'\n')
        .any(|line| !line.starts_with(b"ref:") && line.ends_with(b"\tHEAD"));
    if !has_head && scanner.config.scan.history == "off" {
        return Err("Remote default-branch snapshot is unavailable.".into());
    }
    let mut fetch = vec![
        "fetch",
        "--force",
        "--no-recurse-submodules",
        "--no-write-fetch-head",
        "--",
        url,
        "+refs/heads/*:refs/heads/*",
        "+refs/tags/*:refs/tags/*",
    ];
    if has_head {
        fetch.push("+HEAD:refs/secrethunter/default");
    }
    git.run(&scanner.run, &fetch, 1024 * 1024)?;
    let default = if has_head {
        let bytes = git.run(
            &scanner.run,
            &[
                "rev-parse",
                "--verify",
                "refs/secrethunter/default^{commit}",
            ],
            1024,
        )?;
        Some(
            std::str::from_utf8(&bytes)
                .map_err(|_| "Invalid remote HEAD.")?
                .trim()
                .to_owned(),
        )
    } else {
        None
    };
    history(
        scanner,
        &git,
        Path::new(""),
        default.as_deref(),
        scanner.config.scan.history == "off",
    )
}

fn history(
    scanner: &mut Scanner,
    git: &Git,
    prefix: &Path,
    default: Option<&str>,
    snapshot_only: bool,
) -> Result<(), String> {
    let include_messages = prefix.as_os_str().is_empty();
    if !include_messages && !snapshot_only {
        scanner.scope_exclusion("git_history", "",
            "Repository-global commit/tag messages are outside a subtree-only scan; scan the repository root to inspect them.");
    }
    let refs = git.run(
        &scanner.run,
        &["for-each-ref", "--format=%(refname)%00%(objectname)"],
        32 * 1024 * 1024,
    )?;
    for line in refs.split(|&b| b == b'\n').filter(|v| !v.is_empty()) {
        let Some(index) = line.iter().position(|&b| b == 0) else {
            return Err("Malformed Git ref metadata.".into());
        };
        let name = std::str::from_utf8(&line[..index]).map_err(|_| "Non-UTF-8 Git ref name.")?;
        let oid = std::str::from_utf8(&line[index + 1..]).map_err(|_| "Invalid Git object ID.")?;
        scanner
            .coverage
            .resolved_refs
            .insert(name.into(), oid.into());
        if name.starts_with("refs/tags/") && !snapshot_only && include_messages {
            let mut oid = oid.to_owned();
            for depth in 0..64 {
                if scanner.stopped() {
                    break;
                }
                let kind = git.run(&scanner.run, &["cat-file", "-t", &oid], 128)?;
                if kind != b"tag\n" {
                    break;
                }
                let bytes = git.run(
                    &scanner.run,
                    &["cat-file", "tag", &oid],
                    scanner.config.scan.max_file_bytes,
                )?;
                scanner.record(Record {
                    source: "tag_message".into(),
                    path: "<tag-message>".into(),
                    commit: None,
                    tag: Some(oid.clone()),
                    ref_name: Some(name.into()),
                    blob: Some(oid.clone()),
                    current: false,
                    bytes: message_body(&bytes).to_vec(),
                });
                let header_end = bytes
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .ok_or("Malformed annotated tag.")?;
                let header = std::str::from_utf8(&bytes[..header_end])
                    .map_err(|_| "Invalid annotated tag metadata.")?;
                if !header.lines().any(|line| line == "type tag") {
                    break;
                }
                let next = header
                    .lines()
                    .find_map(|line| line.strip_prefix("object "))
                    .ok_or("Missing nested tag object.")?;
                if !config::is_hex(next, 40) && !config::is_hex(next, 64) {
                    return Err("Invalid nested tag object ID.".into());
                }
                if depth == 63 {
                    return Err("Annotated tag nesting budget exceeded.".into());
                }
                oid = next.into();
            }
        }
    }
    if let Ok(head) = git.run(
        &scanner.run,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        1024,
    ) {
        scanner
            .coverage
            .resolved_refs
            .insert("HEAD".into(), String::from_utf8_lossy(&head).trim().into());
    }
    let commits = if snapshot_only {
        format!("{}\n", default.ok_or("Remote default branch unavailable.")?).into_bytes()
    } else {
        git.run(&scanner.run, &["rev-list", "--all"], 32 * 1024 * 1024)?
    };
    let prefix = prefix.to_str().ok_or("Cannot represent Git subtree.")?;
    let mut prefix = prefix.to_owned();
    if !prefix.is_empty() {
        prefix.push('/');
    }
    for commit in commits.split(|&b| b == b'\n').filter(|v| !v.is_empty()) {
        if scanner.stopped() {
            break;
        }
        let commit = std::str::from_utf8(commit).map_err(|_| "Invalid commit ID.")?;
        if !config::is_hex(commit, 40) && !config::is_hex(commit, 64) {
            return Err("Invalid commit ID.".into());
        }
        if !snapshot_only && include_messages {
            match git.run(
                &scanner.run,
                &["cat-file", "commit", commit],
                scanner.config.scan.max_file_bytes,
            ) {
                Ok(bytes) => scanner.record(Record {
                    source: "commit_message".into(),
                    path: "<commit-message>".into(),
                    commit: Some(commit.into()),
                    tag: None,
                    ref_name: None,
                    blob: None,
                    current: false,
                    bytes: message_body(&bytes).to_vec(),
                }),
                Err(reason) => scanner.issue("commit_message", "", &reason, true),
            }
        }
        let tree = match git.run(
            &scanner.run,
            &["ls-tree", "-r", "-z", "--full-tree", commit],
            32 * 1024 * 1024,
        ) {
            Ok(tree) => tree,
            Err(reason) => {
                scanner.issue("git_history", "", &reason, true);
                continue;
            }
        };
        for entry in tree.split(|&b| b == 0).filter(|v| !v.is_empty()) {
            if scanner.stopped() {
                break;
            }
            let Some(tab) = entry.iter().position(|&b| b == b'\t') else {
                return Err("Malformed Git tree.".into());
            };
            let path = match std::str::from_utf8(&entry[tab + 1..]) {
                Ok(path) => path,
                Err(_) => {
                    scanner.issue("git_history", "", "Non-UTF-8 historical path.", true);
                    continue;
                }
            };
            let Some(path) = path.strip_prefix(&prefix) else {
                continue;
            };
            if scanner.excluded("git_history", path) {
                continue;
            }
            let fields: Vec<_> = entry[..tab].split(|&b| b == b' ').collect();
            if fields.len() != 3 {
                return Err("Malformed Git tree metadata.".into());
            }
            if fields[0] == b"160000" {
                scanner.issue(
                    "git_history",
                    path,
                    "Submodule repository payload is outside scope.",
                    false,
                );
                continue;
            }
            if fields[0] == b"120000" {
                scanner.issue(
                    "git_history",
                    path,
                    "Historical symlink target is not followed.",
                    false,
                );
                continue;
            }
            if fields[1] != b"blob" {
                continue;
            }
            let oid = std::str::from_utf8(fields[2]).map_err(|_| "Invalid blob ID.")?;
            let size = git.run(&scanner.run, &["cat-file", "-s", oid], 128)?;
            let size = std::str::from_utf8(&size)
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or("Invalid blob size.")?;
            if size > scanner.config.scan.max_file_bytes {
                scanner.issue(
                    "git_history",
                    path,
                    "Historical blob exceeds file-byte limit.",
                    true,
                );
                continue;
            }
            match git.run(
                &scanner.run,
                &["cat-file", "blob", oid],
                scanner.config.scan.max_file_bytes,
            ) {
                Ok(bytes) => {
                    if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1") {
                        scanner.issue(
                            "git_history",
                            path,
                            "Git LFS pointer inspected; referenced payload is outside scope.",
                            false,
                        );
                    }
                    scanner.record(Record {
                        source: if snapshot_only {
                            "remote_snapshot"
                        } else {
                            "git_history"
                        }
                        .into(),
                        path: path.into(),
                        commit: Some(commit.into()),
                        tag: None,
                        ref_name: None,
                        blob: Some(oid.into()),
                        current: default == Some(commit),
                        bytes,
                    });
                }
                Err(reason) => scanner.issue("git_history", path, &reason, true),
            }
        }
    }
    Ok(())
}

fn message_body(bytes: &[u8]) -> &[u8] {
    bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(&[], |i| &bytes[i + 2..])
}

fn storage_within_limit(path: &Path, limit: u64) -> bool {
    fn sum(path: &Path, remaining: &mut u64, depth: usize) -> std::io::Result<bool> {
        if depth > 128 {
            return Ok(false);
        }
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let meta = match fs::symlink_metadata(entry.path()) {
                Ok(meta) => meta,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            if meta.is_dir() {
                match sum(&entry.path(), remaining, depth + 1) {
                    Ok(true) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Ok(false) => return Ok(false),
                    Err(err) => return Err(err),
                }
            } else if meta.is_file() && meta.len() <= *remaining {
                *remaining -= meta.len();
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }
    let mut remaining = limit;
    sum(path, &mut remaining, 0).unwrap_or(false)
}
