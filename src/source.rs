use crate::{
    config,
    progress::{Progress, human_bytes},
    scan::{Feeder, FileTask, Origin, Producer, Run, Scanner, Unit},
};
use rustix::fs::{Mode, OFlags, open, openat};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    ffi::{OsStr, OsString},
    fs::{self, File},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;

/// Concurrent `git cat-file --batch` readers; Git decompression is single-threaded
/// per process, so a few readers keep the inspection workers supplied.
const MAX_OBJECT_READERS: usize = 4;
const METADATA_LIMIT: u64 = 32 * 1024 * 1024;
const CLONE_THRESHOLD: u64 = 4 * 1024 * 1024;

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

fn unchanged(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

pub fn read_bounded(mut file: File, max: u64) -> Result<Vec<u8>, String> {
    let before = file.metadata().map_err(|_| "Cannot inspect source file.")?;
    if !before.is_file() || before.len() > max {
        return Err("Non-regular file or file-byte limit exceeded.".into());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Source read failed.")?;
    let after = file
        .metadata()
        .map_err(|_| "Cannot recheck source identity.")?;
    if bytes.len() as u64 > max || !unchanged(&before, &after) {
        return Err("Source changed while being read or exceeded its byte limit.".into());
    }
    Ok(bytes)
}

fn is_bare_repository(root: &Path) -> bool {
    root.join("HEAD").is_file() && root.join("objects").is_dir() && root.join("config").is_file()
}

fn local(scanner: &mut Scanner, root: &Path) -> Result<(), String> {
    for protected in scanner.output.iter().chain(scanner.protected_paths.iter()) {
        if let Ok(relative) = protected.strip_prefix(root) {
            scanner
                .runtime_excludes
                .insert(relative.to_string_lossy().into_owned());
        }
    }
    let history_off = scanner.config.scan.history == "off";
    if history_off && is_bare_repository(root) {
        return Err("A local bare repository requires history=auto or all.".into());
    }
    let repo = if history_off {
        None
    } else {
        find_repository(root)?
    };
    if repo.is_none() && scanner.config.scan.history == "all" {
        return Err("history=all requires a Git repository.".into());
    }
    let bare = repo.as_ref().is_some_and(|(work, git)| work == git);
    let handle = if bare { None } else { Some(root_handle(root)?) };
    if !bare {
        scanner.links.root = Some(root.to_owned());
    }
    let mut files = Vec::new();
    if handle.is_some() {
        scanner.progress.phase("Enumerating files");
        enumerate(scanner, root, Path::new(""), &mut files);
    }
    let mut git = None;
    let mut plan = HistoryPlan::default();
    if let Some((work, git_dir)) = repo
        && !scanner.stopped()
    {
        let prefix = if bare {
            PathBuf::new()
        } else {
            root.strip_prefix(&work)
                .map_err(|_| "Cannot scope Git subtree.")?
                .to_owned()
        };
        let prefix_text = prefix.to_string_lossy();
        if !prefix_text.is_empty() {
            scanner.links.prefix = format!("{prefix_text}/");
        }
        // A history failure must not prevent the already-enumerated files from being scanned.
        match isolate_local(scanner, &git_dir) {
            Ok(isolated) => {
                match plan_history(scanner, &isolated, &prefix, None, false) {
                    Ok(planned) => plan = planned,
                    Err(reason) => scanner.issue("git_history", "", &reason, true),
                }
                link_head(scanner, &isolated);
                git = Some(isolated);
            }
            Err(reason) => scanner.issue("git_history", "", &reason, true),
        }
    }
    let producers = match &git {
        Some(git) => plan.producers(git, scanner),
        None => Vec::new(),
    };
    scanner.execute(handle.as_ref(), files, producers);
    Ok(())
}

fn enumerate(scanner: &mut Scanner, root: &Path, relative: &Path, files: &mut Vec<FileTask>) {
    if scanner.stopped() {
        return;
    }
    if relative.components().count() > 128 {
        scanner.issue(
            "working_tree",
            &relative.to_string_lossy(),
            "Directory nesting budget exhausted.",
            true,
        );
        return;
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
            return;
        }
    };
    let max = scanner.config.scan.max_file_bytes;
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
        // Directory entries are not followed: file_type and metadata come from lstat.
        let meta = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => {
                scanner.issue("working_tree", name, "Cannot inspect entry type.", true);
                continue;
            }
        };
        let kind = meta.file_type();
        if kind.is_symlink() || (!kind.is_dir() && !kind.is_file()) {
            scanner.scope_exclusion(
                "working_tree",
                name,
                "Symlink or special file not followed.",
            );
            continue;
        }
        if kind.is_dir() {
            enumerate(scanner, root, &path, files);
        } else if meta.len() > max {
            scanner.oversized("working_tree", name, "Record exceeds file-byte limit.");
        } else {
            files.push(FileTask {
                path: name.into(),
                size: meta.len(),
            });
            if files.len().is_multiple_of(4096) {
                scanner
                    .progress
                    .status(&format!("{} files found", files.len()));
            }
        }
    }
}

/// Records HEAD and its tracked paths so working-tree findings can link to GitHub.
fn link_head(scanner: &mut Scanner, git: &Git) {
    if scanner.links.github.is_none() {
        return;
    }
    let Some(head) = scanner.coverage.resolved_refs.get("HEAD").cloned() else {
        return;
    };
    let run = scanner.run.clone();
    if let Ok(entries) = tree_entries(git, &run, &head) {
        scanner.links.head_paths = entries.into_iter().map(|(_, _, path)| path).collect();
        scanner.links.head = Some(head);
    }
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
    if is_bare_repository(root) {
        return Ok(Some((root.to_owned(), root.to_owned())));
    }
    Ok(None)
}

struct Git {
    temp: TempDir,
    token: Option<OsString>,
    storage_limit: Option<u64>,
    progress: Progress,
}

fn kill_group(pid: u32) {
    if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
        let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    }
}

fn os_args(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

type InputWriter<'a> = Box<dyn FnOnce(&mut dyn Write) -> Result<(), String> + Send + 'a>;

enum Input<'a> {
    Bytes(Vec<u8>),
    /// Streams stdin from a producer so large inputs never need to be buffered.
    Writer(InputWriter<'a>),
}

enum PackHash {
    Sha1(sha1::Sha1),
    Sha256(Sha256),
}

struct HashingWriter<'a> {
    inner: &'a mut dyn Write,
    hash: PackHash,
}

impl Write for HashingWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        match &mut self.hash {
            PackHash::Sha1(hash) => hash.update(&buf[..written]),
            PackHash::Sha256(hash) => hash.update(&buf[..written]),
        }
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Reads a loose object's `<type> <size>` header from its zlib stream.
fn loose_header(reader: &mut impl Read) -> Result<(u8, u64), String> {
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        reader
            .read_exact(&mut byte)
            .map_err(|_| "Corrupt loose Git object.")?;
        if byte[0] == 0 {
            break;
        }
        header.push(byte[0]);
        if header.len() > 32 {
            return Err("Corrupt loose Git object header.".into());
        }
    }
    let text = std::str::from_utf8(&header).map_err(|_| "Corrupt loose Git object header.")?;
    let (kind, size) = text
        .split_once(' ')
        .ok_or("Corrupt loose Git object header.")?;
    let code = match kind {
        "commit" => 1,
        "tree" => 2,
        "blob" => 3,
        "tag" => 4,
        _ => return Err("Unsupported loose Git object type.".into()),
    };
    let size = size.parse().map_err(|_| "Corrupt loose Git object size.")?;
    Ok((code, size))
}

fn is_loose_object(relative: &Path) -> bool {
    let parts: Vec<_> = relative.iter().filter_map(OsStr::to_str).collect();
    matches!(parts.as_slice(), ["objects", dir, name]
        if dir.len() == 2 && config::is_hex(dir, 2)
            && (config::is_hex(name, 38) || config::is_hex(name, 62)))
}

/// Loose objects whose compressed file exceeds this size are streamed sequentially
/// rather than encoded in memory by parallel workers.
const PARALLEL_LOOSE_MAX: u64 = 1024 * 1024;
const LOOSE_CHUNK_ITEMS: usize = 512;
const LOOSE_CHUNK_BYTES: u64 = 64 * 1024 * 1024;

/// Re-encodes one loose object as an undeltified pack entry. The declared size is
/// reserved against the run-wide expansion budget before any inflation happens.
fn encode_loose(
    handle: &File,
    path: &Path,
    inflated: &AtomicU64,
    budget: u64,
    out: &mut dyn Write,
) -> Result<(), String> {
    let file = open_relative(handle, path, false)?;
    let before = file
        .metadata()
        .map_err(|_| "Cannot inspect loose Git object.")?;
    let mut decoder = flate2::read::ZlibDecoder::new(&file);
    let (code, size) = loose_header(&mut decoder)?;
    let mut used = inflated.load(Ordering::Acquire);
    loop {
        if size > budget.saturating_sub(used) {
            return Err("Loose Git objects exceed the expanded-byte budget.".into());
        }
        match inflated.compare_exchange_weak(used, used + size, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => break,
            Err(actual) => used = actual,
        }
    }
    let io = |_| "Cannot stream loose Git objects.".to_string();
    let mut entry = Vec::with_capacity(10);
    let mut rest = size >> 4;
    let mut first = (code << 4) | (size & 0x0f) as u8;
    if rest > 0 {
        first |= 0x80;
    }
    entry.push(first);
    while rest > 0 {
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            byte |= 0x80;
        }
        entry.push(byte);
    }
    out.write_all(&entry).map_err(io)?;
    let mut encoder = flate2::write::ZlibEncoder::new(out, flate2::Compression::fast());
    let copied = std::io::copy(&mut (&mut decoder).take(size), &mut encoder)
        .map_err(|_| "Corrupt loose Git object.")?;
    encoder.finish().map_err(io)?;
    let mut extra = [0u8; 1];
    if copied != size
        || decoder
            .read(&mut extra)
            .map_err(|_| "Corrupt loose Git object.")?
            != 0
    {
        return Err("Loose Git object size does not match its header.".into());
    }
    let after = file
        .metadata()
        .map_err(|_| "Cannot recheck loose Git object.")?;
    if !unchanged(&before, &after) {
        return Err("Loose Git object changed during acquisition.".into());
    }
    Ok(())
}

/// Order-preserving parallel map over a small batch.
fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    workers: usize,
    f: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let results: Vec<Mutex<Option<R>>> = items.iter().map(|_| Mutex::new(None)).collect();
    thread::scope(|scope| {
        for _ in 0..workers.clamp(1, items.len().max(1)) {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(index) else { break };
                    *results[index].lock().expect("parallel result") = Some(f(item));
                }
            });
        }
    });
    results
        .into_iter()
        .map(|slot| {
            slot.into_inner()
                .expect("parallel result")
                .expect("every item processed")
        })
        .collect()
}

struct PackOptions<'a> {
    handle: &'a File,
    sha256: bool,
    progress: Progress,
    run: Run,
    workers: usize,
    budget: u64,
}

/// Writes loose objects as one undeltified pack. Small objects are encoded on worker
/// threads in bounded, ordered batches; Git's `index-pack` then recomputes every ID.
fn write_loose_pack(
    out: &mut dyn Write,
    loose: &[(PathBuf, u64)],
    options: &PackOptions<'_>,
) -> Result<(), String> {
    let PackOptions {
        handle,
        sha256,
        progress,
        run,
        workers,
        budget,
    } = options;
    let (handle, workers, budget) = (*handle, *workers, *budget);
    let mut writer = HashingWriter {
        inner: out,
        hash: if *sha256 {
            PackHash::Sha256(Sha256::new())
        } else {
            PackHash::Sha1(sha1::Sha1::new())
        },
    };
    let io = |_| "Cannot stream loose Git objects.".to_string();
    writer.write_all(b"PACK").map_err(io)?;
    writer.write_all(&2u32.to_be_bytes()).map_err(io)?;
    let count = u32::try_from(loose.len()).map_err(|_| "Too many loose Git objects.")?;
    writer.write_all(&count.to_be_bytes()).map_err(io)?;
    let inflated = AtomicU64::new(0);
    let mut start = 0;
    while start < loose.len() {
        if run.stopped() {
            return Err("Git metadata acquisition interrupted or exhausted its budget.".into());
        }
        if loose[start].1 > PARALLEL_LOOSE_MAX {
            encode_loose(handle, &loose[start].0, &inflated, budget, &mut writer)?;
            start += 1;
            continue;
        }
        let mut end = start;
        let mut bytes = 0;
        while end < loose.len()
            && end - start < LOOSE_CHUNK_ITEMS
            && bytes < LOOSE_CHUNK_BYTES
            && loose[end].1 <= PARALLEL_LOOSE_MAX
        {
            bytes += loose[end].1;
            end += 1;
        }
        let entries = parallel_map(&loose[start..end], workers, |(path, size)| {
            let mut entry = Vec::with_capacity(*size as usize + 16);
            encode_loose(handle, path, &inflated, budget, &mut entry).map(|_| entry)
        });
        for entry in entries {
            writer.write_all(&entry?).map_err(io)?;
        }
        start = end;
        progress.status(&format!("{start}/{} loose objects packed", loose.len()));
    }
    let trailer = match writer.hash {
        PackHash::Sha1(hash) => hash.finalize().to_vec(),
        PackHash::Sha256(hash) => hash.finalize().to_vec(),
    };
    writer.inner.write_all(&trailer).map_err(io)
}

impl Git {
    fn new(run: &Run, format: &str, progress: Progress) -> Result<Self, String> {
        let temp = tempfile::Builder::new()
            .prefix("secrethunter-")
            .tempdir()
            .map_err(|_| "Cannot create private Git workspace.")?;
        let git = Self {
            temp,
            token: None,
            storage_limit: None,
            progress,
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

    fn command(&self, args: &[OsString]) -> Command {
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
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if let Some(token) = &self.token {
            cmd.env("SECRETHUNTER_AUTH_TOKEN", token)
                .env("GIT_ASKPASS", self.temp.path().join("askpass"));
        } else {
            cmd.env("GIT_ASKPASS", "/usr/bin/false");
        }
        cmd
    }

    fn run(&self, run: &Run, args: &[&str], max: u64) -> Result<Vec<u8>, String> {
        self.run_os(run, &os_args(args), max)
    }

    fn run_os(&self, run: &Run, args: &[OsString], max: u64) -> Result<Vec<u8>, String> {
        self.stream(run, args, None, |reader| {
            let mut bytes = Vec::new();
            reader
                .take(max + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "Cannot read Git output.")?;
            if bytes.len() as u64 > max {
                return Err("Git output exceeds its bounded record or metadata budget.".into());
            }
            Ok(bytes)
        })
    }

    /// Runs Git with optional stdin, handing stdout to `read` as a stream. A watchdog
    /// kills the process group on cancellation, timeout, or acquisition-budget overrun.
    fn stream<T>(
        &self,
        run: &Run,
        args: &[OsString],
        input: Option<Input<'_>>,
        read: impl FnOnce(&mut dyn BufRead) -> Result<T, String>,
    ) -> Result<T, String> {
        if run.stopped() {
            return Err("Git operation interrupted or timed out.".into());
        }
        let mut cmd = self.command(args);
        cmd.stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
        let mut child = cmd
            .spawn()
            .map_err(|_| "Cannot execute Git; install a supported Git release.")?;
        let pid = child.id();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or("Cannot capture Git output.")?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or("Cannot capture Git diagnostics.")?;
        let watch_storage = self
            .storage_limit
            .filter(|_| args.first().is_some_and(|arg| arg == "fetch"));
        let done = AtomicBool::new(false);
        let aborted = AtomicBool::new(false);
        let exceeded = AtomicBool::new(false);
        let writer_error = Mutex::new(None::<String>);
        thread::scope(|scope| {
            let writer_error = &writer_error;
            let writer = match (stdin, input) {
                (Some(mut stdin), Some(input)) => Some(scope.spawn(move || match input {
                    Input::Bytes(data) => {
                        let _ = stdin.write_all(&data);
                    }
                    Input::Writer(produce) => {
                        let mut out = BufWriter::with_capacity(1024 * 1024, stdin);
                        let result = produce(&mut out).and_then(|_| {
                            out.flush()
                                .map_err(|_| "Cannot write Git input.".to_string())
                        });
                        if let Err(reason) = result {
                            *writer_error.lock().expect("writer error") = Some(reason);
                            kill_group(pid);
                        }
                    }
                })),
                _ => None,
            };
            // Drain diagnostics fully so Git never blocks on a full stderr pipe.
            let diagnostics = scope.spawn(move || {
                let mut kept = Vec::new();
                let mut buffer = [0u8; 8192];
                while let Ok(n) = stderr.read(&mut buffer) {
                    if n == 0 {
                        break;
                    }
                    let room = 64 * 1024 - kept.len().min(64 * 1024);
                    kept.extend_from_slice(&buffer[..n.min(room)]);
                }
                kept
            });
            scope.spawn(|| {
                let mut last_check: Option<Instant> = None;
                while !done.load(Ordering::Acquire) {
                    if run.stopped() {
                        aborted.store(true, Ordering::Release);
                        kill_group(pid);
                        return;
                    }
                    if let Some(limit) = watch_storage
                        && last_check.is_none_or(|t| t.elapsed() >= Duration::from_millis(100))
                    {
                        last_check = Some(Instant::now());
                        match storage_size(&self.repo().join("objects"), limit) {
                            Some(size) => self
                                .progress
                                .status(&format!("{} received", human_bytes(size))),
                            None => {
                                exceeded.store(true, Ordering::Release);
                                kill_group(pid);
                                return;
                            }
                        }
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            });
            let mut reader = BufReader::with_capacity(256 * 1024, stdout);
            let result = read(&mut reader);
            drop(reader);
            if result.is_err() {
                kill_group(pid);
            }
            let status = child.wait();
            done.store(true, Ordering::Release);
            let diagnostics = diagnostics.join().unwrap_or_default();
            if let Some(writer) = writer {
                let _ = writer.join();
            }
            if aborted.load(Ordering::Acquire) || run.stopped() {
                return Err("Git operation interrupted or timed out.".into());
            }
            if let Some(reason) = writer_error.lock().expect("writer error").take() {
                return Err(reason);
            }
            if exceeded.load(Ordering::Acquire)
                || watch_storage.is_some_and(|limit| {
                    storage_size(&self.repo().join("objects"), limit).is_none()
                })
            {
                return Err(
                    "Git acquisition storage budget exceeded or object storage could not be inspected."
                        .into(),
                );
            }
            let success = status.map_err(|_| "Cannot wait for Git.")?.success();
            let text = String::from_utf8_lossy(&diagnostics);
            let auth = text.contains("Authentication failed")
                || text.contains("could not read Username")
                || text.contains("Repository not found")
                || text.contains("could not read Password");
            match result {
                Ok(value) if success => Ok(value),
                Err(reason) if !auth => Err(reason),
                _ if auth => Err("GitHub authentication failed or repository is unavailable; select a credential with --github-token-env.".into()),
                _ => Err("Git operation failed: transport, refs, configuration, or objects unavailable (untrusted diagnostic omitted).".into()),
            }
        })
    }

    /// Type and size for each object ID, in input order; `None` means missing.
    fn batch_check(
        &self,
        run: &Run,
        oids: &[String],
    ) -> Result<Vec<Option<(String, u64)>>, String> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }
        let input = join_lines(oids.iter());
        self.stream(
            run,
            &os_args(&["cat-file", "--batch-check"]),
            Some(Input::Bytes(input)),
            |reader| {
                let mut out = Vec::with_capacity(oids.len());
                let mut line = Vec::new();
                for oid in oids {
                    line.clear();
                    if reader
                        .read_until(b'\n', &mut line)
                        .map_err(|_| "Cannot read Git object metadata.")?
                        == 0
                    {
                        return Err("Git object metadata ended early.".into());
                    }
                    let text =
                        std::str::from_utf8(&line).map_err(|_| "Invalid Git object metadata.")?;
                    let fields: Vec<_> = text.trim_end().split(' ').collect();
                    match fields.as_slice() {
                        [id, "missing"] if id == oid => out.push(None),
                        [id, kind, size] if id == oid => out.push(Some((
                            (*kind).to_owned(),
                            size.parse().map_err(|_| "Invalid Git object size.")?,
                        ))),
                        _ => return Err("Malformed Git object metadata.".into()),
                    }
                }
                Ok(out)
            },
        )
    }

    /// Streams objects in input order. `on_object` returns false to stop early.
    fn batch_read(
        &self,
        run: &Run,
        oids: &[String],
        max: u64,
        mut on_object: impl FnMut(usize, Option<(&str, Vec<u8>)>) -> bool,
    ) -> Result<(), String> {
        if oids.is_empty() {
            return Ok(());
        }
        let input = join_lines(oids.iter());
        self.stream(
            run,
            &os_args(&["cat-file", "--batch"]),
            Some(Input::Bytes(input)),
            |reader| {
                let mut header = Vec::new();
                for (index, oid) in oids.iter().enumerate() {
                    header.clear();
                    if reader
                        .read_until(b'\n', &mut header)
                        .map_err(|_| "Cannot read Git object.")?
                        == 0
                    {
                        return Err("Git object stream ended early.".into());
                    }
                    let text =
                        std::str::from_utf8(&header).map_err(|_| "Invalid Git object header.")?;
                    let fields: Vec<_> = text.trim_end().split(' ').collect();
                    let object = match fields.as_slice() {
                        [id, "missing"] if id == oid => None,
                        [id, kind, size] if id == oid => {
                            let size: u64 = size.parse().map_err(|_| "Invalid Git object size.")?;
                            if size > max {
                                // Should not normally happen (callers pre-filter by size), but
                                // the stream position must stay in sync regardless: discard this
                                // object's bytes and report it like a missing object rather than
                                // aborting every remaining object in this reader's batch.
                                let mut newline = [0u8; 1];
                                std::io::copy(&mut reader.take(size), &mut std::io::sink())
                                    .and_then(|_| reader.read_exact(&mut newline))
                                    .map_err(|_| "Truncated Git object stream.")?;
                                None
                            } else {
                                let mut data = vec![0u8; size as usize];
                                let mut newline = [0u8; 1];
                                reader
                                    .read_exact(&mut data)
                                    .and_then(|_| reader.read_exact(&mut newline))
                                    .map_err(|_| "Truncated Git object stream.")?;
                                Some((*kind, data))
                            }
                        }
                        _ => return Err("Malformed Git object header.".into()),
                    };
                    if !on_object(index, object) {
                        return Err("Git object reading stopped.".into());
                    }
                }
                Ok(())
            },
        )
    }
}

fn join_lines<'a>(values: impl Iterator<Item = &'a String>) -> Vec<u8> {
    let mut out = Vec::new();
    for value in values {
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out
}

fn isolate_local(scanner: &mut Scanner, directory: &Path) -> Result<Git, String> {
    scanner.progress.phase("Staging local Git objects");
    let handle = root_handle(directory)?;
    let head = open_relative(&handle, Path::new("HEAD"), false)
        .and_then(|file| read_bounded(file, 1024))?;
    if open_relative(&handle, Path::new("commondir"), false).is_ok() {
        return Err("Linked Git worktrees are unsupported.".into());
    }
    let config_file = open_relative(&handle, Path::new("config"), false)
        .and_then(|f| read_bounded(f, 1024 * 1024))?;
    let run = scanner.run.clone();
    let probe = Git::new(&run, "sha1", Progress::disabled())?;
    let config_path = probe.temp.path().join("source-config");
    fs::write(&config_path, config_file).map_err(|_| "Cannot stage Git metadata.")?;
    let entries = probe.run_os(
        &run,
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
        if key == "remote.origin.url" {
            scanner.links.github = crate::links::github_base(value);
        }
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
    let git = Git::new(&run, format, scanner.progress.clone())?;
    fs::write(git.repo().join("HEAD"), head).map_err(|_| "Cannot stage isolated Git HEAD.")?;
    let mut staging = Staging::default();
    for relative in ["objects", "refs/heads", "refs/tags", "refs/remotes"] {
        if directory.join(relative).exists() {
            copy_metadata(
                scanner,
                &handle,
                directory,
                Path::new(relative),
                &git.repo(),
                &mut staging,
            )?;
        }
    }
    if !staging.loose.is_empty() {
        scanner.progress.phase("Packing loose Git objects");
        let loose = std::mem::take(&mut staging.loose);
        let options = PackOptions {
            handle: &handle,
            sha256: format == "sha256",
            progress: scanner.progress.clone(),
            run: run.clone(),
            workers: scanner.config.scan.workers,
            budget: scanner.config.scan.max_expanded_bytes_total,
        };
        git.stream(
            &run,
            &os_args(&["index-pack", "--stdin"]),
            Some(Input::Writer(Box::new(move |out: &mut dyn Write| {
                write_loose_pack(out, &loose, &options)
            }))),
            |reader| {
                std::io::copy(&mut reader.take(4096), &mut std::io::sink())
                    .map_err(|_| "Cannot read Git pack index result.".to_string())
            },
        )?;
    }
    for name in ["packed-refs", "shallow"] {
        if fs::symlink_metadata(directory.join(name)).is_ok() {
            let bytes = open_relative(&handle, Path::new(name), false)
                .and_then(|f| read_bounded(f, METADATA_LIMIT))?;
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

/// Copy-on-write clone from an already-verified descriptor (APFS); never follows names.
#[cfg(target_os = "macos")]
fn clone_file(source: &File, destination: &Path) -> bool {
    use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};
    unsafe extern "C" {
        fn fclonefileat(
            srcfd: libc::c_int,
            dst_dirfd: libc::c_int,
            dst: *const libc::c_char,
            flags: u32,
        ) -> libc::c_int;
    }
    let Ok(path) = std::ffi::CString::new(destination.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: the descriptor is open and the path is NUL-terminated for the whole call.
    unsafe { fclonefileat(source.as_raw_fd(), libc::AT_FDCWD, path.as_ptr(), 0) == 0 }
}

#[cfg(not(target_os = "macos"))]
fn clone_file(_: &File, _: &Path) -> bool {
    false
}

fn copy_metadata(
    scanner: &mut Scanner,
    handle: &File,
    source: &Path,
    relative: &Path,
    destination: &Path,
    staging: &mut Staging,
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
                staging,
            )?;
        }
        return Ok(());
    }
    let remaining = scanner
        .config
        .scan
        .max_expanded_bytes_total
        .saturating_sub(staging.copied);
    if is_loose_object(relative) {
        if meta.len() > remaining {
            return Err("Git acquisition byte budget exceeded or unsafe object storage.".into());
        }
        // Encoded into one pack later through no-follow handles; avoids one new
        // staging file (and its first-read cost) per loose object.
        staging.copied += meta.len();
        staging.loose.push((relative.to_owned(), meta.len()));
        return Ok(());
    }
    let file = open_relative(handle, relative, false)?;
    let before = file
        .metadata()
        .map_err(|_| "Cannot inspect Git storage file.")?;
    if !before.is_file() || before.len() > remaining {
        return Err("Git acquisition byte budget exceeded or unsafe object storage.".into());
    }
    let target = destination.join(relative);
    // Cloning avoids duplicating large packs, but cloned small loose objects bypass the
    // warm page cache and make Git's first reads disk-bound.
    let cloned = before.len() >= CLONE_THRESHOLD
        && clone_file(&file, &target)
        && fs::symlink_metadata(&target).is_ok_and(|m| m.is_file() && m.len() == before.len());
    if !cloned {
        let _ = fs::remove_file(&target);
        let output = File::create(&target).map_err(|_| "Cannot stage isolated Git storage.")?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, output);
        let mut reader = (&file).take(remaining + 1);
        let bytes = std::io::copy(&mut reader, &mut writer)
            .map_err(|_| "Cannot copy isolated Git storage.")?;
        writer
            .into_inner()
            .map_err(|_| "Cannot write isolated Git storage.")?;
        if bytes != before.len() {
            return Err(
                "Git storage changed during acquisition or exceeded its byte budget.".into(),
            );
        }
    }
    let after = file
        .metadata()
        .map_err(|_| "Cannot recheck Git storage identity.")?;
    if !unchanged(&before, &after) {
        return Err("Git storage changed during acquisition or exceeded its byte budget.".into());
    }
    staging.copied += before.len();
    if relative.extension() == Some(OsStr::new("promisor")) {
        scanner.issue(
            "git_history",
            "",
            "Promisor pack detected: partial repository history is incomplete.",
            true,
        );
    }
    scanner
        .progress
        .status(&format!("{} staged", human_bytes(staging.copied)));
    Ok(())
}

#[derive(Default)]
struct Staging {
    copied: u64,
    loose: Vec<(PathBuf, u64)>,
}

fn remote(scanner: &mut Scanner, url: &str, token_env: Option<&str>) -> Result<(), String> {
    scanner.progress.phase("Connecting to GitHub");
    let run = scanner.run.clone();
    let mut git = Git::new(&run, "sha1", scanner.progress.clone())?;
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
    let advertised = git.run(&run, &["ls-remote", "--symref", "--", url], METADATA_LIMIT)?;
    if advertised.is_empty() {
        scanner.issue(
            "git_history",
            "",
            "Remote repository advertises no reachable refs.",
            false,
        );
        scanner.execute(None, Vec::new(), Vec::new());
        return Ok(());
    }
    let has_head = advertised
        .split(|&b| b == b'\n')
        .any(|line| !line.starts_with(b"ref:") && line.ends_with(b"\tHEAD"));
    if !has_head && scanner.config.scan.history == "off" {
        return Err("Remote default-branch snapshot is unavailable.".into());
    }
    scanner.progress.phase("Fetching repository");
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
    git.run(&run, &fetch, 1024 * 1024)?;
    let default = if has_head {
        let bytes = git.run(
            &run,
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
    let snapshot = scanner.config.scan.history == "off";
    scanner.links.github = crate::links::github_base(url);
    scanner.links.head = default.clone();
    let plan = plan_history(scanner, &git, Path::new(""), default.as_deref(), snapshot)?;
    let producers = plan.producers(&git, scanner);
    scanner.execute(None, Vec::new(), producers);
    Ok(())
}

struct ObjectTask {
    oid: String,
    commit_message: bool,
    size: u64,
    origins: Vec<Origin>,
}

#[derive(Default)]
struct HistoryPlan {
    objects: Vec<ObjectTask>,
    units: Vec<Unit>,
}

impl HistoryPlan {
    /// Splits object reads into size-balanced batches, each on its own Git reader.
    fn producers<'a>(self, git: &'a Git, scanner: &Scanner) -> Vec<Producer<'a>> {
        let mut producers = Vec::new();
        if !self.units.is_empty() {
            let units = self.units;
            producers.push(Producer {
                items: units.len() as u64,
                bytes: units.iter().map(|u| u.weight).sum(),
                task: Box::new(move |feeder: &Feeder| {
                    for unit in units {
                        if !feeder.send(unit) {
                            break;
                        }
                    }
                    Ok(())
                }),
            });
        }
        let readers = scanner
            .config
            .scan
            .workers
            .clamp(1, MAX_OBJECT_READERS)
            .min(self.objects.len().max(1));
        let mut objects = self.objects;
        objects.sort_by(|a, b| b.size.cmp(&a.size).then(a.oid.cmp(&b.oid)));
        let mut batches: Vec<(u64, Vec<ObjectTask>)> =
            (0..readers).map(|_| (0, Vec::new())).collect();
        for task in objects {
            let lightest = batches
                .iter_mut()
                .min_by_key(|(bytes, _)| *bytes)
                .expect("at least one reader");
            lightest.0 += task.size;
            lightest.1.push(task);
        }
        let run = scanner.run.clone();
        let max = scanner.config.scan.max_file_bytes;
        for (bytes, mut batch) in batches.into_iter().filter(|(_, b)| !b.is_empty()) {
            // Object-ID order improves pack locality for Git's delta cache.
            batch.sort_by(|a, b| a.oid.cmp(&b.oid));
            let run = run.clone();
            producers.push(Producer {
                items: batch.len() as u64,
                bytes,
                task: Box::new(move |feeder: &Feeder| {
                    let oids: Vec<String> = batch.iter().map(|task| task.oid.clone()).collect();
                    let mut tasks: Vec<Option<ObjectTask>> = batch.into_iter().map(Some).collect();
                    git.batch_read(&run, &oids, max, |index, object| {
                        let task = tasks[index].take().expect("each object is read once");
                        match object {
                            None => {
                                let path = &task.origins[0].path;
                                // plan_history already pre-filters by size via batch_check, so
                                // this is almost always a genuinely missing object; an oversized
                                // object reaching here (race or sizing bug) looks the same here.
                                feeder.issue(
                                    &task.origins[0].source,
                                    path,
                                    "Reachable Git object is missing or exceeds the file-byte limit.",
                                    true,
                                    task.size,
                                );
                                true
                            }
                            Some((_, data)) => {
                                let bytes = if task.commit_message {
                                    message_body(&data).to_vec()
                                } else {
                                    data
                                };
                                feeder.send(Unit {
                                    origins: task.origins,
                                    bytes,
                                    weight: task.size,
                                })
                            }
                        }
                    })
                }),
            });
        }
        producers
    }
}

fn origin(
    source: &str,
    path: &str,
    commit: Option<&str>,
    blob: Option<&str>,
    current: bool,
    commit_time: Option<i64>,
) -> Origin {
    Origin {
        source: source.into(),
        path: path.into(),
        commit: commit.map(Into::into),
        tag: None,
        ref_name: None,
        blob: blob.map(Into::into),
        current,
        commit_time,
    }
}

fn valid_oid(value: &str) -> bool {
    config::is_hex(value, 40) || config::is_hex(value, 64)
}

/// Enumerates reachable history without reading file contents: each changed path/blob
/// introduction becomes one occurrence, and each unique blob is read exactly once.
fn plan_history(
    scanner: &mut Scanner,
    git: &Git,
    prefix: &Path,
    default: Option<&str>,
    snapshot_only: bool,
) -> Result<HistoryPlan, String> {
    scanner.progress.phase("Enumerating Git history");
    let run = scanner.run.clone();
    let max = scanner.config.scan.max_file_bytes;
    let include_messages = prefix.as_os_str().is_empty();
    if !include_messages && !snapshot_only {
        scanner.scope_exclusion(
            "git_history",
            "",
            "Repository-global commit/tag messages are outside a subtree-only scan; scan the repository root to inspect them.",
        );
    }
    let refs = git.run(
        &run,
        &["for-each-ref", "--format=%(refname)%00%(objectname)"],
        METADATA_LIMIT,
    )?;
    let mut tag_refs = Vec::new();
    for line in refs.split(|&b| b == b'\n').filter(|v| !v.is_empty()) {
        let Some(index) = line.iter().position(|&b| b == 0) else {
            return Err("Malformed Git ref metadata.".into());
        };
        let name = std::str::from_utf8(&line[..index]).map_err(|_| "Non-UTF-8 Git ref name.")?;
        let oid = std::str::from_utf8(&line[index + 1..]).map_err(|_| "Invalid Git object ID.")?;
        if !valid_oid(oid) {
            return Err("Invalid Git object ID.".into());
        }
        scanner
            .coverage
            .resolved_refs
            .insert(name.into(), oid.into());
        if name.starts_with("refs/tags/") {
            tag_refs.push((name.to_owned(), oid.to_owned()));
        }
    }
    if let Ok(head) = git.run(&run, &["rev-parse", "--verify", "HEAD^{commit}"], 1024) {
        scanner
            .coverage
            .resolved_refs
            .insert("HEAD".into(), String::from_utf8_lossy(&head).trim().into());
    }
    let mut prefix = prefix
        .to_str()
        .ok_or("Cannot represent Git subtree.")?
        .to_owned();
    if !prefix.is_empty() {
        prefix.push('/');
    }
    let source = if snapshot_only {
        "remote_snapshot"
    } else {
        "git_history"
    };
    let current_tree = match default {
        Some(commit) => tree_entries(git, &run, commit)?,
        None => Vec::new(),
    };
    let current: HashSet<(String, String)> = current_tree
        .iter()
        .map(|(_, oid, path)| (path.clone(), oid.clone()))
        .collect();
    // Built before `add` so the closure can borrow it immutably without an ordering conflict.
    let mut commits: Vec<String> = Vec::new();
    let mut commit_times: HashMap<String, i64> = HashMap::new();
    if snapshot_only {
        commits.push(
            default
                .ok_or("Remote default branch unavailable.")?
                .to_owned(),
        );
    } else {
        git.stream(
            &run,
            &os_args(&["log", "--all", "--format=%H%x09%ct"]),
            None,
            |reader| {
                for line in reader.lines() {
                    let line = line.map_err(|_| "Cannot read Git commit list.")?;
                    let (hash, stamp) = line
                        .split_once('\t')
                        .ok_or("Malformed Git commit timestamp line.")?;
                    if !valid_oid(hash) {
                        return Err("Invalid commit ID.".into());
                    }
                    let stamp: i64 = stamp.parse().map_err(|_| "Invalid Git commit timestamp.")?;
                    commit_times.insert(hash.to_owned(), stamp);
                    commits.push(hash.to_owned());
                }
                Ok(())
            },
        )?;
        scanner
            .progress
            .status(&format!("{} commits", commits.len()));
    }
    let mut blobs: HashMap<String, Vec<Origin>> = HashMap::new();
    let mut seen: HashSet<(String, String, String)> = HashSet::new();
    let mut add = |scanner: &mut Scanner, mode: &str, oid: &str, path: &str, commit: &str| {
        let Some(path) = path.strip_prefix(prefix.as_str()) else {
            return;
        };
        if !seen.insert((oid.to_owned(), path.to_owned(), commit.to_owned())) {
            return;
        }
        if scanner.excluded(source, path) {
            return;
        }
        match mode {
            "160000" => scanner.issue(
                source,
                path,
                "Submodule repository payload is outside scope.",
                false,
            ),
            "120000" => scanner.issue(
                source,
                path,
                "Historical symlink target is not followed.",
                false,
            ),
            mode if mode.starts_with("100") => {
                let is_current =
                    snapshot_only || current.contains(&(format!("{prefix}{path}"), oid.to_owned()));
                blobs.entry(oid.to_owned()).or_default().push(origin(
                    source,
                    path,
                    Some(commit),
                    Some(oid),
                    is_current,
                    commit_times.get(commit).copied(),
                ));
            }
            _ => {}
        }
    };
    if snapshot_only {
        let commit = &commits[0];
        for (mode, oid, path) in &current_tree {
            add(scanner, mode, oid, path, commit);
        }
    } else {
        let input = join_lines(commits.iter());
        let progress = scanner.progress.clone();
        let args = os_args(&[
            "diff-tree",
            "--stdin",
            "-r",
            "-z",
            "--root",
            "-m",
            "--always",
            "--no-renames",
            "--no-abbrev",
            "--no-ext-diff",
            "--no-textconv",
        ]);
        git.stream(&run, &args, Some(Input::Bytes(input)), |reader| {
            let mut token = Vec::new();
            let mut commit = String::new();
            let mut visited = 0usize;
            let mut pending: Option<(String, String, bool)> = None;
            loop {
                token.clear();
                if reader
                    .read_until(0, &mut token)
                    .map_err(|_| "Cannot read Git history.")?
                    == 0
                {
                    break;
                }
                if token.last() == Some(&0) {
                    token.pop();
                }
                if let Some((mode, oid, deleted)) = pending.take() {
                    match std::str::from_utf8(&token) {
                        Ok(path) if !deleted => add(scanner, &mode, &oid, path, &commit),
                        Ok(_) => {}
                        Err(_) => scanner.issue(source, "", "Non-UTF-8 historical path.", true),
                    }
                    continue;
                }
                let text =
                    std::str::from_utf8(&token).map_err(|_| "Malformed Git history stream.")?;
                if let Some(entry) = text.strip_prefix(':') {
                    let fields: Vec<_> = entry.split(' ').collect();
                    let [_, mode, _, oid, status] = fields.as_slice() else {
                        return Err("Malformed Git history entry.".into());
                    };
                    let deleted = status.starts_with('D') || oid.bytes().all(|b| b == b'0');
                    if !valid_oid(oid) {
                        return Err("Invalid Git object ID in history.".into());
                    }
                    pending = Some(((*mode).to_owned(), (*oid).to_owned(), deleted));
                } else {
                    let header = text.trim();
                    if !valid_oid(header) {
                        return Err("Malformed Git history stream.".into());
                    }
                    if header != commit {
                        visited += 1;
                        if visited.is_multiple_of(256) {
                            progress.status(&format!("{visited} commits examined"));
                        }
                    }
                    commit = header.to_owned();
                }
            }
            Ok(())
        })?;
    }

    let mut units = Vec::new();
    if include_messages && !snapshot_only {
        let mut frontier = tag_refs;
        for depth in 0..64 {
            if frontier.is_empty() {
                break;
            }
            if depth == 63 {
                return Err("Annotated tag nesting budget exceeded.".into());
            }
            let oids: Vec<String> = frontier.iter().map(|(_, oid)| oid.clone()).collect();
            let kinds = git.batch_check(&run, &oids)?;
            let tags: Vec<(String, String)> = frontier
                .into_iter()
                .zip(kinds)
                .filter(|(_, kind)| kind.as_ref().is_some_and(|(kind, _)| kind == "tag"))
                .map(|(entry, _)| entry)
                .collect();
            let oids: Vec<String> = tags.iter().map(|(_, oid)| oid.clone()).collect();
            let mut next = Vec::new();
            let mut failure = None;
            git.batch_read(&run, &oids, max, |index, object| {
                let (name, oid) = &tags[index];
                let Some((_, bytes)) = object else {
                    failure =
                        Some("Annotated tag object is missing or exceeds the file-byte limit.");
                    return true;
                };
                let header_end = bytes
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .unwrap_or(bytes.len());
                let header = std::str::from_utf8(&bytes[..header_end]).unwrap_or("");
                if header.lines().any(|line| line == "type tag")
                    && let Some(nested) = header.lines().find_map(|l| l.strip_prefix("object "))
                    && valid_oid(nested)
                {
                    next.push((name.clone(), nested.to_owned()));
                }
                units.push(Unit {
                    origins: vec![Origin {
                        source: "tag_message".into(),
                        path: "<tag-message>".into(),
                        commit: None,
                        tag: Some(oid.clone()),
                        ref_name: Some(name.clone()),
                        blob: Some(oid.clone()),
                        current: false,
                        commit_time: None,
                    }],
                    weight: bytes.len() as u64,
                    bytes: message_body(&bytes).to_vec(),
                });
                true
            })?;
            if let Some(reason) = failure {
                scanner.issue("tag_message", "", reason, true);
            }
            frontier = next;
        }
    }

    scanner.progress.phase("Sizing Git objects");
    let mut oids: Vec<String> = blobs.keys().cloned().collect();
    oids.sort();
    let mut tasks: Vec<ObjectTask> = oids
        .into_iter()
        .map(|oid| ObjectTask {
            origins: blobs.remove(&oid).unwrap_or_default(),
            oid,
            commit_message: false,
            size: 0,
        })
        .collect();
    if include_messages && !snapshot_only {
        tasks.extend(commits.into_iter().map(|commit| {
            let commit_time = commit_times.get(&commit).copied();
            ObjectTask {
                origins: vec![origin(
                    "commit_message",
                    "<commit-message>",
                    Some(&commit),
                    None,
                    false,
                    commit_time,
                )],
                oid: commit,
                commit_message: true,
                size: 0,
            }
        }));
    }
    let ids: Vec<String> = tasks.iter().map(|task| task.oid.clone()).collect();
    let sizes = git.batch_check(&run, &ids)?;
    let mut objects = Vec::with_capacity(tasks.len());
    for (mut task, size) in tasks.into_iter().zip(sizes) {
        let first = &task.origins[0];
        match size {
            None => scanner.issue(
                &first.source,
                &first.path,
                "Reachable Git object is missing.",
                true,
            ),
            Some((_, size)) if size > max => {
                for origin in &task.origins {
                    scanner.oversized(
                        &origin.source,
                        &origin.path,
                        "Historical blob exceeds file-byte limit.",
                    );
                }
            }
            Some((_, size)) => {
                task.size = size;
                objects.push(task);
            }
        }
    }
    Ok(HistoryPlan { objects, units })
}

/// `(mode, object ID, full path)` for every entry in a commit's tree.
fn tree_entries(
    git: &Git,
    run: &Run,
    commit: &str,
) -> Result<Vec<(String, String, String)>, String> {
    git.stream(
        run,
        &os_args(&["ls-tree", "-r", "-z", "--full-tree", commit]),
        None,
        |reader| {
            let mut entries = Vec::new();
            let mut record = Vec::new();
            loop {
                record.clear();
                if reader
                    .read_until(0, &mut record)
                    .map_err(|_| "Cannot read Git tree.")?
                    == 0
                {
                    break;
                }
                if record.last() == Some(&0) {
                    record.pop();
                }
                let Some(tab) = record.iter().position(|&b| b == b'\t') else {
                    return Err("Malformed Git tree.".into());
                };
                let meta =
                    std::str::from_utf8(&record[..tab]).map_err(|_| "Malformed Git tree.")?;
                let Ok(path) = std::str::from_utf8(&record[tab + 1..]) else {
                    continue;
                };
                let fields: Vec<_> = meta.split(' ').collect();
                let [mode, _, oid] = fields.as_slice() else {
                    return Err("Malformed Git tree metadata.".into());
                };
                entries.push(((*mode).to_owned(), (*oid).to_owned(), path.to_owned()));
            }
            Ok(entries)
        },
    )
}

fn message_body(bytes: &[u8]) -> &[u8] {
    bytes
        .windows(2)
        .position(|w| w == b"\n\n")
        .map_or(&[], |i| &bytes[i + 2..])
}

/// Total size of an object store, or `None` if it exceeds `limit` or cannot be inspected.
fn storage_size(path: &Path, limit: u64) -> Option<u64> {
    fn sum(path: &Path, used: &mut u64, limit: u64, depth: usize) -> std::io::Result<bool> {
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
                match sum(&entry.path(), used, limit, depth + 1) {
                    Ok(true) => {}
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    other => return other,
                }
            } else if meta.is_file() && meta.len() <= limit - *used {
                *used += meta.len();
            } else {
                return Ok(false);
            }
        }
        Ok(true)
    }
    let mut used = 0;
    sum(path, &mut used, limit, 0).ok()?.then_some(used)
}
