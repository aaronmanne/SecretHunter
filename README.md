# SecretHunter

A Rust CLI and reusable library for local-first secret and sensitive-data scanning.
It scans directory contents and reachable Git history, shows each matched value for
fast triage while masking every other identifying detail (paths, descriptions,
coverage reasons), and reports incomplete coverage instead of declaring an
uninspected target clean.

This is the first implementation of the [design](./DESIGN.md), not a claim that
every later delivery milestone is finished. Only scan sources you are authorized
to inspect. A clean scan is not proof that a repository contains no secrets.

## Build

Supported platforms: macOS and Linux. Install Rust through rustup and a maintained,
fully patched Git. The Rust toolchain is pinned in `rust-toolchain.toml`; Cargo
dependencies are pinned in `Cargo.lock`.

```sh
sh scripts/build.sh
./dist/secrethunter --help
```

The script checks formatting, runs Clippy with warnings denied, executes the
synthetic regression tests, and builds a release executable at `dist/secrethunter`.
It exits immediately if any gate fails. An optional Rust target triple supports
cross-compilation once that target and its linker are installed:

```sh
sh scripts/build.sh x86_64-unknown-linux-gnu
```

Development commands:

```sh
cargo run -- scan ./service
cargo test --locked
cargo fmt --all
cargo clippy --locked --all-targets -- -D warnings
```

## Usage

```sh
secrethunter scan ./service
secrethunter scan https://github.com/example/service.git
secrethunter scan ./service --sensitivity 2
secrethunter scan ./service --format markdown --output /tmp/findings.md
secrethunter scan ./service --history off --format json --output -
secrethunter scan ./service --config ./examples/secrethunter.toml
secrethunter scan ./service --audit-ignores --format sarif --output /tmp/findings.sarif
secrethunter config validate --config ./examples/secrethunter.toml
secrethunter rules test --config ./examples/secrethunter.toml
secrethunter config schema
```

No configuration is required: the defaults scan files, history, archives, Java
classes and readable strings in binaries. A policy file is optional. Run
`secrethunter scan --help` (or `secrethunter --help`) for every option, including
worked examples and the full exit-code table.

One target is accepted per scan. By default the report is written to
`./SecretHunter-<UTC timestamp>.html` in the current directory (for example
`SecretHunter-20261019-165650.html`); pass `--output FILE` to choose a path, or
`--output -` to force stdout regardless of format (useful for piping JSON/SARIF
into another tool). `--format terminal` still defaults to stdout when `--output`
is omitted, preserving plain-text piping. Progress goes to stderr. Output files
are replaced atomically with mode 0600. The active output and identity key are
explicitly excluded from current and historical path inspection. Ctrl-C preserves
a partial report when possible and cleans up private workspaces.

### Report formats

| `--format` | Contents |
| --- | --- |
| `html` (default) | Single self-contained, searchable page (no external resources; strict Content-Security-Policy) with a high-level summary, severity/rule breakdowns, and collapsible, searchable findings/coverage/refs sections |
| `markdown` | Summary tables, findings with linked locations and commits, coverage with collapsible path lists |
| `json` | Complete machine-readable report, including every coverage entry and per-occurrence `url` / `file_url` |
| `sarif` | SARIF 2.1.0 for code-scanning tools; links are included as `webUrl` / `fileUrl` result properties |
| `terminal` | Findings, grouped coverage with counts and examples, and a `Result:` line; defaults to stdout |

Links in HTML, Markdown, JSON and SARIF:

- **GitHub targets**, and local clones whose `origin` remote is on `github.com`
  (HTTPS, SSH, or `git@github.com:` forms): historical occurrences link to the file
  at the introducing commit with a `#L` line anchor, and commits link to their
  commit page. Working-tree files tracked at `HEAD` link to the file at `HEAD`
  (local edits may shift lines). Tag messages link to the tag; refs link to
  branch/tag pages.
- **Local working-tree files** also get a `file://` link to the scanned copy;
  untracked files only get the local link.
- Links are built only from the fixed `https://github.com` host, validated
  owner/repository names, hexadecimal commit IDs and percent-encoded paths; target
  URLs are never copied. If masking changes a path, ref or member name, that
  occurrence's links are omitted so an encoded secret cannot leak through a URL.
  Unpushed commits will not resolve on GitHub.

### The HTML report

The default HTML report is a single file with no external resources (fonts,
scripts, or stylesheets are all inline) and a strict Content-Security-Policy, so
it can be opened directly from disk, attached to a ticket, or hosted as a static
file. It opens with an always-visible, never-collapsed high-level summary: a
result banner, an "At a glance" stat strip (findings, active/suppressed
occurrences, distinct files affected, records scanned), key metadata, and
severity/rule breakdown tables.

Below that, the **Findings**, **Coverage**, and **Git refs resolved** sections —
and each individual finding and coverage group within them — are collapsed by
default so a scan with thousands of occurrences still opens to a manageable page;
each section's heading shows its count without needing to expand it. Within a
finding, only its **most recent** occurrence (the working tree if the secret is
still present, otherwise the newest commit that has it) is shown by default; any
earlier occurrences are collapsed behind an "N earlier occurrence(s)" toggle. A
search box filters by any visible text (path, rule ID, description, commit,
coverage reason, etc.), automatically expanding matching sections as you type, and
an "Expand all" / "Collapse all" pair of buttons is available for browsing the
whole report. Search and expand/collapse run from a small inline script with no
external dependencies and no network access.

### Raw values are shown — handle reports as sensitively as the secrets

Every report format shows the actual matched text of each finding (`finding.value`)
so a reviewer can tell a real secret from a false positive without re-opening the
source file. This is the one deliberate exception to masking: paths, descriptions,
coverage reasons, and every other field are still replaced with `[REDACTED]`
wherever an untrusted value could otherwise leak through them. Every report format
carries a visible warning about this; treat generated reports (and wherever you
store or send them) with the same care as the secrets themselves.

### Sensitivity (reducing false positives)

`--sensitivity 0..10` (default `5`; also `scan.sensitivity` in a policy file)
tunes how readily the broad "assignment-style" rules — `generic-secret`,
`generic-secret-double-quoted`, `generic-secret-single-quoted`, and
`connection-password` — accept a match, by requiring more Shannon entropy
(bits/character) in the captured value as the number goes down:

| Sensitivity | Minimum entropy required | Effect |
| --- | --- | --- |
| `10` | none | Every match from those rules is reported, including repeated/placeholder-looking values like `aaaaaaaa` |
| `5` (default) | ~2.0 bits/char | Filters very low-entropy placeholders while still catching ordinary weak passwords |
| `0` | ~4.0 bits/char | Only clearly random-looking values from those rules are reported |

Provider-specific signatures (AWS access keys, GitHub tokens, Slack tokens,
Stripe keys, Google API keys, private-key envelopes, authorization headers,
credential-bearing URIs, Luhn-checked payment cards) always match regardless of
this setting — they already have a fixed, specific format and are not a source of
noise. The built-in rules also already ignore punctuation-only captures (e.g. a
bare `:`) and values containing code-like parentheses or angle/square brackets
(reducing matches on function calls, generics, and array indexing in source
code), independent of `--sensitivity`.

### Progress and performance

Scans first enumerate the work (files, history, object sizes), then show progress
against known totals:

```text
⠙ Scanning [===================>          ]  64% 12847/20000 objects 170.86 MiB/265.99 MiB · 44.70 MiB/s · ETA 2s
```

`--progress` selects the stderr display:

| Mode | Behavior |
| --- | --- |
| `auto` (default) | Animated bar on an interactive terminal; periodic text lines when stderr is redirected or `TERM` is `dumb` |
| `bar` | Always animate |
| `plain` | Stage changes plus a status line every 5 seconds with percent, counts, bytes and remaining-time estimate |
| `off` | No progress output |

Enumeration, staging, and fetch stages show an elapsed-time spinner with counts or
bytes. Progress text is internally generated: it never includes file names, refs,
or matched values, because target-controlled names can themselves be sensitive.
ETA is an estimate based on bytes inspected so far.

Inspection runs on `--workers` threads (default: available CPU cores, capped at 16;
policy range 1–64; an explicit policy or CLI value takes precedence). Workers read working-tree files through no-follow handles and
inspect content in parallel. Up to four `git cat-file --batch` readers stream
historical objects, and the main thread merges results. Findings, fingerprints, and
report ordering do not depend on worker count. Each worker has at most one queued
item, so peak content memory is roughly `2 × workers × max_file_bytes` in the worst
case (default `max_file_bytes` is 100 MiB, so ~1.6 GiB at the default 8 workers);
lower `--workers` or `max_file_bytes` on memory-constrained machines.
Expansion, archive-member, record, and finding budgets apply across the whole run,
not per thread.

On a 20,000-file, 266 MiB synthetic tree with warm caches, the scan took 5.9 seconds
with one worker and 1.2 seconds with eight. History is enumerated with a single
streamed `git diff-tree`; each unique blob is sized and read once in batches instead
of starting Git processes per file. Local loose objects are re-encoded into one
temporary pack validated by `git index-pack`. On-access antivirus can add a
one-time cost the first time new files are opened.

| Exit | Meaning |
| --- | --- |
| 0 | Requested scope completed; no active occurrence meets both failure thresholds |
| 1 | Complete scan with active findings meeting both thresholds |
| 2 | Invalid input/policy, acquisition failure, missing objects, or (only with `--strict-coverage`) oversized/unsupported content; also any exhausted limit or timeout |
| 130 | Operator interruption |

Incomplete coverage takes precedence over findings. Explicit exclusions, documented
scope boundaries, and **limitations** are listed under Coverage but do not change
the exit code by default. Limitations are things the scanner could not fully
inspect but chose not to fail a no-configuration scan over: binary content
inspected through its readable strings, encrypted or unsupported-compression
archive members, office containers, link entries in archives, and files or Git
objects larger than `max_file_bytes` (default 100 MiB — large build artifacts like
shaded/uber JARs are the most common case; they are reported, not silently
skipped, and the terminal report hints at `--max-file-bytes` or `--exclude` when
this happens). Use `--strict-coverage` (or `scan.strict_coverage = true`) when CI
must fail on those limitations too — for example to guarantee every byte of every
in-scope file was actually read, not just sampled as readable strings.

### Interactive prompts

On an interactive terminal (both stdin and stdout attached to a TTY), `secrethunter
scan` asks for anything it needs that was not given on the command line, instead
of erroring:

- A missing `TARGET` is prompted for (defaults to `.`).
- Unless `--llm-verify` or `--no-llm-verify` is given, you are **always** asked
  whether to send findings to a local LLM for verification (see below).
- If you opt in and `--llm-backend` is omitted, both [Ollama](https://ollama.com)
  and [LM Studio](https://lmstudio.ai) are probed: if only one is running, it is
  used automatically (with a note to say which); if both are running, you are
  asked which one to use; if neither is running, you are told no local LLM was
  detected and verification is skipped (hosted/online models are not supported).
- If `--llm-model` is omitted, you are shown the models currently installed on
  the selected backend and asked to pick one.
- If `--llm-rule` is omitted, you are shown each rule ID that matched (with its
  finding count) and asked which ones to send to the LLM. **Rule IDs you do not
  select are dropped from the report entirely**, not just skipped for LLM
  analysis — select everything if you only want to narrow what gets a verdict
  without shrinking the report.

In any non-interactive context (CI, pipes, redirected output, or scripted use) none
of this is ever asked: a missing `TARGET` is an error, LLM verification stays off
unless `--llm-verify` is given explicitly, and if both backends happen to be
running you must pass `--llm-backend` to pick one (an ambiguous pair is otherwise
reported and verification is skipped). When explicit, every rule ID is included,
and nothing is dropped, unless narrowed with `--llm-rule`.

### Optional local LLM verification

`--llm-verify` (or the interactive prompt) sends each selected finding's matched
value, rule, and description to a locally running LLM server — either
[Ollama](https://ollama.com) (default `http://localhost:11434`, override with
`--ollama-endpoint`) or [LM Studio](https://lmstudio.ai) (default
`http://localhost:1234`, override with `--lmstudio-endpoint`) — for a fast
viability verdict, one of **REAL SECRET**, **LIKELY FALSE POSITIVE**, **FALSE
POSITIVE**, or **UNDETERMINED**, with a short 2-3 sentence explanation. A verbose
"thinking"/reasoning model's chain-of-thought is automatically trimmed down to
just its concluding sentences so the report stays readable. Pass `--llm-backend
ollama` or `--llm-backend lmstudio` to pick one explicitly instead of
auto-detecting; without it, SecretHunter probes both and uses whichever single one
is running, asks you to choose if both are, and skips with a clear message if
neither is (hosted/online models are not supported — this is a local-only
feature). This is the only network call SecretHunter ever makes beyond an
explicitly requested GitHub clone, it never leaves the local machine by default,
and it never blocks or fails the scan: an unreachable/model-less backend just
skips verification with a warning and the report is still written. The verdict,
model, backend, and explanation, when present, are attached to the finding and
shown in every report format — and in HTML, a "Filter by LLM verdict" row of
checkboxes (including "No LLM analysis" for anything not sent to the LLM) lets you
narrow the report down to just the categories you care about, e.g. hiding
everything the LLM already flagged as a false positive. Progress (`--progress`
other than `off`) prints a status line per finding sent to the LLM and a final
`analyzed`/`failed` summary to stderr, since this step runs one sequential request
per finding and can take a while on CPU-only hardware or with many findings;
Ctrl-C stops it early and still writes a report with whatever
verdicts were completed.

```sh
# Explicit, fully non-interactive
secrethunter scan . --llm-verify --llm-backend ollama --llm-model llama3.1 \
  --llm-rule generic-secret

# Never ask about it, even on a terminal
secrethunter scan . --no-llm-verify
```

### Git scope and authentication

- `--history auto` inspects local current files plus reachable local branches,
  tags, remote-tracking refs and detached HEAD. Plain directories inspect current
  files only. GitHub inputs inspect advertised branch/tag history and remote HEAD.
- `--history off` inspects current local files, or the GitHub default-branch snapshot.
- `--history all` requires a Git source. Local bare repositories support auto/all.
- Selecting a subtree does not inspect sibling files. Repository-global commit/tag
  messages are excluded from subtree scans, with a visible coverage entry; scan
  the repository root to inspect those messages.
- Historical occurrences record the commit that **introduced** each path/blob pair
  (including root commits and changes in merge commits). Unchanged copies in later
  commits are not repeated as extra occurrences; renamed paths, re-added content,
  and each changed version remain separate occurrences. Each unique blob is
  inspected once, and path-dependent rules and suppressions are evaluated for every
  occurrence. A commit-ID suppression therefore matches the introducing commit.
- Local reflogs, dangling objects, LFS payloads and submodule repositories are outside
  scope. Shallow/partial repositories and missing reachable objects return exit 2.
- Local Git files are copied through no-follow handles into a private isolated
  object/ref store. Large packs use copy-on-write clones on APFS when available,
  loose objects are re-encoded into one pack verified by `git index-pack`, and
  their declared sizes count against `max_expanded_bytes_total`. Target
  configuration, hooks, filters, aliases and include files are never applied.
  Object alternates, Git directory symlinks, linked worktrees, gitfiles and
  unsupported repository extensions are rejected.
- GitHub acquisition fetches into a private bare repository without checkout or
  persistent remote credentials. Only HTTPS GitHub repository URLs are accepted;
  redirects, interactive prompts and all other Git transports are disabled.

Private GitHub repositories use an explicitly selected environment variable:

```sh
# Populate GITHUB_TOKEN through your trusted secret manager, not a command argument.
secrethunter scan https://github.com/example/private-repo --github-token-env GITHUB_TOKEN
```

The token reaches Git only through the private askpass adapter's environment.
Inherited Git config, credential helpers, proxy settings and askpass programs are
not used. Operator-selected credential helpers are not implemented in this release.
Network access is used only for requested GitHub acquisition; detection and
validation are offline. No credential verification, telemetry or update checks run.

### Identity keys and CI

An installation key is created at `~/.config/secrethunter/identity.key` with private
directory/file permissions. Exact extracted values receive domain-separated
HMAC-SHA-256 identities; occurrence fingerprints additionally bind the rule,
canonical target identity, path/member chain and extraction provenance. Lines and
commit IDs are not part of the occurrence fingerprint.

For stable CI comparisons, provision the same protected **32-byte random binary
file**, mode 0600, and pass `--key-file /protected/identity.key`. An explicit key
must already exist; it is never silently regenerated. Never pass key material as a
CLI argument. Key changes invalidate old fingerprints. Local target identity uses
the canonical scan root, so moving the checkout or changing scope changes occurrence
identity. Reports contain a non-secret key identifier, never the key.

## Policy and custom rules

The [example policy](./examples/secrethunter.toml) includes resource limits, custom
organization-specific rules, fixtures and a narrow expiring suppression. Policy
selection is `--config`, then `SECRETHUNTER_CONFIG`, then built-in defaults.
Target-provided policy files and inline ignore comments are never automatically trusted.

The structural schema is available via `secrethunter config schema`.
`config validate` is authoritative for semantic constraints: supported capabilities,
unique IDs, rule references, safe globs, regexes/capture groups, offline validators,
limits and suppression metadata. Unknown fields and duplicate TOML keys are errors.
Regex uses Rust's linear-time `regex` engine (RE2-style syntax; no lookaround or
backreferences), not Go's engine.

Custom rules append to built-ins. Disable individual built-ins with
`ruleset.disabled`, or opt out with `ruleset.builtins = false`. Built-in IDs:

```text
aws-access-key          github-token          slack-token
stripe-secret-key       google-api-key        private-key
generic-secret          authorization-header  credential-uri
connection-password     payment-card
generic-secret-double-quoted
generic-secret-single-quoted
```

Detection includes low-entropy assignments, credential URIs, authorization headers,
provider signatures, multiline private-key envelopes, and Luhn-checked payment-card
candidates. Card validity does not prove a real financial account; private-key
signatures do not prove a usable key. Email and IP rules are not enabled by default.
Overlapping detectors can report the same value under different rule IDs.

Rule options include capture groups, case-sensitive root-relative POSIX globs,
case-insensitive keyword/context requirements, optional Shannon entropy and
allowlisted `luhn` / `pem` validators. PEM validation parses the envelope and base64
payload (and checks the OpenSSH marker for that label); it does not validate DER,
key usability, or cryptographic authenticity.
`*` and `?` never cross `/`; `**` occupies a whole segment and matches zero or more
segments. Dotfiles are ordinary paths. Bracket classes, brace expansion, negation,
absolute paths and `..` are unsupported.

Exclusions skip inspection and appear in the coverage ledger. Suppressions preserve
evidence and remove only matching occurrences from failure evaluation and the
default view. All supplied selector fields must match; list entries are alternatives.
Full-value regex matching, path scopes, exact commit IDs and occurrence fingerprints
are supported. Expiry is inclusive through the UTC date. Validation rejects expired
exceptions; scans warn and treat them as inactive. `--audit-ignores` exposes their
owner/reason/ticket/expiry without raw values and does not change CI policy.

Failure thresholds are inclusive and require **both** severity and confidence.
CLI overrides include `--fail-on-severity`, `--fail-on-confidence`, `--workers`,
`--max-file-bytes`, `--timeout-seconds`, and repeatable `--exclude GLOB` (appended to
the policy's `exclude_paths`, e.g. `--exclude '**/target/**'` for build outputs).
Built-in rules ignore captures without any ASCII letter or digit (such as `token: :`)
but still report short real values such as `password=cat`.

## Inspection and coverage boundaries

- Whole-record text matching is bounded by `max_file_bytes` (default 100 MiB);
  it has no chunk-edge gaps. Oversized files or Git objects are not silently
  truncated: they are skipped entirely and reported in Coverage (a default
  limitation; incomplete only with `--strict-coverage`).
- UTF-8, BOM-marked UTF-16, ZIP, TAR and GZIP are supported. Archive contents are
  inspected in memory, never extracted to filesystem paths. Unsafe names, corrupt
  streams and exhausted nesting/member/byte budgets are incomplete coverage.
  Encrypted members, link entries and office containers are reported limitations.
  Files that only look like ZIP/TAR archives are inspected as binary strings.
- Text with legacy-encoded bytes (for example Latin-1 commit messages) is fully
  inspected: valid UTF-8 is kept and each invalid byte maps to its Latin-1
  character (`latin1_bytes` offsets). Content is treated as text when it has no NUL
  bytes and only a few stray control characters; terminal escape sequences are fine.
- Bounded base64, hex and percent decoding inspect original and decoded views.
  Only decoded content that is readable text is inspected further; ordinary words
  that happen to be valid base64 decode to noise and are ignored.
  A decoded finding maps to its enclosing encoded byte range; UTF-16
  findings map to original UTF-16 bytes. Compressed members use uncompressed
  member-relative offsets, not invented compressed-file offsets.
- Archive/member paths are typed chains; literal `!` is escaped in display output.
  Each member path and the outer source path participate in rule and ignore scopes.
- Java `.class` files (including inside JAR/WAR ZIPs) are fully supported for text:
  every constant-pool string (literals, names, annotation values) is decoded from
  Java modified UTF-8 and scanned, with findings mapped to original byte offsets
  (`class_constant_bytes`). Bytecode carries no other text. Malformed classes and
  Mach-O universal binaries (same magic number) are inspected as binary strings.
- Other binaries (images, native executables, compiled PDFs, etc.) are inspected
  like `strings`: printable ASCII/UTF-8 runs and UTF-16LE runs of at least four
  characters, with findings mapped to original byte offsets
  (`binary_string_bytes`) and decoded base64/hex/percent text inside those strings
  also checked. Data that is compressed or encrypted inside a binary cannot be
  read this way, so each such file is listed as a limitation.
  Symlinks and special filesystem objects are never followed. Files changed during
  reading are reported as incomplete, not a consistent snapshot.
- Configured budgets bound files, expansion, nesting, workers, time, records and
  finding occurrences. Local Git staging caps copied storage bytes by
  `max_expanded_bytes_total`; remote fetches sample object-store size every 100 ms
  and check it again at completion. This is not a filesystem quota: transient
  acquisition size can exceed the sampled threshold before cancellation.
  Git metadata command output is capped at 32 MiB.
  Directory traversal is capped at 128 levels. Repeated historical blobs are read
  and inspected once in memory, with path-specific policy reevaluated for every
  occurrence; nothing is cached on disk. Reports and redaction bookkeeping also
  have finite budgets, including a 16 MiB cap on retained sensitive values for
  metadata masking.

JSON/YAML/TOML/dotenv/connection-string **text signatures** work, but full structured
parser extraction and escaped-string normalization are not implemented. OCR,
office/document semantic extraction, baseline storage/comparison, cross-scan
`not_observed_in_scope` decisions, online verification and performance/precision
benchmark claims remain later milestones. Unsupported policy requests such as
network verification, context output, unredacted output, symlink following and
automatic `.gitignore` handling are rejected rather than silently ignored.

Reports omit source snippets and message bodies. Detected values are masked in
target- and policy-derived metadata (paths, member names, refs, rule and suppression
text); scanner-generated messages are fixed text and are not altered. Values of 8 or
more characters are masked wherever they appear. Shorter values are masked only as
standalone tokens (not adjacent to ASCII letters or digits), so `password=admin` masks
`admin/notes` but not `administrator.cfg`. Control characters are escaped.
SARIF 2.1.0 uses logical locations; GitHub and local links are provided as result
properties, and exact byte/line/provenance metadata is retained. HTML escapes all
target text and Markdown backslash-escapes it. Reports themselves are sensitive
metadata.
Temporary repository cleanup is best effort, not secure erasure; Rust cannot
guarantee zeroization of all in-memory values.

The terminal report lists findings first, then groups coverage entries by status and
reason with counts and up to three example paths, then ends with a `Result:` line
explaining the exit code. JSON, HTML, Markdown and SARIF keep every coverage entry.

## Library

The library exposes separate policy, source, extraction, detector, finding,
scanner, progress, links, document, and report modules. Construct a validated
`Config`, `Identity`, `Run` and `Scanner`, optionally assign
`scanner.progress = Progress::new(mode)`, call `source::scan`, then
`Scanner::finish` and a reporter. Progress is disabled by default for library
callers. `Scanner::record` inspects a single record on the calling thread;
`source::scan` uses the parallel pipeline.
Acquisition failures become incomplete coverage entries, preserving earlier
findings. Construction/configuration errors return `Result` without target data.

## Verification

`cargo test --locked` uses synthetic values and private temporary repositories.
It covers history deletion/renames/refs, detached HEAD, subtree isolation, malicious
Git settings and alternates, strict policy loading, suppression semantics, archives,
UTF-16/decoding/location mapping, limits, stable fingerprints, redacted metadata
alongside shown finding values, file permissions, cancellation, CLI exit behavior,
worker-count-independent reports, packed plus loose history, loose-object expansion
limits, progress output that omits paths and values, the sensitivity entropy floor,
default report naming, `--output -`, recency-ordered/collapsed occurrences, the
non-interactive LLM-verify flag paths, and the HTML report's search/collapse
structure. Tests do not use live credentials or intentionally contact GitHub or a
real Ollama instance.

No license has been chosen for this project. No upstream detector packs or source
code have been copied; dependency licenses remain their respective owners'.
