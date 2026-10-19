# SecretHunter

A Rust CLI and reusable library for local-first secret and sensitive-data scanning.
It scans directory contents and reachable Git history, emits fully masked findings,
and reports incomplete coverage instead of declaring an uninspected target clean.

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
secrethunter scan ./service --history off --format json --output /tmp/findings.json
secrethunter scan ./service --config ./examples/secrethunter.toml
secrethunter scan ./service --audit-ignores --format sarif --output /tmp/findings.sarif
secrethunter config validate --config ./examples/secrethunter.toml
secrethunter rules test --config ./examples/secrethunter.toml
secrethunter config schema
```

One target is accepted per scan. Reports go to stdout or `--output`; progress goes
to stderr. Output files are replaced atomically with mode 0600. The active output
and identity key are explicitly excluded from current and historical path inspection.
Ctrl-C preserves a partial report when possible and cleans up private workspaces.

| Exit | Meaning |
| --- | --- |
| 0 | Requested scope completed; no active occurrence meets both failure thresholds |
| 1 | Complete scan with active findings meeting both thresholds |
| 2 | Invalid input/policy, acquisition failure, unsupported encountered content, or exhausted limits |
| 130 | Operator interruption |

Incomplete coverage takes precedence over findings. Explicit exclusions and
documented scope boundaries remain visible but do not alone make a scan incomplete.

### Git scope and authentication

- `--history auto` inspects local current files plus reachable local branches,
  tags, remote-tracking refs and detached HEAD. Plain directories inspect current
  files only. GitHub inputs inspect advertised branch/tag history and remote HEAD.
- `--history off` inspects current local files, or the GitHub default-branch snapshot.
- `--history all` requires a Git source. Local bare repositories support auto/all.
- Selecting a subtree does not inspect sibling files. Repository-global commit/tag
  messages are excluded from subtree scans, with a visible coverage entry; scan
  the repository root to inspect those messages.
- Local reflogs, dangling objects, LFS payloads and submodule repositories are outside
  scope. Shallow/partial repositories and missing reachable objects return exit 2.
- Local Git files are copied through no-follow handles into a private isolated
  object/ref store. Target configuration, hooks, filters, aliases and include files
  are never applied. Object alternates, Git directory symlinks, linked worktrees,
  gitfiles and unsupported repository extensions are rejected.
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
`--max-file-bytes` and `--timeout-seconds`.

## Inspection and coverage boundaries

- Whole-record text matching is bounded by `max_file_bytes`; it has no chunk-edge
  gaps. Oversized records are not silently truncated and return incomplete coverage.
- UTF-8, BOM-marked UTF-16, ZIP, TAR and GZIP are supported. Archive contents are
  inspected in memory, never extracted to filesystem paths. Unsafe names, links,
  encrypted members, corrupt streams and exhausted nesting/member/byte budgets
  are reported. Office containers are partial document coverage, even if raw XML
  archive members can be scanned.
- Bounded base64, hex and percent decoding inspect original and decoded views.
  Heuristic decoding targets text-like candidates rather than every arbitrary byte
  sequence. A decoded finding maps to its enclosing encoded byte range; UTF-16
  findings map to original UTF-16 bytes. Compressed members use uncompressed
  member-relative offsets, not invented compressed-file offsets.
- Archive/member paths are typed chains; literal `!` is escaped in display output.
  Each member path and the outer source path participate in rule and ignore scopes.
- Unsupported binary documents receive printable-byte inspection and exit 2.
  Symlinks and special filesystem objects are never followed. Files changed during
  reading are reported as incomplete, not a consistent snapshot.
- Configured budgets bound files, expansion, nesting, workers, time, records and
  finding occurrences. Local Git staging caps copied storage bytes by
  `max_expanded_bytes_total`; remote fetches sample object-store size every 100 ms
  and check it again at completion. This is not a filesystem quota: transient
  acquisition size can exceed the sampled threshold before cancellation.
  Git metadata command output is capped at 32 MiB.
  Directory traversal is capped at 128 levels. The sanitized blob-result cache is
  bounded and path-specific policy is always reevaluated; evicted blobs can be
  rescanned. Reports and redaction bookkeeping also have finite budgets, including
  a 16 MiB cap on retained sensitive values for metadata masking.

JSON/YAML/TOML/dotenv/connection-string **text signatures** work, but full structured
parser extraction and escaped-string normalization are not implemented. OCR,
office/document semantic extraction, baseline storage/comparison, cross-scan
`not_observed_in_scope` decisions, online verification and performance/precision
benchmark claims remain later milestones. Unsupported policy requests such as
network verification, context output, unredacted output, symlink following and
automatic `.gitignore` handling are rejected rather than silently ignored.

Reports omit source snippets and message bodies. Metadata containing detected
values is masked, and control characters are escaped. SARIF 2.1.0 uses logical
locations instead of untrusted clickable paths; exact byte/line/provenance metadata
is retained in result properties. Reports themselves are sensitive metadata.
Temporary repository cleanup is best effort, not secure erasure; Rust cannot
guarantee zeroization of all in-memory values.

## Library

The library exposes separate policy, source, extraction, detector, finding,
scanner and report modules. Construct a validated `Config`, `Identity`, `Run`
and `Scanner`, call `source::scan`, then `Scanner::finish` and a reporter.
Acquisition failures become incomplete coverage entries, preserving earlier
findings. Construction/configuration errors return `Result` without target data.

## Verification

`cargo test --locked` uses synthetic values and private temporary repositories.
It covers history deletion/renames/refs, detached HEAD, subtree isolation, malicious
Git settings and alternates, strict policy loading, suppression semantics, archives,
UTF-16/decoding/location mapping, limits, stable fingerprints, redacted reports,
file permissions, cancellation and CLI exit behavior. Tests do not use live
credentials or intentionally contact GitHub.

No license has been chosen for this project. No upstream detector packs or source
code have been copied; dependency licenses remain their respective owners'.
