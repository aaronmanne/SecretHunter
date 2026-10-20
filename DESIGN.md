# SecretHunter Design

Status: target design with an initial Rust implementation. See [README.md](./README.md)
for the implemented interface, build instructions, and explicit delivery limitations.

## 1. Purpose

SecretHunter accepts a local directory or a GitHub repository URL and searches
relentlessly for exposed credentials and sensitive information, including formats
that only a particular organization understands. It produces actionable,
redacted findings and an honest account of what it could not inspect.

"Relentless" means layered detection, historical coverage, and visible blind
spots. It does not mean unlimited resource consumption, unauthorized access, or a
promise that a clean scan proves the absence of secrets.

### Goals

- Scan ordinary directories, local Git repositories, and cloned GitHub repositories.
- Detect provider credentials, private keys, generic secrets, connection strings,
  personal information, and organization-specific sensitive identifiers.
- Make custom detection and ignore policies versioned, testable, and explainable.
- Find low-entropy passwords and sensitive records, not only random-looking tokens.
- Preserve evidence of historical exposure even after deletion from the current tree.
- Work locally without transmitting discovered values by default.
- Support investigation and CI through consistent terminal, JSON, Markdown, HTML,
  and SARIF output, with links to GitHub commits and files where available.

### Non-Goals

Initial releases do not crawl GitHub organizations, issues, pull-request comments,
external websites, or arbitrary network endpoints. They do not rotate credentials,
rewrite history, exploit findings, decrypt protected files, or claim regulatory
compliance. OCR, office-document extraction, machine learning, and a web UI are
later possibilities, not dependencies of the initial scanner.

## 2. Positioning

Reference projects:

- [TruffleHog](https://github.com/trufflesecurity/trufflehog): broad source support,
  credential classification and verification, and configurable regex detectors.
- [Gitleaks](https://github.com/gitleaks/gitleaks): Git and filesystem scanning,
  configurable rules and allowlists, baselines, decoding, and archive inspection.

Custom regex, entropy, history scanning, and decoding are established capabilities,
not sufficient differentiators. SecretHunter's proposed identity is a
**project-aware exposure investigator**, combining the following into one workflow:

| Design priority | Intended experience | Acceptance evidence |
| --- | --- | --- |
| Sensitive data beyond credentials | Project rule packs describe customer IDs, private document markers, and internal data formats | Custom sensitive-data fixtures are found without provider signatures |
| Explainable evidence | Show which signature, field, context, or validator caused a finding | Each finding records rule version and evidence codes |
| Exposure lifecycle | Group repeated occurrences while retaining historical and current locations | A removed secret remains historically exposed; a new location is still new exposure |
| Coverage honesty | Report excluded, unreadable, unsupported, and budget-limited content | An incomplete scan cannot return a clean-success exit code |
| Governed exceptions | Narrow, owned, expiring suppressions with audit output | Expired exceptions stop suppressing automatically |
| Rule authoring as a workflow | Validate and test custom patterns against positive and negative fixtures | Invalid rules fail before acquisition; regressions fail rule tests |

These are product commitments to validate with users, not claims that other tools
lack individual features. Do not copy upstream code or rule packs without checking
their licenses and attribution requirements.

## 3. Inputs and Scan Scope

### Local Directory

Accept an existing readable directory and canonicalize its root. Recursively scan
regular files, including hidden files, untracked files, ignored files, logs, dumps,
and generated assets unless an explicit scan exclusion applies. Do not respect
`.gitignore` automatically: ignored files often contain the most valuable findings.
Never follow symlinks by default; report them as coverage exclusions. Do not read
devices, sockets, or named pipes. Open files without following symlinks and check
the opened object's identity to reduce traversal races. Record files that change
while being read rather than claiming snapshot consistency.

For a directory inside a Git repository, scan only the selected subtree in both
the working tree and history. Do not silently expand to the repository root.

### GitHub URL

Initially accept HTTPS URLs of the form `https://github.com/OWNER/REPO` with an
optional `.git` suffix. Reject credentials in URLs, query strings, fragments,
non-GitHub hosts, non-HTTPS schemes, and issue/tree/blob URLs with a useful error.
GitHub Enterprise hosts and SSH are future explicit source adapters.

Clone into a private temporary bare repository without checking files out. Fetch
advertised branch and tag refs and enumerate their reachable objects. Do not use a
shallow clone by default. No hidden/deleted remote objects, forks, server reflogs,
or unadvertised refs are implied by "full history."

Use an explicitly selected environment credential or operator-configured credential
helper for private repositories; never put tokens in command arguments, clone URLs,
logs, or persisted remote configuration. Sanitize subprocess environments, disable
interactive prompting, and distinguish authentication failures from empty scans.

### History Contract

`history = "auto"` scans the working tree plus history for local Git directories,
and reachable history for GitHub inputs. Plain directories scan current files only.
`history = "off"` scans current local files or the remote default-branch snapshot.
`history = "all"` requires a Git source; reject ordinary directories.

For local Git, include local branches, tags, remote-tracking refs, and detached
HEAD. Report the exact resolved refs and object IDs. Local reflogs, dangling
objects, submodule repositories, and Git LFS payloads are not included initially;
report their presence as coverage limitations. Scan submodule/LFS pointer content,
but do not imply the referenced content was inspected.

Detect shallow or partial repositories, missing objects, and failed ref fetches.
Do not fetch additional local history without operator consent. Mark unavailable
requested scope incomplete. Historical scanning reads complete unique blobs, not
only added diff lines; retain all in-scope path/commit occurrences. Secret-bearing
commit messages and annotated tag messages are scanned as separate source records.

## 4. Proposed CLI

```sh
secrethunter scan ./service
secrethunter scan https://github.com/example/service.git
secrethunter scan ./service --history off --format json --output -
secrethunter scan ./service --config ./security/secrethunter.toml
secrethunter scan ./service --audit-ignores --format sarif --output findings.sarif
secrethunter config validate --config ./security/secrethunter.toml
secrethunter rules test --config ./security/secrethunter.toml
```

One target per invocation initially. Progress and diagnostics go to stderr;
machine-readable results go to stdout or an explicit output path. The default
report format is a single self-contained, searchable HTML page with collapsible
findings/coverage sections, written to `./SecretHunter-<timestamp>.html` when no
output path is given; `--output -` forces stdout for any format. Cancellation
preserves a partial report when possible, marks it incomplete, and cleans up clones.
Create outputs outside the scan target, or explicitly exclude the active output
file so the scanner never scans its own report. Write reports atomically with
restrictive permissions.

| Exit code | Meaning |
| --- | --- |
| 0 | Requested scan completed and no unsuppressed finding meets the failure threshold |
| 1 | Scan completed with findings meeting the failure threshold |
| 2 | Invalid input/configuration, acquisition error, or incomplete requested scan |
| 130 | Operator interruption |

Errors/incomplete coverage take precedence over finding exit codes. Explicit
exclusions do not make a run incomplete, but remain visible in the coverage report.
Read failures, missing objects, and exhausted resource/time limits make requested
coverage incomplete. Known format limitations (binary content inspected only
through readable strings, encrypted or unsupported-compression archive members,
office containers, archive link entries, and files or objects exceeding the
configured size limit) are always listed in the coverage report but, so the
scanner works without configuration, only affect the exit code in an opt-in
strict-coverage mode.

A `--sensitivity` dial (0-10, default 5) tunes a minimum-entropy requirement on the
broad assignment-style rules (`password=`/`token=`-shaped matches and
connection-string passwords) to trade detection breadth against false positives,
without affecting provider-specific signature rules. `--help` documents every
flag with its default and worked examples; it is treated as user-facing
documentation, not an afterthought.

## 5. Architecture

Implementation language: Rust, with a CLI and reusable scanning library. Rust
offers a single deployable binary, bounded concurrency, native Git subprocess
integration, and a linear-time regex engine. Pin the Rust toolchain and Cargo
dependencies for reproducible builds; provide a script that validates and builds
the release binary.

```text
CLI -> trusted policy loader -> schema/rule validation -> source acquisition
    -> source records -> bounded extraction/decoding -> detection/validation
    -> evidence + classification -> suppression/baseline evaluation
    -> exposure grouping -> policy decision -> redacted reporters

All stages -> coverage ledger + structured diagnostics
```

### Owning Components

- `source`: directory traversal, safe Git acquisition, ref/object enumeration.
- `extract`: text decoding, structured field extraction, archive traversal, offsets.
- `detect`: built-in/custom rules, keyword indexing, bounded context, local validators.
- `policy`: trusted configuration, excludes, suppressions, baselines, CI thresholds.
- `finding`: evidence, secret identity, exposure occurrences, lifecycle comparison.
- `report`: terminal, JSON schema, Markdown, self-contained HTML, SARIF 2.1.0, and
  coverage summaries.

Use proven Git, parsing, and archive libraries/tools rather than implementing
their formats. Keep interfaces small: a source emits records with origin metadata;
an extractor emits mapped content views; a detector emits candidates; policy
classifies dispositions; reporters consume only sanitized records.

Use bounded queues, cancellation, worker and memory limits, and deterministic
final ordering. Scan repeated blob content once per detector/configuration digest,
but evaluate path-dependent rules and suppressions for every occurrence. Cache keys
include engine/rule versions, extraction settings, and all detection inputs. Cache
only sanitized metadata by default; do not persist plaintext candidate values.

## 6. Detection Strategy

Run complementary layers rather than filtering all candidates through entropy:

1. Provider signatures, PEM/private-key parsers, credential-bearing URIs, and
   generic assignments such as `password`, `client_secret`, and authorization headers.
2. Structured key/value extraction for JSON, YAML, TOML, dotenv, and connection
   strings. Use parsers when possible and still run text detection if parsing fails.
3. Context-aware heuristics for unknown formats. Entropy is optional supporting
   evidence, not a requirement for passwords, personal data, or custom identifiers.
4. Project-specific patterns with captured values, path scopes, nearby terms,
   optional entropy thresholds, and built-in local validators.
5. Sensitive-data rules such as payment-card candidates with Luhn checks and
   organization-specific customer/employee identifiers. Email addresses and private
   IPs are opt-in contextual rules rather than universal high-severity findings.

Severity describes impact; confidence describes evidence strength. Keep them
separate. A checksum match is not proof of a real person's data, and a parseable
credential is not proof it is active. Do not discard expired-looking credentials
or likely examples automatically; lower confidence with a stated reason or use an
explicit suppression. A `.example` suffix alone never makes a file safe.

### Extraction and Location Mapping

Scan UTF-8 and BOM-marked UTF-16 text, ZIP/TAR/GZIP members, and bounded base64,
hex, and percent-decoded candidates. Scan original content as well as decoded
views. Preserve archive member paths, decode chains, original byte ranges, and
line mappings where meaningful. Binary findings use byte offsets when line numbers
would be misleading. Do not interpret encoded content as executable code.

Chunk scanning must preserve matches at boundaries. Use overlap for rules with a
declared finite span; rules with unbounded or larger spans require a bounded
whole-record pass. If that pass exceeds limits, mark coverage incomplete rather
than silently missing multiline keys. Decoder/archiver budgets apply cumulatively
across each source record and the whole run, not independently per nested child.

Binary formats without a dedicated extractor receive bounded readable-string
extraction (printable ASCII/UTF-8 and UTF-16LE runs, mapped to original byte
offsets). This is recorded as a format limitation, not equivalent to document
extraction. Java class files are a supported format: their constant-pool strings
are decoded completely. Text containing legacy-encoded bytes is inspected as text,
and decoded candidates are only inspected further when they decode to readable text.

### Verification

Default to offline detection and local validation. Network credential verification
is a later, explicit opt-in capability with trusted provider adapters, approved
destinations, rate limits, deadlines, and minimal non-mutating requests. Never
derive verification destinations from scanned content or allow arbitrary custom
webhooks/scripts in project rules. Never transmit personal data for verification.

Record `not_attempted`, `verified`, `rejected`, or `unknown` independently of
detection confidence. Network failure is `unknown`, never proof of safety. Negative
verification does not erase evidence of historical exposure.

## 7. Configuration Contract

Use versioned TOML, with a strict schema and no executable expressions. The
following examples define the proposed version-1 format; they are not configs
for TruffleHog or Gitleaks.

Load built-in defaults, then one selected trusted config, then explicit CLI
overrides. Select the config using `--config`, otherwise `SECRETHUNTER_CONFIG`,
otherwise built-in defaults. Never automatically load configuration or ignore
files from the target: a malicious repository must not decide its own scan policy.
An operator can explicitly select a reviewed repository config. CI should obtain
policy from a protected branch or independently managed path, not an untrusted PR.

Custom rules are appended to built-ins by default. IDs must be unique; collisions
are errors, not silent overrides. Disable built-ins only through explicit IDs in
`ruleset.disabled`. Reject unknown keys, duplicate TOML keys, invalid regex/globs,
unknown rule IDs, nonexistent capture groups, invalid limits, and expired/invalid
suppression metadata at validation time. During scans, expired suppressions are
inactive and generate warnings; they never suppress findings.

Relative auxiliary file paths resolve against the selected config's directory.
Detection path globs always resolve against the scan root, not the config directory.
Version 1 has no remote includes, configuration inheritance, or arbitrary environment
interpolation. Report the effective policy digest and detector versions without
dumping sensitive configuration values.

### Pattern Semantics

- Regex uses Rust `regex`/RE2-style syntax: no lookbehind, lookahead, or backreferences. TOML
  single-quoted literal strings preserve backslashes without double escaping.
- `secret_group` is a numeric capture index; `0` means the complete match.
- A rule's `paths` list is optional; any matching path permits detection. If absent,
  all paths are eligible. `keywords` is an optional case-insensitive any-of prefilter
  within the same candidate window; omitting it must not disable a rule.
- `context.any_of`, when present, requires at least one case-insensitive literal
  within `within_lines` lines of the candidate in the same content view. Both
  keyword and context requirements must pass when both are configured.
- Optional `entropy_min` applies to the captured value in bits per character.
  Optional `validators` are allowlisted offline checks, initially `luhn` and `pem`.
- Globs are case-sensitive, root-relative POSIX paths: `*` and `?` do not cross
  `/`, and `**` matches zero or more path segments. Dotfiles are ordinary names;
  there is no negation or last-match-wins behavior. Reject absolute paths and `..`.
- Archive paths are typed member chains displayed as `outer.zip!inner/file`.
  Match path globs against each normalized member path and the outer path;
  report the matching level. Reject unsafe member names and escape literal `!`
  in display output so it cannot impersonate a nesting boundary.

### Example A: General Scanning Policy

```toml
version = 1

[scan]
history = "auto"
respect_gitignore = false
follow_symlinks = false
workers = 4
max_file_bytes = 104857600
max_archive_depth = 2
max_decode_depth = 2
max_expanded_bytes_per_record = 104857600
max_expanded_bytes_total = 1073741824
max_archive_members = 10000
timeout_seconds = 600

[ruleset]
builtins = true
disabled = []

[verification]
mode = "offline"

[output]
format = "json"
redact = true
include_context = false

[policy]
fail_on_severity = "medium"
fail_on_confidence = "low"

[ignore]
exclude_paths = ["**/node_modules/**", "**/.venv/**"]
```

Failure thresholds are inclusive over `low < medium < high < critical` severity
and `low < medium < high` confidence. Both thresholds must be met. No paths are
excluded by default except Git administrative storage, which is handled through
the Git adapter. Dependency exclusions above are deliberate speed/coverage
tradeoffs, not recommended proof that dependencies are safe. Initial symlink
following and automatic `.gitignore` handling are unsupported; setting either
boolean to `true` is a validation error until safely implemented.

### Example B: Nonstandard Secrets and Sensitive Data

This standalone policy adds internal tokens, customer identifiers, and confidential
document markers while retaining built-in detection. All fixtures are synthetic.

```toml
version = 1

[ruleset]
builtins = true
disabled = []

[[rules]]
id = "acme-service-token"
description = "Internal service authentication token"
category = "credential"
severity = "critical"
confidence = "high"
regex = '\bACME_(live|test)_([A-Za-z0-9]{24})\b'
secret_group = 0
keywords = ["ACME_"]
positive_examples = ["ACME_live_0123456789abcdefghijklmn"]
negative_examples = ["ACME_live_short", "ACME_live_${TOKEN}"]
remediation = "Revoke the token, issue a replacement, and use the approved secret store."

[[rules]]
id = "acme-customer-reference"
description = "Internal customer identifier in exported records"
category = "sensitive_data"
severity = "high"
confidence = "medium"
regex = '\bCUST-[0-9]{8}\b'
secret_group = 0
paths = ["exports/**", "**/*.csv", "**/*.json"]
positive_examples = ["CUST-12345678"]
negative_examples = ["CUST-123", "PUBLIC-12345678"]
remediation = "Remove the export and follow the customer-data incident process."

[[rules]]
id = "acme-confidential-marker"
description = "Document explicitly marked as internally restricted"
category = "sensitive_data"
severity = "high"
confidence = "high"
regex = '(?i)ACME[ ]+CONFIDENTIAL[ ]*:[ ]*INTERNAL[ ]+ONLY'
secret_group = 0
positive_examples = ["ACME CONFIDENTIAL: INTERNAL ONLY"]
negative_examples = ["ACME public documentation"]
remediation = "Review document ownership and remove unauthorized copies."
```

Rule tests execute each positive/negative string against the rule's content
predicate. Separate integration fixtures test path scopes, context windows,
decoding, validators, and suppressions. Generic high-entropy detection must never
override an explicit sensitive-data rule simply because the identifier is short.

### Example C: Configurable Ignores

Two distinct mechanisms avoid ambiguous "ignore" behavior:

1. `exclude_paths` skips acquisition or inspection and reduces coverage. Apply it
   consistently to current files, historical occurrences, and archive members.
   Show matched patterns and counts in the coverage ledger.
2. `suppressions` keeps detection evidence but removes matching findings from the
   default active view and CI threshold calculation. Audit output retains them.

Within a suppression, all configured selector fields must match (AND); entries
within a list are alternatives (OR). A suppression requires a rule ID and at least
one narrowing selector: paths, captured-value regex, commit IDs, or occurrence
fingerprints. Value regex matches the captured value and must match the entire
value. Multiple matching suppressions are all recorded. Commit IDs are full object
IDs for the repository's hash format and affect only those occurrences, never all
descendants. Expiry is inclusive through the UTC calendar date.

```toml
version = 1

[ignore]
exclude_paths = ["**/node_modules/**", "**/.venv/**"]

[[ignore.suppressions]]
id = "synthetic-acme-token-fixture"
rule_ids = ["acme-service-token"]
paths = ["tests/fixtures/**"]
value_regex = '^ACME_test_000000000000000000000000$'
reason = "Synthetic parser fixture, not a credential issued by any service."
owner = "app-security@example.com"
ticket = "SEC-1234"
expires = "2027-01-31"

[[ignore.suppressions]]
id = "documented-customer-example"
rule_ids = ["acme-customer-reference"]
paths = ["docs/examples/**"]
value_regex = '^CUST-00000000$'
reason = "Reserved fictional customer identifier used in documentation."
owner = "data-security@example.com"
ticket = "DATA-42"
expires = "2027-01-31"
```

Example C is an ignore-policy fragment to merge into Example B, not a standalone
validated policy: its custom rule IDs must exist. No implicit global suppression
of test directories, `.env.example`, placeholder words, or low-confidence results.
Inline ignore comments are not honored initially because target authors could use
them to hide findings. `--audit-ignores` includes suppressed findings and reports
suppression IDs, owners, reasons, expiry, and aggregate exclusion counts without
revealing raw matches. Audit mode does not bypass exclusions or change CI policy.

## 8. Findings, Identity, and Lifecycle

Each finding carries a schema version, scan ID, rule ID/version, category,
severity, confidence, evidence codes, verification state, remediation, and one or
more occurrences. An occurrence identifies its source, normalized path/member
chain, byte/line range, commit/ref where applicable, and extraction/decode chain.

Replace every captured sensitive value with `[REDACTED]` in all output formats.
Default reports omit source snippets, matched text, author emails, and commit
message bodies. If context reporting is enabled, mask the entire matched span and
all detected sensitive spans before rendering; omit context if safe redaction
cannot be established. Never expose value prefixes/suffixes as a default mask.

> **Deviation (approved):** to let reviewers tell real secrets from false
> positives without re-opening the source, every report format shows each
> finding's actual matched value (`finding.value`) instead of `[REDACTED]`. This
> is the only field exempted from masking — paths, descriptions, coverage
> reasons, and everything else above are still redacted exactly as specified.
> Every report carries a visible warning that it contains raw matched values and
> must be handled as sensitively as the secrets themselves.

Compute secret identity with domain-separated HMAC-SHA-256 of the exact extracted
value and a privately stored random installation key. Do not use unsalted hashes
for low-entropy personal data. Persistent comparison requires the same key and
canonicalization version; CI supplies a protected key file, never a CLI key value.
Record a non-secret key identifier, not the key. Key rotation invalidates prior
fingerprints and requires deliberate baseline regeneration.

Use a separate occurrence fingerprint derived from secret identity, rule ID,
repository identity, path/member chain, and extraction provenance. Track line and
commit separately so ordinary line movement does not make a new finding; a new
path or rule still creates a new occurrence. Preserve distinct physical locations
even if a policy fingerprint groups equivalent occurrences.

A reviewed baseline records accepted occurrence fingerprints, policy/rule digests,
key identifier, owner, reason, and expiry, without raw values. New locations of a
previously accepted value must not be hidden. Policy/key mismatches require review,
not silent acceptance. Baseline CLI and storage format follow after the core MVP.

Lifecycle states distinguish `present_in_current_tree`, `historical_only`, and
`not_observed_in_scope`. Only compare equivalent complete scopes to conclude a
finding is no longer observed. A deleted file, rejected verification, or a narrower
scan is not proof a credential was revoked or sensitive data was contained.

## 9. Security and Resource Boundaries

- Treat repositories, filenames, archives, configs, and candidate values as untrusted.
- Never build, import, source, or run target code, hooks, external diff tools,
  textconv filters, checkout filters, submodules, or target-provided plugins.
- Use patched Git with isolated trusted configuration and disabled hooks; do not
  invoke Git under a target-controlled configuration. For local history, use an
  isolated object-reading path; reject unsafe alternates/config-driven extensions
  rather than relying solely on ordinary `git -C` commands.
- Invoke Git through argument arrays with explicit option boundaries. Restrict
  transport to approved HTTPS hosts, verify TLS, and reject cross-host redirects.
  Explicit trusted credential-helper execution is the only helper exception.
- Store clones under owner-only directories and remove on success, error, or
  cancellation. Cleanup is best effort, not guaranteed secure erasure on modern disks.
- Never extract archive members onto arbitrary filesystem paths. Reject traversal,
  absolute names, symlink members, and compression bombs; cap members, depth,
  expanded bytes, candidate lengths, memory, and wall time. Record all limits hit.
- Escape control characters in terminal output and filenames; sanitize JSON/SARIF
  fields, HTML-escape and Markdown-escape all target text, and only emit report
  links built from trusted components: the fixed `https://github.com` host with
  validated owner/repository names, hexadecimal object IDs, and percent-encoded
  paths, or `file://` links under the operator's scan root. Omit a link whenever
  masking altered the path it encodes. HTML reports load no scripts or external
  resources.
- No telemetry, external model calls, online verification, or update checks during
  scans by default. Acquisition uses network access only for the requested source.
- Do not persist raw secrets. Protect reports and fingerprints as sensitive metadata;
  bounded in-memory values cannot be promised securely zeroized by the Go runtime.

## 10. Verification and Acceptance Criteria

Use synthetic fixtures only, including local bare Git remotes and HTTP mocks;
never commit live credentials or real personal records for testing.

| Area | Required checks |
| --- | --- |
| Input | Plain directory, nested subtree, GitHub URL, private auth failure, malformed URL |
| History | Deleted secret, renamed path, tags/branches, detached HEAD, shallow/partial clone |
| Detection | Built-in signatures, low-entropy password, custom formats, positive/negative rule cases |
| Boundaries | Multiline key and token across chunk edges, huge line, UTF-16 text |
| Extraction | Encoded token, nested archive, duplicate blobs, offsets mapped to original source |
| Ignore policy | Glob semantics, AND/OR selectors, historical/archive paths, expiry, audit visibility |
| Sensitive output | No raw fixture values in logs, errors, JSON, SARIF, caches, or reports |
| Safety | Malicious Git config/hooks, symlinks/races, traversal archive, decompression bomb, cancellation |
| Completeness | Permission errors, unsupported formats, missing objects, limit hits return code 2 |
| Reproducibility | Stable ordering and fingerprints with a fixed key, policy, source, and rule version |

Validate TOML against the published strict schema; compile patterns with the actual
Rust regex engine. Rule tests and integration fixtures are release gates. Track
precision and recall separately for credentials and sensitive-data classes using
a versioned labeled corpus. Compare the same authorized corpus with the reference
tools, publish configurations and coverage differences, and avoid unsupported
claims of superior detection.

Before setting performance targets, benchmark representative small projects,
large monorepos, and history-heavy repositories on documented hardware. Measure
wall time, peak memory, bytes/objects processed, duplicate-content savings, and
extraction expansion. Bounded memory and accurate coverage accounting are required
even when a scan exceeds its time budget.

## 11. Delivery Plan

1. **Core MVP:** directory and safe GitHub acquisition; local/remote reachable
   history; bounded text scanning; provider/generic/custom rules; strict TOML;
   excludes and expiring suppressions; redacted terminal/JSON/SARIF; coverage ledger;
   rule validation/tests; security and synthetic regression fixtures.
2. **Deep inspection:** structured extraction, bounded decoding and archives,
   richer sensitive-data validators, mapped provenance, and performance tuning.
   Until delivered, report encountered unsupported inputs as partial coverage.
3. **Investigation workflow:** keyed exposure grouping, reviewed baselines,
   lifecycle comparisons, CI change summaries, and rule-authoring diagnostics.
4. **Optional extensions:** explicitly approved verification adapters, additional
   source hosts, document extraction, and incremental scans with coverage guarantees.

Configuration fields for deferred features must be rejected as unsupported until
implemented; never silently accept a requested capability that does nothing.
Defaults in Example A describe the target version-1 experience, including deep
inspection, rather than promising every setting in the first milestone.

Product decisions still requiring validation: initial built-in detector coverage,
which personal-data classes should be opt-in, supported platforms and packaging,
project license, and acceptable precision/recall and performance release targets.