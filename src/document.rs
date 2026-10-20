//! Human-readable Markdown and HTML reports. Both consume the already-redacted
//! report; every target-derived string is escaped, and links come only from the
//! validated `url`/`file_url` fields and the canonical repository URL.

use crate::{
    finding::{Finding, Occurrence},
    report::{Report, coverage_groups, display_path, exit_meaning},
};
use std::{collections::BTreeMap, fmt::Write};

const SEVERITIES: [&str; 4] = ["critical", "high", "medium", "low"];

fn trusted_link(url: &str) -> bool {
    url.starts_with("https://github.com/") || url.starts_with("file:///")
}

fn commit_url(report: &Report, commit: &str) -> Option<String> {
    let valid = matches!(commit.len(), 40 | 64) && commit.bytes().all(|b| b.is_ascii_hexdigit());
    report
        .repository_url
        .as_ref()
        .filter(|_| valid)
        .map(|base| format!("{base}/commit/{commit}"))
}

/// Branch, tag, and remote-tracking refs link to GitHub's tree view because annotated
/// tag object IDs are not commit pages; `HEAD` is already resolved to a commit.
fn ref_url(report: &Report, name: &str, oid: &str) -> Option<String> {
    if name == "HEAD" {
        return commit_url(report, oid);
    }
    let short_name = name
        .strip_prefix("refs/heads/")
        .or_else(|| name.strip_prefix("refs/tags/"))
        .or_else(|| {
            name.strip_prefix("refs/remotes/")
                .and_then(|rest| rest.split_once('/').map(|(_, branch)| branch))
        })?;
    report
        .repository_url
        .as_ref()
        .map(|base| format!("{base}/tree/{}", crate::links::encode_path(short_name)))
}

fn short(id: &str) -> &str {
    &id[..id.len().min(10)]
}

fn location(o: &Occurrence) -> String {
    display_path(&o.path, &o.member_chain)
}

fn position(o: &Occurrence) -> String {
    match (o.line_start, o.line_end) {
        (Some(start), Some(end)) if end != start => format!("lines {start}-{end}"),
        (Some(start), _) => format!("line {start}"),
        _ => format!("bytes {}-{}", o.byte_start, o.byte_end),
    }
}

fn severity_summary(report: &Report) -> BTreeMap<usize, (&'static str, usize, usize)> {
    let mut rows = BTreeMap::new();
    for finding in &report.findings {
        let rank = SEVERITIES
            .iter()
            .position(|s| *s == finding.severity)
            .unwrap_or(SEVERITIES.len());
        let label = SEVERITIES.get(rank).copied().unwrap_or("other");
        let row = rows.entry(rank).or_insert((label, 0, 0));
        row.1 += 1;
        row.2 += finding
            .occurrences
            .iter()
            .filter(|o| o.suppressions.is_empty())
            .count();
    }
    rows
}

/// Distinct (source, path) pairs across every occurrence, for the high-level summary.
fn affected_paths_count(report: &Report) -> usize {
    report
        .findings
        .iter()
        .flat_map(|f| &f.occurrences)
        .map(|o| (o.source.as_str(), o.path.as_str()))
        .collect::<std::collections::HashSet<_>>()
        .len()
}

fn ordered(report: &Report) -> Vec<&Finding> {
    let mut findings: Vec<_> = report.findings.iter().collect();
    findings.sort_by_key(|f| {
        SEVERITIES
            .iter()
            .position(|s| *s == f.severity)
            .unwrap_or(SEVERITIES.len())
    });
    findings
}

// ---------------------------------------------------------------- Markdown

/// Escapes Markdown punctuation and flattens line breaks for table cells.
fn md(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' | '\r' => out.push(' '),
            '\\' | '`' | '*' | '_' | '{' | '}' | '[' | ']' | '<' | '>' | '(' | ')' | '#' | '+'
            | '-' | '.' | '!' | '|' | '~' | '&' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

fn md_link(text: &str, url: Option<&str>) -> String {
    match url.filter(|u| trusted_link(u)) {
        Some(url) => format!("[{}]({url})", md(text)),
        None => md(text),
    }
}

pub fn markdown(report: &Report) -> String {
    let mut out = String::new();
    let status = if report.coverage.complete {
        "COMPLETE"
    } else {
        "INCOMPLETE"
    };
    let _ = writeln!(out, "# SecretHunter report\n");
    let _ = writeln!(
        out,
        "**Result:** exit {} \u{2014} {}\n",
        report.exit_code,
        exit_meaning(report.exit_code)
    );
    let _ = writeln!(out, "| | |\n|---|---|");
    let _ = writeln!(out, "| Target | {} |", md(&report.target));
    if let Some(url) = &report.repository_url {
        let name = url.trim_start_matches("https://github.com/");
        let _ = writeln!(out, "| Repository | {} |", md_link(name, Some(url)));
    }
    let _ = writeln!(out, "| Coverage | {status} |");
    let _ = writeln!(out, "| History | {} |", md(&report.history));
    let _ = writeln!(
        out,
        "| Active / suppressed occurrences | {} / {} |",
        report.active_occurrences, report.suppressed_occurrences
    );
    let _ = writeln!(
        out,
        "| Records / bytes scanned | {} / {} |",
        report.coverage.records_scanned,
        crate::progress::human_bytes(report.coverage.bytes_scanned)
    );
    let _ = writeln!(
        out,
        "| Scanner / policy / key | {} / `{}` / `{}` |\n",
        md(&report.scanner_version),
        short(&report.policy_digest),
        report.key_id
    );
    let _ = writeln!(
        out,
        "**WARNING:** this report contains the raw matched value of every finding; \
         handle and store it as sensitively as the secrets themselves. Other metadata \
         (paths, descriptions, coverage reasons) is still masked as `[REDACTED]`.\n"
    );

    let _ = writeln!(out, "## Summary\n");
    if report.findings.is_empty() {
        let _ = writeln!(out, "No findings to display.\n");
    } else {
        let _ = writeln!(
            out,
            "| Severity | Findings | Active occurrences |\n|---|---:|---:|"
        );
        for (label, findings, active) in severity_summary(report).values() {
            let _ = writeln!(out, "| {label} | {findings} | {active} |");
        }
        out.push('\n');
    }

    if !report.findings.is_empty() {
        let _ = writeln!(out, "## Findings\n");
    }
    for (index, finding) in ordered(report).into_iter().enumerate() {
        let _ = writeln!(
            out,
            "### {}. {} \u{b7} {} \u{2014} {}\n",
            index + 1,
            finding.severity.to_uppercase(),
            md(&finding.rule_id),
            md(&finding.description)
        );
        let _ = writeln!(
            out,
            "- Confidence: {} \u{b7} Category: {} \u{b7} Lifecycle: {} \u{b7} Verification: {}",
            md(&finding.confidence),
            md(&finding.category),
            md(&finding.lifecycle),
            md(&finding.verification)
        );
        let _ = writeln!(
            out,
            "- Evidence: {}",
            md(&finding.evidence_codes.join(", "))
        );
        let _ = writeln!(out, "- Remediation: {}", md(&finding.remediation));
        let _ = writeln!(out, "- **Secret value:** `{}`", finding.value);
        if let Some(llm) = &finding.llm {
            let _ = writeln!(
                out,
                "- **LLM analysis** ({}): {} \u{2014} {}",
                md(&llm.model),
                md(&llm.verdict),
                md(&llm.explanation)
            );
        }
        out.push('\n');
        let header =
            "| Location | Position | Commit / tag | Source | Status |\n|---|---|---|---|---|";
        let row = |o: &Occurrence| -> String {
            let mut place = md_link(&location(o), o.url.as_deref());
            if let Some(file) = o.file_url.as_deref().filter(|_| o.url.is_some()) {
                place.push_str(&format!(" ({})", md_link("local", Some(file))));
            } else if o.url.is_none() {
                place = md_link(&location(o), o.file_url.as_deref());
            }
            let revision = match (&o.commit, &o.tag) {
                (Some(commit), _) => md_link(short(commit), commit_url(report, commit).as_deref()),
                (None, Some(tag)) => format!(
                    "tag {} {}",
                    md(o.ref_name.as_deref().unwrap_or("")),
                    md(short(tag))
                ),
                _ => "working tree".into(),
            };
            let state = if o.suppressions.is_empty() {
                "active".to_string()
            } else {
                format!(
                    "suppressed ({})",
                    md(&o
                        .suppressions
                        .iter()
                        .map(|s| s.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", "))
                )
            };
            format!(
                "| {place} | {} | {revision} | {} | {state} |",
                position(o),
                md(&o.source)
            )
        };
        let mut occurrences = finding.occurrences.iter();
        if let Some(most_recent) = occurrences.next() {
            let _ = writeln!(out, "Most recent occurrence:\n");
            let _ = writeln!(out, "{header}");
            let _ = writeln!(out, "{}", row(most_recent));
        }
        let earlier: Vec<_> = occurrences.collect();
        if !earlier.is_empty() {
            let _ = writeln!(
                out,
                "\n<details><summary>{} earlier occurrence(s)</summary>\n",
                earlier.len()
            );
            let _ = writeln!(out, "{header}");
            for o in &earlier {
                let _ = writeln!(out, "{}", row(o));
            }
            let _ = writeln!(out, "\n</details>");
        }
        out.push('\n');
    }

    let groups = coverage_groups(report);
    if !groups.is_empty() {
        let _ = writeln!(out, "## Coverage\n");
        let _ = writeln!(out, "| Status | Reason | Count |\n|---|---|---:|");
        for (status, reason, entries) in &groups {
            let _ = writeln!(
                out,
                "| {} | {} | {} |",
                md(status),
                md(reason),
                entries.len()
            );
        }
        out.push('\n');
        for (status, reason, entries) in &groups {
            let paths: Vec<_> = entries.iter().filter(|e| !e.path.is_empty()).collect();
            if paths.is_empty() {
                continue;
            }
            let _ = writeln!(
                out,
                "<details><summary>{} \u{2014} {} ({})</summary>\n",
                html_escape(status),
                html_escape(reason),
                paths.len()
            );
            for entry in paths {
                let pattern = entry
                    .pattern
                    .as_ref()
                    .map_or(String::new(), |p| format!(" (pattern {})", md(p)));
                let _ = writeln!(out, "- {}{pattern}", md(&entry.path));
            }
            let _ = writeln!(out, "\n</details>\n");
        }
    }
    if !report.coverage.resolved_refs.is_empty() {
        let _ = writeln!(
            out,
            "<details><summary>Git refs resolved ({})</summary>\n",
            report.coverage.resolved_refs.len()
        );
        for (name, oid) in &report.coverage.resolved_refs {
            let _ = writeln!(
                out,
                "- {} \u{2192} {}",
                md(name),
                md_link(short(oid), ref_url(report, name, oid).as_deref())
            );
        }
        let _ = writeln!(out, "\n</details>\n");
    }
    out
}

// -------------------------------------------------------------------- HTML

pub fn html_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn a(text: &str, url: Option<&str>) -> String {
    match url.filter(|u| trusted_link(u)) {
        Some(url) => format!(
            "<a href=\"{}\" rel=\"noopener noreferrer\" target=\"_blank\">{}</a>",
            html_escape(url),
            html_escape(text)
        ),
        None => html_escape(text),
    }
}

const STYLE: &str = r#"
:root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;--link:#0969da;
--critical:#82071e;--high:#cf222e;--medium:#9a6700;--low:#0969da;--ok:#1a7f37;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;
--card:#151b23;--link:#4493f8;--critical:#ff7b72;--high:#f85149;--medium:#d29922;--low:#4493f8;--ok:#3fb950;--bad:#f85149}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px}h1{margin:0 0 4px}
h2{border-bottom:1px solid var(--line);padding-bottom:6px;margin-top:32px;display:flex;align-items:center;gap:10px}
a{color:var(--link)}.muted{color:var(--muted)}code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.result{padding:12px 16px;border-radius:8px;border:1px solid var(--line);background:var(--card);margin:16px 0}
.badge{display:inline-block;padding:1px 8px;border-radius:12px;font-weight:600;font-size:12px;color:#fff;text-transform:uppercase}
.b-critical{background:var(--critical)}.b-high{background:var(--high)}.b-medium{background:var(--medium)}.b-low{background:var(--low)}
.b-ok{background:var(--ok)}.b-bad{background:var(--bad)}.b-other{background:var(--muted)}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
th{background:var(--card)}td.num,th.num{text-align:right}.grid{display:grid;grid-template-columns:max-content 1fr;gap:2px 16px}
.finding{border:1px solid var(--line);border-left:4px solid var(--muted);border-radius:6px;padding:0 16px 8px;margin:10px 0}
.finding.critical{border-left-color:var(--critical)}.finding.high{border-left-color:var(--high)}
.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}
.finding summary{padding:8px 0;font-weight:600}
.loc{word-break:break-all}details{margin:6px 0}summary{cursor:pointer}
details.section>summary{font-size:1.3em;font-weight:600;list-style:none}
details.section>summary::-webkit-details-marker{display:none}
details.section>summary::before{content:"\25b8\0020";display:inline-block}
details.section[open]>summary::before{content:"\25be\0020"}
tr.suppressed td{opacity:.6}.sh-hidden{display:none !important}
.toolbar{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:16px 0;position:sticky;top:0;
background:var(--bg);padding:10px 0;border-bottom:1px solid var(--line);z-index:1}
.toolbar input{flex:1;min-width:220px;padding:7px 10px;border-radius:6px;border:1px solid var(--line);
background:var(--card);color:var(--fg);font-size:14px}
.toolbar button{padding:6px 10px;border-radius:6px;border:1px solid var(--line);background:var(--card);
color:var(--fg);cursor:pointer;font-size:13px}
.toolbar button:hover{background:var(--line)}.stats{display:flex;flex-wrap:wrap;gap:16px;margin:12px 0}
.stat{border:1px solid var(--line);border-radius:8px;padding:8px 14px;background:var(--card);min-width:110px}
.stat .n{font-size:1.5em;font-weight:700;display:block}.stat .l{color:var(--muted);font-size:12px;text-transform:uppercase}
"#;

/// Inline only; no external resources are fetched and no data beyond what this page
/// already renders (already HTML-escaped) is read by the script.
const SCRIPT: &str = r#"
(function(){
  function all(sel){ return Array.prototype.slice.call(document.querySelectorAll(sel)); }
  var expandBtn = document.getElementById('sh-expand');
  var collapseBtn = document.getElementById('sh-collapse');
  if (expandBtn) expandBtn.addEventListener('click', function(){
    all('main details').forEach(function(d){ d.open = true; });
  });
  if (collapseBtn) collapseBtn.addEventListener('click', function(){
    all('main details').forEach(function(d){ d.open = false; });
  });
  var input = document.getElementById('sh-search');
  var countEl = document.getElementById('sh-search-count');
  if (!input) return;
  var items = all('.searchable');
  function apply(){
    var q = input.value.trim().toLowerCase();
    var shown = 0;
    items.forEach(function(el){
      var match = !q || el.textContent.toLowerCase().indexOf(q) !== -1;
      el.classList.toggle('sh-hidden', !match);
      if (match) {
        shown++;
        if (q && !el.open) {
          el.open = true;
          var p = el.closest('details.section');
          if (p && !p.open) { p.open = true; }
        }
      }
    });
    if (countEl) {
      countEl.textContent = q
        ? (shown + ' of ' + items.length + ' match' + (items.length === 1 ? '' : 'es'))
        : '';
    }
  }
  input.addEventListener('input', apply);
  apply();
})();
"#;

pub fn html(report: &Report) -> String {
    let mut out = String::new();
    let complete = report.coverage.complete;
    let _ = write!(
        out,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'\">\
<meta name=\"referrer\" content=\"no-referrer\">\
<title>SecretHunter report \u{2014} {}</title><style>{STYLE}</style></head><body><main>",
        html_escape(&report.target)
    );
    let _ = write!(
        out,
        "<h1>SecretHunter report</h1><div class=\"muted mono\">{}</div>",
        html_escape(&report.target)
    );
    let _ = write!(
        out,
        "<div class=\"result\"><span class=\"badge {}\">{}</span> \
<strong>Exit {}</strong> \u{2014} {}. <strong>{}</strong> active and {} suppressed occurrences \
across {} findings.</div>",
        if complete { "b-ok" } else { "b-bad" },
        if complete { "complete" } else { "incomplete" },
        report.exit_code,
        html_escape(exit_meaning(report.exit_code)),
        report.active_occurrences,
        report.suppressed_occurrences,
        report.findings.len()
    );

    // High-level summary: always visible, never collapsed.
    let _ = write!(
        out,
        "<h2 style=\"border-bottom:none;margin-top:16px\">At a glance</h2><div class=\"stats\">"
    );
    let mut stat = |n: String, label: &str| {
        let _ = write!(
            out,
            "<div class=\"stat\"><span class=\"n\">{n}</span><span class=\"l\">{}</span></div>",
            html_escape(label)
        );
    };
    stat(report.findings.len().to_string(), "Findings");
    stat(report.active_occurrences.to_string(), "Active occurrences");
    stat(report.suppressed_occurrences.to_string(), "Suppressed");
    stat(affected_paths_count(report).to_string(), "Files affected");
    stat(
        report.coverage.records_scanned.to_string(),
        "Records scanned",
    );
    let _ = write!(out, "</div>");

    let _ = write!(out, "<div class=\"grid\">");
    let mut row = |label: &str, value: String| {
        let _ = write!(
            out,
            "<span class=\"muted\">{label}</span><span>{value}</span>"
        );
    };
    if let Some(url) = &report.repository_url {
        row(
            "Repository",
            a(url.trim_start_matches("https://github.com/"), Some(url)),
        );
    }
    row("History", html_escape(&report.history));
    row(
        "Scanned",
        format!(
            "{} records, {}",
            report.coverage.records_scanned,
            crate::progress::human_bytes(report.coverage.bytes_scanned)
        ),
    );
    row(
        "Scanner",
        format!(
            "SecretHunter {} \u{b7} policy <code>{}</code> \u{b7} key <code>{}</code> \u{b7} scan <code>{}</code>",
            html_escape(&report.scanner_version),
            short(&report.policy_digest),
            html_escape(&report.key_id),
            html_escape(&report.scan_id)
        ),
    );
    let _ = write!(
        out,
        "</div><p class=\"muted\"><strong>WARNING:</strong> this report contains the raw matched \
value of every finding; handle and store it as sensitively as the secrets themselves. Other \
metadata (paths, descriptions, coverage reasons) is still masked as <code>[REDACTED]</code>.</p>"
    );

    let _ = write!(
        out,
        "<div class=\"toolbar\"><input id=\"sh-search\" type=\"search\" \
placeholder=\"Search findings, paths, rules, commits, coverage\u{2026}\" \
aria-label=\"Search this report\"><span id=\"sh-search-count\" class=\"muted mono\"></span>\
<button type=\"button\" id=\"sh-expand\">Expand all</button>\
<button type=\"button\" id=\"sh-collapse\">Collapse all</button></div>"
    );

    if !report.findings.is_empty() {
        let _ = write!(
            out,
            "<table><tr><th>Severity</th><th class=\"num\">Findings</th>\
<th class=\"num\">Active occurrences</th></tr>"
        );
        for (label, findings, active) in severity_summary(report).values() {
            let _ = write!(
                out,
                "<tr><td><span class=\"badge b-{label}\">{label}</span></td>\
<td class=\"num\">{findings}</td><td class=\"num\">{active}</td></tr>"
            );
        }
        let _ = write!(out, "</table>");
        let mut rules: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for finding in &report.findings {
            let entry = rules.entry(&finding.rule_id).or_default();
            entry.0 += 1;
            entry.1 += finding.occurrences.len();
        }
        let _ = write!(
            out,
            "<table><tr><th>Rule</th><th class=\"num\">Findings</th>\
<th class=\"num\">Occurrences</th></tr>"
        );
        for (rule, (findings, occurrences)) in rules {
            let _ = write!(
                out,
                "<tr><td><code>{}</code></td><td class=\"num\">{findings}</td>\
<td class=\"num\">{occurrences}</td></tr>",
                html_escape(rule)
            );
        }
        let _ = write!(out, "</table>");
    }

    // Findings, coverage, and refs are collapsed by default (<details> without
    // `open`); the counts in each <summary> stay visible without expanding.
    let _ = write!(
        out,
        "<details class=\"section\" id=\"findings-section\"><summary><h2 style=\"display:inline-flex;border:none;margin:0;padding:0\">Findings ({})</h2></summary>",
        report.findings.len()
    );
    if report.findings.is_empty() {
        let _ = write!(out, "<p>No findings to display.</p>");
    }
    for (index, finding) in ordered(report).into_iter().enumerate() {
        let severity = if SEVERITIES.contains(&finding.severity.as_str()) {
            finding.severity.as_str()
        } else {
            "other"
        };
        let _ = write!(
            out,
            "<details class=\"finding searchable {severity}\" id=\"finding-{}\"><summary>\
<span class=\"badge b-{severity}\">{severity}</span> {}. <code>{}</code> \u{2014} {}</summary>\
<div class=\"muted\">Confidence {} \u{b7} {} \u{b7} {} \u{b7} verification {} \u{b7} evidence {}</div>\
<p><strong>Remediation:</strong> {}</p>\
<p><strong>Secret value:</strong> <code class=\"mono\">{}</code></p>",
            index + 1,
            index + 1,
            html_escape(&finding.rule_id),
            html_escape(&finding.description),
            html_escape(&finding.confidence),
            html_escape(&finding.category),
            html_escape(&finding.lifecycle),
            html_escape(&finding.verification),
            html_escape(&finding.evidence_codes.join(", ")),
            html_escape(&finding.remediation),
            html_escape(&finding.value)
        );
        if let Some(llm) = &finding.llm {
            let _ = write!(
                out,
                "<p><strong>LLM analysis</strong> (<code>{}</code>): \
<span class=\"badge b-{}\">{}</span> {}</p>",
                html_escape(&llm.model),
                match llm.verdict.as_str() {
                    "likely_real" => "bad",
                    "likely_false_positive" => "ok",
                    _ => "other",
                },
                html_escape(&llm.verdict),
                html_escape(&llm.explanation)
            );
        }
        let row = |o: &Occurrence| -> String {
            let mut place = a(&location(o), o.url.as_deref().or(o.file_url.as_deref()));
            if let (Some(_), Some(file)) = (&o.url, &o.file_url) {
                place.push_str(&format!(
                    " <span class=\"muted\">({})</span>",
                    a("local", Some(file))
                ));
            }
            let revision = match (&o.commit, &o.tag) {
                (Some(commit), _) => format!(
                    "<span class=\"mono\">{}</span>",
                    a(short(commit), commit_url(report, commit).as_deref())
                ),
                (None, Some(tag)) => format!(
                    "tag {} <span class=\"mono\">{}</span>",
                    html_escape(o.ref_name.as_deref().unwrap_or("")),
                    html_escape(short(tag))
                ),
                _ => "<span class=\"muted\">working tree</span>".into(),
            };
            let suppressed = !o.suppressions.is_empty();
            let state = if suppressed {
                o.suppressions
                    .iter()
                    .map(|s| {
                        format!(
                            "suppressed by <code>{}</code> ({}, expires {}): {}",
                            html_escape(&s.id),
                            html_escape(&s.owner),
                            html_escape(&s.expires),
                            html_escape(&s.reason)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("<br>")
            } else {
                "active".into()
            };
            format!(
                "<tr{}><td class=\"loc mono\">{place}</td><td>{}</td><td>{revision}</td>\
<td>{}</td><td>{state}</td></tr>",
                if suppressed {
                    " class=\"suppressed\""
                } else {
                    ""
                },
                html_escape(&position(o)),
                html_escape(&o.source)
            )
        };
        const HEADER: &str = "<tr><th>Location</th><th>Position</th><th>Commit / tag</th><th>Source</th><th>Status</th></tr>";
        let mut occurrences = finding.occurrences.iter();
        if let Some(most_recent) = occurrences.next() {
            let _ = write!(
                out,
                "<p class=\"muted\">Most recent occurrence:</p><table>{HEADER}{}</table>",
                row(most_recent)
            );
        }
        let earlier: Vec<_> = occurrences.collect();
        if !earlier.is_empty() {
            let _ = write!(
                out,
                "<details><summary>{} earlier occurrence(s)</summary><table>{HEADER}",
                earlier.len()
            );
            for o in &earlier {
                out.push_str(&row(o));
            }
            let _ = write!(out, "</table></details>");
        }
        let _ = write!(out, "</details>");
    }
    let _ = write!(out, "</details>");

    let groups = coverage_groups(report);
    if !groups.is_empty() {
        let _ = write!(
            out,
            "<details class=\"section\" id=\"coverage-section\"><summary><h2 style=\"display:inline-flex;border:none;margin:0;padding:0\">Coverage ({})</h2></summary>",
            groups.len()
        );
        for (status, reason, entries) in &groups {
            let class = match *status {
                "incomplete" => "b-bad",
                "excluded" => "b-other",
                _ => "b-medium",
            };
            let _ = write!(
                out,
                "<details class=\"searchable\"><summary><span class=\"badge {class}\">{}</span> {} ({})</summary><ul>",
                html_escape(status),
                html_escape(reason),
                entries.len()
            );
            for entry in entries.iter().filter(|e| !e.path.is_empty()) {
                let _ = write!(
                    out,
                    "<li class=\"mono loc\">{}{}</li>",
                    html_escape(&entry.path),
                    entry.pattern.as_ref().map_or(String::new(), |p| format!(
                        " <span class=\"muted\">(pattern {})</span>",
                        html_escape(p)
                    ))
                );
            }
            let _ = write!(out, "</ul></details>");
        }
        let _ = write!(out, "</details>");
    }
    if !report.coverage.resolved_refs.is_empty() {
        let _ = write!(
            out,
            "<details class=\"section\" id=\"refs-section\"><summary><h2 style=\"display:inline-flex;border:none;margin:0;padding:0\">Git refs resolved ({})</h2></summary><table><tr><th>Ref</th><th>Commit</th></tr>",
            report.coverage.resolved_refs.len()
        );
        for (name, oid) in &report.coverage.resolved_refs {
            let _ = write!(
                out,
                "<tr class=\"searchable\"><td class=\"mono\">{}</td><td class=\"mono\">{}</td></tr>",
                html_escape(name),
                a(short(oid), ref_url(report, name, oid).as_deref())
            );
        }
        let _ = write!(out, "</table></details>");
    }
    let _ = writeln!(
        out,
        "<p class=\"muted\">Generated by SecretHunter {}. Links open GitHub or local files only.</p>\
<script>{SCRIPT}</script>\
</main></body></html>",
        html_escape(&report.scanner_version)
    );
    out
}
