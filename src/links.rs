//! Report links. URLs are only ever built from a fixed `https://github.com` host,
//! validated owner/repository names, hexadecimal object IDs and percent-encoded
//! paths, or from the operator's own canonical scan root (`file://`). Target-supplied
//! URLs are never copied into reports.

use crate::scan::Origin;
use std::{collections::HashSet, path::PathBuf};

#[derive(Clone, Debug, Default)]
pub struct Links {
    /// `https://github.com/OWNER/REPO` for GitHub targets or GitHub `origin` remotes.
    pub github: Option<String>,
    /// Canonical working-tree root for `file://` links.
    pub root: Option<PathBuf>,
    /// Repository-relative path of the scanned subtree, with a trailing `/`.
    pub prefix: String,
    pub head: Option<String>,
    /// Repository-relative paths tracked at `head`.
    pub head_paths: HashSet<String>,
}

fn valid_name(part: &str) -> bool {
    !part.is_empty()
        && part != "."
        && part != ".."
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Recognizes GitHub remotes (`https://`, `ssh://`, `git://`, and `git@github.com:`
/// forms) and returns the canonical web base, discarding any credentials.
pub fn github_base(remote: &str) -> Option<String> {
    let path = if let Some(rest) = remote.strip_prefix("git@github.com:") {
        rest.to_owned()
    } else {
        let url = url::Url::parse(remote).ok()?;
        if !matches!(url.scheme(), "https" | "http" | "ssh" | "git")
            || url.host_str() != Some("github.com")
        {
            return None;
        }
        url.path().to_owned()
    };
    let path = path.trim_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let mut parts = path.split('/');
    let (owner, repo) = (parts.next()?, parts.next()?);
    if parts.next().is_some() || !valid_name(owner) || !valid_name(repo) {
        return None;
    }
    Some(format!("https://github.com/{owner}/{repo}"))
}

/// Percent-encodes everything except RFC 3986 unreserved characters and `/`.
pub fn encode_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for byte in path.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

impl Links {
    /// Returns `(web URL, local file URL)` for one occurrence.
    pub fn occurrence(
        &self,
        origin: &Origin,
        line: Option<usize>,
        archived: bool,
    ) -> (Option<String>, Option<String>) {
        let full = format!("{}{}", self.prefix, origin.path);
        let blob = |base: &str, commit: &str| {
            let mut url = format!("{base}/blob/{commit}/{}", encode_path(&full));
            let lower = full.to_ascii_lowercase();
            if [".md", ".markdown", ".mdx", ".rst", ".adoc"]
                .iter()
                .any(|ext| lower.ends_with(ext))
            {
                // Rendered documents ignore line anchors without `plain=1`.
                url.push_str("?plain=1");
            }
            if let (Some(line), false) = (line, archived) {
                url.push_str(&format!("#L{line}"));
            }
            url
        };
        let web = self
            .github
            .as_deref()
            .and_then(|base| match origin.source.as_str() {
                "commit_message" => origin
                    .commit
                    .as_deref()
                    .filter(|c| valid_oid(c))
                    .map(|c| format!("{base}/commit/{c}")),
                "tag_message" => origin
                    .ref_name
                    .as_deref()
                    .and_then(|name| name.strip_prefix("refs/tags/"))
                    .map(|tag| format!("{base}/releases/tag/{}", encode_path(tag))),
                "git_history" | "remote_snapshot" => origin
                    .commit
                    .as_deref()
                    .filter(|c| valid_oid(c))
                    .map(|c| blob(base, c)),
                "working_tree" => self
                    .head
                    .as_deref()
                    .filter(|head| valid_oid(head) && self.head_paths.contains(&full))
                    .map(|head| blob(base, head)),
                _ => None,
            });
        let file = (origin.source == "working_tree")
            .then_some(self.root.as_ref())
            .flatten()
            .map(|root| {
                format!(
                    "file://{}",
                    encode_path(&root.join(&origin.path).to_string_lossy())
                )
            });
        (web, file)
    }
}
