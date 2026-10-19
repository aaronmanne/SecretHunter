use crate::{config::ScanConfig, scan::Run};
use base64::Engine;
use regex::Regex;
use std::{
    io::{Cursor, Read},
    path::{Component, Path},
};

pub struct View {
    pub text: String,
    pub members: Vec<String>,
    pub chain: Vec<String>,
    pub mapped_range: Option<(usize, usize)>,
    pub offsets: Option<Vec<usize>>,
    pub binary: bool,
}

pub struct Issue {
    pub members: Vec<String>,
    pub reason: &'static str,
    pub exclusion: bool,
    pub pattern: Option<String>,
}

struct Budget<'a> {
    config: &'a ScanConfig,
    total: &'a mut u64,
    expanded: u64,
    members: usize,
    all_members: &'a mut usize,
    views: usize,
    issues: Vec<Issue>,
    run: &'a Run,
    excludes: &'a [(String, Regex)],
}

pub fn inspect(
    bytes: &[u8],
    config: &ScanConfig,
    total: &mut u64,
    all_members: &mut usize,
    run: &Run,
    excludes: &[(String, Regex)],
    emit: &mut impl FnMut(View),
) -> Vec<Issue> {
    let mut budget = Budget {
        config,
        total,
        expanded: 0,
        members: 0,
        all_members,
        views: 0,
        issues: Vec::new(),
        run,
        excludes,
    };
    walk(bytes, Vec::new(), Vec::new(), None, 0, 0, &mut budget, emit);
    budget.issues
}

impl Budget<'_> {
    fn issue(&mut self, members: &[String], reason: &'static str) {
        self.issues.push(Issue {
            members: members.to_vec(),
            reason,
            exclusion: false,
            pattern: None,
        });
    }
    fn charge(&mut self, size: usize, members: &[String]) -> bool {
        if size as u64
            > self
                .config
                .max_expanded_bytes_per_record
                .saturating_sub(self.expanded)
            || size as u64
                > self
                    .config
                    .max_expanded_bytes_total
                    .saturating_sub(*self.total)
        {
            self.issue(members, "Expanded-byte budget exhausted.");
            return false;
        }
        self.expanded += size as u64;
        *self.total += size as u64;
        true
    }
    fn member(&mut self, name: &str, members: &[String]) -> bool {
        if !safe_member(name) {
            self.issue(members, "Unsafe archive member name rejected.");
            return false;
        }
        self.members += 1;
        *self.all_members += 1;
        if self.members > self.config.max_archive_members
            || *self.all_members > self.config.max_archive_members
        {
            self.issue(members, "Archive member budget exhausted.");
            return false;
        }
        for (pattern, re) in self.excludes {
            if re.is_match(name) {
                let mut chain = members.to_vec();
                chain.push(name.into());
                self.issues.push(Issue {
                    members: chain,
                    reason: "Explicit archive member exclusion.",
                    exclusion: true,
                    pattern: Some(pattern.clone()),
                });
                return false;
            }
        }
        true
    }
    fn read(&mut self, reader: impl Read, members: &[String]) -> Option<Vec<u8>> {
        let max = self
            .config
            .max_file_bytes
            .min(
                self.config
                    .max_expanded_bytes_per_record
                    .saturating_sub(self.expanded),
            )
            .min(
                self.config
                    .max_expanded_bytes_total
                    .saturating_sub(*self.total),
            );
        let mut bytes = Vec::new();
        match reader.take(max + 1).read_to_end(&mut bytes) {
            Ok(_) if bytes.len() as u64 <= max => {
                if self.charge(bytes.len(), members) {
                    Some(bytes)
                } else {
                    None
                }
            }
            Ok(_) => {
                self.issue(
                    members,
                    "Member or cumulative expanded-byte limit exceeded.",
                );
                None
            }
            Err(_) => {
                self.issue(members, "Archive member could not be decoded completely.");
                None
            }
        }
    }
}

pub fn safe_member(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.contains(':')
        && !name.contains('\0')
        && Path::new(name)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
        && !name.split('/').any(|c| c == "." || c == "..")
}

#[allow(clippy::too_many_arguments)]
fn walk(
    bytes: &[u8],
    members: Vec<String>,
    chain: Vec<String>,
    mapped_range: Option<(usize, usize)>,
    archive_depth: usize,
    decode_depth: usize,
    budget: &mut Budget<'_>,
    emit: &mut impl FnMut(View),
) {
    if budget.run.stopped() {
        budget.issue(&members, "Inspection interrupted or timed out.");
        return;
    }
    budget.views += 1;
    if budget.views > budget.config.max_archive_members {
        budget.issue(&members, "Extraction view budget exhausted.");
        return;
    }
    let zip = bytes.starts_with(b"PK\x03\x04")
        || bytes.starts_with(b"PK\x05\x06")
        || bytes.starts_with(b"PK\x07\x08");
    let gzip = bytes.starts_with(&[0x1f, 0x8b]);
    let tar = bytes.len() >= 512 && (&bytes[257..262] == b"ustar" || tar_header(bytes));
    if zip || gzip || tar {
        if archive_depth >= budget.config.max_archive_depth {
            budget.issue(&members, "Archive nesting limit reached.");
            return;
        }
        if zip {
            let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
                budget.issue(&members, "Malformed or unsupported ZIP archive.");
                return;
            };
            if archive
                .file_names()
                .any(|name| name == "[Content_Types].xml")
            {
                budget.issue(&members, "Office container: raw members inspected, but document-text extraction is unsupported.");
            }
            if archive.len()
                > budget
                    .config
                    .max_archive_members
                    .saturating_sub(*budget.all_members)
            {
                budget.issue(&members, "Archive member budget exhausted.");
                return;
            }
            for index in 0..archive.len() {
                if budget.run.stopped() {
                    budget.issue(&members, "Inspection interrupted or timed out.");
                    break;
                }
                let Ok(mut member) = archive.by_index(index) else {
                    budget.issue(&members, "Unreadable or encrypted ZIP member.");
                    continue;
                };
                let name = member.name().to_owned();
                if !budget.member(&name, &members) {
                    continue;
                }
                if member.is_dir() {
                    continue;
                }
                if member
                    .unix_mode()
                    .is_some_and(|mode| mode & 0o170000 != 0 && mode & 0o170000 != 0o100000)
                {
                    budget.issue(&members, "Non-regular ZIP member rejected.");
                    continue;
                }
                let mut next = members.clone();
                next.push(name);
                if let Some(data) = budget.read(&mut member, &next) {
                    let mut provenance = chain.clone();
                    provenance.push("zip".into());
                    walk(
                        &data,
                        next,
                        provenance,
                        None,
                        archive_depth + 1,
                        decode_depth,
                        budget,
                        emit,
                    );
                }
            }
        } else if gzip {
            let mut next = members.clone();
            next.push("<gzip-payload>".into());
            if budget.member("<gzip-payload>", &members)
                && let Some(data) = budget.read(flate2::read::MultiGzDecoder::new(bytes), &next)
            {
                let mut provenance = chain.clone();
                provenance.push("gzip".into());
                walk(
                    &data,
                    next,
                    provenance,
                    None,
                    archive_depth + 1,
                    decode_depth,
                    budget,
                    emit,
                );
            }
        } else {
            let mut archive = tar::Archive::new(Cursor::new(bytes));
            let Ok(entries) = archive.entries() else {
                budget.issue(&members, "Malformed TAR archive.");
                return;
            };
            for entry in entries {
                if budget.run.stopped() {
                    budget.issue(&members, "Inspection interrupted or timed out.");
                    break;
                }
                let Ok(mut member) = entry else {
                    budget.issue(&members, "Unreadable TAR member.");
                    break;
                };
                let Ok(path) = member.path() else {
                    budget.issue(&members, "Invalid TAR member name.");
                    continue;
                };
                let Some(name) = path.to_str().map(str::to_owned) else {
                    budget.issue(&members, "Non-UTF-8 TAR member name.");
                    continue;
                };
                if !budget.member(&name, &members) {
                    if budget.members > budget.config.max_archive_members
                        || *budget.all_members > budget.config.max_archive_members
                    {
                        break;
                    }
                    continue;
                }
                if member.header().entry_type().is_dir() {
                    continue;
                }
                if !member.header().entry_type().is_file() {
                    budget.issue(&members, "Non-regular TAR member rejected.");
                    continue;
                }
                let mut next = members.clone();
                next.push(name);
                if let Some(data) = budget.read(&mut member, &next) {
                    let mut provenance = chain.clone();
                    provenance.push("tar".into());
                    walk(
                        &data,
                        next,
                        provenance,
                        None,
                        archive_depth + 1,
                        decode_depth,
                        budget,
                        emit,
                    );
                }
            }
        }
        return;
    }

    let (text, offsets, binary, mut provenance) =
        if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
            let little = bytes[0] == 0xff;
            if !bytes.len().is_multiple_of(2) {
                budget.issue(&members, "Truncated UTF-16 text.");
            }
            let units = bytes[2..].as_chunks::<2>().0.iter().map(|b| {
                if little {
                    u16::from_le_bytes([b[0], b[1]])
                } else {
                    u16::from_be_bytes([b[0], b[1]])
                }
            });
            let mut text = String::new();
            let mut offsets = Vec::new();
            let mut original = 2;
            for decoded in char::decode_utf16(units) {
                let c = match decoded {
                    Ok(c) => c,
                    Err(_) => {
                        budget.issue(&members, "Invalid UTF-16 sequence.");
                        '\u{fffd}'
                    }
                };
                offsets.extend(std::iter::repeat_n(original, c.len_utf8()));
                original += c.len_utf16() * 2;
                text.push(c);
            }
            offsets.push(original);
            let mut chain = chain;
            chain.push("utf16".into());
            (text, Some(offsets), false, chain)
        } else {
            match std::str::from_utf8(bytes) {
                Ok(text)
                    if !text.chars().any(|c| {
                        c == '\0' || (c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
                    }) && !bytes.starts_with(b"%PDF-")
                        && !bytes.starts_with(b"{\\rtf") =>
                {
                    (text.to_owned(), None, false, chain)
                }
                _ => {
                    budget.issue(
                        &members,
                        "Unsupported binary: printable-byte inspection is partial coverage.",
                    );
                    let text: String = bytes
                        .iter()
                        .map(|b| {
                            if b.is_ascii_graphic() || b.is_ascii_whitespace() {
                                *b as char
                            } else {
                                ' '
                            }
                        })
                        .collect();
                    let mut chain = chain;
                    chain.push("printable-bytes".into());
                    (text, None, true, chain)
                }
            }
        };
    if offsets.is_some() && !budget.charge(text.len(), &members) {
        return;
    }
    if !binary {
        for (kind, regex) in decode_patterns() {
            for item in regex.find_iter(&text) {
                if budget.run.stopped() {
                    budget.issue(&members, "Inspection interrupted or timed out.");
                    break;
                }
                let decoded = match *kind {
                    "base64" => base64::engine::general_purpose::STANDARD
                        .decode(item.as_str())
                        .or_else(|_| {
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(item.as_str())
                        })
                        .ok(),
                    "hex" => hex::decode(item.as_str()).ok(),
                    "percent" => percent_decode(item.as_str()),
                    _ => None,
                };
                let Some(decoded) = decoded else {
                    continue;
                };
                if decoded.is_empty()
                    || decoded == item.as_str().as_bytes()
                    || !decoded.iter().any(u8::is_ascii_graphic)
                {
                    continue;
                }
                // Random-looking binary is not recursively interpreted as encoded text.
                if std::str::from_utf8(&decoded).is_err()
                    && !decoded.starts_with(&[0xff, 0xfe])
                    && !decoded.starts_with(&[0xfe, 0xff])
                {
                    continue;
                }
                if decode_depth >= budget.config.max_decode_depth {
                    budget.issue(&members, "Decoding nesting limit reached.");
                    break;
                }
                if !budget.charge(decoded.len(), &members) {
                    break;
                }
                let range = mapped_range.or_else(|| {
                    Some(match &offsets {
                        Some(map) => (map[item.start()], map[item.end()]),
                        None => (item.start(), item.end()),
                    })
                });
                let mut next = provenance.clone();
                next.push((*kind).into());
                walk(
                    &decoded,
                    members.clone(),
                    next,
                    range,
                    archive_depth,
                    decode_depth + 1,
                    budget,
                    emit,
                );
                if budget.views > budget.config.max_archive_members {
                    break;
                }
            }
        }
    }
    provenance.shrink_to_fit();
    emit(View {
        text,
        members,
        chain: provenance,
        mapped_range,
        offsets,
        binary,
    });
}

fn tar_header(bytes: &[u8]) -> bool {
    let checksum = std::str::from_utf8(&bytes[148..156])
        .ok()
        .and_then(|s| u64::from_str_radix(s.trim_matches(['\0', ' ']), 8).ok());
    checksum.is_some_and(|sum| {
        sum == bytes[..512]
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    *b as u64
                }
            })
            .sum::<u64>()
    })
}

fn decode_patterns() -> &'static [(&'static str, Regex)] {
    static PATTERNS: std::sync::OnceLock<Vec<(&str, Regex)>> = std::sync::OnceLock::new();
    PATTERNS.get_or_init(|| vec![
        ("base64", Regex::new(r"[A-Za-z0-9+/_-]{16,}={0,2}").expect("static regex")),
        ("hex", Regex::new(r"\b(?:[0-9A-Fa-f]{2}){8,}\b").expect("static regex")),
        ("percent", Regex::new(r"(?:[A-Za-z0-9_.~-]|%[0-9A-Fa-f]{2})*%[0-9A-Fa-f]{2}(?:[A-Za-z0-9_.~-]|%[0-9A-Fa-f]{2})*").expect("static regex")),
    ])
}
fn percent_decode(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            out.push(u8::from_str_radix(value.get(i + 1..i + 3)?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(out)
}
