use crate::{config::ScanConfig, scan::Run};
use base64::Engine;
use regex::Regex;
use std::{
    io::{Cursor, Read},
    path::{Component, Path},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

pub struct View {
    pub text: String,
    pub members: Vec<String>,
    pub chain: Vec<String>,
    pub mapped_range: Option<(usize, usize)>,
    pub offsets: Option<OffsetMap>,
    /// Location-mapping label used when `offsets` is present.
    pub offset_kind: &'static str,
    pub line_numbers: bool,
}

/// Maps positions in a derived text view back to original byte offsets.
pub enum OffsetMap {
    /// One original offset per text byte, plus one end entry.
    Bytes(Vec<usize>),
    /// Contiguous runs where each text byte covers `width` original bytes.
    Segments(Vec<Segment>),
}

#[derive(Clone, Copy)]
pub struct Segment {
    pub text: usize,
    pub original: usize,
    pub width: usize,
}

impl OffsetMap {
    pub fn map(&self, position: usize) -> usize {
        match self {
            Self::Bytes(offsets) => offsets[position.min(offsets.len().saturating_sub(1))],
            Self::Segments(segments) => {
                let index = segments
                    .partition_point(|s| s.text <= position)
                    .saturating_sub(1);
                segments.get(index).map_or(position, |s| {
                    s.original + position.saturating_sub(s.text) * s.width
                })
            }
        }
    }
}

pub struct Issue {
    pub members: Vec<String>,
    pub reason: &'static str,
    pub exclusion: bool,
    pub pattern: Option<String>,
    /// A known format limitation (content inspected as far as the format allows),
    /// as opposed to content that could not be inspected at all.
    pub partial: bool,
}

pub const BINARY_STRINGS: &str = "Binary content: readable strings (ASCII, UTF-8, UTF-16LE) inspected; compressed or encoded data inside it cannot be.";

struct Budget<'a> {
    config: &'a ScanConfig,
    total: &'a AtomicU64,
    expanded: u64,
    members: usize,
    all_members: &'a AtomicUsize,
    views: usize,
    issues: Vec<Issue>,
    run: &'a Run,
    excludes: &'a [(String, Regex)],
}

/// Run-wide budgets are shared atomics so concurrent records cannot jointly exceed them.
pub fn inspect(
    bytes: &[u8],
    config: &ScanConfig,
    total: &AtomicU64,
    all_members: &AtomicUsize,
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
            partial: false,
        });
    }
    fn limit(&mut self, members: &[String], reason: &'static str) {
        self.issues.push(Issue {
            members: members.to_vec(),
            reason,
            exclusion: false,
            pattern: None,
            partial: true,
        });
    }
    fn charge(&mut self, size: usize, members: &[String]) -> bool {
        let size = size as u64;
        if size
            > self
                .config
                .max_expanded_bytes_per_record
                .saturating_sub(self.expanded)
        {
            self.issue(members, "Expanded-byte budget exhausted.");
            return false;
        }
        let limit = self.config.max_expanded_bytes_total;
        let mut used = self.total.load(Ordering::Acquire);
        loop {
            if size > limit.saturating_sub(used) {
                self.issue(members, "Expanded-byte budget exhausted.");
                return false;
            }
            match self.total.compare_exchange_weak(
                used,
                used + size,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => used = actual,
            }
        }
        self.expanded += size;
        true
    }
    fn member(&mut self, name: &str, members: &[String]) -> bool {
        if !safe_member(name) {
            self.issue(members, "Unsafe archive member name rejected.");
            return false;
        }
        self.members += 1;
        let all_members = self.all_members.fetch_add(1, Ordering::AcqRel) + 1;
        if self.members > self.config.max_archive_members
            || all_members > self.config.max_archive_members
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
                    partial: false,
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
                    .saturating_sub(self.total.load(Ordering::Acquire)),
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
    'archive: {
        if zip || gzip || tar {
            if archive_depth >= budget.config.max_archive_depth {
                budget.issue(&members, "Archive nesting limit reached.");
                return;
            }
            if zip {
                // Files that merely start with an archive signature fall back to strings.
                let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(bytes)) else {
                    break 'archive;
                };
                if archive
                    .file_names()
                    .any(|name| name == "[Content_Types].xml")
                {
                    budget.limit(&members, "Office container: raw members inspected, but document-text extraction is unsupported.");
                }
                if archive.len()
                    > budget
                        .config
                        .max_archive_members
                        .saturating_sub(budget.all_members.load(Ordering::Acquire))
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
                        budget.limit(&members, "Encrypted or unsupported-compression ZIP member was not decrypted or decoded.");
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
                        budget.limit(&members, "Non-regular ZIP member (link or device) skipped.");
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
                    break 'archive;
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
                            || budget.all_members.load(Ordering::Acquire)
                                > budget.config.max_archive_members
                        {
                            break;
                        }
                        continue;
                    }
                    if member.header().entry_type().is_dir() {
                        continue;
                    }
                    if !member.header().entry_type().is_file() {
                        budget.limit(&members, "Non-regular TAR member (link or device) skipped.");
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
    }
    if zip || tar {
        budget.limit(
            &members,
            "Malformed or unsupported archive; readable strings inspected instead.",
        );
    }

    let class_strings = bytes
        .starts_with(&[0xca, 0xfe, 0xba, 0xbe])
        .then(|| java_class_strings(bytes))
        .flatten();
    let mut offset_kind = "utf16_bytes";
    let mut line_numbers = true;
    let (text, offsets, mut provenance) = if let Some((text, offsets)) = class_strings {
        // Constant-pool strings hold every literal and name in a class file; line
        // numbers would be misleading, so findings map to original byte offsets.
        offset_kind = "class_constant_bytes";
        line_numbers = false;
        let mut chain = chain;
        chain.push("java-class".into());
        (text, Some(OffsetMap::Bytes(offsets)), chain)
    } else if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        if !bytes.len().is_multiple_of(2) {
            budget.limit(&members, "Truncated UTF-16 text; final odd byte ignored.");
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
                    budget.limit(&members, "Invalid UTF-16 sequence replaced.");
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
        (text, Some(OffsetMap::Bytes(offsets)), chain)
    } else if textual(bytes) {
        match std::str::from_utf8(bytes) {
            Ok(text) => (text.to_owned(), None, chain),
            Err(_) => {
                // Mostly-text content with legacy-encoded bytes (e.g. Latin-1 commit
                // messages) is fully inspected; invalid bytes map to U+0080..U+00FF.
                offset_kind = "latin1_bytes";
                let (text, offsets) = lossless_text(bytes);
                let mut chain = chain;
                chain.push("latin1".into());
                (text, Some(OffsetMap::Bytes(offsets)), chain)
            }
        }
    } else {
        budget.limit(&members, BINARY_STRINGS);
        offset_kind = "binary_string_bytes";
        line_numbers = false;
        let (text, segments) = binary_strings(bytes);
        let mut chain = chain;
        chain.push("binary-strings".into());
        (text, Some(OffsetMap::Segments(segments)), chain)
    };
    if offsets.is_some() && !budget.charge(text.len(), &members) {
        return;
    }
    {
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
                // Only readable text is treated as encoded content; random words that
                // happen to be valid base64/hex decode to noise and are ignored.
                let readable = std::str::from_utf8(&decoded).is_ok_and(|text| {
                    !text
                        .chars()
                        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
                });
                if !readable
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
                        Some(map) => (map.map(item.start()), map.map(item.end())),
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
        offset_kind,
        line_numbers,
    });
}

/// Text heuristic: no NUL bytes, and stray control bytes (other than common whitespace
/// and terminal escapes) stay within 2% of the content plus a small allowance.
fn textual(bytes: &[u8]) -> bool {
    if bytes.contains(&0) {
        return false;
    }
    let controls = bytes
        .iter()
        .filter(|&&b| {
            (b < 0x20 && !matches!(b, b'\t' | b'\n' | b'\r' | 0x07 | 0x08 | 0x0b | 0x0c | 0x1b))
                || b == 0x7f
        })
        .count();
    controls <= bytes.len() / 50 + 4
}

/// Valid UTF-8 is kept; each invalid byte becomes the Latin-1 character with that value.
fn lossless_text(bytes: &[u8]) -> (String, Vec<usize>) {
    let mut text = String::with_capacity(bytes.len());
    let mut offsets = Vec::with_capacity(bytes.len() + 1);
    let mut at = 0;
    for chunk in bytes.utf8_chunks() {
        let valid = chunk.valid();
        text.push_str(valid);
        offsets.extend(at..at + valid.len());
        at += valid.len();
        for &byte in chunk.invalid() {
            let c = char::from(byte);
            text.push(c);
            offsets.extend(std::iter::repeat_n(at, c.len_utf8()));
            at += 1;
        }
    }
    offsets.push(at);
    (text, offsets)
}

const MIN_STRING: usize = 4;

/// Extracts readable runs from binary data like `strings`: printable ASCII/UTF-8 runs
/// and UTF-16LE ASCII runs of at least four characters, newline-separated.
pub fn binary_strings(bytes: &[u8]) -> (String, Vec<Segment>) {
    let mut text = String::new();
    let mut segments = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        let mut chars = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if (0x20..0x7f).contains(&b) || b == b'\t' {
                i += 1;
                chars += 1;
                continue;
            }
            let width = match b {
                0xc2..=0xdf => 2,
                0xe0..=0xef => 3,
                0xf0..=0xf4 => 4,
                _ => 0,
            };
            let printable = width > 0
                && bytes
                    .get(i..i + width)
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .and_then(|s| s.chars().next())
                    .is_some_and(|c| !c.is_control());
            if !printable {
                break;
            }
            i += width;
            chars += 1;
        }
        if chars >= MIN_STRING {
            segments.push(Segment {
                text: text.len(),
                original: start,
                width: 1,
            });
            text.push_str(std::str::from_utf8(&bytes[start..i]).unwrap_or_default());
            text.push('\n');
        }
        if i == start {
            i += 1;
        }
    }
    let mut i = 0;
    while i + 1 < bytes.len() {
        let start = i;
        while i + 1 < bytes.len()
            && ((0x20..0x7f).contains(&bytes[i]) || bytes[i] == b'\t')
            && bytes[i + 1] == 0
        {
            i += 2;
        }
        let chars = (i - start) / 2;
        if chars >= MIN_STRING {
            segments.push(Segment {
                text: text.len(),
                original: start,
                width: 2,
            });
            text.extend((0..chars).map(|k| char::from(bytes[start + 2 * k])));
            text.push('\n');
        }
        if i == start {
            i += 1;
        }
    }
    (text, segments)
}

/// Decodes a Java class file's constant-pool UTF-8 entries (string literals, names,
/// annotation values), newline-separated, with each text byte mapped to its original
/// byte offset. Returns `None` for anything that is not a well-formed constant pool.
fn java_class_strings(bytes: &[u8]) -> Option<(String, Vec<usize>)> {
    let u16_at = |at: usize| Some(u16::from_be_bytes([*bytes.get(at)?, *bytes.get(at + 1)?]));
    // Mach-O universal binaries share this magic; class files have major version >= 45.
    if u16_at(6)? < 45 {
        return None;
    }
    let count = u16_at(8)? as usize;
    let mut text = String::new();
    let mut offsets = Vec::new();
    let mut at = 10;
    let mut index = 1;
    while index < count {
        let tag = *bytes.get(at)?;
        at += 1;
        match tag {
            1 => {
                let len = u16_at(at)? as usize;
                at += 2;
                let data = bytes.get(at..at + len)?;
                if !data.is_empty() {
                    modified_utf8(data, at, &mut text, &mut offsets)?;
                    offsets.push(at + len);
                    text.push('\n');
                }
                at += len;
            }
            3 | 4 | 9 | 10 | 11 | 12 | 17 | 18 => at += 4,
            5 | 6 => {
                at += 8;
                index += 1;
            }
            7 | 8 | 16 | 19 | 20 => at += 2,
            15 => at += 3,
            _ => return None,
        }
        index += 1;
    }
    if at > bytes.len() {
        return None;
    }
    offsets.push(offsets.last().copied().unwrap_or(at));
    Some((text, offsets))
}

/// Java "modified UTF-8": NUL as two bytes and supplementary characters as encoded
/// surrogate pairs. Unpaired surrogates become U+FFFD.
fn modified_utf8(
    data: &[u8],
    base: usize,
    text: &mut String,
    offsets: &mut Vec<usize>,
) -> Option<()> {
    let mut units = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        let b = data[i];
        let continuation = |at: usize| data.get(at).filter(|c| *c & 0xc0 == 0x80).copied();
        let (unit, len) = if b < 0x80 {
            (u16::from(b), 1)
        } else if b & 0xe0 == 0xc0 {
            let b2 = continuation(i + 1)?;
            ((u16::from(b & 0x1f) << 6) | u16::from(b2 & 0x3f), 2)
        } else if b & 0xf0 == 0xe0 {
            let b2 = continuation(i + 1)?;
            let b3 = continuation(i + 2)?;
            (
                (u16::from(b & 0x0f) << 12) | (u16::from(b2 & 0x3f) << 6) | u16::from(b3 & 0x3f),
                3,
            )
        } else {
            return None;
        };
        units.push((unit, base + i));
        i += len;
    }
    let mut unit = 0;
    for decoded in char::decode_utf16(units.iter().map(|(u, _)| *u)) {
        let (c, width) = match decoded {
            Ok(c) => (c, c.len_utf16()),
            Err(_) => ('\u{fffd}', 1),
        };
        offsets.extend(std::iter::repeat_n(units[unit].1, c.len_utf8()));
        text.push(c);
        unit += width;
    }
    Some(())
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
