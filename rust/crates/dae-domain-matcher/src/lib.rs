//! Early Rust migration crate for dae domain matching.
//!
//! This crate intentionally starts with small, testable helpers before the
//! workspace is wired into the active Go runtime path.

use std::borrow::Cow;
use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;

use aho_corasick::AhoCorasick;
use regex::Regex;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;

mod dns_request_matcher;
mod userspace_routing_matcher;

pub use dns_request_matcher::{
    DnsRequestAction, DnsRequestCondition, DnsRequestLookup, DnsRequestMatchError,
    DnsRequestMatcher, DnsRequestPlan, DnsRequestRule, DnsRequestRuntimeError, DomainMatchScratch,
    IpPrefix, IpPrefixSet, match_dns_request_rules,
};
pub use dns_request_matcher::{
    DnsResponseAction, DnsResponseCondition, DnsResponseDecision, DnsResponseMatchError,
    DnsResponseMatcher, DnsResponseRule, DnsResponseRuntimeError, DnsRouting,
    match_dns_response_rules,
};
pub use userspace_routing_matcher::{
    UserspaceRoutingAction, UserspaceRoutingCondition, UserspaceRoutingInput,
    UserspaceRoutingMatch, UserspaceRoutingMatchError, UserspaceRoutingMatcher,
    UserspaceRoutingRule, UserspaceRoutingRuntimeError, UserspaceRoutingSetKind,
    match_userspace_routing_rules,
};

/// Domain pattern kinds mirrored from the current Go matcher surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainPatternKind {
    Full,
    Suffix,
    Keyword,
    Regex,
}

/// A reference pattern set used to build parity tests before optimizing the
/// implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainPatternSet {
    pub bit_index: usize,
    pub kind: DomainPatternKind,
    pub patterns: Vec<String>,
}

/// Errors returned by the staged reference matcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchError {
    BitIndexOutOfRange { bit_index: usize, bit_len: usize },
    BitmapWordLenMismatch { actual: usize, expected: usize },
    KeywordAutomatonBuild { error: String },
    InvalidRegex { pattern: String, error: String },
}

const FFI_OK: i32 = 0;
const FFI_ERROR: i32 = -1;

thread_local! {
    static LAST_FFI_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Opaque FFI builder used by the Go adapter prototype.
pub struct FfiMatcherBuilder {
    bit_len: usize,
    sets: Vec<DomainPatternSet>,
}

/// Opaque FFI matcher used by the Go adapter prototype.
pub struct FfiMatcher {
    matcher: IndexedMatcher,
}

#[derive(Debug)]
enum PreparedPatterns {
    Plain(Vec<String>),
    Regex(Vec<Regex>),
}

#[derive(Debug)]
struct PreparedPatternSet {
    bit_index: usize,
    kind: DomainPatternKind,
    patterns: PreparedPatterns,
}

/// Buildable reference matcher that mirrors the current Go build-then-match
/// split more closely than the direct helper.
#[derive(Debug)]
pub struct ReferenceMatcher {
    bit_len: usize,
    sets: Vec<PreparedPatternSet>,
}

/// Indexed matcher prototype for the first optimized Rust data-structure pass.
///
/// Full domains are matched through an exact hash index, suffix domains through
/// a reversed trie with explicit boundary handling, keywords through an
/// Aho-Corasick automaton, and regex rules through compiled regexes.
#[derive(Debug)]
pub struct IndexedMatcher {
    bit_len: usize,
    full: FxHashMap<String, Vec<u32>>,
    suffix: SuffixTrie,
    keywords: Option<KeywordMatcher>,
    regexes: Vec<(usize, Regex)>,
}

#[derive(Debug)]
struct KeywordMatcher {
    automaton: AhoCorasick,
    bitmaps: Vec<Vec<u32>>,
}

#[derive(Debug)]
struct SuffixTrie {
    nodes: Vec<SuffixTrieNode>,
}

#[derive(Debug, Default)]
struct SuffixTrieNode {
    children: SmallVec<[(u8, usize); 4]>,
    exact_bitmap: Vec<u32>,
    subdomain_bitmap: Vec<u32>,
}

/// Normalizes a domain the same way the current Go userspace matcher does
/// before matching: lower-case and trim trailing dots.
pub fn normalize_domain(domain: &str) -> String {
    normalize_domain_cow(domain).into_owned()
}

/// Normalizes a domain while borrowing the original input when no mutation is
/// required.
pub fn normalize_domain_cow(domain: &str) -> Cow<'_, str> {
    let trimmed = domain.trim_end_matches('.');
    if trimmed.bytes().any(|byte| byte.is_ascii_uppercase()) {
        Cow::Owned(trimmed.to_ascii_lowercase())
    } else {
        Cow::Borrowed(trimmed)
    }
}

/// Returns the number of `u32` words required for a bitmap with `bit_len`
/// bits.
pub fn bitmap_words(bit_len: usize) -> usize {
    bit_len.div_ceil(32)
}

/// Builds a reusable reference matcher from raw pattern sets.
pub fn build_reference_matcher(
    bit_len: usize,
    sets: &[DomainPatternSet],
) -> Result<ReferenceMatcher, MatchError> {
    let sets = sets
        .iter()
        .map(|set| prepare_pattern_set(bit_len, set))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ReferenceMatcher { bit_len, sets })
}

/// Builds the indexed matcher prototype from raw pattern sets.
pub fn build_indexed_matcher(
    bit_len: usize,
    sets: &[DomainPatternSet],
) -> Result<IndexedMatcher, MatchError> {
    let mut full = FxHashMap::default();
    let mut suffix = SuffixTrie::new(bit_len);
    let mut keyword_patterns = Vec::new();
    let mut keyword_bitmaps = Vec::new();
    let mut regexes = Vec::new();

    for set in sets {
        if set.bit_index >= bit_len {
            return Err(MatchError::BitIndexOutOfRange {
                bit_index: set.bit_index,
                bit_len,
            });
        }

        for pattern in &set.patterns {
            let pattern = normalize_domain(pattern);
            match set.kind {
                DomainPatternKind::Full => {
                    if !pattern.bytes().all(is_valid_domain_pattern_char) {
                        continue;
                    }
                    merge_bit(
                        full.entry(pattern).or_insert_with(|| zero_bitmap(bit_len)),
                        set.bit_index,
                    );
                }
                DomainPatternKind::Suffix => {
                    if !pattern.bytes().all(is_valid_domain_pattern_char) {
                        continue;
                    }
                    suffix.insert(&pattern, set.bit_index);
                }
                DomainPatternKind::Keyword => {
                    let mut bitmap = zero_bitmap(bit_len);
                    merge_bit(&mut bitmap, set.bit_index);
                    keyword_patterns.push(pattern);
                    keyword_bitmaps.push(bitmap);
                }
                DomainPatternKind::Regex => {
                    let regex =
                        Regex::new(pattern.as_str()).map_err(|error| MatchError::InvalidRegex {
                            pattern: pattern.clone(),
                            error: error.to_string(),
                        })?;
                    regexes.push((set.bit_index, regex));
                }
            }
        }
    }

    let keywords = if keyword_patterns.is_empty() {
        None
    } else {
        Some(KeywordMatcher {
            automaton: AhoCorasick::new(keyword_patterns).map_err(|error| {
                MatchError::KeywordAutomatonBuild {
                    error: error.to_string(),
                }
            })?,
            bitmaps: keyword_bitmaps,
        })
    };

    Ok(IndexedMatcher {
        bit_len,
        full,
        suffix,
        keywords,
        regexes,
    })
}

/// Reference bitmap matcher used to lock down Go parity semantics before
/// introducing a faster Rust implementation.
pub fn match_domain_bitmap(
    domain: &str,
    bit_len: usize,
    sets: &[DomainPatternSet],
) -> Result<Vec<u32>, MatchError> {
    build_reference_matcher(bit_len, sets)?.match_domain_bitmap(domain)
}

impl ReferenceMatcher {
    /// Matches a domain against the prepared pattern sets.
    pub fn match_domain_bitmap(&self, domain: &str) -> Result<Vec<u32>, MatchError> {
        let mut bitmap = vec![0; bitmap_words(self.bit_len)];
        self.match_domain_bitmap_into(domain, &mut bitmap)?;
        Ok(bitmap)
    }

    /// Matches a domain into a caller-owned bitmap buffer.
    ///
    /// This keeps the current reference matching semantics while separating
    /// matcher cost from output allocation cost for later adapter work.
    pub fn match_domain_bitmap_into(
        &self,
        domain: &str,
        bitmap: &mut [u32],
    ) -> Result<(), MatchError> {
        let mut keyword_scratch = String::new();
        self.match_domain_bitmap_into_with_keyword_scratch(domain, bitmap, &mut keyword_scratch)
    }

    /// Matches a domain into a caller-owned bitmap buffer while reusing the
    /// scratch buffer used for Go-compatible keyword boundary matching.
    pub fn match_domain_bitmap_into_with_keyword_scratch(
        &self,
        domain: &str,
        bitmap: &mut [u32],
        keyword_scratch: &mut String,
    ) -> Result<(), MatchError> {
        let expected = bitmap_words(self.bit_len);
        if bitmap.len() != expected {
            return Err(MatchError::BitmapWordLenMismatch {
                actual: bitmap.len(),
                expected,
            });
        }

        bitmap.fill(0);
        let normalized = normalize_domain_cow(domain);
        let normalized = normalized.as_ref();
        let keyword_domain = write_keyword_match_domain(normalized, keyword_scratch);

        for set in &self.sets {
            let matched = match (&set.kind, &set.patterns) {
                (DomainPatternKind::Full, PreparedPatterns::Plain(patterns)) => {
                    patterns.iter().any(|pattern| pattern == normalized)
                }
                (DomainPatternKind::Suffix, PreparedPatterns::Plain(patterns)) => patterns
                    .iter()
                    .any(|pattern| suffix_matches(normalized, pattern)),
                (DomainPatternKind::Keyword, PreparedPatterns::Plain(patterns)) => patterns
                    .iter()
                    .any(|pattern| keyword_domain.contains(pattern)),
                (DomainPatternKind::Regex, PreparedPatterns::Regex(patterns)) => {
                    patterns.iter().any(|pattern| pattern.is_match(normalized))
                }
                _ => false,
            };

            if matched {
                bitmap[set.bit_index / 32] |= 1 << (set.bit_index % 32);
            }
        }

        Ok(())
    }
}

impl IndexedMatcher {
    /// Matches a domain against the indexed matcher.
    pub fn match_domain_bitmap(&self, domain: &str) -> Result<Vec<u32>, MatchError> {
        let mut bitmap = zero_bitmap(self.bit_len);
        self.match_domain_bitmap_into(domain, &mut bitmap)?;
        Ok(bitmap)
    }

    /// Matches a domain into a caller-owned bitmap buffer.
    pub fn match_domain_bitmap_into(
        &self,
        domain: &str,
        bitmap: &mut [u32],
    ) -> Result<(), MatchError> {
        let mut keyword_scratch = String::new();
        self.match_domain_bitmap_into_with_keyword_scratch(domain, bitmap, &mut keyword_scratch)
    }

    /// Matches a domain into caller-owned bitmap and keyword scratch buffers.
    pub fn match_domain_bitmap_into_with_keyword_scratch(
        &self,
        domain: &str,
        bitmap: &mut [u32],
        keyword_scratch: &mut String,
    ) -> Result<(), MatchError> {
        let expected = bitmap_words(self.bit_len);
        if bitmap.len() != expected {
            return Err(MatchError::BitmapWordLenMismatch {
                actual: bitmap.len(),
                expected,
            });
        }

        bitmap.fill(0);
        let normalized = normalize_domain_cow(domain);
        let normalized = normalized.as_ref();
        let keyword_domain = write_keyword_match_domain(normalized, keyword_scratch);

        if let Some(full_bitmap) = self.full.get(normalized) {
            merge_bitmap(bitmap, full_bitmap);
        }

        self.suffix.match_domain_into(normalized, bitmap);

        if let Some(keywords) = &self.keywords {
            for mat in keywords.automaton.find_overlapping_iter(keyword_domain) {
                merge_bitmap(bitmap, &keywords.bitmaps[mat.pattern().as_usize()]);
            }
        }

        for (bit_index, regex) in &self.regexes {
            if regex.is_match(normalized) {
                merge_bit(bitmap, *bit_index);
            }
        }

        Ok(())
    }
}

impl SuffixTrie {
    fn new(bit_len: usize) -> Self {
        Self {
            nodes: vec![SuffixTrieNode {
                children: SmallVec::new(),
                exact_bitmap: zero_bitmap(bit_len),
                subdomain_bitmap: zero_bitmap(bit_len),
            }],
        }
    }

    fn insert(&mut self, pattern: &str, bit_index: usize) {
        let (pattern, allow_exact, allow_subdomain) = if let Some(rest) = pattern.strip_prefix('.')
        {
            (rest, false, true)
        } else {
            (pattern, true, true)
        };

        let mut node_index = 0;
        for byte in pattern.bytes().rev() {
            if let Some(next) = self.nodes[node_index].child(byte) {
                node_index = next;
                continue;
            }

            let next = self.nodes.len();
            let bitmap_len = self.nodes[0].exact_bitmap.len();
            self.nodes.push(SuffixTrieNode {
                children: SmallVec::new(),
                exact_bitmap: vec![0; bitmap_len],
                subdomain_bitmap: vec![0; bitmap_len],
            });
            self.nodes[node_index].children.push((byte, next));
            node_index = next;
        }

        if allow_exact {
            merge_bit(&mut self.nodes[node_index].exact_bitmap, bit_index);
        }
        if allow_subdomain {
            merge_bit(&mut self.nodes[node_index].subdomain_bitmap, bit_index);
        }
    }

    fn match_domain_into(&self, domain: &str, bitmap: &mut [u32]) {
        let bytes = domain.as_bytes();
        let mut node_index = 0;

        for (offset, byte) in bytes.iter().rev().copied().enumerate() {
            let Some(next) = self.nodes[node_index].child(byte) else {
                break;
            };
            node_index = next;

            if offset + 1 == bytes.len() {
                merge_bitmap(bitmap, &self.nodes[node_index].exact_bitmap);
            } else if bytes[bytes.len() - offset - 2] == b'.' {
                merge_bitmap(bitmap, &self.nodes[node_index].subdomain_bitmap);
            }
        }
    }
}

impl SuffixTrieNode {
    fn child(&self, byte: u8) -> Option<usize> {
        self.children
            .iter()
            .find_map(|(candidate, next)| (*candidate == byte).then_some(*next))
    }
}

fn prepare_pattern_set(
    bit_len: usize,
    set: &DomainPatternSet,
) -> Result<PreparedPatternSet, MatchError> {
    if set.bit_index >= bit_len {
        return Err(MatchError::BitIndexOutOfRange {
            bit_index: set.bit_index,
            bit_len,
        });
    }

    let patterns = match set.kind {
        DomainPatternKind::Full | DomainPatternKind::Suffix => PreparedPatterns::Plain(
            set.patterns
                .iter()
                .map(|pattern| normalize_domain(pattern))
                .filter(|pattern| pattern.bytes().all(is_valid_domain_pattern_char))
                .collect::<Vec<_>>(),
        ),
        DomainPatternKind::Keyword => PreparedPatterns::Plain(
            set.patterns
                .iter()
                .map(|pattern| normalize_domain(pattern))
                .collect::<Vec<_>>(),
        ),
        DomainPatternKind::Regex => PreparedPatterns::Regex(
            set.patterns
                .iter()
                .map(|pattern| {
                    Regex::new(pattern).map_err(|error| MatchError::InvalidRegex {
                        pattern: pattern.clone(),
                        error: error.to_string(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
    };

    Ok(PreparedPatternSet {
        bit_index: set.bit_index,
        kind: set.kind,
        patterns,
    })
}

fn is_valid_domain_pattern_char(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'z' | b'-' | b'.' | b'^' | b'_')
}

fn suffix_matches(domain: &str, pattern: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix('.') {
        domain.len() > rest.len() && domain.ends_with(pattern)
    } else {
        domain == pattern
            || (domain.len() > pattern.len()
                && domain.ends_with(pattern)
                && domain.as_bytes()[domain.len() - pattern.len() - 1] == b'.')
    }
}

fn zero_bitmap(bit_len: usize) -> Vec<u32> {
    vec![0; bitmap_words(bit_len)]
}

fn merge_bit(bitmap: &mut [u32], bit_index: usize) {
    bitmap[bit_index / 32] |= 1 << (bit_index % 32);
}

fn merge_bitmap(to: &mut [u32], from: &[u32]) {
    for (to, from) in to.iter_mut().zip(from) {
        *to |= *from;
    }
}

fn write_keyword_match_domain<'a>(domain: &str, scratch: &'a mut String) -> &'a str {
    scratch.clear();
    scratch.reserve(domain.len() + 2);
    scratch.push('^');
    scratch.push_str(domain);
    scratch.push('$');
    scratch.as_str()
}

/// Returns the last FFI error for this thread.
///
/// The returned pointer remains valid until the next FFI call on the same
/// thread overwrites the stored error.
#[unsafe(no_mangle)]
pub extern "C" fn dae_domain_matcher_last_error() -> *const c_char {
    LAST_FFI_ERROR.with(|last_error| {
        last_error
            .borrow()
            .as_ref()
            .map_or(ptr::null(), |error| error.as_ptr())
    })
}

/// Creates a staged matcher builder.
#[unsafe(no_mangle)]
pub extern "C" fn dae_domain_matcher_builder_new(bit_len: usize) -> *mut FfiMatcherBuilder {
    clear_ffi_error();
    Box::into_raw(Box::new(FfiMatcherBuilder {
        bit_len,
        sets: Vec::new(),
    }))
}

/// Frees a staged matcher builder.
///
/// # Safety
///
/// `builder` must be null or a pointer previously returned by
/// `dae_domain_matcher_builder_new` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_domain_matcher_builder_free(builder: *mut FfiMatcherBuilder) {
    if !builder.is_null() {
        drop(unsafe { Box::from_raw(builder) });
    }
}

/// Adds a single pattern to the staged matcher builder.
///
/// Kind mapping:
/// - 0: full
/// - 1: suffix
/// - 2: keyword
/// - 3: regex
///
/// # Safety
///
/// `builder` must be a valid builder pointer returned by
/// `dae_domain_matcher_builder_new`. `pattern` must point to a valid
/// NUL-terminated UTF-8 string for the duration of this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_domain_matcher_builder_add_pattern(
    builder: *mut FfiMatcherBuilder,
    bit_index: usize,
    kind: u32,
    pattern: *const c_char,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null matcher builder")?;
        let kind = ffi_pattern_kind(kind)?;
        let pattern = ffi_str(pattern, "pattern")?.to_owned();
        builder.sets.push(DomainPatternSet {
            bit_index,
            kind,
            patterns: vec![pattern],
        });
        Ok(())
    })
}

/// Builds an indexed matcher from the staged builder.
///
/// # Safety
///
/// `builder` must be a valid builder pointer returned by
/// `dae_domain_matcher_builder_new`. `out_matcher` must be a valid writable
/// pointer to receive the newly allocated matcher handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_domain_matcher_builder_build(
    builder: *const FfiMatcherBuilder,
    out_matcher: *mut *mut FfiMatcher,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_ref() }.ok_or("null matcher builder")?;
        if out_matcher.is_null() {
            return Err("null matcher output pointer".into());
        }
        let matcher = build_indexed_matcher(builder.bit_len, &builder.sets)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_matcher = Box::into_raw(Box::new(FfiMatcher { matcher }));
        }
        Ok(())
    })
}

/// Frees a built matcher.
///
/// # Safety
///
/// `matcher` must be null or a pointer returned through
/// `dae_domain_matcher_builder_build` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_domain_matcher_free(matcher: *mut FfiMatcher) {
    if !matcher.is_null() {
        drop(unsafe { Box::from_raw(matcher) });
    }
}

/// Matches a domain into a caller-owned `u32` bitmap buffer.
///
/// # Safety
///
/// `matcher` must be a valid matcher pointer returned through
/// `dae_domain_matcher_builder_build`. `domain` must point to a valid
/// NUL-terminated UTF-8 string for the duration of this call. `bitmap` must
/// point to `bitmap_len` writable `u32` words.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_domain_matcher_match_into(
    matcher: *const FfiMatcher,
    domain: *const c_char,
    bitmap: *mut u32,
    bitmap_len: usize,
) -> i32 {
    ffi_status(|| {
        let matcher = unsafe { matcher.as_ref() }.ok_or("null matcher")?;
        let domain = ffi_str(domain, "domain")?;
        if bitmap.is_null() {
            return Err("null bitmap".into());
        }
        let bitmap = unsafe { slice::from_raw_parts_mut(bitmap, bitmap_len) };
        let mut keyword_scratch = String::new();
        matcher
            .matcher
            .match_domain_bitmap_into_with_keyword_scratch(domain, bitmap, &mut keyword_scratch)
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    })
}

/// Matches a domain byte slice into a caller-owned `u32` bitmap buffer.
///
/// # Safety
///
/// `matcher` must be a valid matcher pointer returned through
/// `dae_domain_matcher_builder_build`. `domain` must point to `domain_len`
/// readable UTF-8 bytes for the duration of this call. `bitmap` must point to
/// `bitmap_len` writable `u32` words. Rust must not retain either pointer after
/// this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_domain_matcher_match_bytes_into(
    matcher: *const FfiMatcher,
    domain: *const u8,
    domain_len: usize,
    bitmap: *mut u32,
    bitmap_len: usize,
) -> i32 {
    ffi_status(|| {
        let matcher = unsafe { matcher.as_ref() }.ok_or("null matcher")?;
        let domain = ffi_bytes(domain, domain_len, "domain")?;
        if bitmap.is_null() {
            return Err("null bitmap".into());
        }
        let bitmap = unsafe { slice::from_raw_parts_mut(bitmap, bitmap_len) };
        let mut keyword_scratch = String::new();
        matcher
            .matcher
            .match_domain_bitmap_into_with_keyword_scratch(domain, bitmap, &mut keyword_scratch)
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    })
}

pub(crate) fn ffi_status(operation: impl FnOnce() -> Result<(), String>) -> i32 {
    clear_ffi_error();
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => FFI_OK,
        Ok(Err(error)) => {
            set_ffi_error(error);
            FFI_ERROR
        }
        Err(_) => {
            set_ffi_error("panic across domain matcher FFI boundary");
            FFI_ERROR
        }
    }
}

pub(crate) fn clear_ffi_error() {
    LAST_FFI_ERROR.with(|last_error| {
        *last_error.borrow_mut() = None;
    });
}

pub(crate) fn set_ffi_error(error: impl Into<String>) {
    let mut error = error.into();
    error.retain(|ch| ch != '\0');
    LAST_FFI_ERROR.with(|last_error| {
        *last_error.borrow_mut() =
            Some(CString::new(error).expect("error string was stripped of NUL bytes"));
    });
}

pub(crate) fn ffi_pattern_kind(kind: u32) -> Result<DomainPatternKind, String> {
    match kind {
        0 => Ok(DomainPatternKind::Full),
        1 => Ok(DomainPatternKind::Suffix),
        2 => Ok(DomainPatternKind::Keyword),
        3 => Ok(DomainPatternKind::Regex),
        _ => Err(format!("unknown domain pattern kind: {kind}")),
    }
}

pub(crate) fn ffi_str<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("null {name}"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|error| format!("invalid UTF-8 {name}: {error}"))
}

pub(crate) fn ffi_bytes<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a str, String> {
    if len == 0 {
        return Ok("");
    }
    if ptr.is_null() {
        return Err(format!("null {name}"));
    }
    std::str::from_utf8(unsafe { slice::from_raw_parts(ptr, len) })
        .map_err(|error| format!("invalid UTF-8 {name}: {error}"))
}

#[cfg(test)]
fn live_go_fixture_sets() -> Vec<DomainPatternSet> {
    vec![
        DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Suffix,
            patterns: vec!["test-ipv6.com".into()],
        },
        DomainPatternSet {
            bit_index: 1,
            kind: DomainPatternKind::Full,
            patterns: vec!["dns.google".into()],
        },
        DomainPatternSet {
            bit_index: 2,
            kind: DomainPatternKind::Full,
            patterns: vec!["_https._tcp.mirrors.ustc.edu.cn".into()],
        },
        DomainPatternSet {
            bit_index: 3,
            kind: DomainPatternKind::Keyword,
            patterns: vec!["ads".into()],
        },
        DomainPatternSet {
            bit_index: 4,
            kind: DomainPatternKind::Regex,
            patterns: vec![r"^img.*\.csdn\.net$".into()],
        },
    ]
}

#[cfg(test)]
fn live_go_fixture_cases() -> Vec<(&'static str, Vec<u32>)> {
    vec![
        ("ipv4.master.test-ipv6.com", vec![0b00001]),
        ("dns.google.", vec![0b00010]),
        ("_https._tcp.mirrors.ustc.edu.cn", vec![0b00100]),
        ("ads.trafficjunky.net", vec![0b01000]),
        ("img-bss.csdn.net", vec![0b10000]),
        ("example.org", vec![0]),
    ]
}

#[cfg(test)]
mod tests {
    use super::{
        DomainPatternKind, DomainPatternSet, MatchError, bitmap_words, build_indexed_matcher,
        build_reference_matcher, is_valid_domain_pattern_char, live_go_fixture_cases,
        live_go_fixture_sets, match_domain_bitmap, normalize_domain, normalize_domain_cow,
    };
    use std::borrow::Cow;

    #[test]
    fn normalize_domain_lowercases_ascii() {
        assert_eq!(normalize_domain("Example.COM"), "example.com");
    }

    #[test]
    fn normalize_domain_trims_trailing_dot() {
        assert_eq!(normalize_domain("example.com."), "example.com");
    }

    #[test]
    fn normalize_domain_trims_multiple_trailing_dots() {
        assert_eq!(normalize_domain("example.com..."), "example.com");
    }

    #[test]
    fn normalize_domain_keeps_inner_content() {
        assert_eq!(normalize_domain("a.B-c.example"), "a.b-c.example");
    }

    #[test]
    fn normalize_domain_cow_borrows_when_input_is_already_normalized() {
        let normalized = normalize_domain_cow("example.com");
        assert!(matches!(normalized, Cow::Borrowed("example.com")));
    }

    #[test]
    fn normalize_domain_cow_borrows_trimmed_subslice_without_allocation() {
        let normalized = normalize_domain_cow("example.com.");
        assert!(matches!(normalized, Cow::Borrowed("example.com")));
    }

    #[test]
    fn normalize_domain_cow_allocates_when_ascii_lowercasing_is_required() {
        let normalized = normalize_domain_cow("Example.COM.");
        assert!(matches!(normalized, Cow::Owned(_)));
        assert_eq!(normalized.as_ref(), "example.com");
    }

    #[test]
    fn bitmap_words_round_up() {
        assert_eq!(bitmap_words(0), 0);
        assert_eq!(bitmap_words(1), 1);
        assert_eq!(bitmap_words(32), 1);
        assert_eq!(bitmap_words(33), 2);
    }

    #[test]
    fn match_domain_bitmap_matches_full_suffix_and_keyword() {
        let sets = vec![
            DomainPatternSet {
                bit_index: 0,
                kind: DomainPatternKind::Full,
                patterns: vec!["example.com".into()],
            },
            DomainPatternSet {
                bit_index: 1,
                kind: DomainPatternKind::Suffix,
                patterns: vec!["example.com".into()],
            },
            DomainPatternSet {
                bit_index: 2,
                kind: DomainPatternKind::Keyword,
                patterns: vec!["ample".into()],
            },
        ];

        let bitmap = match_domain_bitmap("Example.COM.", 8, &sets).unwrap();
        assert_eq!(bitmap, vec![0b111]);
    }

    #[test]
    fn suffix_pattern_with_leading_dot_requires_subdomain() {
        let sets = vec![DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Suffix,
            patterns: vec![".example.com".into()],
        }];

        let exact = match_domain_bitmap("example.com", 1, &sets).unwrap();
        let sub = match_domain_bitmap("api.example.com", 1, &sets).unwrap();

        assert_eq!(exact, vec![0]);
        assert_eq!(sub, vec![1]);
    }

    #[test]
    fn bitmap_can_set_bits_beyond_first_word() {
        let sets = vec![DomainPatternSet {
            bit_index: 33,
            kind: DomainPatternKind::Keyword,
            patterns: vec!["example".into()],
        }];

        let bitmap = match_domain_bitmap("example.com", 64, &sets).unwrap();
        assert_eq!(bitmap.len(), 2);
        assert_eq!(bitmap[0], 0);
        assert_eq!(bitmap[1], 0b10);
    }

    #[test]
    fn keyword_matching_uses_go_magic_domain_boundaries() {
        let sets = vec![
            DomainPatternSet {
                bit_index: 0,
                kind: DomainPatternKind::Keyword,
                patterns: vec!["^example".into()],
            },
            DomainPatternSet {
                bit_index: 1,
                kind: DomainPatternKind::Keyword,
                patterns: vec!["com$".into()],
            },
        ];

        let reference = build_reference_matcher(8, &sets).unwrap();
        let indexed = build_indexed_matcher(8, &sets).unwrap();

        assert_eq!(
            reference.match_domain_bitmap("example.com").unwrap(),
            vec![0b11]
        );
        assert_eq!(
            indexed.match_domain_bitmap("example.com").unwrap(),
            vec![0b11]
        );
    }

    #[test]
    fn match_domain_bitmap_into_reuses_caller_buffer() {
        let matcher = build_reference_matcher(
            64,
            &[DomainPatternSet {
                bit_index: 33,
                kind: DomainPatternKind::Keyword,
                patterns: vec!["example".into()],
            }],
        )
        .unwrap();
        let mut bitmap = vec![u32::MAX; 2];

        matcher
            .match_domain_bitmap_into("example.com", &mut bitmap)
            .unwrap();
        assert_eq!(bitmap, vec![0, 0b10]);

        matcher
            .match_domain_bitmap_into("miss.test", &mut bitmap)
            .unwrap();
        assert_eq!(bitmap, vec![0, 0]);
    }

    #[test]
    fn match_domain_bitmap_into_rejects_wrong_buffer_size() {
        let matcher = build_reference_matcher(
            33,
            &[DomainPatternSet {
                bit_index: 32,
                kind: DomainPatternKind::Keyword,
                patterns: vec!["example".into()],
            }],
        )
        .unwrap();
        let mut bitmap = vec![0; 1];

        let err = matcher
            .match_domain_bitmap_into("example.com", &mut bitmap)
            .unwrap_err();
        assert_eq!(
            err,
            MatchError::BitmapWordLenMismatch {
                actual: 1,
                expected: 2,
            }
        );
    }

    #[test]
    fn out_of_range_bit_index_returns_error() {
        let sets = vec![DomainPatternSet {
            bit_index: 4,
            kind: DomainPatternKind::Full,
            patterns: vec!["example.com".into()],
        }];

        let err = match_domain_bitmap("example.com", 4, &sets).unwrap_err();
        assert_eq!(
            err,
            MatchError::BitIndexOutOfRange {
                bit_index: 4,
                bit_len: 4,
            }
        );
    }

    #[test]
    fn regex_matches_normalized_domain() {
        let sets = vec![DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Regex,
            patterns: vec!["^api\\..*\\.example\\.com$".into()],
        }];

        let bitmap = match_domain_bitmap("API.Test.Example.Com.", 1, &sets).unwrap();
        assert_eq!(bitmap, vec![1]);
    }

    #[test]
    fn invalid_regex_returns_error() {
        let sets = vec![DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Regex,
            patterns: vec!["(".into()],
        }];

        let err = match_domain_bitmap("example.com", 1, &sets).unwrap_err();
        match err {
            MatchError::InvalidRegex { pattern, .. } => assert_eq!(pattern, "("),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn invalid_full_and_suffix_patterns_are_skipped_during_build() {
        let matcher = build_reference_matcher(
            2,
            &[
                DomainPatternSet {
                    bit_index: 0,
                    kind: DomainPatternKind::Full,
                    patterns: vec!["exa mple.com".into()],
                },
                DomainPatternSet {
                    bit_index: 1,
                    kind: DomainPatternKind::Suffix,
                    patterns: vec!["exa%mple.com".into()],
                },
            ],
        )
        .unwrap();

        let bitmap = matcher.match_domain_bitmap("example.com").unwrap();
        assert_eq!(bitmap, vec![0]);
    }

    #[test]
    fn valid_domain_pattern_chars_match_live_go_constraints() {
        for ch in b"0123456789abcdefghijklmnopqrstuvwxyz-.^_" {
            assert!(
                is_valid_domain_pattern_char(*ch),
                "expected valid char: {ch}"
            );
        }
        for ch in b" !@#$%&*()+={}[]|\\:;\"'<>,?/" {
            assert!(
                !is_valid_domain_pattern_char(*ch),
                "expected invalid char: {ch}"
            );
        }
    }

    #[test]
    fn live_go_fixture_cases_match_expected_bitmaps() {
        let matcher = build_reference_matcher(8, &live_go_fixture_sets()).unwrap();
        for (domain, expected) in live_go_fixture_cases() {
            let bitmap = matcher.match_domain_bitmap(domain).unwrap();
            assert_eq!(bitmap, expected, "domain: {domain}");
        }
    }

    #[test]
    fn indexed_matcher_matches_reference_for_mixed_patterns() {
        let sets = vec![
            DomainPatternSet {
                bit_index: 0,
                kind: DomainPatternKind::Full,
                patterns: vec!["example.com".into()],
            },
            DomainPatternSet {
                bit_index: 1,
                kind: DomainPatternKind::Suffix,
                patterns: vec!["example.net".into()],
            },
            DomainPatternSet {
                bit_index: 2,
                kind: DomainPatternKind::Suffix,
                patterns: vec![".sub.example.org".into()],
            },
            DomainPatternSet {
                bit_index: 3,
                kind: DomainPatternKind::Keyword,
                patterns: vec!["cdn".into()],
            },
            DomainPatternSet {
                bit_index: 35,
                kind: DomainPatternKind::Regex,
                patterns: vec![r"^img[0-9]+\.example\.io$".into()],
            },
        ];
        let reference = build_reference_matcher(64, &sets).unwrap();
        let indexed = build_indexed_matcher(64, &sets).unwrap();

        for domain in [
            "EXAMPLE.com.",
            "api.example.net",
            "example.net",
            "sub.example.org",
            "api.sub.example.org",
            "static-cdn.example.invalid",
            "img42.example.io",
            "miss.example.invalid",
        ] {
            assert_eq!(
                indexed.match_domain_bitmap(domain).unwrap(),
                reference.match_domain_bitmap(domain).unwrap(),
                "domain: {domain}",
            );
        }
    }

    #[test]
    fn indexed_matcher_reuses_caller_bitmap() {
        let matcher = build_indexed_matcher(
            64,
            &[DomainPatternSet {
                bit_index: 33,
                kind: DomainPatternKind::Suffix,
                patterns: vec!["example.com".into()],
            }],
        )
        .unwrap();
        let mut bitmap = vec![u32::MAX; 2];

        matcher
            .match_domain_bitmap_into("api.example.com", &mut bitmap)
            .unwrap();
        assert_eq!(bitmap, vec![0, 0b10]);

        matcher
            .match_domain_bitmap_into("miss.example.net", &mut bitmap)
            .unwrap();
        assert_eq!(bitmap, vec![0, 0]);
    }

    #[test]
    fn indexed_matcher_reuses_keyword_scratch_buffer() {
        let matcher = build_indexed_matcher(
            8,
            &[
                DomainPatternSet {
                    bit_index: 0,
                    kind: DomainPatternKind::Keyword,
                    patterns: vec!["^example".into()],
                },
                DomainPatternSet {
                    bit_index: 1,
                    kind: DomainPatternKind::Keyword,
                    patterns: vec!["com$".into()],
                },
            ],
        )
        .unwrap();
        let mut bitmap = vec![u32::MAX; 1];
        let mut scratch = String::from("stale-buffer-content");

        matcher
            .match_domain_bitmap_into_with_keyword_scratch(
                "EXAMPLE.com.",
                &mut bitmap,
                &mut scratch,
            )
            .unwrap();

        assert_eq!(bitmap, vec![0b11]);
        assert_eq!(scratch, "^example.com$");
    }

    #[test]
    fn indexed_matcher_matches_live_fixture_cases() {
        let matcher = build_indexed_matcher(8, &live_go_fixture_sets()).unwrap();
        for (domain, expected) in live_go_fixture_cases() {
            let bitmap = matcher.match_domain_bitmap(domain).unwrap();
            assert_eq!(bitmap, expected, "domain: {domain}");
        }
    }
}
