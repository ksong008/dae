use crate::{
    DomainPatternSet, IndexedMatcher, bitmap_words, build_indexed_matcher, ffi_bytes,
    ffi_pattern_kind, ffi_status, ffi_str,
};
use smallvec::SmallVec;
use std::ffi::c_char;
use std::slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRequestAction {
    UserDefined(u8),
    Reject,
    AsIs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequestCondition {
    DomainBit {
        bit_index: usize,
        not: bool,
    },
    QTypeAny {
        values: SmallVec<[u16; 4]>,
        not: bool,
    },
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRequestRule {
    pub conditions: Vec<DnsRequestCondition>,
    pub action: DnsRequestAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequestMatchError {
    EmptyRule,
    DomainBitOutOfRange {
        bit_index: usize,
        bitmap_words: usize,
    },
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsRequestRuntimeError {
    DomainMatch(crate::MatchError),
    Rule(DnsRequestMatchError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseAction {
    UserDefined(u8),
    Accept,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResponseCondition {
    DomainBit {
        bit_index: usize,
        not: bool,
    },
    QTypeAny {
        values: SmallVec<[u16; 4]>,
        not: bool,
    },
    UpstreamAny {
        values: SmallVec<[i16; 4]>,
        not: bool,
    },
    AnyIpInSet {
        set_index: usize,
        not: bool,
    },
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponseRule {
    pub conditions: Vec<DnsResponseCondition>,
    pub action: DnsResponseAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResponseMatchError {
    EmptyRule,
    DomainBitOutOfRange {
        bit_index: usize,
        bitmap_words: usize,
    },
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsResponseRuntimeError {
    DomainMatch(crate::MatchError),
    Rule(DnsResponseMatchError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    addr: [u8; 16],
    bits: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpPrefixSet {
    pub(crate) prefixes: Vec<IpPrefix>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainMatchScratch {
    pub(crate) bitmap: Vec<u32>,
    pub(crate) keyword_scratch: String,
}

#[derive(Debug)]
pub struct DnsRequestMatcher {
    bitmap_words: usize,
    matcher: IndexedMatcher,
    rules: Vec<DnsRequestRule>,
}

#[derive(Debug)]
pub struct DnsResponseMatcher {
    bitmap_words: usize,
    matcher: IndexedMatcher,
    ip_sets: Vec<IpPrefixSet>,
    rules: Vec<DnsResponseRule>,
}

#[derive(Debug)]
pub struct DnsRouting {
    request: DnsRequestMatcher,
    response: DnsResponseMatcher,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsRequestLookup {
    pub qtype: u16,
    pub action: DnsRequestAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsRequestPlan {
    pub requested: DnsRequestLookup,
    pub preferred: Option<DnsRequestLookup>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResponseDecision {
    Accept,
    Reject,
    Retry { action: DnsResponseAction },
}

pub struct FfiDnsRequestMatcherBuilder {
    bit_len: usize,
    domain_sets: Vec<DomainPatternSet>,
    rules: Vec<DnsRequestRule>,
}

pub struct FfiDnsRequestMatcher {
    matcher: DnsRequestMatcher,
}

pub struct FfiDnsResponseMatcherBuilder {
    bit_len: usize,
    domain_sets: Vec<DomainPatternSet>,
    ip_sets: Vec<IpPrefixSet>,
    rules: Vec<DnsResponseRule>,
}

pub struct FfiDnsResponseMatcher {
    matcher: DnsResponseMatcher,
}

pub struct FfiDnsRouting {
    routing: DnsRouting,
}

impl DomainMatchScratch {
    pub(crate) fn prepare(&mut self, bitmap_words: usize) {
        if self.bitmap.len() != bitmap_words {
            self.bitmap.resize(bitmap_words, 0);
        } else {
            self.bitmap.fill(0);
        }
    }
}

impl DnsRequestMatcher {
    pub fn build(
        bit_len: usize,
        domain_sets: &[DomainPatternSet],
        rules: Vec<DnsRequestRule>,
    ) -> Result<Self, crate::MatchError> {
        Ok(Self {
            bitmap_words: bitmap_words(bit_len),
            matcher: build_indexed_matcher(bit_len, domain_sets)?,
            rules,
        })
    }

    pub fn match_qname(
        &self,
        qname: &str,
        qtype: u16,
    ) -> Result<DnsRequestAction, DnsRequestRuntimeError> {
        let mut scratch = DomainMatchScratch::default();
        self.match_qname_with_scratch(qname, qtype, &mut scratch)
    }

    pub fn match_qname_with_scratch(
        &self,
        qname: &str,
        qtype: u16,
        scratch: &mut DomainMatchScratch,
    ) -> Result<DnsRequestAction, DnsRequestRuntimeError> {
        let domain_bitmap = if qname.is_empty() {
            None
        } else {
            scratch.prepare(self.bitmap_words);
            self.matcher
                .match_domain_bitmap_into_with_keyword_scratch(
                    qname,
                    &mut scratch.bitmap,
                    &mut scratch.keyword_scratch,
                )
                .map_err(DnsRequestRuntimeError::DomainMatch)?;
            Some(scratch.bitmap.as_slice())
        };
        match_dns_request_rules(&self.rules, qtype, domain_bitmap)
            .map_err(DnsRequestRuntimeError::Rule)
    }
}

impl DnsResponseMatcher {
    pub fn build(
        bit_len: usize,
        domain_sets: &[DomainPatternSet],
        ip_sets: Vec<IpPrefixSet>,
        rules: Vec<DnsResponseRule>,
    ) -> Result<Self, crate::MatchError> {
        Ok(Self {
            bitmap_words: bitmap_words(bit_len),
            matcher: build_indexed_matcher(bit_len, domain_sets)?,
            ip_sets,
            rules,
        })
    }

    pub fn match_response(
        &self,
        qname: &str,
        qtype: u16,
        request_upstream: i16,
        ips: &[[u8; 16]],
        ip_set_match: impl Fn(usize) -> bool,
    ) -> Result<DnsResponseAction, DnsResponseRuntimeError> {
        let mut scratch = DomainMatchScratch::default();
        self.match_response_with_scratch(
            qname,
            qtype,
            request_upstream,
            ips,
            &mut scratch,
            ip_set_match,
        )
    }

    pub fn match_response_with_scratch(
        &self,
        qname: &str,
        qtype: u16,
        request_upstream: i16,
        ips: &[[u8; 16]],
        scratch: &mut DomainMatchScratch,
        ip_set_match: impl Fn(usize) -> bool,
    ) -> Result<DnsResponseAction, DnsResponseRuntimeError> {
        let domain_bitmap = if qname.is_empty() {
            None
        } else {
            scratch.prepare(self.bitmap_words);
            self.matcher
                .match_domain_bitmap_into_with_keyword_scratch(
                    qname,
                    &mut scratch.bitmap,
                    &mut scratch.keyword_scratch,
                )
                .map_err(DnsResponseRuntimeError::DomainMatch)?;
            Some(scratch.bitmap.as_slice())
        };
        match_dns_response_rules(
            &self.rules,
            qtype,
            request_upstream,
            domain_bitmap,
            |set_index| {
                ip_set_match(set_index)
                    || self
                        .ip_sets
                        .get(set_index)
                        .is_some_and(|set| set.matches_any(ips))
            },
        )
        .map_err(DnsResponseRuntimeError::Rule)
    }
}

impl DnsRouting {
    pub fn new(request: DnsRequestMatcher, response: DnsResponseMatcher) -> Self {
        Self { request, response }
    }

    pub fn match_request(
        &self,
        qname: &str,
        qtype: u16,
    ) -> Result<DnsRequestAction, DnsRequestRuntimeError> {
        self.request.match_qname(qname, qtype)
    }

    pub fn plan_request(
        &self,
        qname: &str,
        qtype: u16,
        preferred_qtype: u16,
    ) -> Result<DnsRequestPlan, DnsRequestRuntimeError> {
        let requested = DnsRequestLookup {
            qtype,
            action: self.match_request(qname, qtype)?,
        };
        let preferred = preferred_lookup_qtype(qtype, preferred_qtype)
            .map(|qtype| {
                self.match_request(qname, qtype)
                    .map(|action| DnsRequestLookup { qtype, action })
            })
            .transpose()?;
        Ok(DnsRequestPlan {
            requested,
            preferred,
        })
    }

    pub fn match_response(
        &self,
        qname: &str,
        qtype: u16,
        request_upstream: i16,
        ips: &[[u8; 16]],
    ) -> Result<DnsResponseAction, DnsResponseRuntimeError> {
        self.response
            .match_response(qname, qtype, request_upstream, ips, |_| false)
    }

    pub fn plan_response(
        &self,
        qname: &str,
        qtype: u16,
        request_upstream: i16,
        ips: &[[u8; 16]],
    ) -> Result<DnsResponseDecision, DnsResponseRuntimeError> {
        let action = self.match_response(qname, qtype, request_upstream, ips)?;
        Ok(match action {
            DnsResponseAction::Accept => DnsResponseDecision::Accept,
            DnsResponseAction::Reject => DnsResponseDecision::Reject,
            DnsResponseAction::UserDefined(value) => DnsResponseDecision::Retry {
                action: DnsResponseAction::UserDefined(value),
            },
        })
    }
}

fn preferred_lookup_qtype(qtype: u16, preferred_qtype: u16) -> Option<u16> {
    const QTYPE_A: u16 = 1;
    const QTYPE_AAAA: u16 = 28;

    if preferred_qtype == 0 || preferred_qtype == qtype {
        return None;
    }
    match qtype {
        QTYPE_A | QTYPE_AAAA => match preferred_qtype {
            QTYPE_A | QTYPE_AAAA => Some(preferred_qtype),
            _ => None,
        },
        _ => None,
    }
}

pub fn match_dns_request_rules(
    rules: &[DnsRequestRule],
    qtype: u16,
    domain_bitmap: Option<&[u32]>,
) -> Result<DnsRequestAction, DnsRequestMatchError> {
    for rule in rules {
        if rule.conditions.is_empty() {
            return Err(DnsRequestMatchError::EmptyRule);
        }
        let mut matched = true;
        for condition in &rule.conditions {
            if !condition_matches(condition, qtype, domain_bitmap)? {
                matched = false;
                break;
            }
        }
        if matched {
            return Ok(rule.action);
        }
    }
    Err(DnsRequestMatchError::NoMatch)
}

fn condition_matches(
    condition: &DnsRequestCondition,
    qtype: u16,
    domain_bitmap: Option<&[u32]>,
) -> Result<bool, DnsRequestMatchError> {
    match condition {
        DnsRequestCondition::DomainBit { bit_index, not } => {
            let matched = domain_bitmap
                .map(|bitmap| domain_bitmap_has_bit(bitmap, *bit_index))
                .transpose()?
                .unwrap_or(false);
            Ok(matched != *not)
        }
        DnsRequestCondition::QTypeAny { values, not } => {
            let matched = values.contains(&qtype);
            Ok(matched != *not)
        }
        DnsRequestCondition::Fallback => Ok(true),
    }
}

fn domain_bitmap_has_bit(bitmap: &[u32], bit_index: usize) -> Result<bool, DnsRequestMatchError> {
    let word_index = bit_index / 32;
    let Some(word) = bitmap.get(word_index) else {
        return Err(DnsRequestMatchError::DomainBitOutOfRange {
            bit_index,
            bitmap_words: bitmap.len(),
        });
    };
    Ok(((word >> (bit_index % 32)) & 1) != 0)
}

#[unsafe(no_mangle)]
pub extern "C" fn dae_dns_request_matcher_builder_new(
    bit_len: usize,
) -> *mut FfiDnsRequestMatcherBuilder {
    Box::into_raw(Box::new(FfiDnsRequestMatcherBuilder {
        bit_len,
        domain_sets: Vec::new(),
        rules: Vec::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_builder_free(
    builder: *mut FfiDnsRequestMatcherBuilder,
) {
    if !builder.is_null() {
        drop(unsafe { Box::from_raw(builder) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_builder_add_domain_pattern(
    builder: *mut FfiDnsRequestMatcherBuilder,
    bit_index: usize,
    kind: u32,
    pattern: *const c_char,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns request matcher builder")?;
        let kind = ffi_pattern_kind(kind)?;
        let pattern = ffi_str(pattern, "pattern")?.to_owned();
        builder.domain_sets.push(DomainPatternSet {
            bit_index,
            kind,
            patterns: vec![pattern],
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_builder_add_rule(
    builder: *mut FfiDnsRequestMatcherBuilder,
    action: i16,
    out_rule_index: *mut usize,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns request matcher builder")?;
        if out_rule_index.is_null() {
            return Err("null dns request matcher rule index output".into());
        }
        let rule_index = builder.rules.len();
        builder.rules.push(DnsRequestRule {
            conditions: Vec::new(),
            action: dns_request_action_from_i16(action)?,
        });
        unsafe {
            *out_rule_index = rule_index;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_builder_add_rule_domain_bit(
    builder: *mut FfiDnsRequestMatcherBuilder,
    rule_index: usize,
    bit_index: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns request matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns request matcher rule index out of range: {rule_index}"))?;
        rule.conditions
            .push(DnsRequestCondition::DomainBit { bit_index, not });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_builder_add_rule_qtypes(
    builder: *mut FfiDnsRequestMatcherBuilder,
    rule_index: usize,
    values: *const u16,
    values_len: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns request matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns request matcher rule index out of range: {rule_index}"))?;
        if values_len == 0 {
            return Err("dns request matcher qtype set cannot be empty".into());
        }
        if values.is_null() {
            return Err("null dns request matcher qtype values".into());
        }
        let values = unsafe { slice::from_raw_parts(values, values_len) };
        rule.conditions.push(DnsRequestCondition::QTypeAny {
            values: SmallVec::from_slice(values),
            not,
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_builder_add_rule_fallback(
    builder: *mut FfiDnsRequestMatcherBuilder,
    rule_index: usize,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns request matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns request matcher rule index out of range: {rule_index}"))?;
        rule.conditions.push(DnsRequestCondition::Fallback);
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_builder_build(
    builder: *const FfiDnsRequestMatcherBuilder,
    out_matcher: *mut *mut FfiDnsRequestMatcher,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_ref() }.ok_or("null dns request matcher builder")?;
        if out_matcher.is_null() {
            return Err("null dns request matcher output pointer".into());
        }
        let matcher =
            DnsRequestMatcher::build(builder.bit_len, &builder.domain_sets, builder.rules.clone())
                .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_matcher = Box::into_raw(Box::new(FfiDnsRequestMatcher { matcher }));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_free(matcher: *mut FfiDnsRequestMatcher) {
    if !matcher.is_null() {
        drop(unsafe { Box::from_raw(matcher) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_request_matcher_match_bytes(
    matcher: *const FfiDnsRequestMatcher,
    qname: *const u8,
    qname_len: usize,
    qtype: u16,
    out_action: *mut i16,
) -> i32 {
    ffi_status(|| {
        let matcher = unsafe { matcher.as_ref() }.ok_or("null dns request matcher")?;
        if out_action.is_null() {
            return Err("null dns request matcher action output".into());
        }
        let qname = ffi_bytes(qname, qname_len, "qname")?;
        let action = matcher
            .matcher
            .match_qname(qname, qtype)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_action = dns_request_action_to_i16(action);
        }
        Ok(())
    })
}

fn dns_request_action_from_i16(action: i16) -> Result<DnsRequestAction, String> {
    match action {
        0..=251 => Ok(DnsRequestAction::UserDefined(action as u8)),
        0xFC => Ok(DnsRequestAction::Reject),
        0xFD => Ok(DnsRequestAction::AsIs),
        _ => Err(format!("unsupported dns request action: {action}")),
    }
}

fn dns_request_action_to_i16(action: DnsRequestAction) -> i16 {
    match action {
        DnsRequestAction::UserDefined(value) => i16::from(value),
        DnsRequestAction::Reject => 0xFC,
        DnsRequestAction::AsIs => 0xFD,
    }
}

fn dns_response_action_from_i16(action: i16) -> Result<DnsResponseAction, String> {
    match action {
        0..=251 => Ok(DnsResponseAction::UserDefined(action as u8)),
        0xFC => Ok(DnsResponseAction::Accept),
        0xFD => Ok(DnsResponseAction::Reject),
        _ => Err(format!("unsupported dns response action: {action}")),
    }
}

fn dns_response_action_to_i16(action: DnsResponseAction) -> i16 {
    match action {
        DnsResponseAction::UserDefined(value) => i16::from(value),
        DnsResponseAction::Accept => 0xFC,
        DnsResponseAction::Reject => 0xFD,
    }
}

pub fn match_dns_response_rules(
    rules: &[DnsResponseRule],
    qtype: u16,
    request_upstream: i16,
    domain_bitmap: Option<&[u32]>,
    ip_set_match: impl Fn(usize) -> bool,
) -> Result<DnsResponseAction, DnsResponseMatchError> {
    for rule in rules {
        if rule.conditions.is_empty() {
            return Err(DnsResponseMatchError::EmptyRule);
        }
        let mut matched = true;
        for condition in &rule.conditions {
            if !response_condition_matches(
                condition,
                qtype,
                request_upstream,
                domain_bitmap,
                &ip_set_match,
            )? {
                matched = false;
                break;
            }
        }
        if matched {
            return Ok(rule.action);
        }
    }
    Err(DnsResponseMatchError::NoMatch)
}

impl IpPrefixSet {
    pub fn from_prefixes(prefixes: Vec<IpPrefix>) -> Self {
        Self { prefixes }
    }

    pub(crate) fn matches_any(&self, ips: &[[u8; 16]]) -> bool {
        ips.iter().any(|ip| self.matches(*ip))
    }

    pub(crate) fn matches(&self, ip: [u8; 16]) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| prefix_matches(ip, *prefix))
    }
}

impl IpPrefix {
    pub fn new(addr: [u8; 16], bits: u8) -> Self {
        Self { addr, bits }
    }
}

fn prefix_matches(ip: [u8; 16], prefix: IpPrefix) -> bool {
    let full_bytes = usize::from(prefix.bits / 8);
    let remaining_bits = prefix.bits % 8;
    if ip[..full_bytes] != prefix.addr[..full_bytes] {
        return false;
    }
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - remaining_bits);
    (ip[full_bytes] & mask) == (prefix.addr[full_bytes] & mask)
}

#[unsafe(no_mangle)]
pub extern "C" fn dae_dns_response_matcher_builder_new(
    bit_len: usize,
) -> *mut FfiDnsResponseMatcherBuilder {
    Box::into_raw(Box::new(FfiDnsResponseMatcherBuilder {
        bit_len,
        domain_sets: Vec::new(),
        ip_sets: Vec::new(),
        rules: Vec::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_free(
    builder: *mut FfiDnsResponseMatcherBuilder,
) {
    if !builder.is_null() {
        drop(unsafe { Box::from_raw(builder) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_domain_pattern(
    builder: *mut FfiDnsResponseMatcherBuilder,
    bit_index: usize,
    kind: u32,
    pattern: *const c_char,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        let kind = ffi_pattern_kind(kind)?;
        let pattern = ffi_str(pattern, "pattern")?.to_owned();
        builder.domain_sets.push(DomainPatternSet {
            bit_index,
            kind,
            patterns: vec![pattern],
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_rule(
    builder: *mut FfiDnsResponseMatcherBuilder,
    action: i16,
    out_rule_index: *mut usize,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        if out_rule_index.is_null() {
            return Err("null dns response matcher rule index output".into());
        }
        let rule_index = builder.rules.len();
        builder.rules.push(DnsResponseRule {
            conditions: Vec::new(),
            action: dns_response_action_from_i16(action)?,
        });
        unsafe {
            *out_rule_index = rule_index;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_rule_domain_bit(
    builder: *mut FfiDnsResponseMatcherBuilder,
    rule_index: usize,
    bit_index: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns response matcher rule index out of range: {rule_index}"))?;
        rule.conditions
            .push(DnsResponseCondition::DomainBit { bit_index, not });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_rule_qtypes(
    builder: *mut FfiDnsResponseMatcherBuilder,
    rule_index: usize,
    values: *const u16,
    values_len: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns response matcher rule index out of range: {rule_index}"))?;
        if values_len == 0 {
            return Err("dns response matcher qtype set cannot be empty".into());
        }
        if values.is_null() {
            return Err("null dns response matcher qtype values".into());
        }
        let values = unsafe { slice::from_raw_parts(values, values_len) };
        rule.conditions.push(DnsResponseCondition::QTypeAny {
            values: SmallVec::from_slice(values),
            not,
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_rule_upstreams(
    builder: *mut FfiDnsResponseMatcherBuilder,
    rule_index: usize,
    values: *const i16,
    values_len: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns response matcher rule index out of range: {rule_index}"))?;
        if values_len == 0 {
            return Err("dns response matcher upstream set cannot be empty".into());
        }
        if values.is_null() {
            return Err("null dns response matcher upstream values".into());
        }
        let values = unsafe { slice::from_raw_parts(values, values_len) };
        rule.conditions.push(DnsResponseCondition::UpstreamAny {
            values: SmallVec::from_slice(values),
            not,
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_rule_ip_set(
    builder: *mut FfiDnsResponseMatcherBuilder,
    rule_index: usize,
    set_index: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns response matcher rule index out of range: {rule_index}"))?;
        rule.conditions
            .push(DnsResponseCondition::AnyIpInSet { set_index, not });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_rule_fallback(
    builder: *mut FfiDnsResponseMatcherBuilder,
    rule_index: usize,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        let rule = builder
            .rules
            .get_mut(rule_index)
            .ok_or_else(|| format!("dns response matcher rule index out of range: {rule_index}"))?;
        rule.conditions.push(DnsResponseCondition::Fallback);
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_add_ip_prefix(
    builder: *mut FfiDnsResponseMatcherBuilder,
    set_index: usize,
    addr: *const u8,
    addr_len: usize,
    prefix_bits: u8,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_mut() }.ok_or("null dns response matcher builder")?;
        if addr_len != 16 {
            return Err(format!(
                "dns response matcher ip prefix addr len={addr_len}, want 16"
            ));
        }
        if addr.is_null() {
            return Err("null dns response matcher ip prefix addr".into());
        }
        if builder.ip_sets.len() <= set_index {
            builder
                .ip_sets
                .resize_with(set_index + 1, IpPrefixSet::default);
        }
        let mut encoded = [0u8; 16];
        encoded.copy_from_slice(unsafe { slice::from_raw_parts(addr, addr_len) });
        builder.ip_sets[set_index].prefixes.push(IpPrefix {
            addr: encoded,
            bits: prefix_bits,
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_builder_build(
    builder: *const FfiDnsResponseMatcherBuilder,
    out_matcher: *mut *mut FfiDnsResponseMatcher,
) -> i32 {
    ffi_status(|| {
        let builder = unsafe { builder.as_ref() }.ok_or("null dns response matcher builder")?;
        if out_matcher.is_null() {
            return Err("null dns response matcher output pointer".into());
        }
        let matcher = DnsResponseMatcher::build(
            builder.bit_len,
            &builder.domain_sets,
            builder.ip_sets.clone(),
            builder.rules.clone(),
        )
        .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_matcher = Box::into_raw(Box::new(FfiDnsResponseMatcher { matcher }));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_free(matcher: *mut FfiDnsResponseMatcher) {
    if !matcher.is_null() {
        drop(unsafe { Box::from_raw(matcher) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_response_matcher_match_bytes(
    matcher: *const FfiDnsResponseMatcher,
    qname: *const u8,
    qname_len: usize,
    qtype: u16,
    request_upstream: i16,
    ips: *const u8,
    ips_len: usize,
    out_action: *mut i16,
) -> i32 {
    ffi_status(|| {
        let matcher = unsafe { matcher.as_ref() }.ok_or("null dns response matcher")?;
        if out_action.is_null() {
            return Err("null dns response matcher action output".into());
        }
        let qname = ffi_bytes(qname, qname_len, "qname")?;
        if !ips_len.is_multiple_of(16) {
            return Err(format!(
                "dns response matcher ip bytes len={ips_len}, want multiple of 16"
            ));
        }
        let ips = if ips_len == 0 {
            &[][..]
        } else {
            if ips.is_null() {
                return Err("null dns response matcher ips".into());
            }
            unsafe { slice::from_raw_parts(ips.cast::<[u8; 16]>(), ips_len / 16) }
        };
        let action = matcher
            .matcher
            .match_response(qname, qtype, request_upstream, ips, |_| false)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_action = dns_response_action_to_i16(action);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_routing_new(
    request_matcher: *mut FfiDnsRequestMatcher,
    response_matcher: *mut FfiDnsResponseMatcher,
    out_routing: *mut *mut FfiDnsRouting,
) -> i32 {
    ffi_status(|| {
        if request_matcher.is_null() {
            return Err("null dns request matcher".into());
        }
        if response_matcher.is_null() {
            return Err("null dns response matcher".into());
        }
        if out_routing.is_null() {
            return Err("null dns routing output pointer".into());
        }
        let request = unsafe { Box::from_raw(request_matcher) }.matcher;
        let response = unsafe { Box::from_raw(response_matcher) }.matcher;
        unsafe {
            *out_routing = Box::into_raw(Box::new(FfiDnsRouting {
                routing: DnsRouting::new(request, response),
            }));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_routing_free(routing: *mut FfiDnsRouting) {
    if !routing.is_null() {
        drop(unsafe { Box::from_raw(routing) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_routing_match_request_bytes(
    routing: *const FfiDnsRouting,
    qname: *const u8,
    qname_len: usize,
    qtype: u16,
    out_action: *mut i16,
) -> i32 {
    ffi_status(|| {
        let routing = unsafe { routing.as_ref() }.ok_or("null dns routing")?;
        if out_action.is_null() {
            return Err("null dns routing request action output".into());
        }
        let qname = ffi_bytes(qname, qname_len, "qname")?;
        let action = routing
            .routing
            .match_request(qname, qtype)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_action = dns_request_action_to_i16(action);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_routing_plan_request_bytes(
    routing: *const FfiDnsRouting,
    qname: *const u8,
    qname_len: usize,
    qtype: u16,
    preferred_qtype: u16,
    out_has_preferred: *mut bool,
    out_requested_action: *mut i16,
    out_preferred_action: *mut i16,
) -> i32 {
    ffi_status(|| {
        let routing = unsafe { routing.as_ref() }.ok_or("null dns routing")?;
        if out_has_preferred.is_null() {
            return Err("null dns routing request preferred flag output".into());
        }
        if out_requested_action.is_null() {
            return Err("null dns routing request action output".into());
        }
        if out_preferred_action.is_null() {
            return Err("null dns routing preferred action output".into());
        }
        let qname = ffi_bytes(qname, qname_len, "qname")?;
        let plan = routing
            .routing
            .plan_request(qname, qtype, preferred_qtype)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_has_preferred = plan.preferred.is_some();
            *out_requested_action = dns_request_action_to_i16(plan.requested.action);
            *out_preferred_action = plan
                .preferred
                .map(|lookup| dns_request_action_to_i16(lookup.action))
                .unwrap_or(dns_request_action_to_i16(plan.requested.action));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_routing_match_response_bytes(
    routing: *const FfiDnsRouting,
    qname: *const u8,
    qname_len: usize,
    qtype: u16,
    request_upstream: i16,
    ips: *const u8,
    ips_len: usize,
    out_action: *mut i16,
) -> i32 {
    ffi_status(|| {
        let routing = unsafe { routing.as_ref() }.ok_or("null dns routing")?;
        if out_action.is_null() {
            return Err("null dns routing response action output".into());
        }
        let qname = ffi_bytes(qname, qname_len, "qname")?;
        if !ips_len.is_multiple_of(16) {
            return Err(format!(
                "dns routing ip bytes len={ips_len}, want multiple of 16"
            ));
        }
        let ips = if ips_len == 0 {
            &[][..]
        } else {
            if ips.is_null() {
                return Err("null dns routing ips".into());
            }
            unsafe { slice::from_raw_parts(ips.cast::<[u8; 16]>(), ips_len / 16) }
        };
        let action = routing
            .routing
            .match_response(qname, qtype, request_upstream, ips)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_action = dns_response_action_to_i16(action);
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_dns_routing_plan_response_bytes(
    routing: *const FfiDnsRouting,
    qname: *const u8,
    qname_len: usize,
    qtype: u16,
    request_upstream: i16,
    ips: *const u8,
    ips_len: usize,
    out_decision_kind: *mut u8,
    out_retry_action: *mut i16,
) -> i32 {
    ffi_status(|| {
        let routing = unsafe { routing.as_ref() }.ok_or("null dns routing")?;
        if out_decision_kind.is_null() {
            return Err("null dns routing response decision output".into());
        }
        if out_retry_action.is_null() {
            return Err("null dns routing response retry action output".into());
        }
        let qname = ffi_bytes(qname, qname_len, "qname")?;
        if !ips_len.is_multiple_of(16) {
            return Err(format!(
                "dns routing ip bytes len={ips_len}, want multiple of 16"
            ));
        }
        let ips = if ips_len == 0 {
            &[][..]
        } else {
            if ips.is_null() {
                return Err("null dns routing ips".into());
            }
            unsafe { slice::from_raw_parts(ips.cast::<[u8; 16]>(), ips_len / 16) }
        };
        let decision = routing
            .routing
            .plan_response(qname, qtype, request_upstream, ips)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            match decision {
                DnsResponseDecision::Accept => {
                    *out_decision_kind = 0;
                    *out_retry_action = dns_response_action_to_i16(DnsResponseAction::Accept);
                }
                DnsResponseDecision::Reject => {
                    *out_decision_kind = 1;
                    *out_retry_action = dns_response_action_to_i16(DnsResponseAction::Reject);
                }
                DnsResponseDecision::Retry { action } => {
                    *out_decision_kind = 2;
                    *out_retry_action = dns_response_action_to_i16(action);
                }
            }
        }
        Ok(())
    })
}

fn response_condition_matches(
    condition: &DnsResponseCondition,
    qtype: u16,
    request_upstream: i16,
    domain_bitmap: Option<&[u32]>,
    ip_set_match: &impl Fn(usize) -> bool,
) -> Result<bool, DnsResponseMatchError> {
    match condition {
        DnsResponseCondition::DomainBit { bit_index, not } => {
            let matched = domain_bitmap
                .map(|bitmap| {
                    domain_bitmap_has_bit(bitmap, *bit_index).map_err(|err| match err {
                        DnsRequestMatchError::DomainBitOutOfRange {
                            bit_index,
                            bitmap_words,
                        } => DnsResponseMatchError::DomainBitOutOfRange {
                            bit_index,
                            bitmap_words,
                        },
                        DnsRequestMatchError::EmptyRule | DnsRequestMatchError::NoMatch => {
                            unreachable!("domain bit lookup only returns out-of-range errors")
                        }
                    })
                })
                .transpose()?
                .unwrap_or(false);
            Ok(matched != *not)
        }
        DnsResponseCondition::QTypeAny { values, not } => {
            let matched = values.contains(&qtype);
            Ok(matched != *not)
        }
        DnsResponseCondition::UpstreamAny { values, not } => {
            let matched = values.contains(&request_upstream);
            Ok(matched != *not)
        }
        DnsResponseCondition::AnyIpInSet { set_index, not } => {
            let matched = ip_set_match(*set_index);
            Ok(matched != *not)
        }
        DnsResponseCondition::Fallback => Ok(true),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DnsRequestAction, DnsRequestCondition, DnsRequestLookup, DnsRequestMatchError,
        DnsRequestMatcher, DnsRequestPlan, DnsRequestRule, DnsResponseAction, DnsResponseCondition,
        DnsResponseDecision, DnsResponseMatchError, DnsResponseMatcher, DnsResponseRule,
        DnsRouting, IpPrefix, IpPrefixSet, match_dns_request_rules, match_dns_response_rules,
    };
    use crate::{DomainPatternKind, DomainPatternSet};
    use smallvec::smallvec;

    fn request_rules() -> Vec<DnsRequestRule> {
        vec![
            DnsRequestRule {
                conditions: vec![
                    DnsRequestCondition::DomainBit {
                        bit_index: 0,
                        not: false,
                    },
                    DnsRequestCondition::QTypeAny {
                        values: smallvec![1, 28],
                        not: false,
                    },
                ],
                action: DnsRequestAction::UserDefined(3),
            },
            DnsRequestRule {
                conditions: vec![DnsRequestCondition::QTypeAny {
                    values: smallvec![15],
                    not: true,
                }],
                action: DnsRequestAction::Reject,
            },
            DnsRequestRule {
                conditions: vec![DnsRequestCondition::Fallback],
                action: DnsRequestAction::AsIs,
            },
        ]
    }

    #[test]
    fn request_rules_domain_and_qtype_rule_hits_first() {
        let rules = request_rules();
        let domain_bitmap = [1u32];
        assert_eq!(
            match_dns_request_rules(&rules, 1, Some(&domain_bitmap)).unwrap(),
            DnsRequestAction::UserDefined(3)
        );
        assert_eq!(
            match_dns_request_rules(&rules, 28, Some(&domain_bitmap)).unwrap(),
            DnsRequestAction::UserDefined(3)
        );
    }

    #[test]
    fn request_rules_negated_qtype_rule_matches_when_primary_rule_misses() {
        let rules = request_rules();
        assert_eq!(
            match_dns_request_rules(&rules, 16, None).unwrap(),
            DnsRequestAction::Reject
        );
    }

    #[test]
    fn request_rules_fallback_handles_negated_qtype_miss() {
        let rules = request_rules();
        assert_eq!(
            match_dns_request_rules(&rules, 15, None).unwrap(),
            DnsRequestAction::AsIs
        );
        let domain_bitmap = [1u32];
        assert_eq!(
            match_dns_request_rules(&rules, 15, Some(&domain_bitmap)).unwrap(),
            DnsRequestAction::AsIs
        );
    }

    #[test]
    fn request_rules_return_out_of_range_for_short_domain_bitmap() {
        let rules = vec![DnsRequestRule {
            conditions: vec![DnsRequestCondition::DomainBit {
                bit_index: 32,
                not: false,
            }],
            action: DnsRequestAction::UserDefined(1),
        }];
        let err = match_dns_request_rules(&rules, 1, Some(&[0u32])).unwrap_err();
        assert_eq!(
            err,
            DnsRequestMatchError::DomainBitOutOfRange {
                bit_index: 32,
                bitmap_words: 1,
            }
        );
    }

    #[test]
    fn request_rules_reject_empty_rule_lists_with_empty_rule_error() {
        let rules = vec![DnsRequestRule {
            conditions: Vec::new(),
            action: DnsRequestAction::AsIs,
        }];
        assert_eq!(
            match_dns_request_rules(&rules, 1, None).unwrap_err(),
            DnsRequestMatchError::EmptyRule
        );
    }

    fn response_rules() -> Vec<DnsResponseRule> {
        vec![
            DnsResponseRule {
                conditions: vec![
                    DnsResponseCondition::DomainBit {
                        bit_index: 0,
                        not: false,
                    },
                    DnsResponseCondition::QTypeAny {
                        values: smallvec![1, 28],
                        not: false,
                    },
                    DnsResponseCondition::UpstreamAny {
                        values: smallvec![3],
                        not: false,
                    },
                ],
                action: DnsResponseAction::UserDefined(7),
            },
            DnsResponseRule {
                conditions: vec![DnsResponseCondition::AnyIpInSet {
                    set_index: 1,
                    not: false,
                }],
                action: DnsResponseAction::Reject,
            },
            DnsResponseRule {
                conditions: vec![DnsResponseCondition::Fallback],
                action: DnsResponseAction::Accept,
            },
        ]
    }

    #[test]
    fn response_rules_domain_qtype_and_upstream_rule_hits_first() {
        let rules = response_rules();
        let domain_bitmap = [1u32];
        assert_eq!(
            match_dns_response_rules(&rules, 1, 3, Some(&domain_bitmap), |_| false).unwrap(),
            DnsResponseAction::UserDefined(7)
        );
    }

    #[test]
    fn response_rules_ip_rule_hits_when_primary_rule_misses() {
        let rules = response_rules();
        assert_eq!(
            match_dns_response_rules(&rules, 15, 9, None, |set_index| set_index == 1).unwrap(),
            DnsResponseAction::Reject
        );
    }

    #[test]
    fn response_rules_fallback_handles_total_miss() {
        let rules = response_rules();
        assert_eq!(
            match_dns_response_rules(&rules, 15, 9, None, |_| false).unwrap(),
            DnsResponseAction::Accept
        );
    }

    #[test]
    fn response_rules_return_out_of_range_for_short_domain_bitmap() {
        let rules = vec![DnsResponseRule {
            conditions: vec![DnsResponseCondition::DomainBit {
                bit_index: 32,
                not: false,
            }],
            action: DnsResponseAction::UserDefined(1),
        }];
        let err = match_dns_response_rules(&rules, 1, 0, Some(&[0u32]), |_| false).unwrap_err();
        assert_eq!(
            err,
            DnsResponseMatchError::DomainBitOutOfRange {
                bit_index: 32,
                bitmap_words: 1,
            }
        );
    }

    #[test]
    fn response_rules_reject_empty_rule_lists_with_empty_rule_error() {
        let rules = vec![DnsResponseRule {
            conditions: Vec::new(),
            action: DnsResponseAction::Accept,
        }];
        assert_eq!(
            match_dns_response_rules(&rules, 1, 0, None, |_| false).unwrap_err(),
            DnsResponseMatchError::EmptyRule
        );
    }

    #[test]
    fn dns_routing_plan_request_adds_preferred_lookup_for_non_preferred_ip_queries() {
        let domain_sets = vec![DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Full,
            patterns: vec!["example.com".into()],
        }];
        let routing = DnsRouting::new(
            DnsRequestMatcher::build(32, &domain_sets, request_rules()).unwrap(),
            DnsResponseMatcher::build(
                32,
                &domain_sets,
                vec![
                    IpPrefixSet::default(),
                    IpPrefixSet::from_prefixes(vec![IpPrefix::new(
                        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 1, 1, 1, 8],
                        128,
                    )]),
                ],
                response_rules(),
            )
            .unwrap(),
        );

        assert_eq!(
            routing.plan_request("example.com.", 1, 28).unwrap(),
            DnsRequestPlan {
                requested: DnsRequestLookup {
                    qtype: 1,
                    action: DnsRequestAction::UserDefined(3),
                },
                preferred: Some(DnsRequestLookup {
                    qtype: 28,
                    action: DnsRequestAction::UserDefined(3),
                }),
            }
        );
    }

    #[test]
    fn dns_routing_plan_request_skips_preferred_lookup_for_matching_or_non_ip_queries() {
        let domain_sets = vec![DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Full,
            patterns: vec!["example.com".into()],
        }];
        let routing = DnsRouting::new(
            DnsRequestMatcher::build(32, &domain_sets, request_rules()).unwrap(),
            DnsResponseMatcher::build(
                32,
                &domain_sets,
                vec![IpPrefixSet::default()],
                response_rules(),
            )
            .unwrap(),
        );

        let plan = routing.plan_request("example.com.", 28, 28).unwrap();
        assert_eq!(plan.preferred, None);

        let non_ip = routing.plan_request("example.com.", 15, 28).unwrap();
        assert_eq!(non_ip.preferred, None);
        assert_eq!(
            non_ip.requested,
            DnsRequestLookup {
                qtype: 15,
                action: DnsRequestAction::AsIs,
            }
        );
    }

    #[test]
    fn dns_routing_plan_response_maps_accept_reject_and_retry() {
        let domain_sets = vec![DomainPatternSet {
            bit_index: 0,
            kind: DomainPatternKind::Full,
            patterns: vec!["example.com".into()],
        }];
        let response_rules = vec![
            DnsResponseRule {
                conditions: vec![DnsResponseCondition::UpstreamAny {
                    values: smallvec![3],
                    not: false,
                }],
                action: DnsResponseAction::UserDefined(7),
            },
            DnsResponseRule {
                conditions: vec![DnsResponseCondition::UpstreamAny {
                    values: smallvec![9],
                    not: false,
                }],
                action: DnsResponseAction::Reject,
            },
            DnsResponseRule {
                conditions: vec![DnsResponseCondition::Fallback],
                action: DnsResponseAction::Accept,
            },
        ];
        let routing = DnsRouting::new(
            DnsRequestMatcher::build(32, &domain_sets, request_rules()).unwrap(),
            DnsResponseMatcher::build(
                32,
                &domain_sets,
                vec![IpPrefixSet::default()],
                response_rules,
            )
            .unwrap(),
        );

        assert_eq!(
            routing.plan_response("example.com.", 1, 3, &[]).unwrap(),
            DnsResponseDecision::Retry {
                action: DnsResponseAction::UserDefined(7),
            }
        );
        assert_eq!(
            routing.plan_response("miss.example.", 15, 11, &[]).unwrap(),
            DnsResponseDecision::Accept
        );
        assert_eq!(
            routing.plan_response("miss.example.", 15, 9, &[]).unwrap(),
            DnsResponseDecision::Reject
        );
    }
}
