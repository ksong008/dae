use crate::{
    DomainPatternSet, IndexedMatcher, IpPrefix, IpPrefixSet, MatchError, bitmap_words,
    build_indexed_matcher, ffi_bytes, ffi_pattern_kind, ffi_status, ffi_str,
};
use smallvec::SmallVec;
use std::ffi::c_char;
use std::slice;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserspaceRoutingSetKind {
    DestIp,
    SourceIp,
    Mac,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserspaceRoutingAction {
    ContinueMust,
    Route { outbound: u8, mark: u32, must: bool },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserspaceRoutingCondition {
    DomainBit {
        bit_index: usize,
        not: bool,
    },
    AnySet {
        kind: UserspaceRoutingSetKind,
        set_index: usize,
        not: bool,
    },
    DestPortAny {
        ranges: SmallVec<[(u16, u16); 4]>,
        not: bool,
    },
    SourcePortAny {
        ranges: SmallVec<[(u16, u16); 4]>,
        not: bool,
    },
    L4ProtoMask {
        mask: u8,
        not: bool,
    },
    IpVersionMask {
        mask: u8,
        not: bool,
    },
    ProcessNameAny {
        names: SmallVec<[[u8; 16]; 4]>,
        not: bool,
    },
    DscpAny {
        values: SmallVec<[u8; 4]>,
        not: bool,
    },
    Fallback,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserspaceRoutingRule {
    pub conditions: Vec<UserspaceRoutingCondition>,
    pub action: UserspaceRoutingAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserspaceRoutingInput<'a> {
    pub domain_bitmap: Option<&'a [u32]>,
    pub source_port: u16,
    pub dest_port: u16,
    pub ip_version: u8,
    pub l4proto: u8,
    pub process_name: [u8; 16],
    pub dscp: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserspaceRoutingMatch {
    pub outbound: u8,
    pub mark: u32,
    pub must: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserspaceRoutingMatchError {
    EmptyRule,
    DomainBitOutOfRange {
        bit_index: usize,
        bitmap_words: usize,
    },
    NoMatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserspaceRoutingRuntimeError {
    DomainMatch(MatchError),
    Rule(UserspaceRoutingMatchError),
}

#[derive(Debug)]
pub struct UserspaceRoutingMatcher {
    bitmap_words: usize,
    matcher: IndexedMatcher,
    dest_ip_sets: Vec<IpPrefixSet>,
    source_ip_sets: Vec<IpPrefixSet>,
    mac_sets: Vec<IpPrefixSet>,
    rules: Vec<UserspaceRoutingRule>,
}

pub struct FfiUserspaceRoutingMatcherBuilder {
    bit_len: usize,
    domain_sets: Vec<DomainPatternSet>,
    dest_ip_sets: Vec<IpPrefixSet>,
    source_ip_sets: Vec<IpPrefixSet>,
    mac_sets: Vec<IpPrefixSet>,
    rules: Vec<UserspaceRoutingRule>,
}

pub struct FfiUserspaceRoutingMatcher {
    matcher: UserspaceRoutingMatcher,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FfiUserspaceRoutingMatchResult {
    pub status: i32,
    pub outbound: u8,
    pub mark: u32,
    pub must: u8,
}

pub fn match_userspace_routing_rules(
    rules: &[UserspaceRoutingRule],
    input: &UserspaceRoutingInput<'_>,
    set_match: impl Fn(UserspaceRoutingSetKind, usize) -> bool,
) -> Result<UserspaceRoutingMatch, UserspaceRoutingMatchError> {
    let mut must = false;
    for rule in rules {
        if rule.conditions.is_empty() {
            return Err(UserspaceRoutingMatchError::EmptyRule);
        }
        let mut matched = true;
        for condition in &rule.conditions {
            if !routing_condition_matches(condition, input, &set_match)? {
                matched = false;
                break;
            }
        }
        if !matched {
            continue;
        }
        match rule.action {
            UserspaceRoutingAction::ContinueMust => {
                must = true;
            }
            UserspaceRoutingAction::Route {
                outbound,
                mark,
                must: rule_must,
            } => {
                return Ok(UserspaceRoutingMatch {
                    outbound,
                    mark,
                    must: must || rule_must,
                });
            }
        }
    }
    Err(UserspaceRoutingMatchError::NoMatch)
}

impl UserspaceRoutingMatcher {
    pub fn build(
        bit_len: usize,
        domain_sets: &[DomainPatternSet],
        dest_ip_sets: Vec<IpPrefixSet>,
        source_ip_sets: Vec<IpPrefixSet>,
        mac_sets: Vec<IpPrefixSet>,
        rules: Vec<UserspaceRoutingRule>,
    ) -> Result<Self, MatchError> {
        Ok(Self {
            bitmap_words: bitmap_words(bit_len),
            matcher: build_indexed_matcher(bit_len, domain_sets)?,
            dest_ip_sets,
            source_ip_sets,
            mac_sets,
            rules,
        })
    }

    pub fn match_input(
        &self,
        input: &UserspaceRoutingInput<'_>,
        domain: &str,
        dest_ip: [u8; 16],
        source_ip: [u8; 16],
        mac: [u8; 16],
    ) -> Result<UserspaceRoutingMatch, UserspaceRoutingRuntimeError> {
        let mut scratch = crate::DomainMatchScratch::default();
        self.match_input_with_scratch(input, domain, dest_ip, source_ip, mac, &mut scratch)
    }

    pub fn match_input_with_scratch(
        &self,
        input: &UserspaceRoutingInput<'_>,
        domain: &str,
        dest_ip: [u8; 16],
        source_ip: [u8; 16],
        mac: [u8; 16],
        scratch: &mut crate::DomainMatchScratch,
    ) -> Result<UserspaceRoutingMatch, UserspaceRoutingRuntimeError> {
        let domain_bitmap = if domain.is_empty() {
            None
        } else {
            scratch.prepare(self.bitmap_words);
            self.matcher
                .match_domain_bitmap_into_with_keyword_scratch(
                    domain,
                    &mut scratch.bitmap,
                    &mut scratch.keyword_scratch,
                )
                .map_err(UserspaceRoutingRuntimeError::DomainMatch)?;
            Some(scratch.bitmap.as_slice())
        };
        let rust_input = UserspaceRoutingInput {
            domain_bitmap: domain_bitmap.or(input.domain_bitmap),
            source_port: input.source_port,
            dest_port: input.dest_port,
            ip_version: input.ip_version,
            l4proto: input.l4proto,
            process_name: input.process_name,
            dscp: input.dscp,
        };
        match_userspace_routing_rules(&self.rules, &rust_input, |kind, set_index| match kind {
            UserspaceRoutingSetKind::DestIp => self
                .dest_ip_sets
                .get(set_index)
                .is_some_and(|set| set.matches(dest_ip)),
            UserspaceRoutingSetKind::SourceIp => self
                .source_ip_sets
                .get(set_index)
                .is_some_and(|set| set.matches(source_ip)),
            UserspaceRoutingSetKind::Mac => self
                .mac_sets
                .get(set_index)
                .is_some_and(|set| set.matches(mac)),
        })
        .map_err(UserspaceRoutingRuntimeError::Rule)
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn dae_userspace_routing_matcher_builder_new(
    bit_len: usize,
) -> *mut FfiUserspaceRoutingMatcherBuilder {
    Box::into_raw(Box::new(FfiUserspaceRoutingMatcherBuilder {
        bit_len,
        domain_sets: Vec::new(),
        dest_ip_sets: Vec::new(),
        source_ip_sets: Vec::new(),
        mac_sets: Vec::new(),
        rules: Vec::new(),
    }))
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_free(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
) {
    if !builder.is_null() {
        drop(unsafe { Box::from_raw(builder) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_domain_pattern(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    bit_index: usize,
    kind: u32,
    pattern: *const c_char,
) -> i32 {
    ffi_status(|| {
        let builder =
            unsafe { builder.as_mut() }.ok_or("null userspace routing matcher builder")?;
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
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_ip_prefix(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    set_kind: u32,
    set_index: usize,
    addr: *const u8,
    addr_len: usize,
    prefix_bits: u8,
) -> i32 {
    ffi_status(|| {
        let builder =
            unsafe { builder.as_mut() }.ok_or("null userspace routing matcher builder")?;
        if addr_len != 16 {
            return Err(format!(
                "userspace routing matcher ip prefix addr len={addr_len}, want 16"
            ));
        }
        if addr.is_null() {
            return Err("null userspace routing matcher ip prefix addr".into());
        }
        let set = match ffi_set_kind(set_kind)? {
            UserspaceRoutingSetKind::DestIp => ensure_ip_set(&mut builder.dest_ip_sets, set_index),
            UserspaceRoutingSetKind::SourceIp => {
                ensure_ip_set(&mut builder.source_ip_sets, set_index)
            }
            UserspaceRoutingSetKind::Mac => ensure_ip_set(&mut builder.mac_sets, set_index),
        };
        let mut encoded = [0u8; 16];
        encoded.copy_from_slice(unsafe { slice::from_raw_parts(addr, addr_len) });
        set.prefixes.push(IpPrefix::new(encoded, prefix_bits));
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    action_kind: u32,
    outbound: u8,
    mark: u32,
    must: bool,
    out_rule_index: *mut usize,
) -> i32 {
    ffi_status(|| {
        let builder =
            unsafe { builder.as_mut() }.ok_or("null userspace routing matcher builder")?;
        if out_rule_index.is_null() {
            return Err("null userspace routing matcher rule index output".into());
        }
        let action = match action_kind {
            0 => UserspaceRoutingAction::ContinueMust,
            1 => UserspaceRoutingAction::Route {
                outbound,
                mark,
                must,
            },
            _ => {
                return Err(format!(
                    "unknown userspace routing action kind: {action_kind}"
                ));
            }
        };
        let rule_index = builder.rules.len();
        builder.rules.push(UserspaceRoutingRule {
            conditions: Vec::new(),
            action,
        });
        unsafe {
            *out_rule_index = rule_index;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_domain_bit(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
    bit_index: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        rule.conditions
            .push(UserspaceRoutingCondition::DomainBit { bit_index, not });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_set(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
    set_kind: u32,
    set_index: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        rule.conditions.push(UserspaceRoutingCondition::AnySet {
            kind: ffi_set_kind(set_kind)?,
            set_index,
            not,
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_ports(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
    is_source: bool,
    ranges: *const u16,
    ranges_len: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        if ranges_len == 0 || !ranges_len.is_multiple_of(2) {
            return Err("userspace routing matcher port ranges must be non-empty pairs".into());
        }
        if ranges.is_null() {
            return Err("null userspace routing matcher port ranges".into());
        }
        let ranges = unsafe { slice::from_raw_parts(ranges, ranges_len) };
        let parsed: SmallVec<[(u16, u16); 4]> = ranges
            .chunks_exact(2)
            .map(|chunk| (chunk[0], chunk[1]))
            .collect();
        rule.conditions.push(if is_source {
            UserspaceRoutingCondition::SourcePortAny {
                ranges: parsed,
                not,
            }
        } else {
            UserspaceRoutingCondition::DestPortAny {
                ranges: parsed,
                not,
            }
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_l4proto_mask(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
    mask: u8,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        rule.conditions
            .push(UserspaceRoutingCondition::L4ProtoMask { mask, not });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_ip_version_mask(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
    mask: u8,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        rule.conditions
            .push(UserspaceRoutingCondition::IpVersionMask { mask, not });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_process_names(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
    names: *const u8,
    names_len: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        if names_len == 0 || !names_len.is_multiple_of(16) {
            return Err(
                "userspace routing matcher process names must be non-empty 16-byte chunks".into(),
            );
        }
        if names.is_null() {
            return Err("null userspace routing matcher process names".into());
        }
        let names = unsafe { slice::from_raw_parts(names, names_len) };
        let parsed: SmallVec<[[u8; 16]; 4]> = names
            .chunks_exact(16)
            .map(|chunk| {
                let mut name = [0u8; 16];
                name.copy_from_slice(chunk);
                name
            })
            .collect();
        rule.conditions
            .push(UserspaceRoutingCondition::ProcessNameAny { names: parsed, not });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_dscp_values(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
    values: *const u8,
    values_len: usize,
    not: bool,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        if values_len == 0 {
            return Err("userspace routing matcher dscp set cannot be empty".into());
        }
        if values.is_null() {
            return Err("null userspace routing matcher dscp values".into());
        }
        let values = unsafe { slice::from_raw_parts(values, values_len) };
        rule.conditions.push(UserspaceRoutingCondition::DscpAny {
            values: SmallVec::from_slice(values),
            not,
        });
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_add_rule_fallback(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
) -> i32 {
    ffi_status(|| {
        let rule = get_routing_rule_mut(builder, rule_index)?;
        rule.conditions.push(UserspaceRoutingCondition::Fallback);
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_builder_build(
    builder: *const FfiUserspaceRoutingMatcherBuilder,
    out_matcher: *mut *mut FfiUserspaceRoutingMatcher,
) -> i32 {
    ffi_status(|| {
        let builder =
            unsafe { builder.as_ref() }.ok_or("null userspace routing matcher builder")?;
        if out_matcher.is_null() {
            return Err("null userspace routing matcher output pointer".into());
        }
        let matcher = UserspaceRoutingMatcher::build(
            builder.bit_len,
            &builder.domain_sets,
            builder.dest_ip_sets.clone(),
            builder.source_ip_sets.clone(),
            builder.mac_sets.clone(),
            builder.rules.clone(),
        )
        .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_matcher = Box::into_raw(Box::new(FfiUserspaceRoutingMatcher { matcher }));
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_free(
    matcher: *mut FfiUserspaceRoutingMatcher,
) {
    if !matcher.is_null() {
        drop(unsafe { Box::from_raw(matcher) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_match_domain_bitmap_bytes_into(
    matcher: *const FfiUserspaceRoutingMatcher,
    domain: *const u8,
    domain_len: usize,
    bitmap: *mut u32,
    bitmap_len: usize,
) -> i32 {
    ffi_status(|| {
        let matcher = unsafe { matcher.as_ref() }.ok_or("null userspace routing matcher")?;
        let domain = ffi_bytes(domain, domain_len, "domain")?;
        if bitmap.is_null() {
            return Err("null userspace routing matcher bitmap".into());
        }
        let bitmap = unsafe { slice::from_raw_parts_mut(bitmap, bitmap_len) };
        let mut keyword_scratch = String::new();
        matcher
            .matcher
            .matcher
            .match_domain_bitmap_into_with_keyword_scratch(domain, bitmap, &mut keyword_scratch)
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_match_bytes(
    matcher: *const FfiUserspaceRoutingMatcher,
    source_addr: *const u8,
    source_addr_len: usize,
    dest_addr: *const u8,
    dest_addr_len: usize,
    source_port: u16,
    dest_port: u16,
    ip_version: u8,
    l4proto: u8,
    domain: *const u8,
    domain_len: usize,
    process_name: *const u8,
    process_name_len: usize,
    dscp: u8,
    mac: *const u8,
    mac_len: usize,
    out_outbound: *mut u8,
    out_mark: *mut u32,
    out_must: *mut bool,
) -> i32 {
    ffi_status(|| {
        let matcher = unsafe { matcher.as_ref() }.ok_or("null userspace routing matcher")?;
        if out_outbound.is_null() || out_mark.is_null() || out_must.is_null() {
            return Err("null userspace routing matcher output pointer".into());
        }
        let source_addr = ffi_addr16(source_addr, source_addr_len, "source_addr")?;
        let dest_addr = ffi_addr16(dest_addr, dest_addr_len, "dest_addr")?;
        let domain = ffi_bytes(domain, domain_len, "domain")?;
        let process_name = ffi_name16(process_name, process_name_len, "process_name")?;
        let mac = ffi_addr16(mac, mac_len, "mac")?;
        let input = UserspaceRoutingInput {
            domain_bitmap: None,
            source_port,
            dest_port,
            ip_version,
            l4proto,
            process_name,
            dscp,
        };
        let matched = matcher
            .matcher
            .match_input(&input, domain, dest_addr, source_addr, mac)
            .map_err(|error| format!("{error:?}"))?;
        unsafe {
            *out_outbound = matched.outbound;
            *out_mark = matched.mark;
            *out_must = matched.must;
        }
        Ok(())
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_userspace_routing_matcher_match_words(
    matcher: *const FfiUserspaceRoutingMatcher,
    source_addr_hi: u64,
    source_addr_lo: u64,
    dest_addr_hi: u64,
    dest_addr_lo: u64,
    source_port: u16,
    dest_port: u16,
    ip_version: u8,
    l4proto: u8,
    domain: *const u8,
    domain_len: usize,
    process_name_hi: u64,
    process_name_lo: u64,
    dscp: u8,
    mac_hi: u64,
    mac_lo: u64,
) -> FfiUserspaceRoutingMatchResult {
    let mut matched = UserspaceRoutingMatch {
        outbound: 0,
        mark: 0,
        must: false,
    };
    let status = ffi_status(|| {
        let matcher = unsafe { matcher.as_ref() }.ok_or("null userspace routing matcher")?;
        let domain = ffi_bytes(domain, domain_len, "domain")?;
        let input = UserspaceRoutingInput {
            domain_bitmap: None,
            source_port,
            dest_port,
            ip_version,
            l4proto,
            process_name: ffi_words_to_addr16(process_name_hi, process_name_lo),
            dscp,
        };
        matched = matcher
            .matcher
            .match_input(
                &input,
                domain,
                ffi_words_to_addr16(dest_addr_hi, dest_addr_lo),
                ffi_words_to_addr16(source_addr_hi, source_addr_lo),
                ffi_words_to_addr16(mac_hi, mac_lo),
            )
            .map_err(|error| format!("{error:?}"))?;
        Ok(())
    });
    FfiUserspaceRoutingMatchResult {
        status,
        outbound: matched.outbound,
        mark: matched.mark,
        must: u8::from(matched.must),
    }
}

fn ensure_ip_set(sets: &mut Vec<IpPrefixSet>, set_index: usize) -> &mut IpPrefixSet {
    if sets.len() <= set_index {
        sets.resize_with(set_index + 1, IpPrefixSet::default);
    }
    &mut sets[set_index]
}

fn get_routing_rule_mut<'a>(
    builder: *mut FfiUserspaceRoutingMatcherBuilder,
    rule_index: usize,
) -> Result<&'a mut UserspaceRoutingRule, String> {
    let builder = unsafe { builder.as_mut() }.ok_or("null userspace routing matcher builder")?;
    builder
        .rules
        .get_mut(rule_index)
        .ok_or_else(|| format!("userspace routing matcher rule index out of range: {rule_index}"))
}

fn ffi_set_kind(kind: u32) -> Result<UserspaceRoutingSetKind, String> {
    match kind {
        0 => Ok(UserspaceRoutingSetKind::DestIp),
        1 => Ok(UserspaceRoutingSetKind::SourceIp),
        2 => Ok(UserspaceRoutingSetKind::Mac),
        _ => Err(format!("unknown userspace routing set kind: {kind}")),
    }
}

fn ffi_addr16(ptr: *const u8, len: usize, name: &str) -> Result<[u8; 16], String> {
    if len != 16 {
        return Err(format!("{name} len={len}, want 16"));
    }
    if ptr.is_null() {
        return Err(format!("null {name}"));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(unsafe { slice::from_raw_parts(ptr, len) });
    Ok(out)
}

fn ffi_name16(ptr: *const u8, len: usize, name: &str) -> Result<[u8; 16], String> {
    ffi_addr16(ptr, len, name)
}

fn ffi_words_to_addr16(hi: u64, lo: u64) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&hi.to_be_bytes());
    out[8..].copy_from_slice(&lo.to_be_bytes());
    out
}

fn routing_condition_matches(
    condition: &UserspaceRoutingCondition,
    input: &UserspaceRoutingInput<'_>,
    set_match: &impl Fn(UserspaceRoutingSetKind, usize) -> bool,
) -> Result<bool, UserspaceRoutingMatchError> {
    match condition {
        UserspaceRoutingCondition::DomainBit { bit_index, not } => {
            let matched = input
                .domain_bitmap
                .map(|bitmap| domain_bitmap_has_bit(bitmap, *bit_index))
                .transpose()?
                .unwrap_or(false);
            Ok(matched != *not)
        }
        UserspaceRoutingCondition::AnySet {
            kind,
            set_index,
            not,
        } => Ok(set_match(*kind, *set_index) != *not),
        UserspaceRoutingCondition::DestPortAny { ranges, not } => {
            let matched = ranges
                .iter()
                .any(|(start, end)| input.dest_port >= *start && input.dest_port <= *end);
            Ok(matched != *not)
        }
        UserspaceRoutingCondition::SourcePortAny { ranges, not } => {
            let matched = ranges
                .iter()
                .any(|(start, end)| input.source_port >= *start && input.source_port <= *end);
            Ok(matched != *not)
        }
        UserspaceRoutingCondition::L4ProtoMask { mask, not } => {
            let matched = input.l4proto & *mask != 0;
            Ok(matched != *not)
        }
        UserspaceRoutingCondition::IpVersionMask { mask, not } => {
            let matched = input.ip_version & *mask != 0;
            Ok(matched != *not)
        }
        UserspaceRoutingCondition::ProcessNameAny { names, not } => {
            let matched = names.contains(&input.process_name);
            Ok(matched != *not)
        }
        UserspaceRoutingCondition::DscpAny { values, not } => {
            let matched = values.contains(&input.dscp);
            Ok(matched != *not)
        }
        UserspaceRoutingCondition::Fallback => Ok(true),
    }
}

fn domain_bitmap_has_bit(
    bitmap: &[u32],
    bit_index: usize,
) -> Result<bool, UserspaceRoutingMatchError> {
    let word_index = bit_index / 32;
    let Some(word) = bitmap.get(word_index) else {
        return Err(UserspaceRoutingMatchError::DomainBitOutOfRange {
            bit_index,
            bitmap_words: bitmap.len(),
        });
    };
    Ok(((word >> (bit_index % 32)) & 1) != 0)
}

#[cfg(test)]
mod tests {
    use super::{
        UserspaceRoutingAction, UserspaceRoutingCondition, UserspaceRoutingInput,
        UserspaceRoutingMatch, UserspaceRoutingMatchError, UserspaceRoutingRule,
        UserspaceRoutingSetKind, match_userspace_routing_rules,
    };
    use smallvec::smallvec;

    fn process_name(name: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..name.len()].copy_from_slice(name);
        out
    }

    fn routing_rules() -> Vec<UserspaceRoutingRule> {
        vec![
            UserspaceRoutingRule {
                conditions: vec![
                    UserspaceRoutingCondition::DomainBit {
                        bit_index: 0,
                        not: false,
                    },
                    UserspaceRoutingCondition::DestPortAny {
                        ranges: smallvec![(443, 443)],
                        not: false,
                    },
                ],
                action: UserspaceRoutingAction::ContinueMust,
            },
            UserspaceRoutingRule {
                conditions: vec![
                    UserspaceRoutingCondition::L4ProtoMask {
                        mask: 1,
                        not: false,
                    },
                    UserspaceRoutingCondition::DscpAny {
                        values: smallvec![46],
                        not: false,
                    },
                ],
                action: UserspaceRoutingAction::Route {
                    outbound: 7,
                    mark: 123,
                    must: false,
                },
            },
            UserspaceRoutingRule {
                conditions: vec![
                    UserspaceRoutingCondition::AnySet {
                        kind: UserspaceRoutingSetKind::DestIp,
                        set_index: 1,
                        not: false,
                    },
                    UserspaceRoutingCondition::ProcessNameAny {
                        names: smallvec![process_name(b"curl")],
                        not: false,
                    },
                ],
                action: UserspaceRoutingAction::Route {
                    outbound: 9,
                    mark: 0,
                    must: false,
                },
            },
            UserspaceRoutingRule {
                conditions: vec![UserspaceRoutingCondition::Fallback],
                action: UserspaceRoutingAction::Route {
                    outbound: 2,
                    mark: 0,
                    must: false,
                },
            },
        ]
    }

    #[test]
    fn routing_rules_carry_must_state_into_later_route() {
        let rules = routing_rules();
        let domain_bitmap = [1u32];
        let input = UserspaceRoutingInput {
            domain_bitmap: Some(&domain_bitmap),
            source_port: 40000,
            dest_port: 443,
            ip_version: 1,
            l4proto: 1,
            process_name: process_name(b"curl"),
            dscp: 46,
        };
        assert_eq!(
            match_userspace_routing_rules(&rules, &input, |_, _| false).unwrap(),
            UserspaceRoutingMatch {
                outbound: 7,
                mark: 123,
                must: true,
            }
        );
    }

    #[test]
    fn routing_rules_ip_set_and_process_name_rule_hits_when_must_rule_misses() {
        let rules = routing_rules();
        let input = UserspaceRoutingInput {
            domain_bitmap: None,
            source_port: 30000,
            dest_port: 80,
            ip_version: 1,
            l4proto: 2,
            process_name: process_name(b"curl"),
            dscp: 0,
        };
        assert_eq!(
            match_userspace_routing_rules(&rules, &input, |kind, index| {
                kind == UserspaceRoutingSetKind::DestIp && index == 1
            })
            .unwrap(),
            UserspaceRoutingMatch {
                outbound: 9,
                mark: 0,
                must: false,
            }
        );
    }

    #[test]
    fn routing_rules_fallback_handles_total_miss() {
        let rules = routing_rules();
        let input = UserspaceRoutingInput {
            domain_bitmap: None,
            source_port: 30000,
            dest_port: 53,
            ip_version: 2,
            l4proto: 2,
            process_name: process_name(b"dae"),
            dscp: 0,
        };
        assert_eq!(
            match_userspace_routing_rules(&rules, &input, |_, _| false).unwrap(),
            UserspaceRoutingMatch {
                outbound: 2,
                mark: 0,
                must: false,
            }
        );
    }

    #[test]
    fn routing_rules_return_out_of_range_for_short_domain_bitmap() {
        let rules = vec![UserspaceRoutingRule {
            conditions: vec![UserspaceRoutingCondition::DomainBit {
                bit_index: 32,
                not: false,
            }],
            action: UserspaceRoutingAction::Route {
                outbound: 1,
                mark: 0,
                must: false,
            },
        }];
        let input = UserspaceRoutingInput {
            domain_bitmap: Some(&[0u32]),
            source_port: 0,
            dest_port: 0,
            ip_version: 0,
            l4proto: 0,
            process_name: [0; 16],
            dscp: 0,
        };
        assert_eq!(
            match_userspace_routing_rules(&rules, &input, |_, _| false).unwrap_err(),
            UserspaceRoutingMatchError::DomainBitOutOfRange {
                bit_index: 32,
                bitmap_words: 1,
            }
        );
    }

    #[test]
    fn routing_rules_reject_empty_rule_lists_with_empty_rule_error() {
        let rules = vec![UserspaceRoutingRule {
            conditions: Vec::new(),
            action: UserspaceRoutingAction::Route {
                outbound: 1,
                mark: 0,
                must: false,
            },
        }];
        let input = UserspaceRoutingInput {
            domain_bitmap: None,
            source_port: 0,
            dest_port: 0,
            ip_version: 0,
            l4proto: 0,
            process_name: [0; 16],
            dscp: 0,
        };
        assert_eq!(
            match_userspace_routing_rules(&rules, &input, |_, _| false).unwrap_err(),
            UserspaceRoutingMatchError::EmptyRule
        );
    }
}
