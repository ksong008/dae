/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <team@v2raya.org>
 */

use memchr::memchr;
use ring::aead::quic::{self as ring_quic, HeaderProtectionKey};
use ring::aead::{self as ring_aead, Aad as RingAad, LessSafeKey, Nonce as RingNonce};
use ring::hkdf::{self as ring_hkdf, KeyType as RingKeyType};
use smallvec::SmallVec;
use std::cell::RefCell;
use std::convert::TryFrom;
use std::ffi::{CString, c_char};
use std::ops::Range;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::{ptr, slice};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffError {
    NotApplicable,
    NeedMore,
    NotFound,
    InvalidUtf8,
}

const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
const TLS_EXTENSION_SERVER_NAME: u16 = 0;
const TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME: u8 = 0;
const VERSION_TLS_1_0: [u8; 2] = [0x03, 0x01];
const VERSION_TLS_1_2: [u8; 2] = [0x03, 0x03];
const QUIC_FLAG_LONG_PACKET_TYPE_SHIFT: u8 = 4;
const QUIC_FLAG_HEADER_FORM_SHIFT: u8 = 7;
const QUIC_FLAG_LONG_HEADER: u8 = 1;
const QUIC_LONG_PACKET_TYPE_INITIAL: u8 = 0;
const QUIC_MAX_PACKET_NUMBER_LENGTH: usize = 4;
const QUIC_SAMPLE_SIZE: usize = 16;
const QUIC_FRAME_TYPE_PADDING: u64 = 0;
const QUIC_FRAME_TYPE_PING: u64 = 1;
const QUIC_FRAME_TYPE_CRYPTO: u64 = 6;
const QUIC_FRAME_TYPE_CONNECTION_CLOSE: u64 = 0x1c;
const QUIC_FRAME_TYPE_CONNECTION_CLOSE_APP: u64 = 0x1d;
const QUIC_AEAD_TAG_LEN: usize = 16;
const FFI_OK: i32 = 0;
const FFI_ERROR: i32 = -1;
const QUIC_INITIAL_CLIENT_LABEL: &[u8] = b"client in";
const QUIC_V1_INITIAL_SALT: &[u8; 20] = &[
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];
const QUIC_V2_INITIAL_SALT: &[u8; 20] = &[
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];
const QUIC_DRAFT_INITIAL_SALT: &[u8; 20] = &[
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99,
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuicInitialHeader {
    pub version: u32,
    pub destination_connection_id: SmallVec<[u8; 20]>,
    pub source_connection_id: SmallVec<[u8; 20]>,
    pub payload_offset: usize,
    pub protected_header_len: usize,
    pub block_end: usize,
}

pub struct QuicSniffScratch {
    protected: Vec<u8>,
    crypto: Vec<u8>,
    cached_keys: Option<CachedQuicInitialKeys>,
}

pub struct FfiQuicSniffScratch {
    scratch: QuicSniffScratch,
}

thread_local! {
    static LAST_FFI_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

impl QuicSniffScratch {
    pub fn new() -> Self {
        Self {
            protected: Vec::new(),
            crypto: Vec::new(),
            cached_keys: None,
        }
    }

    pub fn clear(&mut self) {
        self.protected.clear();
        self.crypto.clear();
    }
}

impl Default for QuicSniffScratch {
    fn default() -> Self {
        Self::new()
    }
}

pub fn sniff_http_host(data: &[u8]) -> Result<String, SniffError> {
    sniff_http_host_ref(data).map(str::to_string)
}

pub fn sniff_http_host_ref(data: &[u8]) -> Result<&str, SniffError> {
    let first = *data.first().ok_or(SniffError::NotApplicable)?;
    if !is_go_unicode_print_ascii(first) {
        return Err(SniffError::NotApplicable);
    }

    let search_len = data.len().min(12);
    let method_end = memchr(b' ', &data[..search_len]).ok_or(SniffError::NotApplicable)?;
    let method = std::str::from_utf8(&data[..method_end]).map_err(|_| SniffError::NotApplicable)?;
    if !is_valid_http_method(method) {
        return Err(SniffError::NotApplicable);
    }

    let mut remaining = data;
    while !remaining.is_empty() {
        let line_end = memchr(b'\n', remaining).map_or(remaining.len(), |index| index + 1);
        let mut line = &remaining[..line_end];
        remaining = &remaining[line_end..];

        if let Some(stripped) = line.strip_suffix(b"\n") {
            line = stripped;
        }
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = memchr(b':', line) else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"host") {
            return std::str::from_utf8(&line[colon + 1..]).map_err(|_| SniffError::InvalidUtf8);
        }
    }
    Err(SniffError::NotFound)
}

pub fn sniff_tls_sni(record: &[u8]) -> Result<String, SniffError> {
    sniff_tls_sni_ref(record).map(str::to_string)
}

pub fn sniff_tls_sni_ref(record: &[u8]) -> Result<&str, SniffError> {
    if record.len() < 5 {
        return Err(SniffError::NotApplicable);
    }
    if record[0] != CONTENT_TYPE_HANDSHAKE
        || (record[1..3] != VERSION_TLS_1_0 && record[1..3] != VERSION_TLS_1_2)
    {
        return Err(SniffError::NotApplicable);
    }

    let length = u16::from_be_bytes([record[3], record[4]]) as usize;
    let search = &record[5..];
    if search.len() < length {
        return Err(SniffError::NeedMore);
    }
    extract_sni_from_tls_ref(&search[..length])
}

pub fn parse_quic_initial_header(data: &[u8]) -> Result<QuicInitialHeader, SniffError> {
    if data.len() < 6 {
        return Err(SniffError::NotApplicable);
    }
    let protected_flag = data[0];
    if ((protected_flag >> QUIC_FLAG_HEADER_FORM_SHIFT) & 0b1) != QUIC_FLAG_LONG_HEADER
        || ((protected_flag >> QUIC_FLAG_LONG_PACKET_TYPE_SHIFT) & 0b11)
            != QUIC_LONG_PACKET_TYPE_INITIAL
    {
        return Err(SniffError::NotApplicable);
    }

    let version = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let destination_connection_id_len = data[5] as usize;
    let destination_connection_id_start = 6usize;
    let destination_connection_id_end =
        destination_connection_id_start + destination_connection_id_len;
    if data.len() < destination_connection_id_end + 1 {
        return Err(SniffError::NotApplicable);
    }
    let source_connection_id_len = data[destination_connection_id_end] as usize;
    let source_connection_id_start = destination_connection_id_end + 1;
    let source_connection_id_end = source_connection_id_start + source_connection_id_len;
    if data.len() < source_connection_id_end {
        return Err(SniffError::NotApplicable);
    }

    let (token_len, token_len_size) = read_quic_varint(&data[source_connection_id_end..])?;
    let token_start = source_connection_id_end + token_len_size;
    let token_end = token_start + token_len as usize;
    if data.len() < token_end {
        return Err(SniffError::NotApplicable);
    }
    let (payload_len, payload_len_size) = read_quic_varint(&data[token_end..])?;
    let payload_offset = token_end + payload_len_size;
    let block_end = payload_offset + payload_len as usize;
    let protected_header_len = payload_offset + QUIC_MAX_PACKET_NUMBER_LENGTH;
    if data.len() < block_end || data.len() < protected_header_len {
        return Err(SniffError::NotApplicable);
    }

    Ok(QuicInitialHeader {
        version,
        destination_connection_id: SmallVec::from_slice(
            &data[destination_connection_id_start..destination_connection_id_end],
        ),
        source_connection_id: SmallVec::from_slice(
            &data[source_connection_id_start..source_connection_id_end],
        ),
        payload_offset,
        protected_header_len,
        block_end,
    })
}

pub fn sniff_quic_initial_sni(packets: &[&[u8]]) -> Result<String, SniffError> {
    let mut scratch = QuicSniffScratch::new();
    sniff_quic_initial_sni_ref(packets, &mut scratch).map(str::to_string)
}

pub fn sniff_quic_initial_sni_ref<'a>(
    packets: &[&[u8]],
    scratch: &'a mut QuicSniffScratch,
) -> Result<&'a str, SniffError> {
    scratch.clear();
    let mut sni_range = None;
    for packet in packets {
        let plaintext_len = decrypt_quic_initial_packet_into(packet, scratch)?;
        reassemble_quic_crypto(&mut scratch.crypto, &scratch.protected[..plaintext_len])?;
        if let Ok(range) = extract_sni_range_from_tls(&scratch.crypto) {
            sni_range = Some(range);
            break;
        }
    }
    let Some(range) = sni_range else {
        return Err(SniffError::NeedMore);
    };
    std::str::from_utf8(&scratch.crypto[range]).map_err(|_| SniffError::InvalidUtf8)
}

fn decrypt_quic_initial_packet_into(
    packet: &[u8],
    scratch: &mut QuicSniffScratch,
) -> Result<usize, SniffError> {
    let header = parse_quic_initial_header(packet)?;
    if header.protected_header_len + QUIC_SAMPLE_SIZE > packet.len() {
        return Err(SniffError::NotApplicable);
    }
    scratch.ensure_keys(header.version, header.destination_connection_id.as_slice())?;
    scratch.protected.clear();
    scratch
        .protected
        .extend_from_slice(&packet[..header.block_end]);
    let sample =
        &packet[header.protected_header_len..header.protected_header_len + QUIC_SAMPLE_SIZE];
    let mask = scratch
        .cached_keys
        .as_ref()
        .expect("cached keys")
        .keys
        .header_protection_mask(sample)?;

    scratch.protected[0] ^= mask[0] & 0x0f;
    let packet_number_len = ((scratch.protected[0] & 0x03) + 1) as usize;
    if header.payload_offset + packet_number_len > header.block_end {
        return Err(SniffError::NotApplicable);
    }
    for i in 0..packet_number_len {
        scratch.protected[header.payload_offset + i] ^= mask[1 + i];
    }

    let header_len = header.payload_offset + packet_number_len;
    let mut nonce = scratch.cached_keys.as_ref().expect("cached keys").keys.iv;
    for (i, packet_number_byte) in scratch.protected[header.payload_offset..header_len]
        .iter()
        .enumerate()
    {
        nonce[nonce.len() - packet_number_len + i] ^= packet_number_byte;
    }
    let payload_len = header.block_end - header_len;
    if payload_len < QUIC_AEAD_TAG_LEN {
        return Err(SniffError::NotApplicable);
    }
    let plaintext_len = payload_len - QUIC_AEAD_TAG_LEN;
    let (protected, cached_keys) = (&mut scratch.protected, &scratch.cached_keys);
    let keys = &cached_keys.as_ref().expect("cached keys").keys;
    let (aad, payload) = protected[..header.block_end].split_at_mut(header_len);
    let (msg, tag) = payload.split_at_mut(plaintext_len);
    let tag_bytes: [u8; QUIC_AEAD_TAG_LEN] =
        tag.try_into().map_err(|_| SniffError::NotApplicable)?;
    let tag = ring_aead::Tag::from(tag_bytes);
    keys.aead
        .open_in_place_separate_tag(
            RingNonce::assume_unique_for_key(nonce),
            RingAad::from(aad),
            tag,
            msg,
            0..,
        )
        .map_err(|_| SniffError::NotApplicable)?;
    protected.copy_within(header_len..header_len + plaintext_len, 0);
    protected.truncate(plaintext_len);
    Ok(plaintext_len)
}

struct QuicInitialKeys {
    iv: [u8; 12],
    header_protection: HeaderProtectionKey,
    aead: LessSafeKey,
}

struct CachedQuicInitialKeys {
    version: u32,
    destination_connection_id: SmallVec<[u8; 20]>,
    keys: QuicInitialKeys,
}

impl QuicSniffScratch {
    fn ensure_keys(
        &mut self,
        version: u32,
        destination_connection_id: &[u8],
    ) -> Result<(), SniffError> {
        let reuse = self.cached_keys.as_ref().is_some_and(|cached| {
            cached.version == version
                && cached.destination_connection_id.as_slice() == destination_connection_id
        });
        if !reuse {
            self.cached_keys = Some(CachedQuicInitialKeys {
                version,
                destination_connection_id: SmallVec::from_slice(destination_connection_id),
                keys: QuicInitialKeys::new(version, destination_connection_id)?,
            });
        }
        Ok(())
    }
}

impl QuicInitialKeys {
    fn new(version: u32, destination_connection_id: &[u8]) -> Result<Self, SniffError> {
        let salt = ring_hkdf::Salt::new(ring_hkdf::HKDF_SHA256, quic_initial_salt(version)?);
        let initial = salt.extract(destination_connection_id);
        let client_info =
            build_hkdf_label_info(QUIC_INITIAL_CLIENT_LABEL, ring_hkdf::HKDF_SHA256.len());
        let client: ring_hkdf::Prk = initial
            .expand(&[client_info.as_slice()], ring_hkdf::HKDF_SHA256)
            .map_err(|_| SniffError::NotApplicable)?
            .into();

        let mut iv = [0u8; 12];
        hkdf_expand_label(&client, quic_iv_label(version)?, &mut iv)?;

        let key_info =
            build_hkdf_label_info(quic_key_label(version)?, ring_aead::AES_128_GCM.key_len());
        let aead = LessSafeKey::new(
            client
                .expand(&[key_info.as_slice()], &ring_aead::AES_128_GCM)
                .map_err(|_| SniffError::NotApplicable)?
                .into(),
        );

        let hp_info =
            build_hkdf_label_info(quic_hp_label(version)?, ring_quic::AES_128.sample_len());
        let header_protection = client
            .expand(&[hp_info.as_slice()], &ring_quic::AES_128)
            .map_err(|_| SniffError::NotApplicable)?
            .into();

        Ok(Self {
            iv,
            header_protection,
            aead,
        })
    }

    fn header_protection_mask(&self, sample: &[u8]) -> Result<[u8; 5], SniffError> {
        self.header_protection
            .new_mask(sample)
            .map_err(|_| SniffError::NotApplicable)
    }
}

#[derive(Clone, Copy)]
struct HkdfOutputLen(usize);

impl RingKeyType for HkdfOutputLen {
    fn len(&self) -> usize {
        self.0
    }
}

fn build_hkdf_label_info(label: &[u8], output_len: usize) -> SmallVec<[u8; 64]> {
    let mut info = SmallVec::<[u8; 64]>::new();
    info.extend_from_slice(
        &(u16::try_from(output_len).expect("hkdf output length fits in u16")).to_be_bytes(),
    );
    info.push(
        (6 + label.len())
            .try_into()
            .expect("hkdf label length fits in u8"),
    );
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(0);
    info
}

fn hkdf_expand_label(
    hkdf: &ring_hkdf::Prk,
    label: &[u8],
    out: &mut [u8],
) -> Result<(), SniffError> {
    let info = build_hkdf_label_info(label, out.len());
    hkdf.expand(&[info.as_slice()], HkdfOutputLen(out.len()))
        .map_err(|_| SniffError::NotApplicable)?
        .fill(out)
        .map_err(|_| SniffError::NotApplicable)
}

fn quic_initial_salt(version: u32) -> Result<&'static [u8; 20], SniffError> {
    match version {
        1 => Ok(QUIC_V1_INITIAL_SALT),
        0x6b3343cf => Ok(QUIC_V2_INITIAL_SALT),
        version if (version & 0xff00_0000) == 0xff00_0000 => Ok(QUIC_DRAFT_INITIAL_SALT),
        _ => Err(SniffError::NotApplicable),
    }
}

fn quic_key_label(version: u32) -> Result<&'static [u8], SniffError> {
    match version {
        0x6b3343cf => Ok(b"quicv2 key"),
        1 => Ok(b"quic key"),
        version if (version & 0xff00_0000) == 0xff00_0000 => Ok(b"quic key"),
        _ => Err(SniffError::NotApplicable),
    }
}

fn quic_iv_label(version: u32) -> Result<&'static [u8], SniffError> {
    match version {
        0x6b3343cf => Ok(b"quicv2 iv"),
        1 => Ok(b"quic iv"),
        version if (version & 0xff00_0000) == 0xff00_0000 => Ok(b"quic iv"),
        _ => Err(SniffError::NotApplicable),
    }
}

fn quic_hp_label(version: u32) -> Result<&'static [u8], SniffError> {
    match version {
        0x6b3343cf => Ok(b"quicv2 hp"),
        1 => Ok(b"quic hp"),
        version if (version & 0xff00_0000) == 0xff00_0000 => Ok(b"quic hp"),
        _ => Err(SniffError::NotApplicable),
    }
}

fn reassemble_quic_crypto(crypto: &mut Vec<u8>, plaintext: &[u8]) -> Result<(), SniffError> {
    let mut offset = 0usize;
    while offset < plaintext.len() {
        let (frame_type, frame_type_len) = read_quic_varint(&plaintext[offset..])?;
        let mut next = offset + frame_type_len;
        match frame_type {
            QUIC_FRAME_TYPE_PADDING => {
                while next < plaintext.len() && plaintext[next] == 0 {
                    next += 1;
                }
            }
            QUIC_FRAME_TYPE_PING => {}
            QUIC_FRAME_TYPE_CRYPTO => {
                let (crypto_offset, n) = read_quic_varint(&plaintext[next..])?;
                next += n;
                let (crypto_len, n) = read_quic_varint(&plaintext[next..])?;
                next += n;
                let crypto_end = next + crypto_len as usize;
                if crypto_end > plaintext.len() {
                    return Err(SniffError::NotApplicable);
                }
                let upper_end = crypto_offset as usize + crypto_len as usize;
                if crypto.len() < upper_end {
                    crypto.resize(upper_end, 0);
                }
                crypto[crypto_offset as usize..upper_end]
                    .copy_from_slice(&plaintext[next..crypto_end]);
                next = crypto_end;
            }
            QUIC_FRAME_TYPE_CONNECTION_CLOSE | QUIC_FRAME_TYPE_CONNECTION_CLOSE_APP => {
                return Err(SniffError::NotFound);
            }
            _ => return Err(SniffError::NotApplicable),
        }
        offset = next;
    }
    Ok(())
}

fn read_quic_varint(data: &[u8]) -> Result<(u64, usize), SniffError> {
    let first = *data.first().ok_or(SniffError::NotApplicable)?;
    let len = 1usize << (first >> 6);
    if data.len() < len {
        return Err(SniffError::NotApplicable);
    }
    let mut value = (first & 0x3f) as u64;
    for b in &data[1..len] {
        value = (value << 8) | *b as u64;
    }
    Ok((value, len))
}

fn extract_sni_from_tls_ref(search: &[u8]) -> Result<&str, SniffError> {
    let range = extract_sni_range_from_tls(search)?;
    std::str::from_utf8(&search[range]).map_err(|_| SniffError::InvalidUtf8)
}

fn extract_sni_range_from_tls(search: &[u8]) -> Result<Range<usize>, SniffError> {
    let mut boundary = 39usize;
    if search.len() < boundary {
        return Err(SniffError::NotApplicable);
    }
    if search[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(SniffError::NotApplicable);
    }

    let length2 = ((search[1] as usize) << 16) + ((search[2] as usize) << 8) + search[3] as usize;
    if search.len() > length2 + 4 {
        return Err(SniffError::NotApplicable);
    }
    if search[4..6] != VERSION_TLS_1_2 {
        return Err(SniffError::NotApplicable);
    }

    let session_id_length = search[boundary - 1] as usize;
    boundary += session_id_length + 2;
    if search.len() < boundary {
        return Err(SniffError::NotApplicable);
    }

    let cipher_suite_length =
        u16::from_be_bytes([search[boundary - 2], search[boundary - 1]]) as usize;
    boundary += cipher_suite_length + 1;
    if search.len() < boundary {
        return Err(SniffError::NotApplicable);
    }

    let compress_methods_length = search[boundary - 1] as usize;
    boundary += compress_methods_length + 2;
    if search.len() < boundary {
        return Err(SniffError::NotApplicable);
    }

    let extensions_length =
        u16::from_be_bytes([search[boundary - 2], search[boundary - 1]]) as usize;
    boundary += extensions_length;
    if search.len() < boundary {
        return Err(SniffError::NotApplicable);
    }
    let extension_start = boundary - extensions_length;
    let range = find_sni_extension_range(&search[extension_start..boundary])?;
    Ok(extension_start + range.start..extension_start + range.end)
}

fn find_sni_extension_range(search: &[u8]) -> Result<Range<usize>, SniffError> {
    let mut i = 0usize;
    loop {
        if i + 4 >= search.len() {
            return Err(SniffError::NotFound);
        }
        let typ = u16::from_be_bytes([search[i], search[i + 1]]);
        let ext_length = u16::from_be_bytes([search[i + 2], search[i + 3]]) as usize;
        let i_next_field = i + 4 + ext_length;
        if i_next_field > search.len() {
            return Err(SniffError::NotApplicable);
        }
        if typ == TLS_EXTENSION_SERVER_NAME {
            if i + 6 > search.len() {
                return Err(SniffError::NotApplicable);
            }
            let sni_len = u16::from_be_bytes([search[i + 4], search[i + 5]]) as usize;
            if ext_length < sni_len + 2 {
                return Err(SniffError::NotApplicable);
            }
            let mut j = i + 6;
            while j + 3 <= i_next_field {
                let indicator_len = u16::from_be_bytes([search[j + 1], search[j + 2]]) as usize;
                if search[j] == TLS_EXTENSION_SERVER_NAME_TYPE_HOST_NAME {
                    if j + 3 + indicator_len > i_next_field {
                        return Err(SniffError::NotApplicable);
                    }
                    let mut end = j + 3 + indicator_len;
                    if search[end - 1] == b'.' {
                        end -= 1;
                    }
                    return Ok(j + 3..end);
                }
                j += indicator_len;
            }
        }
        i = i_next_field;
    }
}

fn is_go_unicode_print_ascii(b: u8) -> bool {
    b >= 0x20 && b != 0x7f
}

fn is_valid_http_method(method: &str) -> bool {
    matches!(
        method,
        "GET"
            | "POST"
            | "PUT"
            | "PATCH"
            | "DELETE"
            | "COPY"
            | "HEAD"
            | "OPTIONS"
            | "LINK"
            | "UNLINK"
            | "PURGE"
            | "LOCK"
            | "UNLOCK"
            | "PROPFIND"
            | "CONNECT"
            | "TRACE"
    )
}

/// Returns the last sniffing FFI error for this thread.
///
/// The returned pointer remains valid until the next sniffing FFI call on the
/// same thread overwrites the stored error.
#[unsafe(no_mangle)]
pub extern "C" fn dae_sniffing_last_error() -> *const c_char {
    LAST_FFI_ERROR.with(|last_error| {
        last_error
            .borrow()
            .as_ref()
            .map_or(ptr::null(), |error| error.as_ptr())
    })
}

/// Creates a reusable QUIC sniffing scratch handle.
#[unsafe(no_mangle)]
pub extern "C" fn dae_sniffing_quic_scratch_new() -> *mut FfiQuicSniffScratch {
    clear_ffi_error();
    Box::into_raw(Box::new(FfiQuicSniffScratch {
        scratch: QuicSniffScratch::new(),
    }))
}

/// Frees a QUIC sniffing scratch handle.
///
/// # Safety
///
/// `scratch` must be null or a pointer returned by
/// `dae_sniffing_quic_scratch_new` that has not already been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_sniffing_quic_scratch_free(scratch: *mut FfiQuicSniffScratch) {
    if !scratch.is_null() {
        drop(unsafe { Box::from_raw(scratch) });
    }
}

/// Sniffs SNI from one or two QUIC Initial packets into a caller-owned buffer.
///
/// `packet2` may be null only when `packet2_len` is zero.
///
/// # Safety
///
/// `scratch` must be a valid pointer returned by
/// `dae_sniffing_quic_scratch_new`. `packet1` must point to `packet1_len`
/// readable bytes for the duration of this call. If `packet2_len` is non-zero,
/// `packet2` must point to `packet2_len` readable bytes. `out` must point to
/// `out_len` writable bytes when `out_len` is non-zero. `written` must be a
/// valid writable pointer. Rust must not retain any caller-owned pointer after
/// this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_sniffing_quic_initial_sni_two_into(
    scratch: *mut FfiQuicSniffScratch,
    packet1: *const u8,
    packet1_len: usize,
    packet2: *const u8,
    packet2_len: usize,
    out: *mut u8,
    out_len: usize,
    written: *mut usize,
) -> i32 {
    ffi_status(|| {
        let scratch = unsafe { scratch.as_mut() }.ok_or("null quic scratch")?;
        let packet1 = ffi_bytes(packet1, packet1_len, "packet1")?;
        let packet2 = ffi_optional_bytes(packet2, packet2_len, "packet2")?;
        if written.is_null() {
            return Err("null written pointer".into());
        }
        let packets = if let Some(packet2) = packet2 {
            SmallVec::<[&[u8]; 2]>::from_slice(&[packet1, packet2])
        } else {
            SmallVec::<[&[u8]; 2]>::from_slice(&[packet1])
        };
        let sni = sniff_quic_initial_sni_ref(&packets, &mut scratch.scratch)
            .map_err(|error| format!("{error:?}"))?;
        write_ffi_output(sni, out, out_len, written)
    })
}

/// Sniffs an HTTP Host header into a caller-owned buffer.
///
/// # Safety
///
/// `data` must point to `data_len` readable bytes for the duration of this
/// call. `out` must point to `out_len` writable bytes when `out_len` is
/// non-zero. `written` must be a valid writable pointer. Rust must not retain
/// any caller-owned pointer after this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_sniffing_http_host_into(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
    written: *mut usize,
) -> i32 {
    ffi_status(|| {
        let data = ffi_bytes(data, data_len, "http data")?;
        let host = sniff_http_host_ref(data).map_err(|error| format!("{error:?}"))?;
        write_ffi_output(host, out, out_len, written)
    })
}

/// Sniffs a TLS SNI value into a caller-owned buffer.
///
/// # Safety
///
/// `data` must point to `data_len` readable bytes for the duration of this
/// call. `out` must point to `out_len` writable bytes when `out_len` is
/// non-zero. `written` must be a valid writable pointer. Rust must not retain
/// any caller-owned pointer after this call returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dae_sniffing_tls_sni_into(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
    written: *mut usize,
) -> i32 {
    ffi_status(|| {
        let data = ffi_bytes(data, data_len, "tls data")?;
        let sni = sniff_tls_sni_ref(data).map_err(|error| format!("{error:?}"))?;
        write_ffi_output(sni, out, out_len, written)
    })
}

fn write_ffi_output(
    value: &str,
    out: *mut u8,
    out_len: usize,
    written: *mut usize,
) -> Result<(), String> {
    if written.is_null() {
        return Err("null written pointer".into());
    }
    if value.len() > out_len {
        return Err(format!(
            "output buffer too small: got {out_len}, need {}",
            value.len()
        ));
    }
    if !value.is_empty() && out.is_null() {
        return Err("null output buffer".into());
    }
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    out[..value.len()].copy_from_slice(value.as_bytes());
    unsafe {
        *written = value.len();
    }
    Ok(())
}

fn ffi_status(operation: impl FnOnce() -> Result<(), String>) -> i32 {
    clear_ffi_error();
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => FFI_OK,
        Ok(Err(error)) => {
            set_ffi_error(error);
            FFI_ERROR
        }
        Err(_) => {
            set_ffi_error("panic across sniffing FFI boundary");
            FFI_ERROR
        }
    }
}

fn clear_ffi_error() {
    LAST_FFI_ERROR.with(|last_error| {
        *last_error.borrow_mut() = None;
    });
}

fn set_ffi_error(error: impl Into<String>) {
    let mut error = error.into();
    error.retain(|ch| ch != '\0');
    LAST_FFI_ERROR.with(|last_error| {
        *last_error.borrow_mut() =
            Some(CString::new(error).expect("error string was stripped of NUL bytes"));
    });
}

fn ffi_bytes<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(format!("null {name}"));
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn ffi_optional_bytes<'a>(
    ptr: *const u8,
    len: usize,
    name: &str,
) -> Result<Option<&'a [u8]>, String> {
    if len == 0 {
        return Ok(None);
    }
    ffi_bytes(ptr, len, name).map(Some)
}

#[cfg(test)]
mod tests {
    use super::{
        SniffError, parse_quic_initial_header, sniff_http_host, sniff_http_host_ref,
        sniff_quic_initial_sni, sniff_tls_sni, sniff_tls_sni_ref,
    };

    fn decode_hex(input: &str) -> Vec<u8> {
        assert_eq!(input.len() % 2, 0);
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).unwrap())
            .collect()
    }

    fn go_hex_const(name: &str) -> &'static str {
        let source = include_str!("../../../../component/sniffing/tls_test.go");
        let prefix = format!("var {name}, _ = hex.DecodeString(\"");
        let start = source.find(&prefix).unwrap() + prefix.len();
        let tail = &source[start..];
        let end = tail.find('"').unwrap();
        &tail[..end]
    }

    fn go_quic_hex_const(name: &str) -> &'static str {
        let source = include_str!("../../../../component/sniffing/quic_test.go");
        let prefix = format!("var {name}, _ = hex.DecodeString(\"");
        let start = source.find(&prefix).unwrap() + prefix.len();
        let tail = &source[start..];
        let end = tail.find('"').unwrap();
        &tail[..end]
    }

    fn decode_go_hex_const(name: &str) -> Vec<u8> {
        decode_hex(go_hex_const(name))
    }

    fn decode_go_quic_hex_const(name: &str) -> Vec<u8> {
        decode_hex(go_quic_hex_const(name))
    }

    #[test]
    fn http_host_matches_go_current_whitespace_behavior() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        assert_eq!(sniff_http_host(request).unwrap(), " example.com");
        assert_eq!(sniff_http_host_ref(request).unwrap(), " example.com");
    }

    #[test]
    fn http_host_matches_final_line_without_trailing_newline() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com";
        assert_eq!(sniff_http_host(request).unwrap(), " example.com");
        assert_eq!(sniff_http_host_ref(request).unwrap(), " example.com");
    }

    #[test]
    fn http_rejects_unknown_method() {
        let request = b"WHAT / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            sniff_http_host(request).unwrap_err(),
            SniffError::NotApplicable
        );
    }

    #[test]
    fn tls_sni_matches_google_fixture_from_go_const() {
        let stream = decode_go_hex_const("tlsStreamGoogle");
        assert_eq!(sniff_tls_sni(&stream).unwrap(), "www.google.com");
        assert_eq!(sniff_tls_sni_ref(&stream).unwrap(), "www.google.com");
    }

    #[test]
    fn tls_sni_matches_go_fixture_table() {
        let cases = [
            ("tlsStreamGoogle", "www.google.com"),
            ("tlsStreamWindowsOdinGame", "odin.game.daum.net"),
            ("tlsCurlIpsb", "ip.sb"),
        ];
        for (fixture, want) in cases {
            let stream = decode_go_hex_const(fixture);
            assert_eq!(sniff_tls_sni(&stream).unwrap(), want, "{fixture}");
        }
    }

    #[test]
    fn tls_sni_matches_split_go_fixture() {
        let mut stream = decode_go_hex_const("tlsWebTelegramOrm");
        assert_eq!(sniff_tls_sni(&stream).unwrap_err(), SniffError::NeedMore);
        stream.extend(decode_go_hex_const("tlsWebTelegramOrm2"));
        assert_eq!(sniff_tls_sni(&stream).unwrap(), "web.telegram.org");
    }

    #[test]
    #[ignore = "superseded by tls_sni_matches_google_fixture_from_go_const"]
    fn tls_sni_matches_google_fixture() {
        let stream = decode_hex(
            "1603010200010001fc0303d90fdf25b0c7a11c3eb968604a065157a149407c139c22ed32f5c6f486ed2c04206c51c32da7f83c3c19766be60d45d264e898c77504e34915c44caa69513c2221003e130213031301c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff0100017500000013001100000e7777772e676f6f676c652e636f6d000b000403000102000a00160014001d0017001e00190018010001010102010301040010000e000c02683208687474702f312e31001600000017000000310000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b0009080304030303020301002d00020101003300260024001d00207fe08226bdc4fb1715e477506b6afe8f3abe2d20daa1f8c78c5483f1a90a9b19001500af00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(sniff_tls_sni(&stream).unwrap(), "www.google.com");
    }

    #[test]
    fn tls_sni_returns_need_more_for_partial_record() {
        let partial = [0x16, 0x03, 0x01, 0x00, 0x10, 0x01];
        assert_eq!(sniff_tls_sni(&partial).unwrap_err(), SniffError::NeedMore);
    }

    #[test]
    fn quic_initial_header_matches_go_fixture_boundaries() {
        for fixture in ["QuicStream2_1", "QuicStream2_2", "QuicStream3"] {
            let stream = decode_go_quic_hex_const(fixture);
            let header = parse_quic_initial_header(&stream).unwrap();
            assert_eq!(header.version, 1, "{fixture}");
            assert!(!header.destination_connection_id.is_empty(), "{fixture}");
            assert!(header.protected_header_len <= header.block_end, "{fixture}");
            assert!(header.block_end <= stream.len(), "{fixture}");
            if fixture != "QuicStream3" {
                assert_eq!(header.block_end, stream.len(), "{fixture}");
            }
        }
    }

    #[test]
    fn quic_initial_header_rejects_short_or_non_initial_packets() {
        assert_eq!(
            parse_quic_initial_header(&[0xc0, 0x00]).unwrap_err(),
            SniffError::NotApplicable
        );
        assert_eq!(
            parse_quic_initial_header(b"GET / HTTP/1.1\r\n").unwrap_err(),
            SniffError::NotApplicable
        );
    }

    #[test]
    fn quic_initial_sni_matches_split_go_fixture() {
        let stream1 = decode_go_quic_hex_const("QuicStream2_1");
        let stream2 = decode_go_quic_hex_const("QuicStream2_2");
        assert_eq!(
            sniff_quic_initial_sni(&[&stream1, &stream2]).unwrap(),
            "i.ytimg.com"
        );
    }

    #[test]
    fn quic_initial_sni_ref_reuses_scratch() {
        let stream1 = decode_go_quic_hex_const("QuicStream2_1");
        let stream2 = decode_go_quic_hex_const("QuicStream2_2");
        let mut scratch = super::QuicSniffScratch::new();
        for _ in 0..3 {
            assert_eq!(
                super::sniff_quic_initial_sni_ref(&[&stream1, &stream2], &mut scratch).unwrap(),
                "i.ytimg.com"
            );
        }
    }

    #[test]
    fn quic_initial_sni_matches_single_go_fixture() {
        let stream = decode_go_quic_hex_const("QuicStream3");
        assert_eq!(sniff_quic_initial_sni(&[&stream]).unwrap(), "i.ytimg.com");
    }
}
