// SPDX-License-Identifier: MIT
use libc::{free, malloc};
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use std::convert::TryInto;
use std::ptr;
use std::slice;

const WORKER_API_VERSION: u32 = 1;
const FLAG_PRIVATE_KEYS_PRESENT: u32 = 1 << 1;
const FLAG_PUBLIC_KEYS_PRESENT: u32 = 1 << 2;
const SUPPORTED_FLAGS_MASK: u32 = (1 << 0) | FLAG_PRIVATE_KEYS_PRESENT | FLAG_PUBLIC_KEYS_PRESENT;
const INPUT_TYPE_P2WPKH: u8 = 0x01;
const INPUT_TYPE_P2TR_KEYPATH: u8 = 0x02;
const INPUT_TYPE_P2SH_P2WPKH: u8 = 0x03;

type CompressedPubkey = [u8; 33];
type OutputRecord = (CompressedPubkey, [u8; 32]);

#[repr(u32)]
#[derive(Copy, Clone)]
enum Status {
    Ok = 0,
    InvalidInput = 1,
    PointAtInfinity = 2,
    ZeroScalar = 3,
    InvalidPubkey = 4,
    TweakOutOfRange = 5,
    Internal = 255,
}

struct Reader<'a> {
    buf: &'a [u8],
    off: usize,
}

#[derive(Clone)]
struct InputEntry {
    outpoint_txid: [u8; 32],
    outpoint_vout: u32,
    input_type: u8,
    privkey: Option<[u8; 32]>,
    pubkey: Option<CompressedPubkey>,
}

struct CaseV1 {
    output_count: u16,
    inputs: Vec<InputEntry>,
    scan_pubkey: CompressedPubkey,
    spend_pubkey: CompressedPubkey,
    labels: Vec<u32>,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, off: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.off + 1 > self.buf.len() {
            return None;
        }
        let value = self.buf[self.off];
        self.off += 1;
        Some(value)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.off + 2 > self.buf.len() {
            return None;
        }
        let value = u16::from_le_bytes([self.buf[self.off], self.buf[self.off + 1]]);
        self.off += 2;
        Some(value)
    }

    fn read_u32(&mut self) -> Option<u32> {
        if self.off + 4 > self.buf.len() {
            return None;
        }
        let value = u32::from_le_bytes([
            self.buf[self.off],
            self.buf[self.off + 1],
            self.buf[self.off + 2],
            self.buf[self.off + 3],
        ]);
        self.off += 4;
        Some(value)
    }

    fn read_u64(&mut self) -> Option<u64> {
        if self.off + 8 > self.buf.len() {
            return None;
        }
        let value = u64::from_le_bytes([
            self.buf[self.off],
            self.buf[self.off + 1],
            self.buf[self.off + 2],
            self.buf[self.off + 3],
            self.buf[self.off + 4],
            self.buf[self.off + 5],
            self.buf[self.off + 6],
            self.buf[self.off + 7],
        ]);
        self.off += 8;
        Some(value)
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.off + len > self.buf.len() {
            return None;
        }
        let bytes = &self.buf[self.off..self.off + len];
        self.off += len;
        Some(bytes)
    }
}

fn is_valid_input_type(input_type: u8) -> bool {
    matches!(
        input_type,
        INPUT_TYPE_P2WPKH | INPUT_TYPE_P2TR_KEYPATH | INPUT_TYPE_P2SH_P2WPKH
    )
}

fn looks_like_compressed_pubkey(pubkey: &[u8]) -> bool {
    pubkey.len() == 33 && matches!(pubkey[0], 0x02 | 0x03)
}

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(payload: &[u8]) -> [u8; 32] {
    fn ch(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ ((!x) & z)
    }
    fn maj(x: u32, y: u32, z: u32) -> u32 {
        (x & y) ^ (x & z) ^ (y & z)
    }
    fn big_sigma0(x: u32) -> u32 {
        x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
    }
    fn big_sigma1(x: u32) -> u32 {
        x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
    }
    fn small_sigma0(x: u32) -> u32 {
        x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
    }
    fn small_sigma1(x: u32) -> u32 {
        x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
    }

    let bit_len = (payload.len() as u64) * 8;
    let mut message = payload.to_vec();
    message.push(0x80);
    while (message.len() % 64) != 56 {
        message.push(0x00);
    }
    message.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = SHA256_INITIAL_STATE;
    for chunk in message.chunks_exact(64) {
        let mut w = [0u32; 64];
        for (i, word) in w.iter_mut().take(16).enumerate() {
            let base = i * 4;
            *word = u32::from_be_bytes([
                chunk[base],
                chunk[base + 1],
                chunk[base + 2],
                chunk[base + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

        for i in 0..64 {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

// BIP352 uses BIP340-style tagged hashes and then interprets the digest as a
// scalar. Invalid scalars are treated as tweak-out-of-range.
fn tagged_hash_scalar(tag: &str, message: &[u8]) -> Result<Scalar, Status> {
    let tag_hash = sha256(tag.as_bytes());
    let mut payload = Vec::with_capacity(tag_hash.len() * 2 + message.len());
    payload.extend_from_slice(&tag_hash);
    payload.extend_from_slice(&tag_hash);
    payload.extend_from_slice(message);
    Scalar::from_be_bytes(sha256(&payload)).map_err(|_| Status::TweakOutOfRange)
}

fn serialize_pubkey(pubkey: &PublicKey) -> CompressedPubkey {
    pubkey.serialize()
}

/// Apply the BIP 352 Taproot sender rule.
///
/// Taproot inputs use the negated secret key when the corresponding full
/// public key has odd Y so the derived x-only key follows the even-Y
/// convention.
pub fn negate_if_odd_y(secp: &Secp256k1<secp256k1::All>, secret_key: SecretKey) -> SecretKey {
    let pubkey = PublicKey::from_secret_key(secp, &secret_key);
    let serialized = pubkey.serialize();
    let y_parity_byte = serialized[0];

    if y_parity_byte == 0x03 {
        secret_key.negate()
    } else {
        secret_key
    }
}

/// Normalize one input private key for the v1 worker path.
///
/// Only Taproot inputs use the BIP 352 negation rule; all other supported
/// input types pass through unchanged.
pub fn prepare_input_key(
    secp: &Secp256k1<secp256k1::All>,
    secret_key: SecretKey,
    input_type: u8,
) -> SecretKey {
    match input_type {
        INPUT_TYPE_P2TR_KEYPATH => negate_if_odd_y(secp, secret_key),
        _ => secret_key,
    }
}

fn parse_case_v1(input: *const u8, input_len: usize) -> Option<CaseV1> {
    if input.is_null() {
        return None;
    }

    let buf = unsafe { slice::from_raw_parts(input, input_len) };
    let mut reader = Reader::new(buf);

    let version = reader.read_u8()?;
    if version != 1 {
        return None;
    }

    reader.read_u64()?;

    let flags = reader.read_u32()?;
    if (flags & !SUPPORTED_FLAGS_MASK) != 0 {
        return None;
    }

    let input_count = reader.read_u16()?;
    let output_count = reader.read_u16()?;

    let has_priv = (flags & FLAG_PRIVATE_KEYS_PRESENT) != 0;
    let has_pub = (flags & FLAG_PUBLIC_KEYS_PRESENT) != 0;
    let mut inputs = Vec::with_capacity(input_count as usize);

    for _ in 0..input_count {
        let outpoint_txid: [u8; 32] = reader.read_bytes(32)?.try_into().ok()?;
        let outpoint_vout = reader.read_u32()?;
        let input_type = reader.read_u8()?;
        if !is_valid_input_type(input_type) {
            return None;
        }

        let privkey = if has_priv {
            Some(reader.read_bytes(32)?.try_into().ok()?)
        } else {
            None
        };
        let pubkey = if has_pub {
            let value: CompressedPubkey = reader.read_bytes(33)?.try_into().ok()?;
            Some(value)
        } else {
            None
        };

        inputs.push(InputEntry {
            outpoint_txid,
            outpoint_vout,
            input_type,
            privkey,
            pubkey,
        });
    }

    let scan_pubkey: CompressedPubkey = reader.read_bytes(33)?.try_into().ok()?;
    let spend_pubkey: CompressedPubkey = reader.read_bytes(33)?.try_into().ok()?;
    if !looks_like_compressed_pubkey(&scan_pubkey) || !looks_like_compressed_pubkey(&spend_pubkey) {
        return None;
    }

    let label_count = reader.read_u16()?;
    let mut labels = Vec::with_capacity(label_count as usize);
    for _ in 0..label_count {
        labels.push(reader.read_u32()?);
    }

    if reader.off != buf.len() {
        return None;
    }

    Some(CaseV1 {
        output_count,
        inputs,
        scan_pubkey,
        spend_pubkey,
        labels,
    })
}

fn derive_input_material(
    secp: &Secp256k1<secp256k1::All>,
    entry: &InputEntry,
) -> Result<(SecretKey, PublicKey), Status> {
    if !is_valid_input_type(entry.input_type) {
        return Err(Status::InvalidInput);
    }
    let raw_privkey = entry.privkey.ok_or(Status::InvalidInput)?;
    let secret_key = SecretKey::from_slice(&raw_privkey).map_err(|_| Status::InvalidInput)?;
    let normalized = prepare_input_key(secp, secret_key, entry.input_type);
    let derived_pubkey = PublicKey::from_secret_key(secp, &normalized);

    if let Some(pubkey_bytes) = entry.pubkey {
        if serialize_pubkey(&derived_pubkey) != pubkey_bytes {
            return Err(Status::InvalidInput);
        }
    }

    Ok((normalized, derived_pubkey))
}

// BIP352 hashes the lexicographically smallest serialized outpoint, not the
// first input encountered in the case payload.
fn build_smallest_outpoint(inputs: &[InputEntry]) -> Result<[u8; 36], Status> {
    let mut smallest: Option<[u8; 36]> = None;
    for entry in inputs {
        let mut current = [0u8; 36];
        current[..32].copy_from_slice(&entry.outpoint_txid);
        current[32..36].copy_from_slice(&entry.outpoint_vout.to_le_bytes());
        smallest = match smallest {
            Some(existing) if existing <= current => Some(existing),
            _ => Some(current),
        };
    }
    smallest.ok_or(Status::InvalidInput)
}

fn sum_input_secret_keys(input_keys: &[SecretKey]) -> Result<SecretKey, Status> {
    let mut iter = input_keys.iter().copied();
    let mut sum = iter.next().ok_or(Status::InvalidInput)?;
    for key in iter {
        sum = sum
            .add_tweak(&Scalar::from(key))
            .map_err(|_| Status::ZeroScalar)?;
    }
    Ok(sum)
}

fn compute_input_hash(
    input_pubkey_sum: &PublicKey,
    smallest_outpoint: &[u8; 36],
) -> Result<Scalar, Status> {
    let mut message = Vec::with_capacity(36 + 33);
    message.extend_from_slice(smallest_outpoint);
    message.extend_from_slice(&serialize_pubkey(input_pubkey_sum));
    tagged_hash_scalar("BIP0352/Inputs", &message)
}

// shared_secret = input_hash * a_sum * B_scan for the sender path.
// mul_tweak failures are mapped separately so bad scalar inputs do not turn
// into a silent wrong result.
fn compute_shared_secret(
    secp: &Secp256k1<secp256k1::All>,
    scan_pubkey: &PublicKey,
    input_private_key_sum: SecretKey,
    input_hash: Scalar,
) -> Result<PublicKey, Status> {
    let input_scalar = Scalar::from(input_private_key_sum);
    let after_input_sum = scan_pubkey
        .mul_tweak(secp, &input_scalar)
        .map_err(|_| Status::Internal)?;
    after_input_sum
        .mul_tweak(secp, &input_hash)
        .map_err(|_| Status::TweakOutOfRange)
}

fn build_output_records(
    secp: &Secp256k1<secp256k1::All>,
    parsed: &CaseV1,
) -> Result<Vec<OutputRecord>, Status> {
    // The v1 byte-worker path does not implement label-derived outputs. Labels
    // belong to the richer v2 semantic path.
    if !parsed.labels.is_empty() {
        return Err(Status::InvalidInput);
    }

    if parsed.output_count == 0 {
        return Ok(Vec::new());
    }

    let mut input_keys = Vec::with_capacity(parsed.inputs.len());
    let mut input_pubkeys = Vec::with_capacity(parsed.inputs.len());
    for entry in &parsed.inputs {
        let (secret_key, pubkey) = derive_input_material(secp, entry)?;
        input_keys.push(secret_key);
        input_pubkeys.push(pubkey);
    }

    let input_private_key_sum = sum_input_secret_keys(&input_keys)?;

    let input_pubkey_refs: Vec<&PublicKey> = input_pubkeys.iter().collect();
    // combine_keys fails when the normalized sender input pubkeys sum to the
    // point at infinity. Surface that explicitly instead of continuing with a
    // bogus input hash.
    let input_pubkey_sum =
        PublicKey::combine_keys(&input_pubkey_refs).map_err(|_| Status::PointAtInfinity)?;

    let smallest_outpoint = build_smallest_outpoint(&parsed.inputs)?;
    let input_hash = compute_input_hash(&input_pubkey_sum, &smallest_outpoint)?;

    let scan_pubkey =
        PublicKey::from_slice(&parsed.scan_pubkey).map_err(|_| Status::InvalidPubkey)?;
    let spend_pubkey =
        PublicKey::from_slice(&parsed.spend_pubkey).map_err(|_| Status::InvalidPubkey)?;
    let shared_secret =
        compute_shared_secret(secp, &scan_pubkey, input_private_key_sum, input_hash)?;
    let shared_secret_bytes = serialize_pubkey(&shared_secret);

    let mut outputs = Vec::with_capacity(parsed.output_count as usize);
    // Per-output tweaks use ser32(index) in big-endian order:
    // tweak_n = tagged_hash("BIP0352/SharedSecret", shared_secret || ser32(n)).
    for index in 0..u32::from(parsed.output_count) {
        let mut message = Vec::with_capacity(shared_secret_bytes.len() + 4);
        message.extend_from_slice(&shared_secret_bytes);
        message.extend_from_slice(&index.to_be_bytes());
        let tweak = tagged_hash_scalar("BIP0352/SharedSecret", &message)?;
        let tweaked_pubkey = spend_pubkey
            .add_exp_tweak(secp, &tweak)
            .map_err(|_| Status::TweakOutOfRange)?;
        outputs.push((serialize_pubkey(&tweaked_pubkey), tweak.to_be_bytes()));
    }

    Ok(outputs)
}

fn serialize_output_payload(status: Status, outputs: &[OutputRecord]) -> Vec<u8> {
    let output_count = if matches!(status, Status::Ok) {
        outputs.len() as u16
    } else {
        0
    };
    let mut payload = Vec::with_capacity(4 + usize::from(output_count) * (33 + 32));
    payload.push(1);
    payload.push(status as u8);
    payload.extend_from_slice(&output_count.to_le_bytes());
    if !matches!(status, Status::Ok) {
        return payload;
    }
    for (pubkey, _) in outputs {
        payload.extend_from_slice(pubkey);
    }
    for (_, tweak) in outputs {
        payload.extend_from_slice(tweak);
    }
    payload
}

fn run_case_v1(input: *const u8, input_len: usize) -> Result<Vec<u8>, ()> {
    let parsed = match parse_case_v1(input, input_len) {
        Some(value) => value,
        None => return Ok(serialize_output_payload(Status::InvalidInput, &[])),
    };

    let secp = Secp256k1::new();
    match build_output_records(&secp, &parsed) {
        Ok(records) => Ok(serialize_output_payload(Status::Ok, &records)),
        Err(status) => Ok(serialize_output_payload(status, &[])),
    }
}

#[no_mangle]
pub extern "C" fn sp_differ_worker_api_version() -> u32 {
    WORKER_API_VERSION
}

#[no_mangle]
/// Runs the v1 byte-worker ABI entrypoint.
///
/// # Safety
/// `output` and `output_len` must be valid writable pointers. When `input_len`
/// is non-zero, `input` must point to `input_len` readable bytes. Any buffer
/// returned through `output` must be released with `sp_differ_worker_free`.
pub unsafe extern "C" fn sp_differ_worker_run(
    input: *const u8,
    input_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> i32 {
    if output.is_null() || output_len.is_null() {
        return -1;
    }

    let payload = match run_case_v1(input, input_len) {
        Ok(value) => value,
        Err(()) => return -1,
    };
    let size = if payload.is_empty() { 1 } else { payload.len() };

    unsafe {
        let ptr = malloc(size) as *mut u8;
        if ptr.is_null() {
            return -1;
        }
        if !payload.is_empty() {
            ptr::copy_nonoverlapping(payload.as_ptr(), ptr, payload.len());
        }
        *output = ptr;
        *output_len = payload.len();
    }

    0
}

#[no_mangle]
/// Releases a buffer returned by `sp_differ_worker_run`.
///
/// # Safety
/// `output` must be null or a pointer returned by `sp_differ_worker_run` that
/// has not already been freed.
pub unsafe extern "C" fn sp_differ_worker_free(output: *mut u8) {
    if !output.is_null() {
        unsafe { free(output as *mut libc::c_void) };
    }
}

#[cfg(test)]
mod taproot_negation_tests {
    use super::*;
    use serde_json::Value;
    use std::fs;
    use std::path::PathBuf;

    fn build_v1_case(input_type: u8) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.push(1);
        payload.extend_from_slice(&0u64.to_le_bytes());
        payload.extend_from_slice(&FLAG_PRIVATE_KEYS_PRESENT.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&1u16.to_le_bytes());
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.push(input_type);

        let mut privkey = [0u8; 32];
        privkey[31] = 1;
        payload.extend_from_slice(&privkey);

        payload.push(0x02);
        payload.extend_from_slice(&[0u8; 32]);
        payload.push(0x02);
        payload.extend_from_slice(&[0u8; 32]);
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload
    }

    fn repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workers/")
            .parent()
            .expect("repo root")
            .to_path_buf()
    }

    fn run_case_payload(payload: &[u8]) -> Vec<u8> {
        let mut output = ptr::null_mut();
        let mut output_len = 0usize;
        let rc = unsafe {
            sp_differ_worker_run(
                payload.as_ptr(),
                payload.len(),
                &mut output,
                &mut output_len,
            )
        };
        assert_eq!(rc, 0, "worker must return success");
        let bytes = unsafe { slice::from_raw_parts(output, output_len) }.to_vec();
        unsafe { sp_differ_worker_free(output) };
        bytes
    }

    fn parse_output_payload(payload: &[u8]) -> (u8, u16, Vec<[u8; 33]>, Vec<[u8; 32]>) {
        assert!(payload.len() >= 4);
        let status = payload[1];
        let output_count = u16::from_le_bytes([payload[2], payload[3]]);
        let mut off = 4usize;
        let mut pubkeys = Vec::new();
        for _ in 0..output_count {
            let value: [u8; 33] = payload[off..off + 33].try_into().unwrap();
            pubkeys.push(value);
            off += 33;
        }
        let mut tweaks = Vec::new();
        for _ in 0..output_count {
            let value: [u8; 32] = payload[off..off + 32].try_into().unwrap();
            tweaks.push(value);
            off += 32;
        }
        (status, output_count, pubkeys, tweaks)
    }

    fn decode_hex(input: &str) -> Vec<u8> {
        fn nibble(ch: u8) -> u8 {
            match ch {
                b'0'..=b'9' => ch - b'0',
                b'a'..=b'f' => 10 + (ch - b'a'),
                b'A'..=b'F' => 10 + (ch - b'A'),
                _ => panic!("invalid hex"),
            }
        }

        let bytes = input.as_bytes();
        assert_eq!(bytes.len() % 2, 0);
        let mut out = Vec::with_capacity(bytes.len() / 2);
        let mut i = 0usize;
        while i < bytes.len() {
            out.push((nibble(bytes[i]) << 4) | nibble(bytes[i + 1]));
            i += 2;
        }
        out
    }

    fn encode_hex(input: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(input.len() * 2);
        for byte in input {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn test_taproot_odd_y_key_is_negated() {
        let secp = Secp256k1::new();

        let mut found_odd: Option<SecretKey> = None;
        for i in 2u32..1000 {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&i.to_be_bytes());
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                let pk = PublicKey::from_secret_key(&secp, &sk);
                let serialized = pk.serialize();
                if serialized[0] == 0x03 {
                    found_odd = Some(sk);
                    break;
                }
            }
        }

        let odd_y_key = found_odd.expect("Should find odd-Y key within first 1000 scalars");
        let negated = prepare_input_key(&secp, odd_y_key, INPUT_TYPE_P2TR_KEYPATH);

        let negated_pk = PublicKey::from_secret_key(&secp, &negated);
        let negated_serialized = negated_pk.serialize();
        assert_eq!(
            negated_serialized[0], 0x02,
            "After negation, Y coordinate must be even (0x02 prefix). Got 0x{:02x}.",
            negated_serialized[0]
        );
    }

    #[test]
    fn test_non_taproot_key_is_not_negated() {
        let secp = Secp256k1::new();

        let mut odd_key: Option<SecretKey> = None;
        for i in 2u32..1000 {
            let mut bytes = [0u8; 32];
            bytes[28..32].copy_from_slice(&i.to_be_bytes());
            if let Ok(sk) = SecretKey::from_slice(&bytes) {
                let pk = PublicKey::from_secret_key(&secp, &sk);
                if pk.serialize()[0] == 0x03 {
                    odd_key = Some(sk);
                    break;
                }
            }
        }

        let key = odd_key.expect("Should find odd-Y key within first 1000 scalars");
        let key_bytes_before = key.secret_bytes();

        let result = prepare_input_key(&secp, key, INPUT_TYPE_P2WPKH);
        assert_eq!(
            result.secret_bytes(),
            key_bytes_before,
            "Non-Taproot keys must NOT be negated regardless of Y parity"
        );
    }

    #[test]
    fn test_v1_rejects_p2pkh_marker() {
        let payload = build_v1_case(0x04);
        let output = run_case_payload(&payload);
        let (status, _, _, _) = parse_output_payload(&output);
        assert_eq!(status, Status::InvalidInput as u8);
    }

    #[test]
    fn test_official_case_07_matches_expected_xonly_output() {
        let root = repo_root();
        let case_path = root.join("tests/vectors/bip352/derived/v1/official_case_07_send_00.hex");
        let manifest_path = root.join("tests/vectors/bip352/derived/v1/manifest.json");
        let payload = fs::read_to_string(case_path).unwrap();
        let output = run_case_payload(&decode_hex(payload.trim()));
        let (status, output_count, pubkeys, _) = parse_output_payload(&output);
        assert_eq!(status, Status::Ok as u8);
        assert_eq!(output_count, 1);

        let manifest: Value =
            serde_json::from_str(&fs::read_to_string(manifest_path).unwrap()).unwrap();
        let case = manifest["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["official_case_index"] == 7)
            .unwrap();
        let expected_xonly = case["expected_outputs_xonly_groups"][0][0]
            .as_str()
            .unwrap();
        let actual_xonly = encode_hex(&pubkeys[0][1..]);
        assert_eq!(actual_xonly, expected_xonly);
    }

    #[test]
    fn test_official_case_25_returns_zero_scalar() {
        let root = repo_root();
        let case_path = root.join("tests/vectors/bip352/derived/v1/official_case_25_send_00.hex");
        let payload = fs::read_to_string(case_path).unwrap();
        let output = run_case_payload(&decode_hex(payload.trim()));
        let (status, output_count, _, _) = parse_output_payload(&output);
        assert_eq!(status, Status::ZeroScalar as u8);
        assert_eq!(output_count, 0);
    }
}
