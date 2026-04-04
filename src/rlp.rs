//! Minimal RLP encoding for HCA transactions.
//!
//! We implement only what's needed for HCA transaction encoding,
//! avoiding external dependencies for this simple, fixed-schema use case.
//!
//! RLP (Recursive Length Prefix) encoding rules:
//! - Single byte [0x00, 0x7f]: encoded as itself
//! - String 0-55 bytes: [0x80 + len, ...bytes]
//! - String >55 bytes: [0xb7 + len_of_len, ...len_bytes, ...bytes]
//! - List 0-55 bytes: [0xc0 + len, ...items]
//! - List >55 bytes: [0xf7 + len_of_len, ...len_bytes, ...items]

#[cfg(not(feature = "std"))]
use alloc::{format, string::String, string::ToString, vec, vec::Vec};

use crate::constants::HCA_TX_TYPE;
use crate::error::{HcaError, HcaResult};
use crate::witness::{HCAWitness, TxMessage};

/// Encode an unsigned integer as RLP
///
/// Integers are encoded as big-endian bytes with leading zeros stripped.
/// Zero is encoded as 0x80 (empty byte string).
///
/// # Examples
///
/// ```
/// use hca_rs::rlp::encode_uint;
///
/// assert_eq!(encode_uint(0), vec![0x80]);
/// assert_eq!(encode_uint(15), vec![0x0f]);
/// assert_eq!(encode_uint(1024), vec![0x82, 0x04, 0x00]);
/// ```
pub fn encode_uint(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80]; // empty byte string
    }

    // Convert to big-endian bytes, strip leading zeros
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let trimmed = &bytes[start..];

    // Single byte in range [0x00, 0x7f] encodes as itself
    if trimmed.len() == 1 && trimmed[0] < 0x80 {
        return vec![trimmed[0]];
    }

    encode_bytes(trimmed)
}

/// Encode a byte array as RLP
///
/// # Examples
///
/// ```
/// use hca_rs::rlp::encode_bytes;
///
/// // Empty bytes
/// assert_eq!(encode_bytes(&[]), vec![0x80]);
///
/// // Single byte < 0x80
/// assert_eq!(encode_bytes(&[0x42]), vec![0x42]);
///
/// // Short string
/// assert_eq!(encode_bytes(&[0x82, 0x83]), vec![0x82, 0x82, 0x83]);
/// ```
pub fn encode_bytes(data: &[u8]) -> Vec<u8> {
    let len = data.len();

    if len == 0 {
        return vec![0x80]; // empty string
    }

    // Single byte in range [0x00, 0x7f] encodes as itself
    if len == 1 && data[0] < 0x80 {
        return vec![data[0]];
    }

    if len <= 55 {
        // Short string: [0x80 + len, ...data]
        let mut result = Vec::with_capacity(1 + len);
        result.push(0x80 + len as u8);
        result.extend_from_slice(data);
        result
    } else {
        // Long string: [0xb7 + len_of_len, ...len_bytes, ...data]
        let len_bytes = encode_length(len);
        let mut result = Vec::with_capacity(1 + len_bytes.len() + len);
        result.push(0xb7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(data);
        result
    }
}

/// Encode a list of RLP-encoded items
///
/// # Examples
///
/// ```
/// use hca_rs::rlp::{encode_list, encode_uint};
///
/// let items = vec![encode_uint(1), encode_uint(2), encode_uint(3)];
/// let encoded = encode_list(&items);
/// assert_eq!(encoded, vec![0xc3, 0x01, 0x02, 0x03]);
/// ```
pub fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    // Concatenate all items
    let total_len: usize = items.iter().map(|item| item.len()).sum();

    if total_len <= 55 {
        // Short list: [0xc0 + len, ...items]
        let mut result = Vec::with_capacity(1 + total_len);
        result.push(0xc0 + total_len as u8);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    } else {
        // Long list: [0xf7 + len_of_len, ...len_bytes, ...items]
        let len_bytes = encode_length(total_len);
        let mut result = Vec::with_capacity(1 + len_bytes.len() + total_len);
        result.push(0xf7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
        for item in items {
            result.extend_from_slice(item);
        }
        result
    }
}

/// Encode an address (20 bytes) as RLP
pub fn encode_address(address: &[u8; 20]) -> Vec<u8> {
    let mut result = Vec::with_capacity(21);
    result.push(0x80 + 20); // 0x94
    result.extend_from_slice(address);
    result
}

/// Encode HCA transaction as EIP-2718 typed transaction
///
/// Format: HCA_TX_TYPE || RLP([fields...])
///
/// Returns the complete transaction bytes ready for signing or broadcasting.
pub fn encode_hca_tx(tx: &TxMessage, witness: &HCAWitness) -> HcaResult<Vec<u8>> {
    if !witness.is_signed() {
        return Err(HcaError::WitnessNotSigned);
    }

    // Encode merkle proof siblings as a list
    let siblings: Vec<Vec<u8>> = witness
        .merkle_proof
        .siblings
        .iter()
        .map(|s| encode_bytes(s))
        .collect();

    // Build the transaction field list
    let fields = vec![
        // Transaction fields
        encode_uint(tx.chain_id as u128),
        encode_uint(tx.nonce as u128),
        encode_address(&tx.from),
        encode_address(&tx.to),
        encode_uint(tx.value),
        encode_uint(tx.gas_limit as u128),
        encode_uint(tx.max_fee_per_gas),
        encode_uint(tx.max_priority_fee_per_gas),
        // Empty access list (for now)
        encode_list(&[]),
        // Calldata
        encode_bytes(&tx.data),
        // Witness fields
        encode_uint(witness.leaf_version as u128),
        encode_bytes(&witness.leaf_script),
        encode_uint(witness.merkle_proof.leaf_index as u128),
        encode_list(&siblings),
        encode_bytes(&witness.witness_data),
    ];

    // Encode the full transaction list
    let rlp_payload = encode_list(&fields);

    // Prepend EIP-2718 transaction type
    let mut result = Vec::with_capacity(1 + rlp_payload.len());
    result.push(HCA_TX_TYPE);
    result.extend_from_slice(&rlp_payload);

    Ok(result)
}

// ── Decoding ─────────────────────────────────────────────────────────────────

/// Decode an RLP-encoded byte string.
///
/// Returns `(decoded_bytes, bytes_consumed)`.
///
/// # Errors
///
/// Returns `HcaError::RlpDecodeError` if the input is truncated or malformed.
pub fn decode_bytes(input: &[u8]) -> HcaResult<(Vec<u8>, usize)> {
    if input.is_empty() {
        return Err(HcaError::RlpDecodeError("empty input".to_string()));
    }

    let first = input[0];

    if first < 0x80 {
        // Single byte — encodes itself
        return Ok((vec![first], 1));
    }

    if first <= 0xb7 {
        // Short string: length in first byte
        let len = (first - 0x80) as usize;
        if input.len() < 1 + len {
            return Err(HcaError::RlpDecodeError(format!(
                "short string truncated: need {} bytes, have {}",
                len,
                input.len() - 1
            )));
        }
        return Ok((input[1..1 + len].to_vec(), 1 + len));
    }

    if first <= 0xbf {
        // Long string: next (first - 0xb7) bytes are the length
        let len_of_len = (first - 0xb7) as usize;
        if input.len() < 1 + len_of_len {
            return Err(HcaError::RlpDecodeError(
                "long string length bytes truncated".to_string(),
            ));
        }
        let len = decode_usize_be(&input[1..1 + len_of_len])?;
        if input.len() < 1 + len_of_len + len {
            return Err(HcaError::RlpDecodeError(format!(
                "long string payload truncated: need {} bytes",
                len
            )));
        }
        return Ok((
            input[1 + len_of_len..1 + len_of_len + len].to_vec(),
            1 + len_of_len + len,
        ));
    }

    Err(HcaError::RlpDecodeError(format!(
        "expected byte string, got list prefix 0x{:02x}",
        first
    )))
}

/// Decode an RLP-encoded unsigned integer.
///
/// Returns `(value_as_u128, bytes_consumed)`.
///
/// # Errors
///
/// Returns `HcaError::RlpDecodeError` if the integer is wider than 16 bytes (u128).
pub fn decode_uint(input: &[u8]) -> HcaResult<(u128, usize)> {
    let (bytes, consumed) = decode_bytes(input)?;
    if bytes.len() > 16 {
        return Err(HcaError::RlpDecodeError(format!(
            "integer too wide: {} bytes (max 16)",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 16];
    buf[16 - bytes.len()..].copy_from_slice(&bytes);
    Ok((u128::from_be_bytes(buf), consumed))
}

/// Decode an RLP-encoded list.
///
/// Returns `(raw_items_payload, bytes_consumed)` — callers decode individual
/// items from the payload themselves.
///
/// # Errors
///
/// Returns `HcaError::RlpDecodeError` if the input is not a valid RLP list.
pub fn decode_list(input: &[u8]) -> HcaResult<(Vec<u8>, usize)> {
    if input.is_empty() {
        return Err(HcaError::RlpDecodeError("empty input".to_string()));
    }

    let first = input[0];

    if first < 0xc0 {
        return Err(HcaError::RlpDecodeError(format!(
            "expected list prefix >= 0xc0, got 0x{:02x}",
            first
        )));
    }

    if first <= 0xf7 {
        // Short list
        let len = (first - 0xc0) as usize;
        if input.len() < 1 + len {
            return Err(HcaError::RlpDecodeError(format!(
                "short list truncated: need {} bytes, have {}",
                len,
                input.len() - 1
            )));
        }
        return Ok((input[1..1 + len].to_vec(), 1 + len));
    }

    // Long list
    let len_of_len = (first - 0xf7) as usize;
    if input.len() < 1 + len_of_len {
        return Err(HcaError::RlpDecodeError(
            "long list length bytes truncated".to_string(),
        ));
    }
    let len = decode_usize_be(&input[1..1 + len_of_len])?;
    if input.len() < 1 + len_of_len + len {
        return Err(HcaError::RlpDecodeError(format!(
            "long list payload truncated: need {} bytes",
            len
        )));
    }
    Ok((
        input[1 + len_of_len..1 + len_of_len + len].to_vec(),
        1 + len_of_len + len,
    ))
}

/// Decode a raw HCA typed transaction.
///
/// Expects bytes in the format produced by `encode_hca_tx()`:
/// `HCA_TX_TYPE || RLP([fields...])`
///
/// Returns `(TxMessage, HCAWitness)` on success.
///
/// # Errors
///
/// - `RlpDecodeError` if bytes are malformed or truncated
/// - `RlpDecodeError` if the type byte is not `HCA_TX_TYPE`
#[allow(unused_assignments)]
pub fn decode_hca_tx(raw: &[u8]) -> HcaResult<(TxMessage, HCAWitness)> {
    use crate::merkle::{Leaf, MerkleProof};

    if raw.is_empty() {
        return Err(HcaError::RlpDecodeError("empty input".to_string()));
    }

    if raw[0] != HCA_TX_TYPE {
        return Err(HcaError::RlpDecodeError(format!(
            "wrong tx type: expected 0x{:02x}, got 0x{:02x}",
            HCA_TX_TYPE, raw[0]
        )));
    }

    // Decode the outer list
    let (payload, _) = decode_list(&raw[1..])?;
    let mut cursor = 0usize;

    macro_rules! next_uint {
        () => {{
            let (val, consumed) = decode_uint(&payload[cursor..])?;
            cursor += consumed;
            val
        }};
    }

    macro_rules! next_bytes {
        () => {{
            let (val, consumed) = decode_bytes(&payload[cursor..])?;
            cursor += consumed;
            val
        }};
    }

    macro_rules! next_list_payload {
        () => {{
            let (val, consumed) = decode_list(&payload[cursor..])?;
            cursor += consumed;
            val
        }};
    }

    // ── Transaction fields ────────────────────────────────────────────────────
    let chain_id = next_uint!() as u64;
    let nonce = next_uint!() as u64;

    let from_bytes = next_bytes!();
    if from_bytes.len() != 20 {
        return Err(HcaError::RlpDecodeError(format!(
            "from address must be 20 bytes, got {}",
            from_bytes.len()
        )));
    }
    let mut from = [0u8; 20];
    from.copy_from_slice(&from_bytes);

    let to_bytes = next_bytes!();
    if to_bytes.len() != 20 {
        return Err(HcaError::RlpDecodeError(format!(
            "to address must be 20 bytes, got {}",
            to_bytes.len()
        )));
    }
    let mut to = [0u8; 20];
    to.copy_from_slice(&to_bytes);

    let value = next_uint!();
    let gas_limit = next_uint!() as u64;
    let max_fee_per_gas = next_uint!();
    let max_priority_fee_per_gas = next_uint!();

    // Skip access list (empty list — consumed but ignored)
    let _ = next_list_payload!();

    let data = next_bytes!();

    // ── Witness fields ────────────────────────────────────────────────────────
    let leaf_version = next_uint!() as u8;
    let leaf_script = next_bytes!();

    let leaf_index = next_uint!() as usize;

    // Decode siblings list
    let siblings_payload = next_list_payload!();
    let mut siblings: Vec<[u8; 32]> = Vec::new();
    let mut sib_cursor = 0usize;
    while sib_cursor < siblings_payload.len() {
        let (sib_bytes, consumed) = decode_bytes(&siblings_payload[sib_cursor..])?;
        sib_cursor += consumed;
        if sib_bytes.len() != 32 {
            return Err(HcaError::RlpDecodeError(format!(
                "sibling must be 32 bytes, got {}",
                sib_bytes.len()
            )));
        }
        let mut sib = [0u8; 32];
        sib.copy_from_slice(&sib_bytes);
        siblings.push(sib);
    }

    let witness_data = next_bytes!();

    // Reconstruct TxMessage
    let tx = TxMessage {
        chain_id,
        nonce,
        from,
        to,
        value,
        data,
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    };

    // Reconstruct HCAWitness — bypass Leaf::new() validation since we're
    // decoding an already-encoded transaction (script was validated on encode).
    let leaf = Leaf {
        version: leaf_version,
        script: leaf_script.clone(),
        description: String::new(),
    };
    let proof = MerkleProof {
        leaf_index,
        siblings,
    };
    let mut witness = HCAWitness::build(&leaf, proof);
    if !witness_data.is_empty() {
        witness.attach_signature(witness_data)?;
    }

    Ok((tx, witness))
}

/// Helper: decode a big-endian usize from raw bytes (no RLP prefix)
///
/// Uses u64 internally to stay compatible with 32-bit targets (WASM).
fn decode_usize_be(bytes: &[u8]) -> HcaResult<usize> {
    if bytes.len() > 8 {
        return Err(HcaError::RlpDecodeError(format!(
            "length field too wide: {} bytes",
            bytes.len()
        )));
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(bytes);
    let val = u64::from_be_bytes(buf);
    usize::try_from(val).map_err(|_| {
        HcaError::RlpDecodeError(format!("length {} overflows usize on this platform", val))
    })
}

/// Helper: encode length as big-endian bytes (strip leading zeros)
fn encode_length(len: usize) -> Vec<u8> {
    let bytes = len.to_be_bytes();
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes.len() - 1);
    bytes[start..].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_uint_zero() {
        assert_eq!(encode_uint(0), vec![0x80]);
    }

    #[test]
    fn test_encode_uint_small() {
        assert_eq!(encode_uint(1), vec![0x01]);
        assert_eq!(encode_uint(15), vec![0x0f]);
        assert_eq!(encode_uint(127), vec![0x7f]);
    }

    #[test]
    fn test_encode_uint_medium() {
        // 128 = 0x80 -> needs encoding as string
        assert_eq!(encode_uint(128), vec![0x81, 0x80]);
        // 1024 = 0x0400
        assert_eq!(encode_uint(1024), vec![0x82, 0x04, 0x00]);
    }

    #[test]
    fn test_encode_bytes_empty() {
        assert_eq!(encode_bytes(&[]), vec![0x80]);
    }

    #[test]
    fn test_encode_bytes_single() {
        // Single byte < 0x80 encodes as itself
        assert_eq!(encode_bytes(&[0x00]), vec![0x00]);
        assert_eq!(encode_bytes(&[0x42]), vec![0x42]);
        assert_eq!(encode_bytes(&[0x7f]), vec![0x7f]);
    }

    #[test]
    fn test_encode_bytes_short() {
        // 2 bytes
        assert_eq!(encode_bytes(&[0x82, 0x83]), vec![0x82, 0x82, 0x83]);
        // 10 bytes
        let data = vec![0xaa; 10];
        let mut expected = vec![0x80 + 10];
        expected.extend_from_slice(&data);
        assert_eq!(encode_bytes(&data), expected);
    }

    #[test]
    fn test_encode_list_empty() {
        assert_eq!(encode_list(&[]), vec![0xc0]);
    }

    #[test]
    fn test_encode_list_simple() {
        // [1, 2, 3]
        let items = vec![vec![0x01], vec![0x02], vec![0x03]];
        assert_eq!(encode_list(&items), vec![0xc3, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_encode_list_nested() {
        // [[]]
        let items = vec![vec![0xc0]];
        assert_eq!(encode_list(&items), vec![0xc1, 0xc0]);
    }

    #[test]
    fn test_encode_address() {
        let addr = [0xaa; 20];
        let encoded = encode_address(&addr);
        assert_eq!(encoded[0], 0x94); // 0x80 + 20
        assert_eq!(encoded.len(), 21);
        assert_eq!(&encoded[1..], &addr[..]);
    }

    #[test]
    fn test_encode_length() {
        assert_eq!(encode_length(56), vec![0x38]);
        assert_eq!(encode_length(256), vec![0x01, 0x00]);
        assert_eq!(encode_length(65535), vec![0xff, 0xff]);
    }

    #[test]
    fn test_rlp_encoding_deterministic() {
        let data = b"hello world";
        let enc1 = encode_bytes(data);
        let enc2 = encode_bytes(data);
        assert_eq!(enc1, enc2);
    }

    // ── Decoder tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_decode_bytes_single_byte() {
        // Single byte < 0x80 decodes as itself
        let (val, consumed) = decode_bytes(&[0x42]).unwrap();
        assert_eq!(val, vec![0x42]);
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_bytes_empty() {
        let (val, consumed) = decode_bytes(&[0x80]).unwrap();
        assert_eq!(val, Vec::<u8>::new());
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_bytes_short_string() {
        let encoded = encode_bytes(b"hello");
        let (val, consumed) = decode_bytes(&encoded).unwrap();
        assert_eq!(val, b"hello");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_bytes_long_string() {
        let data = vec![0xaau8; 100];
        let encoded = encode_bytes(&data);
        let (val, consumed) = decode_bytes(&encoded).unwrap();
        assert_eq!(val, data);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_decode_bytes_truncated_returns_error() {
        // Short string header says 5 bytes but only 2 follow
        let input = vec![0x85, 0x01, 0x02]; // 0x80+5, only 2 bytes
        assert!(decode_bytes(&input).is_err());
    }

    #[test]
    fn test_decode_bytes_list_prefix_returns_error() {
        // 0xc3 is a list prefix, not a byte string
        assert!(decode_bytes(&[0xc3, 0x01, 0x02, 0x03]).is_err());
    }

    #[test]
    fn test_decode_uint_zero() {
        let encoded = encode_uint(0);
        let (val, _) = decode_uint(&encoded).unwrap();
        assert_eq!(val, 0);
    }

    #[test]
    fn test_decode_uint_small() {
        for n in [1u128, 15, 127, 128, 1024, u64::MAX as u128] {
            let encoded = encode_uint(n);
            let (val, consumed) = decode_uint(&encoded).unwrap();
            assert_eq!(val, n, "round-trip failed for {}", n);
            assert_eq!(consumed, encoded.len());
        }
    }

    #[test]
    fn test_decode_list_empty() {
        let encoded = encode_list(&[]);
        let (payload, consumed) = decode_list(&encoded).unwrap();
        assert_eq!(payload, Vec::<u8>::new());
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_decode_list_simple() {
        let items = vec![encode_uint(1), encode_uint(2), encode_uint(3)];
        let encoded = encode_list(&items);
        let (payload, consumed) = decode_list(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());

        // Decode items from payload
        let mut cursor = 0;
        for expected in [1u128, 2, 3] {
            let (val, n) = decode_uint(&payload[cursor..]).unwrap();
            assert_eq!(val, expected);
            cursor += n;
        }
        assert_eq!(cursor, payload.len());
    }

    #[test]
    fn test_decode_list_non_list_returns_error() {
        // byte string prefix, not list
        assert!(decode_list(&[0x82, 0x01, 0x02]).is_err());
    }

    // ── Round-trip tests ──────────────────────────────────────────────────────

    fn make_test_tx_and_witness() -> (TxMessage, HCAWitness) {
        use crate::merkle::{Leaf, MerkleTree};

        let leaves = vec![
            Leaf::new(0x01, b"spend_script".to_vec(), "primary").unwrap(),
            Leaf::new(0x01, b"recover_script".to_vec(), "recovery").unwrap(),
        ];
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let proof = tree.proof(0).unwrap();

        let mut witness = HCAWitness::build(&leaves[0], proof);
        witness
            .attach_signature(vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe])
            .unwrap();

        let tx = TxMessage {
            chain_id: 1,
            nonce: 7,
            from: [0x11u8; 20],
            to: [0x22u8; 20],
            value: 1_000_000_000_000_000u128,
            data: vec![0x60, 0x60, 0x60, 0x40], // valid EVM (PUSH1 + PUSH1)
            gas_limit: 100_000,
            max_fee_per_gas: 2_000_000_000u128,
            max_priority_fee_per_gas: 1_000_000_000u128,
        };

        (tx, witness)
    }

    #[test]
    fn test_round_trip_basic() {
        let (tx, witness) = make_test_tx_and_witness();

        let encoded = encode_hca_tx(&tx, &witness).unwrap();
        let (tx2, witness2) = decode_hca_tx(&encoded).unwrap();

        assert_eq!(tx2.chain_id, tx.chain_id);
        assert_eq!(tx2.nonce, tx.nonce);
        assert_eq!(tx2.from, tx.from);
        assert_eq!(tx2.to, tx.to);
        assert_eq!(tx2.value, tx.value);
        assert_eq!(tx2.data, tx.data);
        assert_eq!(tx2.gas_limit, tx.gas_limit);
        assert_eq!(tx2.max_fee_per_gas, tx.max_fee_per_gas);
        assert_eq!(tx2.max_priority_fee_per_gas, tx.max_priority_fee_per_gas);

        assert_eq!(witness2.leaf_version, witness.leaf_version);
        assert_eq!(witness2.leaf_script, witness.leaf_script);
        assert_eq!(
            witness2.merkle_proof.leaf_index,
            witness.merkle_proof.leaf_index
        );
        assert_eq!(
            witness2.merkle_proof.siblings,
            witness.merkle_proof.siblings
        );
        assert_eq!(witness2.witness_data, witness.witness_data);
    }

    #[test]
    fn test_round_trip_empty_calldata() {
        let (mut tx, witness) = make_test_tx_and_witness();
        tx.data = vec![];

        let encoded = encode_hca_tx(&tx, &witness).unwrap();
        let (tx2, _) = decode_hca_tx(&encoded).unwrap();

        assert_eq!(tx2.data, Vec::<u8>::new());
    }

    #[test]
    fn test_round_trip_zero_value() {
        let (mut tx, witness) = make_test_tx_and_witness();
        tx.value = 0;

        let encoded = encode_hca_tx(&tx, &witness).unwrap();
        let (tx2, _) = decode_hca_tx(&encoded).unwrap();

        assert_eq!(tx2.value, 0);
    }

    #[test]
    fn test_round_trip_no_siblings() {
        use crate::merkle::{Leaf, MerkleProof};

        let leaf = Leaf::new(0x01, b"solo".to_vec(), "solo leaf").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };
        let mut witness = HCAWitness::build(&leaf, proof);
        witness.attach_signature(vec![0x01]).unwrap();

        let tx = TxMessage {
            chain_id: 11155111,
            nonce: 0,
            from: [0xaau8; 20],
            to: [0xbbu8; 20],
            value: 0,
            data: vec![],
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        let encoded = encode_hca_tx(&tx, &witness).unwrap();
        let (tx2, witness2) = decode_hca_tx(&encoded).unwrap();

        assert_eq!(tx2.chain_id, tx.chain_id);
        assert!(witness2.merkle_proof.siblings.is_empty());
        assert_eq!(witness2.witness_data, vec![0x01]);
    }

    #[test]
    fn test_decode_wrong_tx_type_returns_error() {
        let (tx, witness) = make_test_tx_and_witness();
        let mut encoded = encode_hca_tx(&tx, &witness).unwrap();
        encoded[0] = 0x02; // tamper with type byte
        assert!(decode_hca_tx(&encoded).is_err());
    }

    #[test]
    fn test_decode_empty_returns_error() {
        assert!(decode_hca_tx(&[]).is_err());
    }

    #[test]
    fn test_decode_truncated_returns_error() {
        let (tx, witness) = make_test_tx_and_witness();
        let encoded = encode_hca_tx(&tx, &witness).unwrap();
        // Truncate to first 10 bytes
        assert!(decode_hca_tx(&encoded[..10]).is_err());
    }

    #[test]
    fn test_round_trip_is_deterministic() {
        let (tx, witness) = make_test_tx_and_witness();

        let enc1 = encode_hca_tx(&tx, &witness).unwrap();
        let enc2 = encode_hca_tx(&tx, &witness).unwrap();
        assert_eq!(enc1, enc2);

        let (tx2, _) = decode_hca_tx(&enc1).unwrap();
        assert_eq!(tx2.nonce, tx.nonce);
    }
}
