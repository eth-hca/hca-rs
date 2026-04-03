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
}
