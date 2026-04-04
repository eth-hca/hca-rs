//! HCA transaction witness construction and signing hash computation.
//!
//! The witness contains:
//! - The leaf script being spent
//! - Merkle proof showing the leaf is in auth_root
//! - Signature data satisfying the leaf's spending condition
//!
//! NOTE: This module is partially implemented. Full implementation in PR2.

use crate::error::{HcaError, HcaResult};
use crate::hash::{tagged_hash, tags};
use crate::merkle::{Leaf, MerkleProof};

/// Transaction message to be signed
#[derive(Clone, Debug)]
pub struct TxMessage {
    /// Chain ID (prevents cross-chain replay)
    pub chain_id: u64,
    /// Transaction nonce
    pub nonce: u64,
    /// Sender address (explicit in HCA)
    pub from: [u8; 20],
    /// Recipient address
    pub to: [u8; 20],
    /// Value to transfer in wei
    pub value: u128,
    /// Calldata for contract interactions
    pub data: Vec<u8>,
    /// Gas limit
    pub gas_limit: u64,
    /// Maximum fee per gas
    pub max_fee_per_gas: u128,
    /// Maximum priority fee per gas
    pub max_priority_fee_per_gas: u128,
}

impl TxMessage {
    /// Compute the signing hash for this transaction
    ///
    /// The signing hash commits to:
    /// - chain_id (prevents cross-chain replay)
    /// - nonce (prevents same-chain replay)
    /// - from (prevents cross-account replay)
    /// - leaf_hash (binds signature to specific spending condition)
    /// - All transaction fields
    ///
    /// Formula:
    /// ```text
    /// signing_hash = tagged_hash("HCAWitness",
    ///   chain_id || nonce || from || to || value || leaf_hash || ...)
    /// ```
    pub fn signing_hash(&self, leaf_hash: &[u8; 32]) -> [u8; 32] {
        let mut data = Vec::new();

        // Encode fields for hashing
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.to);
        data.extend_from_slice(&self.value.to_be_bytes());
        // Include calldata length + content so different calldata → different hash
        let data_len = self.data.len() as u64;
        data.extend_from_slice(&data_len.to_be_bytes());
        data.extend_from_slice(&self.data);
        data.extend_from_slice(&self.gas_limit.to_be_bytes());
        data.extend_from_slice(&self.max_fee_per_gas.to_be_bytes());
        data.extend_from_slice(&self.max_priority_fee_per_gas.to_be_bytes());
        data.extend_from_slice(leaf_hash);

        tagged_hash(tags::WITNESS, &data)
    }
}

/// HCA transaction witness
///
/// Contains everything needed to spend from an HCA account:
/// - The leaf script (spending condition)
/// - Merkle proof (proves leaf is in auth_root)
/// - Witness data (signature satisfying the leaf's condition)
#[derive(Clone, Debug)]
pub struct HCAWitness {
    /// Leaf version byte
    pub leaf_version: u8,
    /// Leaf script (spending condition bytecode)
    pub leaf_script: Vec<u8>,
    /// Merkle proof for this leaf
    pub merkle_proof: MerkleProof,
    /// Signature data (empty until signed)
    pub witness_data: Vec<u8>,
}

impl HCAWitness {
    /// Build an unsigned witness from a leaf and proof
    pub fn build(leaf: &Leaf, proof: MerkleProof) -> Self {
        Self {
            leaf_version: leaf.version,
            leaf_script: leaf.script.clone(),
            merkle_proof: proof,
            witness_data: Vec::new(),
        }
    }

    /// Attach signature data to the witness
    ///
    /// Returns `Err(HcaError::EmptySignature)` if `signature` is empty.
    pub fn attach_signature(&mut self, signature: Vec<u8>) -> HcaResult<()> {
        if signature.is_empty() {
            return Err(HcaError::EmptySignature);
        }
        self.witness_data = signature;
        Ok(())
    }

    /// Check if witness has been signed
    pub fn is_signed(&self) -> bool {
        !self.witness_data.is_empty()
    }

    /// Estimate gas cost for this witness
    ///
    /// Gas cost depends on:
    /// - Merkle proof depth
    /// - Static gas of leaf script opcodes (per EVM Berlin schedule)
    ///
    /// Returns the actual static gas consumed by the script if it validates,
    /// or `MAX_LEAF_GAS` as a conservative upper bound if the script cannot
    /// be analysed (e.g. contains a banned opcode — those are rejected at
    /// `Leaf::new()` time so this path is a defensive fallback).
    pub fn estimate_gas(&self) -> u64 {
        use crate::constants::{MAX_LEAF_GAS, MERKLE_BASE_GAS, MERKLE_GAS_PER_LEVEL};
        use crate::evm::opcode::validate_leaf_script;

        let proof_gas =
            MERKLE_BASE_GAS + (self.merkle_proof.siblings.len() as u64 * MERKLE_GAS_PER_LEVEL);
        let leaf_gas = validate_leaf_script(&self.leaf_script).unwrap_or(MAX_LEAF_GAS); // fallback: conservative upper bound

        proof_gas + leaf_gas
    }

    /// Encode witness data only (not the full transaction)
    ///
    /// For full transaction encoding including witness, use `rlp::encode_hca_tx()`.
    ///
    /// Returns a serialized representation of the witness fields:
    /// - leaf_version
    /// - leaf_script
    /// - merkle_proof (leaf_index + siblings)
    /// - witness_data (signature)
    pub fn encode(&self) -> HcaResult<Vec<u8>> {
        use crate::constants::MAX_WITNESS_SIZE;
        use crate::rlp::{encode_bytes, encode_list, encode_uint};

        if !self.is_signed() {
            return Err(HcaError::WitnessNotSigned);
        }

        let mut fields = Vec::new();
        fields.push(encode_uint(self.leaf_version as u128));
        fields.push(encode_bytes(&self.leaf_script));
        fields.push(encode_uint(self.merkle_proof.leaf_index as u128));

        // Encode merkle proof siblings
        let siblings: Vec<Vec<u8>> = self
            .merkle_proof
            .siblings
            .iter()
            .map(|s| encode_bytes(s))
            .collect();
        fields.push(encode_list(&siblings));

        fields.push(encode_bytes(&self.witness_data));

        let encoded = encode_list(&fields);
        if encoded.len() > MAX_WITNESS_SIZE {
            return Err(HcaError::WitnessTooLarge {
                size: encoded.len(),
            });
        }
        Ok(encoded)
    }
}

/// Authorization request to replace an account's `authRoot`.
///
/// Per EIP-8215 §authRoot rotation:
/// - The rotation tx MUST NOT transfer value or execute external calls
/// - The new `auth_root` MUST be a non-zero 32-byte value
/// - Signed with the `HCARotate` domain tag to prevent cross-context replay
///
/// The rotation leaf script inside the current auth tree validates
/// the signature over this hash before the node replaces `authRoot`.
#[derive(Clone, Debug)]
pub struct RotationRequest {
    /// Chain ID — prevents cross-chain replay
    pub chain_id: u64,
    /// Current account nonce
    pub nonce: u64,
    /// HCA account address being rotated
    pub from: [u8; 20],
    /// The new auth_root to replace the current one
    pub new_auth_root: [u8; 32],
}

impl RotationRequest {
    /// Create a new rotation request, validating that `new_auth_root` is non-zero.
    ///
    /// Returns `Err(HcaError::InvalidRotation)` if `new_auth_root` is all zeros.
    pub fn new(
        chain_id: u64,
        nonce: u64,
        from: [u8; 20],
        new_auth_root: [u8; 32],
    ) -> HcaResult<Self> {
        if new_auth_root == [0u8; 32] {
            return Err(HcaError::InvalidRotation(
                "new_auth_root must not be zero".to_string(),
            ));
        }
        Ok(Self {
            chain_id,
            nonce,
            from,
            new_auth_root,
        })
    }

    /// Compute the signing hash for this rotation request.
    ///
    /// Uses the `HCARotate` domain tag to prevent cross-context replay
    /// with regular transaction signing hashes.
    ///
    /// Formula:
    /// ```text
    /// rotation_hash = tagged_hash("HCARotate",
    ///   chain_id || nonce || from || new_auth_root)
    /// ```
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut data = Vec::with_capacity(8 + 8 + 20 + 32);
        data.extend_from_slice(&self.chain_id.to_be_bytes());
        data.extend_from_slice(&self.nonce.to_be_bytes());
        data.extend_from_slice(&self.from);
        data.extend_from_slice(&self.new_auth_root);
        tagged_hash(tags::ROTATE, &data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx_message_signing_hash() {
        let tx = TxMessage {
            chain_id: 11155111,
            nonce: 0,
            from: [1u8; 20],
            to: [2u8; 20],
            value: 1_000_000_000_000_000u128,
            data: vec![],
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        let leaf_hash = [0u8; 32];
        let hash = tx.signing_hash(&leaf_hash);

        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_signing_hash_deterministic() {
        let tx = TxMessage {
            chain_id: 1,
            nonce: 5,
            from: [0xAAu8; 20],
            to: [0xBBu8; 20],
            value: 1000u128,
            data: vec![],
            gas_limit: 21000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        let leaf_hash = [0xCCu8; 32];
        let hash1 = tx.signing_hash(&leaf_hash);
        let hash2 = tx.signing_hash(&leaf_hash);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_signing_hash_includes_chain_id() {
        let leaf_hash = [0u8; 32];

        let tx1 = TxMessage {
            chain_id: 1,
            nonce: 0,
            from: [1u8; 20],
            to: [2u8; 20],
            value: 1000u128,
            data: vec![],
            gas_limit: 21000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        let tx2 = TxMessage {
            chain_id: 11155111,
            ..tx1.clone()
        };

        let hash1 = tx1.signing_hash(&leaf_hash);
        let hash2 = tx2.signing_hash(&leaf_hash);

        assert_ne!(
            hash1, hash2,
            "Different chain_id must produce different signing hash"
        );
    }

    #[test]
    fn test_signing_hash_includes_data() {
        let leaf_hash = [0u8; 32];

        let tx_no_data = TxMessage {
            chain_id: 1,
            nonce: 0,
            from: [1u8; 20],
            to: [2u8; 20],
            value: 0,
            data: vec![],
            gas_limit: 21000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        let tx_with_data = TxMessage {
            data: vec![0xde, 0xad, 0xbe, 0xef],
            ..tx_no_data.clone()
        };

        assert_ne!(
            tx_no_data.signing_hash(&leaf_hash),
            tx_with_data.signing_hash(&leaf_hash),
            "Different calldata must produce different signing hash"
        );
    }

    #[test]
    fn test_witness_unsigned_by_default() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };

        let witness = HCAWitness::build(&leaf, proof);
        assert!(!witness.is_signed());
    }

    #[test]
    fn test_witness_signed_after_attach() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };

        let mut witness = HCAWitness::build(&leaf, proof);
        witness.attach_signature(vec![0x01, 0x02, 0x03]).unwrap();
        assert!(witness.is_signed());
    }

    #[test]
    fn test_witness_estimate_gas() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![[0u8; 32], [0u8; 32], [0u8; 32]], // depth 3
        };

        let witness = HCAWitness::build(&leaf, proof);
        let gas = witness.estimate_gas();
        assert!(gas > 0);
    }

    #[test]
    fn test_witness_too_large() {
        use crate::constants::MAX_WITNESS_SIZE;
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };
        let mut witness = HCAWitness::build(&leaf, proof);
        // Attach oversized signature to push encoded size over MAX_WITNESS_SIZE
        witness
            .attach_signature(vec![0xAAu8; MAX_WITNESS_SIZE])
            .unwrap();
        let result = witness.encode();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HcaError::WitnessTooLarge { .. }
        ));
    }

    #[test]
    fn test_encode_unsigned_witness_fails() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };

        let witness = HCAWitness::build(&leaf, proof);
        let result = witness.encode();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HcaError::WitnessNotSigned);
    }

    // ── Input validation tests ────────────────────────────────────────────────

    #[test]
    fn test_attach_empty_signature_fails() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };
        let mut witness = HCAWitness::build(&leaf, proof);
        let result = witness.attach_signature(vec![]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HcaError::EmptySignature);
    }

    #[test]
    fn test_attach_signature_succeeds_with_data() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test").unwrap();
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };
        let mut witness = HCAWitness::build(&leaf, proof);
        assert!(witness.attach_signature(vec![0xAB; 65]).is_ok());
        assert!(witness.is_signed());
    }

    // ── Rotation tests ────────────────────────────────────────────────────────

    #[test]
    fn test_rotation_request_valid() {
        let req = RotationRequest::new(1, 0, [0x01u8; 20], [0xABu8; 32]);
        assert!(req.is_ok());
    }

    #[test]
    fn test_rotation_request_rejects_zero_auth_root() {
        let result = RotationRequest::new(1, 0, [0x01u8; 20], [0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HcaError::InvalidRotation(_)));
    }

    #[test]
    fn test_rotation_signing_hash_deterministic() {
        let req = RotationRequest::new(1, 0, [0x01u8; 20], [0xABu8; 32]).unwrap();
        assert_eq!(req.signing_hash(), req.signing_hash());
    }

    #[test]
    fn test_rotation_signing_hash_chain_separation() {
        let req1 = RotationRequest::new(1, 0, [0x01u8; 20], [0xABu8; 32]).unwrap();
        let req2 = RotationRequest::new(11155111, 0, [0x01u8; 20], [0xABu8; 32]).unwrap();
        assert_ne!(
            req1.signing_hash(),
            req2.signing_hash(),
            "Different chain_id must produce different rotation hash"
        );
    }

    #[test]
    fn test_rotation_signing_hash_differs_from_tx_hash() {
        // Same fields — rotation hash must differ from tx signing hash
        let new_root = [0xABu8; 32];
        let req = RotationRequest::new(1, 0, [0x01u8; 20], new_root).unwrap();

        let tx = TxMessage {
            chain_id: 1,
            nonce: 0,
            from: [0x01u8; 20],
            to: [0u8; 20],
            value: 0,
            data: vec![],
            gas_limit: 21000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        assert_ne!(
            req.signing_hash(),
            tx.signing_hash(&new_root),
            "Rotation hash must differ from tx signing hash — domain separation"
        );
    }

    #[test]
    fn test_rotation_new_auth_root_sensitivity() {
        let req1 = RotationRequest::new(1, 0, [0x01u8; 20], [0xABu8; 32]).unwrap();
        let req2 = RotationRequest::new(1, 0, [0x01u8; 20], [0xCDu8; 32]).unwrap();
        assert_ne!(
            req1.signing_hash(),
            req2.signing_hash(),
            "Different new_auth_root must produce different rotation hash"
        );
    }
}
