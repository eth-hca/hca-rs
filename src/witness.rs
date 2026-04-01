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
    pub fn attach_signature(&mut self, signature: Vec<u8>) {
        self.witness_data = signature;
    }

    /// Check if witness has been signed
    pub fn is_signed(&self) -> bool {
        !self.witness_data.is_empty()
    }

    /// Estimate gas cost for this witness
    ///
    /// Gas cost depends on:
    /// - Merkle proof depth
    /// - Leaf script execution cost
    /// - Signature verification cost
    pub fn estimate_gas(&self) -> u64 {
        use crate::constants::{MAX_LEAF_GAS, MERKLE_BASE_GAS, MERKLE_GAS_PER_LEVEL};

        let proof_gas =
            MERKLE_BASE_GAS + (self.merkle_proof.siblings.len() as u64 * MERKLE_GAS_PER_LEVEL);
        let leaf_gas = MAX_LEAF_GAS; // Conservative estimate

        proof_gas + leaf_gas
    }

    /// Encode witness for transaction submission
    ///
    /// NOTE: Full RLP encoding will be implemented in PR3
    pub fn encode(&self) -> HcaResult<Vec<u8>> {
        if !self.is_signed() {
            return Err(HcaError::WitnessNotSigned);
        }

        // Placeholder: will implement full RLP encoding in PR3
        let mut encoded = Vec::new();
        encoded.push(self.leaf_version);
        encoded.extend_from_slice(&self.leaf_script);
        // TODO: encode merkle_proof and witness_data

        Ok(encoded)
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
    fn test_witness_unsigned_by_default() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test");
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };

        let witness = HCAWitness::build(&leaf, proof);
        assert!(!witness.is_signed());
    }

    #[test]
    fn test_witness_signed_after_attach() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test");
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };

        let mut witness = HCAWitness::build(&leaf, proof);
        witness.attach_signature(vec![0x01, 0x02, 0x03]);
        assert!(witness.is_signed());
    }

    #[test]
    fn test_witness_estimate_gas() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test");
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![[0u8; 32], [0u8; 32], [0u8; 32]], // depth 3
        };

        let witness = HCAWitness::build(&leaf, proof);
        let gas = witness.estimate_gas();
        assert!(gas > 0);
    }

    #[test]
    fn test_encode_unsigned_witness_fails() {
        let leaf = Leaf::new(0x01, b"script".to_vec(), "test");
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![],
        };

        let witness = HCAWitness::build(&leaf, proof);
        let result = witness.encode();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HcaError::WitnessNotSigned);
    }
}
