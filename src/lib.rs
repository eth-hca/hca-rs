// lib.rs
//
// hca-rs — Hash-Committed Account cryptographic core
//
// Exposes modules:
//   hash      — keccak256, tagged_hash, domain separation tags
//   address   — derive_address, address formatting
//   merkle    — Leaf, MerkleTree, MerkleProof
//   witness   — TxMessage, HCAWitness
//   rlp       — RLP encoding for HCA transactions
//   error     — HcaError, HcaResult<T>
//   constants — Protocol constants
//   wasm      — WASM bindings (feature = "wasm")
//
// WASM bindings expose these operations to JavaScript for use in
// browser-based wallets via wasm-bindgen.

pub mod constants;
pub mod error;
pub mod evm;
pub mod hash;
pub mod address;
pub mod merkle;
pub mod witness;
pub mod rlp;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export most common types for convenience
pub use address::derive_address;
pub use error::{HcaError, HcaResult};
pub use hash::{keccak256, tagged_hash};
pub use merkle::{Leaf, MerkleProof, MerkleTree};
pub use witness::{HCAWitness, RotationRequest, TxMessage};

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_hca_flow() {
        // 1. Create leaves
        let leaves = vec![
            Leaf::new(0x01, b"primary_ecdsa_script".to_vec(), "Primary key").unwrap(),
            Leaf::new(0x01, b"recovery_ecdsa_script".to_vec(), "Recovery key").unwrap(),
            Leaf::new(0x01, b"timelock_script".to_vec(), "Timelock 30 days").unwrap(),
        ];

        // 2. Build Merkle tree
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let auth_root = tree.auth_root();

        // 3. Derive HCA address
        let address = derive_address(&auth_root);
        assert_eq!(address.len(), 20);
        assert_ne!(address, [0u8; 20]);

        // 4. Generate proof for primary leaf
        let proof = tree.proof(0).unwrap();

        // 5. Build witness
        let witness = HCAWitness::build(&leaves[0], proof.clone());
        assert!(!witness.is_signed());

        // 6. Build signing hash
        let tx = TxMessage {
            chain_id: 11155111,
            nonce: 0,
            from: address,
            to: [0x02u8; 20],
            value: 1_000_000_000_000_000u128,
            data: vec![],
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        let leaf_hash = leaves[0].hash();
        let signing_hash = tx.signing_hash(&leaf_hash);
        assert_ne!(signing_hash, [0u8; 32]);

        // 7. Verify proof
        assert!(MerkleTree::verify(&leaf_hash, &proof, &auth_root).unwrap());

        // 8. Verify wrong leaf fails
        let wrong_hash = leaves[1].hash();
        assert!(!MerkleTree::verify(&wrong_hash, &proof, &auth_root).unwrap());
    }
}