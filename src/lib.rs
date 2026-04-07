//! # hca-rs — Hash-Committed Account cryptographic primitives
//!
//! Reference implementation of [EIP-8215](https://github.com/eth-hca/hca-rs)
//! (Hash-Committed Account), a proposed Ethereum account type that eliminates
//! the quantum long-exposure attack surface by removing the public key from
//! address derivation.
//!
//! ## Address derivation
//!
//! ```text
//! address = keccak256(tagged_hash("HCAAddr", auth_root))[12..]
//! ```
//!
//! The `auth_root` is the root of a Merkle tree of spending conditions
//! (EVM bytecode scripts). No public key enters the derivation chain.
//!
//! ## Quick start
//!
//! ```rust
//! use hca_rs::{TreeBuilder, TxBuilder, MerkleTree, derive_address};
//!
//! // 1. Define spending conditions
//! let tree = TreeBuilder::new()
//!     .add_leaf(0x01, b"primary_script".to_vec(), "Primary key")
//!     .add_leaf(0x01, b"recovery_script".to_vec(), "Recovery key")
//!     .build()
//!     .unwrap();
//!
//! // 2. Derive HCA address from the Merkle root
//! let address = derive_address(&tree.auth_root());
//! assert_eq!(address.len(), 20);
//! ```
//!
//! ## Feature flags
//!
//! | Feature | Default | Description |
//! |---------|---------|-------------|
//! | `std`   | ✓       | Links against std; enables `serde_json` and hex formatting helpers |
//! | `serde` | ✓       | Derives `Serialize`/`Deserialize` on `Leaf` and `MerkleProof` |
//! | `wasm`  |         | Compiles WASM bindings via `wasm-bindgen` |
//!
//! Compile with `default-features = false` for `no_std + alloc` environments.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod address;
pub mod builder;
pub mod constants;
pub mod error;
pub mod evm;
pub mod hash;
pub mod leaf_version;
pub mod merkle;
pub mod rlp;
pub mod witness;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export most common types for convenience
pub use address::derive_address;
pub use builder::{TreeBuilder, TxBuilder};
pub use error::{HcaError, HcaResult};
pub use hash::{keccak256, tagged_hash};
pub use leaf_version::{validate_for_version, LeafVersion};
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
