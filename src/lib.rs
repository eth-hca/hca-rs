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
//
// WASM bindings (feature = "wasm") expose these to JavaScript
// for use in hca-wallet browser extension.

pub mod constants;
pub mod error;
pub mod hash;
pub mod address;
pub mod merkle;
pub mod witness;
pub mod rlp;

// Re-export most common types for convenience
pub use address::derive_address;
pub use error::{HcaError, HcaResult};
pub use hash::{keccak256, tagged_hash};
pub use merkle::{Leaf, MerkleProof, MerkleTree};
pub use witness::{HCAWitness, TxMessage};

#[cfg(feature = "wasm")]
pub mod wasm_bindings {
    use wasm_bindgen::prelude::*;
    use crate::{Leaf, MerkleTree, HCAWitness, TxMessage};
    use crate::address::derive_address;

    #[wasm_bindgen(start)]
    pub fn init() {
        #[cfg(feature = "console_error_panic_hook")]
        console_error_panic_hook::set_once();
    }

    /// Create HCA account from JSON leaves array
    /// Returns JSON: { address, auth_root, leaf_count, leaves }
    #[wasm_bindgen]
    pub fn create_hca_account(leaves_json: &str) -> Result<String, JsValue> {
        let raw: Vec<serde_json::Value> = serde_json::from_str(leaves_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let leaves: Vec<Leaf> = raw.iter().map(|l| {
            Leaf::new(
                l["version"].as_u64().unwrap_or(1) as u8,
                hex::decode(l["script"].as_str().unwrap_or("").trim_start_matches("0x"))
                    .unwrap_or_default(),
                l["description"].as_str().unwrap_or(""),
            )
        }).collect();

        let tree = MerkleTree::new(leaves.clone())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let auth_root = tree.auth_root();
        let address = derive_address(&auth_root);

        let result = serde_json::json!({
            "address": format!("0x{}", hex::encode(address)),
            "auth_root": format!("0x{}", hex::encode(auth_root)),
            "leaf_count": leaves.len(),
            "leaves": leaves.iter().enumerate().map(|(i, l)| serde_json::json!({
                "index": i,
                "version": l.version,
                "hash": format!("0x{}", hex::encode(l.hash())),
                "description": l.description
            })).collect::<Vec<_>>()
        });

        Ok(result.to_string())
    }

    /// Generate Merkle proof for leaf at given index
    #[wasm_bindgen]
    pub fn generate_proof(leaves_json: &str, leaf_index: usize) -> Result<String, JsValue> {
        let raw: Vec<serde_json::Value> = serde_json::from_str(leaves_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let leaves: Vec<Leaf> = raw.iter().map(|l| {
            Leaf::new(
                l["version"].as_u64().unwrap_or(1) as u8,
                hex::decode(l["script"].as_str().unwrap_or("").trim_start_matches("0x"))
                    .unwrap_or_default(),
                l["description"].as_str().unwrap_or(""),
            )
        }).collect();

        let tree = MerkleTree::new(leaves.clone())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let proof = tree.proof(leaf_index)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let leaf_hash = leaves[leaf_index].hash();

        let result = serde_json::json!({
            "leaf_index": proof.leaf_index,
            "leaf_hash": format!("0x{}", hex::encode(leaf_hash)),
            "siblings": proof.siblings.iter().map(|s| format!("0x{}", hex::encode(s))).collect::<Vec<_>>(),
            "auth_root": format!("0x{}", hex::encode(tree.auth_root()))
        });

        Ok(result.to_string())
    }

    /// Build witness and return signing hash for wallet to sign
    #[wasm_bindgen]
    pub fn build_witness(leaves_json: &str, leaf_index: usize, tx_json: &str) -> Result<String, JsValue> {
        let raw: Vec<serde_json::Value> = serde_json::from_str(leaves_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let leaves: Vec<Leaf> = raw.iter().map(|l| {
            Leaf::new(
                l["version"].as_u64().unwrap_or(1) as u8,
                hex::decode(l["script"].as_str().unwrap_or("").trim_start_matches("0x"))
                    .unwrap_or_default(),
                l["description"].as_str().unwrap_or(""),
            )
        }).collect();

        let tx: serde_json::Value = serde_json::from_str(tx_json)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let from_bytes = hex::decode(tx["from"].as_str().unwrap_or("").trim_start_matches("0x"))
            .unwrap_or_default();
        let to_bytes = hex::decode(tx["to"].as_str().unwrap_or("").trim_start_matches("0x"))
            .unwrap_or_default();

        let mut from = [0u8; 20];
        let mut to = [0u8; 20];
        if from_bytes.len() == 20 { from.copy_from_slice(&from_bytes); }
        if to_bytes.len() == 20 { to.copy_from_slice(&to_bytes); }

        let msg = TxMessage {
            chain_id: tx["chain_id"].as_u64().unwrap_or(11155111),
            nonce: tx["nonce"].as_u64().unwrap_or(0),
            from, to,
            value: tx["value"].as_u64().unwrap_or(0) as u128,
            gas_limit: tx["gas_limit"].as_u64().unwrap_or(100_000),
            max_fee_per_gas: tx["max_fee"].as_u64().unwrap_or(1_000_000_000) as u128,
            max_priority_fee_per_gas: tx["max_priority_fee"].as_u64().unwrap_or(100_000_000) as u128,
        };

        let tree = MerkleTree::new(leaves.clone())
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let proof = tree.proof(leaf_index)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        let leaf_hash = leaves[leaf_index].hash();
        let signing_hash = msg.signing_hash(&leaf_hash);
        let witness = HCAWitness::build(&leaves[leaf_index], proof.clone());

        let result = serde_json::json!({
            "leaf_hash": format!("0x{}", hex::encode(leaf_hash)),
            "signing_hash": format!("0x{}", hex::encode(signing_hash)),
            "leaf_script": format!("0x{}", hex::encode(&witness.leaf_script)),
            "leaf_version": witness.leaf_version,
            "merkle_proof": {
                "leaf_index": proof.leaf_index,
                "siblings": proof.siblings.iter().map(|s| format!("0x{}", hex::encode(s))).collect::<Vec<_>>()
            },
            "estimated_gas": witness.estimate_gas(),
            "auth_root": format!("0x{}", hex::encode(tree.auth_root()))
        });

        Ok(result.to_string())
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[test]
    fn test_full_hca_flow() {
        // 1. Create leaves
        let leaves = vec![
            Leaf::new(0x01, b"primary_ecdsa_script".to_vec(), "Primary key"),
            Leaf::new(0x01, b"recovery_ecdsa_script".to_vec(), "Recovery key"),
            Leaf::new(0x01, b"timelock_script".to_vec(), "Timelock 30 days"),
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