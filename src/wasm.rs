//! WASM bindings for HCA cryptographic operations.
//!
//! This module provides JavaScript-friendly interfaces for use in browser
//! environments via wasm-bindgen. All functions take JSON strings as input
//! and return JSON strings as output.
//!
//! Enable with the "wasm" feature flag:
//! ```toml
//! hca-rs = { version = "0.1.0", features = ["wasm"] }
//! ```

use crate::address::derive_address;
use crate::{HCAWitness, Leaf, MerkleTree, TxMessage};
use wasm_bindgen::prelude::*;

/// Initialize WASM module with panic hooks
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Create HCA account from JSON leaves array
///
/// # Input JSON Format
/// ```json
/// [
///   {
///     "version": 1,
///     "script": "0x4f505f434845434b534947",
///     "description": "Primary key"
///   }
/// ]
/// ```
///
/// # Output JSON Format
/// ```json
/// {
///   "address": "0x...",
///   "auth_root": "0x...",
///   "leaf_count": 1,
///   "leaves": [
///     {
///       "index": 0,
///       "version": 1,
///       "hash": "0x...",
///       "description": "Primary key"
///     }
///   ]
/// }
/// ```
#[wasm_bindgen]
pub fn create_hca_account(leaves_json: &str) -> Result<String, JsValue> {
    let raw: Vec<serde_json::Value> =
        serde_json::from_str(leaves_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let leaves: Vec<Leaf> = raw
        .iter()
        .map(|l| {
            Leaf::new(
                l["version"].as_u64().unwrap_or(1) as u8,
                hex::decode(l["script"].as_str().unwrap_or("").trim_start_matches("0x"))
                    .unwrap_or_default(),
                l["description"].as_str().unwrap_or(""),
            )
        })
        .collect();

    let tree = MerkleTree::new(leaves.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;

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
///
/// # Input
/// - `leaves_json`: JSON array of leaves (same format as `create_hca_account`)
/// - `leaf_index`: Zero-based index of the leaf to prove
///
/// # Output JSON Format
/// ```json
/// {
///   "leaf_index": 0,
///   "leaf_hash": "0x...",
///   "siblings": ["0x...", "0x..."],
///   "auth_root": "0x..."
/// }
/// ```
#[wasm_bindgen]
pub fn generate_proof(leaves_json: &str, leaf_index: usize) -> Result<String, JsValue> {
    let raw: Vec<serde_json::Value> =
        serde_json::from_str(leaves_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let leaves: Vec<Leaf> = raw
        .iter()
        .map(|l| {
            Leaf::new(
                l["version"].as_u64().unwrap_or(1) as u8,
                hex::decode(l["script"].as_str().unwrap_or("").trim_start_matches("0x"))
                    .unwrap_or_default(),
                l["description"].as_str().unwrap_or(""),
            )
        })
        .collect();

    let tree = MerkleTree::new(leaves.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let proof = tree
        .proof(leaf_index)
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
///
/// # Input
/// - `leaves_json`: JSON array of leaves
/// - `leaf_index`: Index of the leaf being spent
/// - `tx_json`: Transaction details
///
/// # Transaction JSON Format
/// ```json
/// {
///   "chain_id": 11155111,
///   "nonce": 0,
///   "from": "0x...",
///   "to": "0x...",
///   "value": "1000000000000000000",
///   "gas_limit": 100000,
///   "max_fee": "1000000000",
///   "max_priority_fee": "100000000"
/// }
/// ```
///
/// # Output JSON Format
/// ```json
/// {
///   "leaf_hash": "0x...",
///   "signing_hash": "0x...",
///   "leaf_script": "0x...",
///   "leaf_version": 1,
///   "merkle_proof": {
///     "leaf_index": 0,
///     "siblings": ["0x..."]
///   },
///   "estimated_gas": 100200,
///   "auth_root": "0x..."
/// }
/// ```
#[wasm_bindgen]
pub fn build_witness(
    leaves_json: &str,
    leaf_index: usize,
    tx_json: &str,
) -> Result<String, JsValue> {
    let raw: Vec<serde_json::Value> =
        serde_json::from_str(leaves_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let leaves: Vec<Leaf> = raw
        .iter()
        .map(|l| {
            Leaf::new(
                l["version"].as_u64().unwrap_or(1) as u8,
                hex::decode(l["script"].as_str().unwrap_or("").trim_start_matches("0x"))
                    .unwrap_or_default(),
                l["description"].as_str().unwrap_or(""),
            )
        })
        .collect();

    let tx: serde_json::Value =
        serde_json::from_str(tx_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let from_bytes =
        hex::decode(tx["from"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
    let to_bytes =
        hex::decode(tx["to"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();

    let mut from = [0u8; 20];
    let mut to = [0u8; 20];
    if from_bytes.len() == 20 {
        from.copy_from_slice(&from_bytes);
    }
    if to_bytes.len() == 20 {
        to.copy_from_slice(&to_bytes);
    }

    let msg = TxMessage {
        chain_id: tx["chain_id"].as_u64().unwrap_or(11155111),
        nonce: tx["nonce"].as_u64().unwrap_or(0),
        from,
        to,
        value: tx["value"].as_u64().unwrap_or(0) as u128,
        data: tx["data"]
            .as_str()
            .and_then(|s| hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok())
            .unwrap_or_default(),
        gas_limit: tx["gas_limit"].as_u64().unwrap_or(100_000),
        max_fee_per_gas: tx["max_fee"].as_u64().unwrap_or(1_000_000_000) as u128,
        max_priority_fee_per_gas: tx["max_priority_fee"].as_u64().unwrap_or(100_000_000) as u128,
    };

    let tree = MerkleTree::new(leaves.clone()).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let proof = tree
        .proof(leaf_index)
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
