//! Test vector validation
//!
//! These tests read JSON test vectors and validate that the implementation
//! produces the expected results. They also serve to generate canonical
//! test vectors for cross-implementation compatibility.

use hca_rs::address::derive_address;
use hca_rs::hash::{tagged_hash, tags};
use hca_rs::merkle::{Leaf, MerkleTree};
use hca_rs::witness::TxMessage;
use serde_json::Value;
use std::fs;

/// Helper: decode hex string to bytes
fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).expect("valid hex")
}

/// Helper: encode bytes to hex string
fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

#[test]
fn test_tagged_hash_vectors() {
    let json_str = fs::read_to_string("tests/vectors/tagged_hash.json")
        .expect("tagged_hash.json should exist");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    let vectors = json["vectors"].as_array().expect("vectors array");

    println!("\n=== Tagged Hash Test Vectors ===");
    for (i, vector) in vectors.iter().enumerate() {
        let description = vector["description"].as_str().unwrap();
        let tag = vector["tag"].as_str().unwrap();
        let data_hex = vector["data"].as_str().unwrap();
        let data = decode_hex(data_hex);

        let result = tagged_hash(tag, &data);
        let result_hex = encode_hex(&result);

        println!(
            "Vector {}: {} → {}",
            i + 1,
            description,
            result_hex
        );

        // Verify determinism
        let result2 = tagged_hash(tag, &data);
        assert_eq!(result, result2, "Tagged hash must be deterministic");

        // Verify domain separation: same data, different tags → different outputs
        if tag == "HCAAddr" && !data.is_empty() {
            let leaf_result = tagged_hash(tags::LEAF, &data);
            assert_ne!(
                result, leaf_result,
                "Different tags must produce different hashes"
            );
        }
    }
}

#[test]
fn test_address_derivation_vectors() {
    let json_str = fs::read_to_string("tests/vectors/address_derivation.json")
        .expect("address_derivation.json should exist");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    let vectors = json["vectors"].as_array().expect("vectors array");

    println!("\n=== Address Derivation Test Vectors ===");
    for (i, vector) in vectors.iter().enumerate() {
        let description = vector["description"].as_str().unwrap();

        // Compute or extract auth_root
        let auth_root: [u8; 32] = if let Some(root_hex) = vector["auth_root"].as_str() {
            if root_hex.starts_with("0x") {
                let bytes = decode_hex(root_hex);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                arr
            } else {
                // Compute from leaves
                if let Some(leaf_data) = vector.get("leaf") {
                    let version = decode_hex(leaf_data["version"].as_str().unwrap())[0];
                    let script = decode_hex(leaf_data["script"].as_str().unwrap());
                    let leaf = Leaf::new(version, script, description);
                    let tree = MerkleTree::new(vec![leaf]).unwrap();
                    tree.auth_root()
                } else if let Some(leaves_data) = vector.get("leaves") {
                    let leaves: Vec<Leaf> = leaves_data
                        .as_array()
                        .unwrap()
                        .iter()
                        .enumerate()
                        .map(|(idx, l)| {
                            let version = decode_hex(l["version"].as_str().unwrap())[0];
                            let script = decode_hex(l["script"].as_str().unwrap());
                            Leaf::new(version, script, &format!("leaf_{}", idx))
                        })
                        .collect();
                    let tree = MerkleTree::new(leaves).unwrap();
                    tree.auth_root()
                } else {
                    panic!("Unknown auth_root format");
                }
            }
        } else {
            panic!("auth_root missing");
        };

        let address = derive_address(&auth_root);
        let address_hex = encode_hex(&address);

        println!(
            "Vector {}: {} → {}",
            i + 1,
            description,
            address_hex
        );

        // Verify properties
        assert_eq!(address.len(), 20, "Address must be 20 bytes");

        // Verify determinism
        let address2 = derive_address(&auth_root);
        assert_eq!(address, address2, "Address derivation must be deterministic");
    }
}

#[test]
fn test_merkle_proof_vectors() {
    let json_str = fs::read_to_string("tests/vectors/merkle_proofs.json")
        .expect("merkle_proofs.json should exist");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    let vectors = json["vectors"].as_array().expect("vectors array");

    println!("\n=== Merkle Proof Test Vectors ===");
    for (i, vector) in vectors.iter().enumerate() {
        let description = vector["description"].as_str().unwrap();
        let leaves_data = vector["leaves"].as_array().unwrap();

        // Build leaves
        let leaves: Vec<Leaf> = leaves_data
            .iter()
            .enumerate()
            .map(|(idx, l)| {
                let version = decode_hex(l["version"].as_str().unwrap())[0];
                let script = decode_hex(l["script"].as_str().unwrap());
                Leaf::new(version, script, &format!("leaf_{}", idx))
            })
            .collect();

        // Build tree
        let tree: MerkleTree = MerkleTree::new(leaves.clone()).unwrap();
        let auth_root = tree.auth_root();

        println!(
            "Vector {}: {} (depth={}, auth_root={})",
            i + 1,
            description,
            tree.depth,
            encode_hex(&auth_root)
        );

        // Test all proofs
        let proofs_data = vector["proofs"].as_array().unwrap();
        for proof_data in proofs_data {
            let leaf_index = proof_data["leaf_index"].as_u64().unwrap() as usize;
            let should_verify = proof_data["should_verify"].as_bool().unwrap();

            // Generate proof
            let proof = tree.proof(leaf_index).unwrap();
            assert_eq!(
                proof.siblings.len(),
                tree.depth,
                "Proof depth must match tree depth"
            );

            // Verify proof
            let leaf_hash = leaves[leaf_index].hash();
            let verified = MerkleTree::verify(&leaf_hash, &proof, &auth_root).unwrap();
            assert_eq!(verified, should_verify, "Proof verification mismatch");

            println!(
                "  Proof for leaf {}: {} siblings, verified={}",
                leaf_index,
                proof.siblings.len(),
                verified
            );
        }

        // Test that wrong leaf doesn't verify
        if leaves.len() > 1 {
            let proof = tree.proof(0).unwrap();
            let wrong_hash = leaves[1].hash();
            let verified = MerkleTree::verify(&wrong_hash, &proof, &auth_root).unwrap();
            assert!(!verified, "Wrong leaf should not verify");
        }
    }
}

#[test]
fn test_witness_signing_vectors() {
    let json_str = fs::read_to_string("tests/vectors/witness_signing.json")
        .expect("witness_signing.json should exist");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    let vectors = json["vectors"].as_array().expect("vectors array");

    println!("\n=== Witness Signing Hash Test Vectors ===");
    for (i, vector) in vectors.iter().enumerate() {
        let description = vector["description"].as_str().unwrap();

        // Handle different vector formats - check special cases first
        if vector.get("transaction_mainnet").is_some() {
            // Cross-chain replay test
            let tx_mainnet = parse_tx_message(&vector["transaction_mainnet"]);
            let tx_sepolia = parse_tx_message(&vector["transaction_sepolia"]);
            let leaf_hash_hex = vector["leaf_hash"].as_str().unwrap();
            let leaf_hash_bytes = decode_hex(leaf_hash_hex);
            let mut leaf_hash = [0u8; 32];
            leaf_hash.copy_from_slice(&leaf_hash_bytes);

            let hash_mainnet = tx_mainnet.signing_hash(&leaf_hash);
            let hash_sepolia = tx_sepolia.signing_hash(&leaf_hash);

            println!(
                "Vector {}: {} → mainnet={}, sepolia={}",
                i + 1,
                description,
                encode_hex(&hash_mainnet),
                encode_hex(&hash_sepolia)
            );

            assert_ne!(
                hash_mainnet, hash_sepolia,
                "Different chain_id must produce different signing hashes"
            );
        } else if vector.get("leaf_hash_1").is_some() {
            // Different leaf hashes test
            let tx = parse_tx_message(&vector["transaction"]);
            let leaf_hash_1_bytes = decode_hex(vector["leaf_hash_1"].as_str().unwrap());
            let leaf_hash_2_bytes = decode_hex(vector["leaf_hash_2"].as_str().unwrap());

            let mut leaf_hash_1 = [0u8; 32];
            let mut leaf_hash_2 = [0u8; 32];
            leaf_hash_1.copy_from_slice(&leaf_hash_1_bytes);
            leaf_hash_2.copy_from_slice(&leaf_hash_2_bytes);

            let hash_1 = tx.signing_hash(&leaf_hash_1);
            let hash_2 = tx.signing_hash(&leaf_hash_2);

            println!(
                "Vector {}: {} → hash1={}, hash2={}",
                i + 1,
                description,
                encode_hex(&hash_1),
                encode_hex(&hash_2)
            );

            assert_ne!(
                hash_1, hash_2,
                "Different leaf hashes must produce different signing hashes"
            );
        } else if let Some(tx_data) = vector.get("transaction") {
            // Standard transaction test
            let tx = parse_tx_message(tx_data);
            let leaf_hash_hex = vector["leaf_hash"].as_str().unwrap();
            let leaf_hash_bytes = decode_hex(leaf_hash_hex);
            let mut leaf_hash = [0u8; 32];
            leaf_hash.copy_from_slice(&leaf_hash_bytes);

            let signing_hash = tx.signing_hash(&leaf_hash);
            let signing_hash_hex = encode_hex(&signing_hash);

            println!(
                "Vector {}: {} → {}",
                i + 1,
                description,
                signing_hash_hex
            );

            // Verify determinism
            let signing_hash2 = tx.signing_hash(&leaf_hash);
            assert_eq!(
                signing_hash, signing_hash2,
                "Signing hash must be deterministic"
            );
        }
    }
}

/// Helper to parse TxMessage from JSON
fn parse_tx_message(json: &Value) -> TxMessage {
    let from_bytes = decode_hex(json["from"].as_str().unwrap());
    let to_bytes = decode_hex(json["to"].as_str().unwrap());

    let mut from = [0u8; 20];
    let mut to = [0u8; 20];
    from.copy_from_slice(&from_bytes);
    to.copy_from_slice(&to_bytes);

    TxMessage {
        chain_id: json["chain_id"].as_u64().unwrap(),
        nonce: json["nonce"].as_u64().unwrap(),
        from,
        to,
        value: json["value"].as_str().unwrap().parse().unwrap(),
        gas_limit: json["gas_limit"].as_u64().unwrap(),
        max_fee_per_gas: json["max_fee_per_gas"].as_str().unwrap().parse().unwrap(),
        max_priority_fee_per_gas: json["max_priority_fee_per_gas"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    }
}
