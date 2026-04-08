//! Cross-implementation test vector validation.
//!
//! Every `expected` field in the JSON vectors is a hardcoded hash/address —
//! no `"computed_at_runtime"` placeholders.  These vectors are the canonical
//! reference for hca-go and any future implementation.

use hca_rs::address::{address_to_hex, derive_address};
use hca_rs::hash::tagged_hash_str as tagged_hash;
use hca_rs::merkle::{Leaf, MerkleProof, MerkleTree};
use hca_rs::rlp::{encode_address, encode_bytes, encode_hca_tx, encode_list, encode_uint};
use hca_rs::witness::{HCAWitness, RotationRequest, TxMessage};
use serde_json::Value;
use std::fs;

// ── helpers ───────────────────────────────────────────────────────────────────

fn decode_hex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("valid hex")
}

fn encode_hex(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let v = decode_hex(s);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    arr
}

fn decode_hex20(s: &str) -> [u8; 20] {
    let v = decode_hex(s);
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&v);
    arr
}

// ── tagged hash vectors ───────────────────────────────────────────────────────

#[test]
fn test_tagged_hash_vectors() {
    let json_str = fs::read_to_string("tests/vectors/tagged_hash.json").expect("tagged_hash.json");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    for (i, v) in json["vectors"].as_array().unwrap().iter().enumerate() {
        let description = v["description"].as_str().unwrap();
        let tag = v["tag"].as_str().unwrap();
        let data = decode_hex(v["data"].as_str().unwrap());
        let expected = v["expected"].as_str().unwrap();

        let got = tagged_hash(tag, &data);
        assert_eq!(
            encode_hex(&got),
            expected,
            "Vector {}: {} — hash mismatch",
            i + 1,
            description
        );
    }
}

// ── address derivation vectors ────────────────────────────────────────────────

#[test]
fn test_address_derivation_vectors() {
    let json_str = fs::read_to_string("tests/vectors/address_derivation.json")
        .expect("address_derivation.json");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    for (i, v) in json["vectors"].as_array().unwrap().iter().enumerate() {
        let description = v["description"].as_str().unwrap();
        let expected = v["expected_address"].as_str().unwrap();

        let auth_root = match v["auth_root"].as_str().unwrap() {
            s if s.starts_with("0x") => decode_hex32(s),
            _ => {
                // Derive from leaf(s) defined in the vector
                if let Some(leaf_data) = v.get("leaf") {
                    let version = decode_hex(leaf_data["version"].as_str().unwrap())[0];
                    let script = decode_hex(leaf_data["script"].as_str().unwrap());
                    let leaf = Leaf::new(version, script, description).unwrap();
                    MerkleTree::new(vec![leaf]).unwrap().auth_root()
                } else {
                    let leaves: Vec<Leaf> = v["leaves"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .enumerate()
                        .map(|(idx, l)| {
                            let version = decode_hex(l["version"].as_str().unwrap())[0];
                            let script = decode_hex(l["script"].as_str().unwrap());
                            Leaf::new(version, script, &format!("leaf_{}", idx)).unwrap()
                        })
                        .collect();
                    MerkleTree::new(leaves).unwrap().auth_root()
                }
            }
        };

        let got = derive_address(&auth_root);
        assert_eq!(
            encode_hex(&got),
            expected,
            "Vector {}: {} — address mismatch",
            i + 1,
            description
        );
    }
}

// ── merkle proof vectors ──────────────────────────────────────────────────────

#[test]
fn test_merkle_proof_vectors() {
    let json_str =
        fs::read_to_string("tests/vectors/merkle_proofs.json").expect("merkle_proofs.json");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    for (i, v) in json["vectors"].as_array().unwrap().iter().enumerate() {
        let description = v["description"].as_str().unwrap();
        let expected_root = v["tree"]["auth_root"].as_str().unwrap();
        let expected_depth = v["tree"]["depth"].as_u64().unwrap() as usize;

        let leaves: Vec<Leaf> = v["leaves"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(idx, l)| {
                let version = decode_hex(l["version"].as_str().unwrap())[0];
                let script = decode_hex(l["script"].as_str().unwrap());
                Leaf::new(version, script, &format!("leaf_{}", idx)).unwrap()
            })
            .collect();

        let tree = MerkleTree::new(leaves.clone()).unwrap();

        assert_eq!(
            encode_hex(&tree.auth_root()),
            expected_root,
            "Vector {}: {} — auth_root mismatch",
            i + 1,
            description
        );
        assert_eq!(
            tree.depth,
            expected_depth,
            "Vector {}: {} — depth mismatch",
            i + 1,
            description
        );

        for proof_data in v["proofs"].as_array().unwrap() {
            let leaf_index = proof_data["leaf_index"].as_u64().unwrap() as usize;
            let should_verify = proof_data["should_verify"].as_bool().unwrap();
            let expected_siblings: Vec<String> = proof_data["siblings"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_string())
                .collect();

            let proof = tree.proof(leaf_index).unwrap();

            // Assert each sibling matches the vector
            assert_eq!(
                proof.siblings.len(),
                expected_siblings.len(),
                "Vector {}: leaf {} sibling count mismatch",
                i + 1,
                leaf_index
            );
            for (j, (got, want)) in proof
                .siblings
                .iter()
                .zip(expected_siblings.iter())
                .enumerate()
            {
                assert_eq!(
                    encode_hex(got),
                    *want,
                    "Vector {}: leaf {} sibling[{}] mismatch",
                    i + 1,
                    leaf_index,
                    j
                );
            }

            let leaf_hash = leaves[leaf_index].hash();
            let verified = MerkleTree::verify(&leaf_hash, &proof, &tree.auth_root()).unwrap();
            assert_eq!(
                verified,
                should_verify,
                "Vector {}: leaf {} proof verify mismatch",
                i + 1,
                leaf_index
            );
        }

        // Wrong leaf must not verify
        if leaves.len() > 1 {
            let proof = tree.proof(0).unwrap();
            let wrong_hash = leaves[1].hash();
            assert!(
                !MerkleTree::verify(&wrong_hash, &proof, &tree.auth_root()).unwrap(),
                "Vector {}: wrong leaf must not verify",
                i + 1
            );
        }
    }
}

// ── witness signing hash vectors ──────────────────────────────────────────────

#[test]
fn test_witness_signing_vectors() {
    let json_str =
        fs::read_to_string("tests/vectors/witness_signing.json").expect("witness_signing.json");
    let json: Value = serde_json::from_str(&json_str).expect("valid JSON");

    for (i, v) in json["vectors"].as_array().unwrap().iter().enumerate() {
        let description = v["description"].as_str().unwrap();

        if v.get("transaction_mainnet").is_some() {
            // Cross-chain replay vector
            let tx_main = parse_tx(&v["transaction_mainnet"]);
            let tx_sep = parse_tx(&v["transaction_sepolia"]);
            let leaf_hash = decode_hex32(v["leaf_hash"].as_str().unwrap());

            let got_main = encode_hex(&tx_main.signing_hash(&leaf_hash));
            let got_sep = encode_hex(&tx_sep.signing_hash(&leaf_hash));

            assert_eq!(
                got_main,
                v["expected_signing_hash_mainnet"].as_str().unwrap(),
                "Vector {}: {} — mainnet hash mismatch",
                i + 1,
                description
            );
            assert_eq!(
                got_sep,
                v["expected_signing_hash_sepolia"].as_str().unwrap(),
                "Vector {}: {} — sepolia hash mismatch",
                i + 1,
                description
            );
            assert_ne!(got_main, got_sep, "Cross-chain hashes must differ");
        } else if v.get("leaf_hash_1").is_some() {
            // Different leaf hashes vector
            let tx = parse_tx(&v["transaction"]);
            let lh1 = decode_hex32(v["leaf_hash_1"].as_str().unwrap());
            let lh2 = decode_hex32(v["leaf_hash_2"].as_str().unwrap());

            let got1 = encode_hex(&tx.signing_hash(&lh1));
            let got2 = encode_hex(&tx.signing_hash(&lh2));

            assert_eq!(
                got1,
                v["expected_signing_hash_1"].as_str().unwrap(),
                "Vector {}: {} — hash_1 mismatch",
                i + 1,
                description
            );
            assert_eq!(
                got2,
                v["expected_signing_hash_2"].as_str().unwrap(),
                "Vector {}: {} — hash_2 mismatch",
                i + 1,
                description
            );
            assert_ne!(
                got1, got2,
                "Different leaf hashes must produce different signing hashes"
            );
        } else {
            // Standard transaction vector
            let tx = parse_tx(&v["transaction"]);
            let leaf_hash = decode_hex32(v["leaf_hash"].as_str().unwrap());
            let expected = v["expected_signing_hash"].as_str().unwrap();

            let got = encode_hex(&tx.signing_hash(&leaf_hash));
            assert_eq!(
                got,
                expected,
                "Vector {}: {} — signing hash mismatch",
                i + 1,
                description
            );
        }
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────

#[test]
fn test_hca_construction_vector() {
    let json_str = fs::read_to_string("tests/vectors/hca_construction.json")
        .expect("hca_construction.json should exist");
    let v: Value = serde_json::from_str(&json_str).expect("valid JSON");

    // Build leaves
    let leaves: Vec<Leaf> = v["leaves"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            let version = u8::from_str_radix(
                l["version"].as_str().unwrap().strip_prefix("0x").unwrap(),
                16,
            )
            .unwrap();
            let script = decode_hex(l["script"].as_str().unwrap());
            Leaf::new(version, script, "").unwrap()
        })
        .collect();

    // Verify leaf hashes
    let expected_hashes = v["leaf_hashes"].as_array().unwrap();
    for (i, leaf) in leaves.iter().enumerate() {
        assert_eq!(
            encode_hex(&leaf.hash()),
            expected_hashes[i].as_str().unwrap(),
            "leaf_hash[{}] mismatch",
            i
        );
    }

    // Build tree and verify auth_root
    let tree = MerkleTree::new(leaves.clone()).unwrap();
    let expected_auth_root = v["tree"]["auth_root"].as_str().unwrap();
    assert_eq!(
        encode_hex(&tree.auth_root()),
        expected_auth_root,
        "auth_root mismatch"
    );

    // Verify address
    let expected_address = v["address"].as_str().unwrap();
    assert_eq!(
        address_to_hex(&derive_address(&tree.auth_root())),
        expected_address,
        "address mismatch"
    );

    // Verify proof
    let leaf_index = v["proof"]["leaf_index"].as_u64().unwrap() as usize;
    let proof = tree.proof(leaf_index).unwrap();
    let expected_leaf_hash = v["proof"]["leaf_hash"].as_str().unwrap();
    assert_eq!(
        encode_hex(&leaves[leaf_index].hash()),
        expected_leaf_hash,
        "proof leaf_hash mismatch"
    );
    let expected_siblings = v["proof"]["siblings"].as_array().unwrap();
    assert_eq!(
        proof.siblings.len(),
        expected_siblings.len(),
        "sibling count mismatch"
    );
    for (i, sib) in proof.siblings.iter().enumerate() {
        assert_eq!(
            encode_hex(sib),
            expected_siblings[i].as_str().unwrap(),
            "sibling[{}] mismatch",
            i
        );
    }
    assert!(
        MerkleTree::verify(&leaves[leaf_index].hash(), &proof, &tree.auth_root()).unwrap(),
        "proof verification failed"
    );

    // Verify signing hash
    let tx = parse_tx(&v["transaction"]);
    let leaf_hash = decode_hex32(expected_leaf_hash);
    let expected_signing_hash = v["signing_hash"].as_str().unwrap();
    assert_eq!(
        encode_hex(&tx.signing_hash(&leaf_hash)),
        expected_signing_hash,
        "signing_hash mismatch"
    );
}

#[test]
fn test_rotation_vectors() {
    let json_str =
        fs::read_to_string("tests/vectors/rotation.json").expect("rotation.json should exist");
    let v: Value = serde_json::from_str(&json_str).expect("valid JSON");

    let vectors = v["vectors"].as_array().unwrap();
    println!("\n=== Rotation Signing Hash Vectors ===");

    for (i, vec) in vectors.iter().enumerate() {
        let description = vec["description"].as_str().unwrap();
        let chain_id = vec["chain_id"].as_u64().unwrap();
        let nonce = vec["nonce"].as_u64().unwrap();
        let from = decode_hex20(vec["from"].as_str().unwrap());
        let new_auth_root = decode_hex32(vec["new_auth_root"].as_str().unwrap());
        let expected = vec["expected"].as_str().unwrap();

        let req = RotationRequest::new(chain_id, nonce, from, new_auth_root).unwrap();
        let got = encode_hex(&req.signing_hash());

        println!("Vector {}: {} => {}", i + 1, description, got);
        assert_eq!(
            got,
            expected,
            "Vector {}: {} — signing hash mismatch",
            i + 1,
            description
        );
    }

    // Cross-check: all hashes must be distinct
    let hashes: Vec<String> = vectors
        .iter()
        .map(|vec| {
            let req = RotationRequest::new(
                vec["chain_id"].as_u64().unwrap(),
                vec["nonce"].as_u64().unwrap(),
                decode_hex20(vec["from"].as_str().unwrap()),
                decode_hex32(vec["new_auth_root"].as_str().unwrap()),
            )
            .unwrap();
            encode_hex(&req.signing_hash())
        })
        .collect();

    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "Vectors {} and {} produced the same hash",
                i, j
            );
        }
    }
}

#[test]
fn test_rlp_encoding_vectors() {
    let json_str = fs::read_to_string("tests/vectors/rlp_encoding.json")
        .expect("rlp_encoding.json should exist");
    let v: Value = serde_json::from_str(&json_str).expect("valid JSON");

    // encode_uint
    for (i, vec) in v["encode_uint"].as_array().unwrap().iter().enumerate() {
        let value: u128 = vec["value"].as_str().unwrap().parse().unwrap();
        let expected = vec["expected"].as_str().unwrap();
        assert_eq!(
            encode_hex(&encode_uint(value)),
            expected,
            "encode_uint[{}] mismatch",
            i
        );
    }

    // encode_bytes
    for (i, vec) in v["encode_bytes"].as_array().unwrap().iter().enumerate() {
        let input = decode_hex(vec["input"].as_str().unwrap());
        let expected = vec["expected"].as_str().unwrap();
        assert_eq!(
            encode_hex(&encode_bytes(&input)),
            expected,
            "encode_bytes[{}] mismatch",
            i
        );
    }

    // encode_list — items are already RLP-encoded hex strings
    for (i, vec) in v["encode_list"].as_array().unwrap().iter().enumerate() {
        let items: Vec<Vec<u8>> = vec["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| decode_hex(s.as_str().unwrap()))
            .collect();
        let expected = vec["expected"].as_str().unwrap();
        assert_eq!(
            encode_hex(&encode_list(&items)),
            expected,
            "encode_list[{}] mismatch",
            i
        );
    }

    // encode_address
    for (i, vec) in v["encode_address"].as_array().unwrap().iter().enumerate() {
        let input = decode_hex(vec["input"].as_str().unwrap());
        let expected = vec["expected"].as_str().unwrap();
        assert_eq!(
            encode_hex(&encode_address(&input.try_into().unwrap())),
            expected,
            "encode_address[{}] mismatch",
            i
        );
    }

    // encode_hca_tx
    for (i, vec) in v["encode_hca_tx"].as_array().unwrap().iter().enumerate() {
        let tx = parse_tx(&vec["tx"]);
        let w = &vec["witness"];
        let leaf_version = u8::from_str_radix(
            w["leaf_version"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap(),
            16,
        )
        .unwrap();
        let leaf_script = decode_hex(w["leaf_script"].as_str().unwrap());
        let leaf = Leaf::new(leaf_version, leaf_script, "").unwrap();
        let siblings: Vec<[u8; 32]> = w["siblings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| decode_hex32(s.as_str().unwrap()))
            .collect();
        let proof = MerkleProof {
            leaf_index: w["leaf_index"].as_u64().unwrap() as usize,
            siblings,
        };
        let mut witness = HCAWitness::build(&leaf, proof);
        let witness_data = decode_hex(w["witness_data"].as_str().unwrap());
        witness.attach_signature(witness_data).unwrap();

        let encoded = encode_hca_tx(&tx, &witness).unwrap();
        let expected = vec["expected"].as_str().unwrap();
        assert_eq!(
            encode_hex(&encoded),
            expected,
            "encode_hca_tx[{}] mismatch",
            i
        );
    }
}

fn parse_tx(j: &Value) -> TxMessage {
    TxMessage {
        chain_id: j["chain_id"].as_u64().unwrap(),
        nonce: j["nonce"].as_u64().unwrap(),
        from: decode_hex20(j["from"].as_str().unwrap()),
        to: decode_hex20(j["to"].as_str().unwrap()),
        value: j["value"].as_str().unwrap().parse().unwrap(),
        data: j["data"].as_str().map(decode_hex).unwrap_or_default(),
        gas_limit: j["gas_limit"].as_u64().unwrap(),
        max_fee_per_gas: j["max_fee_per_gas"].as_str().unwrap().parse().unwrap(),
        max_priority_fee_per_gas: j["max_priority_fee_per_gas"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap(),
    }
}
