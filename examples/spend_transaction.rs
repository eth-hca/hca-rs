//! Example: Spending from an HCA account
//!
//! Demonstrates generating a Merkle proof, building a transaction witness,
//! and computing the signing hash for a spending transaction.

use hca_rs::{
    address::derive_address,
    merkle::{Leaf, MerkleTree},
    witness::{HCAWitness, TxMessage},
};

fn main() {
    // Create account
    let leaves = vec![
        Leaf {
            version: 0x01,
            script: b"OP_CHECKSIG_primary_key".to_vec(),
            description: "Primary key".to_string(),
        },
        Leaf {
            version: 0x01,
            script: b"OP_CHECKSIG_recovery_key".to_vec(),
            description: "Recovery key".to_string(),
        },
    ];

    let tree = MerkleTree::new(leaves.clone()).expect("Failed to create tree");
    let auth_root = tree.auth_root();
    let from_address = derive_address(&auth_root);

    // Select spending condition and generate proof
    let leaf_index = 0;
    let selected_leaf = &leaves[leaf_index];
    let proof = tree.proof(leaf_index).expect("Failed to generate proof");

    // Build transaction
    let tx = TxMessage {
        chain_id: 1,
        nonce: 0,
        from: from_address,
        to: [0x12; 20],
        value: 1_000_000_000_000_000u128, // 0.001 ETH
        data: vec![],
        gas_limit: 100_000,
        max_fee_per_gas: 50_000_000_000u128,
        max_priority_fee_per_gas: 2_000_000_000u128,
    };

    // Build witness
    let mut witness = HCAWitness::build(selected_leaf, proof);

    // Compute signing hash
    let leaf_hash = selected_leaf.hash();
    let signing_hash = tx.signing_hash(&leaf_hash);

    // Attach signature (simulated - in production, wallet signs signing_hash)
    let signature = vec![0xAAu8; 65]; // Dummy 65-byte ECDSA signature
    witness.attach_signature(signature);

    println!("from:         0x{}", hex::encode(from_address));
    println!("to:           0x{}", hex::encode(tx.to));
    println!("value:        {} wei", tx.value);
    println!("signing_hash: 0x{}", hex::encode(signing_hash));
    println!("gas_estimate: {}", witness.estimate_gas());
    println!("signed:       {}", witness.is_signed());
}
