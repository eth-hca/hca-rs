//! Example: Verifying Merkle proofs
//!
//! Demonstrates proof generation and verification,
//! including validation of proof integrity.

use hca_rs::{merkle::Leaf, MerkleTree};

fn main() {
    // Create tree
    let leaves = vec![
        Leaf {
            version: 0x01,
            script: b"condition_A".to_vec(),
            description: "Condition A".to_string(),
        },
        Leaf {
            version: 0x01,
            script: b"condition_B".to_vec(),
            description: "Condition B".to_string(),
        },
        Leaf {
            version: 0x01,
            script: b"condition_C".to_vec(),
            description: "Condition C".to_string(),
        },
        Leaf {
            version: 0x01,
            script: b"condition_D".to_vec(),
            description: "Condition D".to_string(),
        },
    ];

    let tree = MerkleTree::new(leaves.clone()).expect("Failed to create tree");
    let auth_root = tree.auth_root();

    println!("Tree: {} leaves, depth {}", leaves.len(), tree.depth);
    println!("Root: 0x{}\n", hex::encode(auth_root));

    // Verify all proofs
    for (index, leaf) in leaves.iter().enumerate() {
        let proof = tree.proof(index).expect("Failed to generate proof");
        let leaf_hash = leaf.hash();
        let valid =
            MerkleTree::verify(&leaf_hash, &proof, &auth_root).expect("Verification failed");

        println!(
            "Leaf {}: {} - {}",
            index,
            if valid { "VALID" } else { "INVALID" },
            leaf.description
        );
    }

    // Test cross-tree verification (should fail)
    println!("\nCross-tree verification:");
    let other_tree = MerkleTree::new(vec![Leaf {
        version: 0x01,
        script: b"different".to_vec(),
        description: "Different".to_string(),
    }])
    .expect("Failed to create tree");
    let other_root = other_tree.auth_root();

    let proof = tree.proof(0).expect("Failed to generate proof");
    let leaf_hash = leaves[0].hash();
    let valid = MerkleTree::verify(&leaf_hash, &proof, &other_root).expect("Verification failed");

    println!(
        "Proof from tree1 vs tree2 root: {}",
        if valid { "VALID" } else { "INVALID" }
    );

    // Test tampered leaf (should fail)
    println!("\nTampered leaf verification:");
    let mut tampered = leaves[0].clone();
    tampered.script = b"tampered".to_vec();
    let tampered_hash = tampered.hash();
    let valid =
        MerkleTree::verify(&tampered_hash, &proof, &auth_root).expect("Verification failed");

    println!(
        "Tampered leaf vs original proof: {}",
        if valid { "VALID" } else { "INVALID" }
    );
}
