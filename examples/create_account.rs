//! Example: Creating an HCA account
//!
//! Demonstrates building a Merkle tree from spending conditions
//! and deriving the quantum-resistant HCA address.

use hca_rs::{address::derive_address, merkle::Leaf, MerkleTree};

fn main() {
    // Define spending conditions
    let leaves = vec![
        Leaf {
            version: 0x01,
            script: b"OP_CHECKSIG_primary_key".to_vec(),
            description: "Primary ECDSA key".to_string(),
        },
        Leaf {
            version: 0x01,
            script: b"OP_CHECKSIG_recovery_key".to_vec(),
            description: "Recovery key".to_string(),
        },
        Leaf {
            version: 0x01,
            script: b"OP_TIMELOCK_30days".to_vec(),
            description: "Timelock 30 days".to_string(),
        },
        Leaf {
            version: 0x01,
            script: b"OP_MULTISIG_2of3".to_vec(),
            description: "2-of-3 multisig".to_string(),
        },
    ];

    // Build tree
    let tree = MerkleTree::new(leaves).expect("Failed to create tree");
    let auth_root = tree.auth_root();

    // Derive address
    let address = derive_address(&auth_root);

    println!("auth_root: 0x{}", hex::encode(auth_root));
    println!("address:   0x{}", hex::encode(address));
}
