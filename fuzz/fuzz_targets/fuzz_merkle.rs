#![no_main]

use libfuzzer_sys::fuzz_target;
use hca_rs::merkle::{Leaf, MerkleTree};

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small
    if data.len() < 2 {
        return;
    }

    // Use first byte to determine number of leaves (1-16)
    let leaf_count = (data[0] % 16) as usize + 1;

    // Use remaining data to create leaves
    let mut leaves = Vec::new();
    let mut offset = 1;

    for i in 0..leaf_count {
        if offset >= data.len() {
            break;
        }

        // Take up to 32 bytes for script
        let script_len = (data[offset] as usize).min(32).min(data.len() - offset - 1);
        offset += 1;

        if offset + script_len > data.len() {
            break;
        }

        let script = data[offset..offset + script_len].to_vec();
        offset += script_len;

        leaves.push(Leaf {
            version: 0x01,
            script,
            description: format!("Leaf {}", i),
        });
    }

    // Must have at least one leaf
    if leaves.is_empty() {
        return;
    }

    // Test tree construction
    if let Ok(tree) = MerkleTree::new(leaves.clone()) {
        // Test auth_root computation
        let _ = tree.auth_root();

        // Test proof generation for first leaf
        if let Ok(proof) = tree.proof(0) {
            let leaf_hash = leaves[0].hash();
            let root = tree.auth_root();

            // Test proof verification (should never panic)
            let _ = MerkleTree::verify(&leaf_hash, &proof, &root);
        }
    }
});
