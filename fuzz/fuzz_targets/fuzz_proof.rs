#![no_main]

use libfuzzer_sys::fuzz_target;
use hca_rs::merkle::{MerkleProof, MerkleTree};

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small
    if data.len() < 66 {
        return; // Need at least leaf_hash (32) + root (32) + some siblings
    }

    // Extract leaf_hash and root from fuzzer data
    let mut leaf_hash = [0u8; 32];
    leaf_hash.copy_from_slice(&data[0..32]);

    let mut root = [0u8; 32];
    root.copy_from_slice(&data[32..64]);

    // Use remaining data to build proof siblings
    let remaining = &data[64..];
    let sibling_count = (remaining.len() / 32).min(32); // Max depth is 32

    let mut siblings = Vec::new();
    for i in 0..sibling_count {
        let start = i * 32;
        if start + 32 <= remaining.len() {
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(&remaining[start..start + 32]);
            siblings.push(sibling);
        }
    }

    // Construct proof
    let proof = MerkleProof {
        leaf_index: 0, // Always use index 0 for fuzzing
        siblings,
    };

    // Test verification (should never panic, even with invalid data)
    let _ = MerkleTree::verify(&leaf_hash, &proof, &root);
});
