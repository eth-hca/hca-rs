#![no_main]

use libfuzzer_sys::fuzz_target;
use hca_rs::{
    merkle::{Leaf, MerkleProof},
    witness::{HCAWitness, TxMessage},
};

fuzz_target!(|data: &[u8]| {
    // Skip if data is too small
    if data.len() < 100 {
        return;
    }

    // Parse transaction fields from fuzzer data
    let chain_id = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let nonce = u64::from_le_bytes([
        data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
    ]);

    let mut from = [0u8; 20];
    from.copy_from_slice(&data[16..36]);

    let mut to = [0u8; 20];
    to.copy_from_slice(&data[36..56]);

    let value = u128::from_le_bytes([
        data[56], data[57], data[58], data[59], data[60], data[61], data[62], data[63],
        data[64], data[65], data[66], data[67], data[68], data[69], data[70], data[71],
    ]);

    let gas_limit = u64::from_le_bytes([
        data[72], data[73], data[74], data[75], data[76], data[77], data[78], data[79],
    ]);

    let max_fee_per_gas = u128::from_le_bytes([
        data[80], data[81], data[82], data[83], data[84], data[85], data[86], data[87],
        data[88], data[89], data[90], data[91], data[92], data[93], data[94], data[95],
    ]);

    let max_priority_fee_per_gas = if data.len() >= 112 {
        u128::from_le_bytes([
            data[96], data[97], data[98], data[99], data[100], data[101], data[102], data[103],
            data[104], data[105], data[106], data[107], data[108], data[109], data[110],
            data[111],
        ])
    } else {
        0
    };

    // Create transaction message
    let tx = TxMessage {
        chain_id,
        nonce,
        from,
        to,
        value,
        data: vec![],
        gas_limit,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    };

    // Create a simple leaf for testing
    let script = if data.len() > 112 {
        data[112..].to_vec()
    } else {
        vec![0x01]
    };

    let leaf = Leaf {
        version: 0x01,
        script,
        description: "Fuzz test".to_string(),
    };

    // Create minimal proof
    let proof = MerkleProof {
        leaf_index: 0,
        siblings: vec![],
    };

    // Test witness building
    let mut witness = HCAWitness::build(&leaf, proof);

    // Test signing hash computation (should never panic)
    let leaf_hash = leaf.hash();
    let _ = tx.signing_hash(&leaf_hash);

    // Test gas estimation
    let _ = witness.estimate_gas();

    // Test signature attachment
    if data.len() > 150 {
        let sig = data[150..].to_vec();
        let _ = witness.attach_signature(sig);
        let _ = witness.is_signed();
    }
});
