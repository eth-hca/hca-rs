//! Full flow benchmarks
//!
//! End-to-end benchmarks for complete HCA workflows.
//! Simulates real-world usage patterns from account creation to transaction signing.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hca_rs::{
    address::derive_address,
    merkle::{Leaf, MerkleTree},
    witness::{HCAWitness, TxMessage},
};

/// Generate test leaves for full flow
fn generate_leaves(count: usize) -> Vec<Leaf> {
    (0..count)
        .map(|i| Leaf {
            version: 0x01,
            script: vec![i as u8; 64], // Typical ECDSA script size
            description: format!("Key {}", i),
        })
        .collect()
}

/// Benchmark full account creation flow
/// Steps: leaves → tree → auth_root → address
fn bench_account_creation(c: &mut Criterion) {
    let mut group = c.benchmark_group("account_creation");

    for leaf_count in [1, 2, 4, 8, 16].iter() {
        let leaves = generate_leaves(*leaf_count);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_leaves", leaf_count)),
            leaf_count,
            |b, _| {
                b.iter(|| {
                    let tree = MerkleTree::new(black_box(leaves.clone())).unwrap();
                    let auth_root = tree.auth_root();
                    let _address = derive_address(&auth_root);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark transaction preparation flow
/// Steps: tree → proof → witness → signing_hash
fn bench_transaction_preparation(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_preparation");

    for leaf_count in [2, 4, 8, 16, 64].iter() {
        let leaves = generate_leaves(*leaf_count);
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let auth_root = tree.auth_root();
        let address = derive_address(&auth_root);

        let tx = TxMessage {
            chain_id: 1,
            nonce: 0,
            from: address,
            to: [0x02u8; 20],
            value: 1_000_000_000_000_000u128,
            data: vec![],
            gas_limit: 100_000,
            max_fee_per_gas: 1_000_000_000u128,
            max_priority_fee_per_gas: 100_000_000u128,
        };

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_leaves", leaf_count)),
            leaf_count,
            |b, _| {
                b.iter(|| {
                    // Generate proof for first leaf
                    let proof = tree.proof(black_box(0)).unwrap();
                    let leaf = &leaves[0];

                    // Build witness
                    let witness = HCAWitness::build(leaf, proof);

                    // Compute signing hash
                    let leaf_hash = leaf.hash();
                    let _signing_hash = tx.signing_hash(&leaf_hash);

                    black_box(witness);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark full flow: account creation + transaction preparation
fn bench_complete_flow(c: &mut Criterion) {
    let mut group = c.benchmark_group("complete_flow");

    for leaf_count in [2, 4, 8, 16].iter() {
        let leaves = generate_leaves(*leaf_count);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_leaves", leaf_count)),
            leaf_count,
            |b, _| {
                b.iter(|| {
                    // 1. Create tree and derive address
                    let tree = MerkleTree::new(black_box(leaves.clone())).unwrap();
                    let auth_root = tree.auth_root();
                    let address = derive_address(&auth_root);

                    // 2. Prepare transaction
                    let tx = TxMessage {
                        chain_id: 1,
                        nonce: 0,
                        from: address,
                        to: [0x02u8; 20],
                        value: 1_000_000_000_000_000u128,
                        data: vec![],
                        gas_limit: 100_000,
                        max_fee_per_gas: 1_000_000_000u128,
                        max_priority_fee_per_gas: 100_000_000u128,
                    };

                    // 3. Generate proof and build witness
                    let proof = tree.proof(0).unwrap();
                    let leaf = &leaves[0];
                    let witness = HCAWitness::build(leaf, proof);

                    // 4. Compute signing hash
                    let leaf_hash = leaf.hash();
                    let _signing_hash = tx.signing_hash(&leaf_hash);

                    black_box(witness);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark signing hash computation for different transaction patterns
fn bench_signing_hash_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("signing_hash_patterns");

    let address = [0x01u8; 20];
    let leaf_hash = [0x02u8; 32];

    // Minimal value transaction
    let tx_minimal = TxMessage {
        chain_id: 1,
        nonce: 0,
        from: address,
        to: [0x02u8; 20],
        value: 0,
        data: vec![],
        gas_limit: 21_000,
        max_fee_per_gas: 1_000_000_000u128,
        max_priority_fee_per_gas: 100_000_000u128,
    };

    group.bench_function("minimal_tx", |b| {
        b.iter(|| black_box(&tx_minimal).signing_hash(black_box(&leaf_hash)));
    });

    // Large value transaction
    let tx_large_value = TxMessage {
        chain_id: 1,
        nonce: 100,
        from: address,
        to: [0x02u8; 20],
        value: 1_000_000_000_000_000_000u128, // 1 ETH
        data: vec![],
        gas_limit: 100_000,
        max_fee_per_gas: 50_000_000_000u128,
        max_priority_fee_per_gas: 2_000_000_000u128,
    };

    group.bench_function("large_value_tx", |b| {
        b.iter(|| black_box(&tx_large_value).signing_hash(black_box(&leaf_hash)));
    });

    // Different chain
    let tx_alt_chain = TxMessage {
        chain_id: 11_155_111, // Sepolia
        nonce: 42,
        from: address,
        to: [0x02u8; 20],
        value: 500_000_000_000_000u128,
        data: vec![],
        gas_limit: 100_000,
        max_fee_per_gas: 1_000_000_000u128,
        max_priority_fee_per_gas: 100_000_000u128,
    };

    group.bench_function("alt_chain_tx", |b| {
        b.iter(|| black_box(&tx_alt_chain).signing_hash(black_box(&leaf_hash)));
    });

    group.finish();
}

/// Benchmark witness gas estimation
fn bench_witness_gas_estimation(c: &mut Criterion) {
    let mut group = c.benchmark_group("witness_gas_estimation");

    for leaf_count in [2, 4, 8, 16, 64, 256].iter() {
        let leaves = generate_leaves(*leaf_count);
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let proof = tree.proof(0).unwrap();
        let witness = HCAWitness::build(&leaves[0], proof);

        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}_leaves", leaf_count)),
            leaf_count,
            |b, _| {
                b.iter(|| black_box(&witness).estimate_gas());
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_account_creation,
    bench_transaction_preparation,
    bench_complete_flow,
    bench_signing_hash_patterns,
    bench_witness_gas_estimation
);
criterion_main!(benches);
