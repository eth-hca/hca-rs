//! Merkle tree benchmarks
//!
//! Benchmarks for Merkle tree construction, proof generation, and verification.
//! Tests various tree sizes to measure scaling characteristics.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use hca_rs::merkle::{Leaf, MerkleTree};

/// Generate test leaves for benchmarking
fn generate_leaves(count: usize) -> Vec<Leaf> {
    (0..count)
        .map(|i| Leaf {
            version: 0x01,
            script: vec![i as u8; 32],
            description: format!("Leaf {}", i),
        })
        .collect()
}

/// Benchmark MerkleTree::new for various tree sizes
fn bench_merkle_tree_new(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree_new");

    for size in [1, 2, 4, 8, 16, 64, 256].iter() {
        let leaves = generate_leaves(*size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| MerkleTree::new(black_box(leaves.clone())));
        });
    }

    group.finish();
}

/// Benchmark MerkleTree::proof generation for various tree sizes
fn bench_merkle_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_generation");

    for size in [1, 2, 4, 8, 16, 64, 256].iter() {
        let leaves = generate_leaves(*size);
        let tree = MerkleTree::new(leaves).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| tree.proof(black_box(0)));
        });
    }

    group.finish();
}

/// Benchmark MerkleTree::verify for various tree sizes
fn bench_merkle_proof_verification(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_verification");

    for size in [1, 2, 4, 8, 16, 64, 256].iter() {
        let leaves = generate_leaves(*size);
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let proof = tree.proof(0).unwrap();
        let leaf_hash = leaves[0].hash();
        let root = tree.auth_root();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| {
                MerkleTree::verify(black_box(&leaf_hash), black_box(&proof), black_box(&root))
            });
        });
    }

    group.finish();
}

/// Benchmark generating all proofs for a tree (worst case)
fn bench_merkle_all_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_all_proofs");

    for size in [4, 8, 16, 32, 64].iter() {
        let leaves = generate_leaves(*size);
        let tree = MerkleTree::new(leaves).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, size| {
            b.iter(|| {
                for i in 0..*size {
                    let _ = tree.proof(black_box(i));
                }
            });
        });
    }

    group.finish();
}

/// Benchmark leaf hashing (component of tree building)
fn bench_leaf_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("leaf_hash");

    for script_size in [32, 64, 128, 256, 512].iter() {
        let leaf = Leaf {
            version: 0x01,
            script: vec![0u8; *script_size],
            description: String::from("Test leaf"),
        };

        group.bench_with_input(
            BenchmarkId::from_parameter(script_size),
            script_size,
            |b, _| {
                b.iter(|| black_box(&leaf).hash());
            },
        );
    }

    group.finish();
}

/// Benchmark auth_root computation (cached vs recomputation)
fn bench_auth_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_root");

    for size in [8, 16, 64, 256].iter() {
        let leaves = generate_leaves(*size);
        let tree = MerkleTree::new(leaves).unwrap();

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| tree.auth_root());
        });
    }

    group.finish();
}

/// Benchmark parallel vs serial tree construction at large sizes
#[cfg(feature = "parallel")]
fn bench_merkle_tree_new_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree_new_parallel");

    for size in [64, 256, 1024, 4096].iter() {
        let leaves = generate_leaves(*size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| MerkleTree::new(black_box(leaves.clone())));
        });
    }

    group.finish();
}

#[cfg(not(feature = "parallel"))]
criterion_group!(
    benches,
    bench_merkle_tree_new,
    bench_merkle_proof_generation,
    bench_merkle_proof_verification,
    bench_merkle_all_proofs,
    bench_leaf_hash,
    bench_auth_root
);

#[cfg(feature = "parallel")]
criterion_group!(
    benches,
    bench_merkle_tree_new,
    bench_merkle_proof_generation,
    bench_merkle_proof_verification,
    bench_merkle_all_proofs,
    bench_leaf_hash,
    bench_auth_root,
    bench_merkle_tree_new_parallel
);

criterion_main!(benches);
