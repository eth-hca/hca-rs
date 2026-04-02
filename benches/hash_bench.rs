//! Hash function benchmarks
//!
//! Benchmarks for keccak256 and tagged_hash throughput.
//! Measures performance on various input sizes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use hca_rs::hash::{keccak256, tagged_hash};

/// Benchmark keccak256 throughput for different input sizes
fn bench_keccak256(c: &mut Criterion) {
    let mut group = c.benchmark_group("keccak256");

    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| keccak256(black_box(&data)));
        });
    }

    group.finish();
}

/// Benchmark tagged_hash throughput for different input sizes
fn bench_tagged_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("tagged_hash");

    for size in [32, 64, 128, 256, 512, 1024, 4096].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        let data = vec![0u8; *size];

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, _| {
            b.iter(|| tagged_hash(black_box("HCALeaf"), black_box(&data)));
        });
    }

    group.finish();
}

/// Benchmark tagged_hash with different tags (domain separation cost)
fn bench_tagged_hash_tags(c: &mut Criterion) {
    let mut group = c.benchmark_group("tagged_hash_tags");
    let data = vec![0u8; 256];

    let tags = ["HCAAddr", "HCALeaf", "HCABranch", "HCAWitness", "HCARotate"];

    for tag in tags.iter() {
        group.bench_with_input(BenchmarkId::from_parameter(tag), tag, |b, &tag| {
            b.iter(|| tagged_hash(black_box(tag), black_box(&data)));
        });
    }

    group.finish();
}

/// Benchmark sequential hashing (simulates tree building)
fn bench_sequential_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("sequential_hashing");

    for count in [10, 50, 100, 500, 1000].iter() {
        let data = vec![0u8; 32];

        group.bench_with_input(BenchmarkId::from_parameter(count), count, |b, &count| {
            b.iter(|| {
                for _ in 0..count {
                    keccak256(black_box(&data));
                }
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_keccak256,
    bench_tagged_hash,
    bench_tagged_hash_tags,
    bench_sequential_hashing
);
criterion_main!(benches);
