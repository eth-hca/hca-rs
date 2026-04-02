//! Address derivation benchmarks
//!
//! Benchmarks for HCA address derivation from auth_root.
//! Measures throughput of the address derivation function.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use hca_rs::address::derive_address;

/// Benchmark derive_address throughput
fn bench_derive_address(c: &mut Criterion) {
    let mut group = c.benchmark_group("derive_address");
    group.throughput(Throughput::Elements(1));

    // Test with different auth_roots
    let auth_roots: Vec<[u8; 32]> = (0..10)
        .map(|i| {
            let mut root = [0u8; 32];
            root[0] = i;
            root
        })
        .collect();

    group.bench_function("single", |b| {
        b.iter(|| derive_address(black_box(&auth_roots[0])));
    });

    group.finish();
}

/// Benchmark batch address derivation (simulates wallet with multiple accounts)
fn bench_derive_address_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("derive_address_batch");

    for count in [10, 50, 100, 500].iter() {
        let auth_roots: Vec<[u8; 32]> = (0..*count)
            .map(|i| {
                let mut root = [0u8; 32];
                root[0] = (i % 256) as u8;
                root[1] = ((i / 256) % 256) as u8;
                root
            })
            .collect();

        group.throughput(Throughput::Elements(*count as u64));

        group.bench_function(format!("batch_{}", count), |b| {
            b.iter(|| {
                for root in &auth_roots {
                    let _ = derive_address(black_box(root));
                }
            });
        });
    }

    group.finish();
}

/// Benchmark address derivation with varying auth_root patterns
fn bench_derive_address_patterns(c: &mut Criterion) {
    let mut group = c.benchmark_group("derive_address_patterns");

    // All zeros
    let root_zeros = [0u8; 32];
    group.bench_function("all_zeros", |b| {
        b.iter(|| derive_address(black_box(&root_zeros)));
    });

    // All ones
    let root_ones = [0xFFu8; 32];
    group.bench_function("all_ones", |b| {
        b.iter(|| derive_address(black_box(&root_ones)));
    });

    // Sequential pattern
    let mut root_sequential = [0u8; 32];
    for (i, byte) in root_sequential.iter_mut().enumerate() {
        *byte = i as u8;
    }
    group.bench_function("sequential", |b| {
        b.iter(|| derive_address(black_box(&root_sequential)));
    });

    // Random-like pattern (pseudo-random)
    let mut root_random = [0u8; 32];
    for (i, byte) in root_random.iter_mut().enumerate() {
        *byte = ((i * 137 + 42) % 256) as u8;
    }
    group.bench_function("random_like", |b| {
        b.iter(|| derive_address(black_box(&root_random)));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_derive_address,
    bench_derive_address_batch,
    bench_derive_address_patterns
);
criterion_main!(benches);
