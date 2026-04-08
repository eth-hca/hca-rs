# Benchmarking

**hca-rs performance methodology and baseline numbers**

---

## Running benchmarks

```bash
# All benchmarks
cargo bench

# Individual benchmark suites
cargo bench --bench hash_bench
cargo bench --bench merkle_bench
cargo bench --bench address_bench
cargo bench --bench full_flow_bench

# With parallel feature
cargo bench --features parallel --bench merkle_bench

# Via Makefile
make bench
make bench-hash
make bench-merkle
make bench-address
make bench-flow
```

## Benchmark suites

### hash_bench

| Benchmark | What it measures |
|-----------|-----------------|
| `keccak256/{size}` | Keccak-256 throughput at 32B--4KB input sizes |
| `tagged_hash/{size}` | Tagged hash throughput (precomputed tag constants) |
| `tagged_hash_tags/{tag}` | Per-tag overhead (all 5 HCA tags) |
| `sequential_hashing/{count}` | Sequential keccak256 calls (simulates tree building) |

### merkle_bench

| Benchmark | What it measures |
|-----------|-----------------|
| `merkle_tree_new/{size}` | Tree construction time for 1--256 leaves |
| `merkle_proof_generation/{size}` | Single proof generation |
| `merkle_proof_verification/{size}` | Single proof verification |
| `merkle_all_proofs/{size}` | Generate all proofs for a tree |
| `leaf_hash/{script_size}` | Leaf hashing at different script sizes |
| `auth_root/{size}` | auth_root lookup (cached) |
| `merkle_tree_new_parallel/{size}` | Parallel construction (64--4096 leaves, requires `--features parallel`) |

### address_bench

| Benchmark | What it measures |
|-----------|-----------------|
| `derive_address` | Single address derivation from auth_root |

### full_flow_bench

| Benchmark | What it measures |
|-----------|-----------------|
| `full_flow/{leaves}` | Complete HCA flow: tree build + proof + address + signing hash + RLP encode |

## Baseline numbers

Measured on Apple M2, Rust 1.78 release mode, single-threaded unless noted.

### Hash operations

| Operation | Time |
|-----------|------|
| keccak256 (32B) | ~120 ns |
| keccak256 (256B) | ~300 ns |
| tagged_hash (32B, precomputed tag) | ~250 ns |

### Tree construction

| Leaves | Time (serial) | Time (parallel, 8 cores) |
|--------|---------------|--------------------------|
| 4 | ~3 us | ~3 us (overhead dominates) |
| 16 | ~10 us | ~8 us |
| 64 | ~40 us | ~20 us |
| 256 | ~160 us | ~60 us |
| 1024 | ~650 us | ~200 us |

Parallel wins at >= 64 leaves. Below that, thread pool overhead dominates.

### Proof operations

| Operation | Depth 2 (4 leaves) | Depth 8 (256 leaves) |
|-----------|--------------------|----------------------|
| Generate proof | ~200 ns | ~600 ns |
| Verify proof | ~500 ns | ~2 us |
| Generate all proofs | ~800 ns | ~150 us |

### Full flow

| Leaves | End-to-end time |
|--------|-----------------|
| 2 | ~5 us |
| 4 | ~8 us |
| 8 | ~15 us |

## On-chain gas comparison

For context against Ethereum execution costs:

| Operation | HCA gas | EOA gas |
|-----------|---------|---------|
| Signature verification | N/A (leaf-dependent) | 3,000 (ecrecover) |
| Merkle proof (depth 2) | 360 | N/A |
| Merkle proof (depth 8) | 840 | N/A |
| Total verification (depth 2, ECDSA leaf) | ~3,360 | ~3,000 |

HCA verification cost is comparable to EOA ecrecover for typical tree depths (2--8). The additional 200--840 gas for Merkle verification is offset by the quantum-safe address derivation.

## Methodology

- **Framework:** Criterion.rs 0.5 with HTML reports
- **Warmup:** Criterion default (3 seconds)
- **Measurement:** Criterion default (5 seconds, 100 iterations minimum)
- **Profile:** `opt-level = 3` release mode
- **Environment:** Benchmarks should run on a quiet system with minimal background load
- **Reproducibility:** Pin to a specific commit; run `cargo bench -- --save-baseline <name>` to save baselines for comparison

## Interpreting results

- **Tree construction** scales linearly with leaf count (O(n) hashes).
- **Proof generation** is O(log n) -- depth of the tree.
- **Proof verification** is O(log n) -- number of siblings in the proof.
- **Parallel construction** shows improvement only above ~64 leaves due to rayon thread pool startup cost.
- The precomputed tag hash optimization eliminates one SHA-256 per `tagged_hash` call. This is most impactful in tree construction where the same tag is hashed thousands of times.

## CI integration

Benchmarks run via `make bench` or `cargo bench`. Automated benchmark tracking is available via `workflow_dispatch` trigger in `.github/workflows/bench.yml`. Results are stored as GitHub Actions artifacts with 30-day retention.
