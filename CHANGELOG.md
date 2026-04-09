# Changelog

All notable changes to this project will be documented in this file.

## [0.3.0] - 2026-04-09

### Added
- `LeafVersion` registry with per-version validation dispatch — `Leaf::new()` now routes through `LeafVersion::from_byte()` so only active versions (`0x01`) are accepted and reserved versions (`0x02`+) are rejected at construction (#41, #47)
- `CompactProofSet` — deduplicated Merkle sibling table for batch proofs, with `expand()` and `verify_all()` helpers (#38)
- Batch proof generation and verification: `MerkleTree::proofs()` and `MerkleTree::verify_batch()` (#37)
- `parallel` feature flag — rayon-based parallel tree construction for large leaf sets (#42)
- Precomputed SHA256 tag hashes as `const [u8; 32]` in `hash::tag_hashes` module — eliminates per-call SHA256 overhead in every tagged hash (#43)
- `tagged_hash_str` runtime variant for tests and arbitrary tag strings (#43, #44)
- `MerkleTree` serde support — custom `Serialize`/`Deserialize` that persists only `leaves` and rebuilds internal nodes on load (#40)
- `hca rotation-hash` CLI subcommand — computes rotation signing hash with `HCARotate` domain tag (#39)
- `hca generate-vectors` and `hca verify-vectors` CLI subcommands for cross-implementation test vector workflow (#44)
- `SPECIFICATION.md` — standalone protocol specification mirroring EIP-8215 (#45)
- `ARCHITECTURE.md` — crate design and module dependency guide (#45)
- `BENCHMARKING.md` — benchmark methodology and baseline numbers (#45)
- Two new fuzz targets: `fuzz_rlp_decode` and `fuzz_evm_opcode` — bringing total to 6 libfuzzer targets (#33)
- RLP encoding cross-implementation test vectors (#34)
- `RotationRequest` signing hash test vectors (#35)
- `make cli-rotation`, `make fuzz-smoke-*` Makefile targets (#28, #33, #39)

### Changed
- `derive_address` now applies an outer `keccak256` over `tagged_hash("HCAAddr", auth_root)` — aligns with EIP-8215 §Address derivation (#27)
- EVM opcode ban list aligned with EIP-8215 spec — `STATICCALL` and `SLOAD` are explicitly permitted for oracle and time-lock conditions (#25)
- `TreeBuilder` leaf insertion order now stable — preserves the order leaves were added (#26)
- `validate_leaf_script` dispatched per leaf version instead of called unconditionally (#41)
- README rewritten for v0.3.0 surface area and honest scope (#28)
- Property tests expanded for calldata sensitivity and `leaf_index` edge cases (#36)

### Fixed
- RLP decoder `usize` overflow in `decode_bytes` and `decode_list` — security hardening (#28, #33)
- `hca_construction.json` full-flow vector filled with real values instead of placeholders (#32)
- Minor correctness issues caught during review (#31)
- `SPECIFICATION.md` §7 signing hash formula now includes `data_len[8] || data[variable]` between `value` and `gas_limit` — matches the implementation's calldata binding (#47)
- `README.md` fuzz target count updated from 4 to 6 (#47)

### Security
- `Leaf::new()` now rejects `0x02` and other reserved leaf versions at construction time — previously any non-zero byte was accepted (#47)
- RLP decoder hardened against oversized length prefixes and integer overflow (#28)

### Dependencies
- Pinned `rayon = "=1.9.0"` and `rayon-core = "=1.12.1"` to maintain MSRV 1.71 compatibility (#42)
- Pinned `clap = "=4.4.18"` for MSRV 1.71 (#37)

## [0.2.0] - 2026-04-04

### Added
- `hca` CLI binary with six commands: `create-account`, `derive-address`, `generate-proof`, `verify-proof`, `encode-tx`, `signing-hash` — all JSON I/O (#23)
- `clap` derive API for `--help`, `--version`, and per-subcommand help (#23)
- `make cli`, `make cli-help`, `make cli-demo` Makefile targets (#23)
- `TreeBuilder` and `TxBuilder` builder APIs for ergonomic tree and transaction construction (#20)
- `serde` feature flag — opt-in `Serialize`/`Deserialize` for `Leaf` and `MerkleProof` (#21)
- `no_std` + `alloc` support for embedded and constrained environments (#19)
- Gas metering via `GasCounter` — enforces `MAX_LEAF_GAS` (100k) per leaf script (#17)
- `GasExhausted` error variant with `limit` and `consumed` fields (#17)
- Crate-level rustdoc with quick-start example and feature flag table (#22)
- `#![warn(missing_docs)]` — all public items documented (#22)
- Hardcoded cross-implementation test vectors for tagged hash, address derivation, Merkle proofs, and witness signing (#18)

### Changed
- `validate_leaf_script` returns `HcaResult<u64>` (gas consumed) instead of `HcaResult<()>` (#17)
- `estimate_gas` now uses static script analysis instead of a fixed constant (#17)
- `std` feature is now opt-in via `default = ["std", "serde"]`; `serde_json` is optional (#19, #21)
- `clap` gated behind `std` feature — no_std lib builds unaffected (#23)

### Fixed
- Broken `[12:]` intra-doc links in `address.rs` and `hash.rs` (#22)
- Property tests updated to avoid `DuplicateLeaf` errors at large tree sizes (#16)

## [0.1.0] - initial release

- `MerkleTree` construction, proof generation, and static `verify()`
- `derive_address` — `keccak256(tagged_hash("HCAAddr", auth_root))[12..]`
- `HCAWitness` and `TxMessage` with `signing_hash()`
- RLP encoder for EIP-2718 type `0x05` transactions
- WASM bindings via `wasm-bindgen`
- 4 libfuzzer fuzz targets
- Property-based tests with proptest
