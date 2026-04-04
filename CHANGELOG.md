# Changelog

All notable changes to this project will be documented in this file.

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
