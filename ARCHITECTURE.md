# Architecture

**hca-rs crate design guide**

---

## Module dependency graph

```
constants --> error --> hash --> merkle --> address
                        |           \
                    leaf_version     witness
                                      |
                        rlp <---------+
                         |
                       builder
                         |
                      bin/hca (CLI)
                         |
                       wasm (feature-gated)
```

Arrows mean "depends on". No cycles.

## Core modules

### `hash` (src/hash.rs)

Foundation of the entire crate. Provides:

- `keccak256(data) -> [u8; 32]` -- standard Keccak-256.
- `tagged_hash(tag_hash, data) -> [u8; 32]` -- BIP-340 style domain-separated hash. Accepts precomputed `&[u8; 32]` tag hash (zero SHA-256 overhead per call).
- `tagged_hash_str(tag, data) -> [u8; 32]` -- runtime tag string variant (computes SHA-256 of tag on each call).
- `tag_hashes` module -- compile-time `const [u8; 32]` for all five HCA domain tags.
- `tags` module -- tag string constants for documentation and cross-impl compatibility.

**Design decision:** SHA-256 of each tag string is precomputed. This eliminates one SHA-256 call per `tagged_hash` invocation -- significant in tree construction where thousands of hashes occur.

### `merkle` (src/merkle.rs)

Merkle tree construction, proof generation, and verification.

- `Leaf` -- spending condition (version byte + EVM script + description).
- `MerkleTree` -- built from leaves, stores all node levels.
- `MerkleProof` -- leaf index + sibling hashes.
- `CompactProofSet` -- deduplicated sibling table for multi-leaf proofs.
- `MerkleTree::verify()` -- **static** method, no tree instance required.

**Key patterns:**
- Trees pad to next power-of-two by repeating the last leaf.
- Duplicate leaves are rejected at construction time.
- `#[cfg(feature = "parallel")]` gates rayon-based parallel hashing.
- Serde serializes only `leaves`; nodes are recomputed on deserialization.

### `address` (src/address.rs)

Single function: `derive_address(auth_root) -> [u8; 20]`.

Formula: `keccak256(tagged_hash("HCAAddr", auth_root))[12:]`.

### `witness` (src/witness.rs)

Transaction primitives:

- `TxMessage` -- all transaction fields (chain_id, nonce, from, to, value, data, gas fields).
- `HCAWitness` -- leaf + proof + optional signature. `build()` creates unsigned, `attach_signature()` completes it.
- `RotationRequest` -- rotation-specific signing hash with `HCARotate` domain tag.

`signing_hash()` commits to chain_id + nonce + from + to + value + gas + leaf_hash.

### `rlp` (src/rlp.rs)

Minimal RLP encoder/decoder for HCA typed transactions (EIP-2718, type `0x05`).

- Encoder: `encode_hca_tx(tx, witness) -> Vec<u8>`.
- Decoder: `decode_hca_tx(bytes) -> (TxMessage, HCAWitness)` with canonical encoding checks.
- Security: rejects non-canonical length prefixes, trailing bytes, invalid leaf versions, oversized scripts.

### `leaf_version` (src/leaf_version.rs)

Version registry and validation dispatch:

- `LeafVersion` enum -- `V1` (active, EVM), `V2` (reserved, EIP-7932).
- `validate_for_version()` -- routes to EVM opcode validation for V1, rejects V2.
- `from_byte()` rejects `0x00` and unknown versions.

### `evm` (src/evm/)

EVM opcode validator and gas counter:

- `opcode::validate_leaf_script()` -- scans bytecode, rejects banned opcodes, enforces MAX_LEAF_GAS.
- `gas::GasCounter` -- tracks cumulative gas, returns error on overflow.
- PUSH1-PUSH32 data bytes are skipped during scanning.

### `builder` (src/builder.rs)

Ergonomic builder pattern:

- `TreeBuilder` -- fluent API for constructing trees.
- `TxBuilder` -- fluent API for constructing transactions.

### `bin/hca` (src/bin/hca.rs)

CLI tool with clap subcommands:

| Command | Description |
|---------|-------------|
| `create-account` | Build tree, derive address |
| `derive-address` | Address from auth_root |
| `generate-proof` | Merkle proof for a leaf |
| `verify-proof` | Check proof against auth_root |
| `encode-tx` | RLP-encode signed HCA transaction |
| `signing-hash` | Compute transaction signing hash |
| `rotation-hash` | Compute rotation signing hash |
| `generate-vectors` | Output cross-impl test vectors |
| `verify-vectors` | Verify a test vector file |

All output is JSON to stdout. Errors go to stderr with exit code 1.

### `wasm` (src/wasm.rs)

JavaScript bindings via `wasm-bindgen`. Feature-gated behind `--features wasm`. All I/O as JSON strings.

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | yes | Links against std, enables serde_json, hex formatting, clap |
| `serde` | yes | Derives Serialize/Deserialize on core types |
| `parallel` | no | Rayon-based parallel tree construction |
| `wasm` | no | WASM bindings via wasm-bindgen |

`no_std + alloc` supported with `default-features = false`.

## Design principles

1. **No panics in crypto code.** All fallible operations return `HcaResult`. Panics only in tests.
2. **Domain separation everywhere.** Every hash uses a distinct tag. Cross-context collisions are impossible by construction.
3. **Static verification.** `MerkleTree::verify()` needs only leaf_hash + proof + auth_root. No tree instance, no global state.
4. **Feature-gated dependencies.** rayon, serde, wasm-bindgen are all optional. Core crypto is dependency-light.
5. **Precomputed constants.** Tag hashes and protocol constants are compile-time values.

## Testing layers

| Layer | Location | Count | Purpose |
|-------|----------|-------|---------|
| Unit tests | `src/*.rs` | ~145 | Edge cases per module |
| Property tests | `tests/property_tests.rs` | ~40 | Determinism, collision resistance, avalanche |
| Vector tests | `tests/vector_tests.rs` | ~10 | Cross-impl compatibility (JSON vectors) |
| Integration tests | `src/lib.rs` | 1 | Full HCA flow end-to-end |
| Fuzz targets | `fuzz/` | 6 | libfuzzer targets for merkle, proof, witness, RLP, EVM |

## CI pipeline

GitHub Actions enforces: `cargo fmt`, `cargo clippy -D warnings`, tests on Linux/macOS/Windows, WASM build, MSRV 1.71, and `no_std` build for `thumbv7em-none-eabihf`.
