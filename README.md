# hca-rs

**Hash-Committed Account (HCA) — Rust reference implementation of [EIP-8215](https://eips.ethereum.org/EIPS/eip-8215)**

[![CI](https://github.com/eth-hca/hca-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/eth-hca/hca-rs/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV: 1.71](https://img.shields.io/badge/MSRV-1.71-orange.svg)]()

---

> **Warning**: This is research-grade software implementing a **draft** EIP. It has **not been audited**. Do not use to secure real funds.

---

## What is HCA

HCA is a new Ethereum account type where the address is derived from a Merkle root of spending conditions — not from a public key.

```
address   = keccak256(tagged_hash("HCAAddr", auth_root))[12:]
auth_root = merkle_root([leaf_0, leaf_1, ..., leaf_n])
leaf_n    = tagged_hash("HCALeaf", version || evm_bytecode)
```

No public key enters the derivation chain. The quantum long-exposure attack surface is eliminated by design. Key rotation is possible without changing the address.

## Quick start

```rust
use hca_rs::builder::TreeBuilder;
use hca_rs::address::derive_address;

// 1. Define spending conditions as leaves
let tree = TreeBuilder::new()
    .add_leaf(0x01, b"primary_script".to_vec(), "Primary ECDSA key")
    .add_leaf(0x01, b"recovery_script".to_vec(), "Recovery key")
    .add_leaf(0x01, b"timelock_script".to_vec(), "Timelock 30d")
    .build()
    .unwrap();

// 2. Derive the HCA address
let address = derive_address(&tree.auth_root());
println!("HCA address: 0x{}", hex::encode(address));

// 3. Generate a Merkle proof for spending with leaf 0
let proof = tree.proof(0).unwrap();
assert!(hca_rs::merkle::MerkleTree::verify(
    &tree.leaves[0].hash(), &proof, &tree.auth_root()
).unwrap());
```

## CLI

Install the `hca` binary:

```bash
cargo install --path .
```

```
$ hca --help
Hash-Committed Account CLI (EIP-8215)

Usage: hca <COMMAND>

Commands:
  create-account  Build a Merkle tree of spending conditions and derive the HCA address
  derive-address  Derive an HCA address from an auth_root
  generate-proof  Generate a Merkle inclusion proof for a leaf
  verify-proof    Verify a Merkle inclusion proof against an auth_root
  encode-tx       RLP-encode a signed HCA transaction (EIP-2718 type 0x05)
  signing-hash    Compute the signing hash for a transaction
```

Example flow:

```bash
# Create an account with 3 spending conditions
hca create-account --leaves '[
  {"version":"0x01","script":"0x6001","description":"Primary key"},
  {"version":"0x01","script":"0x6002","description":"Recovery key"},
  {"version":"0x01","script":"0x6003","description":"Timelock 30d"}
]'

# Derive address from auth_root
hca derive-address --auth-root 0x<auth_root_from_above>

# Generate and verify a Merkle proof
hca generate-proof --leaves '[...]' --index 0
hca verify-proof --leaf-hash 0x... --proof '{...}' --auth-root 0x...

# Or run the full demo end-to-end
make cli-demo
```

## Feature flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | yes | Standard library support, hex helpers, `serde_json` |
| `serde` | yes | `Serialize`/`Deserialize` derives on `Leaf` and `MerkleProof` |
| `wasm` | no | JavaScript bindings via `wasm-bindgen` |

```bash
# no_std + alloc (embedded / constrained)
cargo build --no-default-features

# WASM
wasm-pack build --target web --features wasm
```

## Modules

| Module | Description |
|--------|-------------|
| `hash` | `keccak256` and `tagged_hash` with BIP-340 style domain separation |
| `merkle` | Merkle tree construction, proof generation, static `verify()` |
| `address` | `derive_address(auth_root)` — the core HCA formula |
| `witness` | `TxMessage` and `HCAWitness` — transaction and witness building |
| `rlp` | RLP encoder/decoder for EIP-2718 type `0x05` transactions |
| `evm` | Opcode validator and gas metering for leaf scripts |
| `builder` | `TreeBuilder` and `TxBuilder` — ergonomic construction APIs |
| `wasm` | JavaScript bindings (feature-gated) |

## Installation

```toml
[dependencies]
hca-rs = { git = "https://github.com/eth-hca/hca-rs" }

# With serde only
hca-rs = { git = "https://github.com/eth-hca/hca-rs", default-features = false, features = ["serde"] }

# no_std
hca-rs = { git = "https://github.com/eth-hca/hca-rs", default-features = false }
```

## Building and testing

```bash
cargo build                    # Debug build
cargo test --all-features      # All tests (unit + property + vector + CLI)
cargo bench                    # Criterion benchmarks
make ci                        # Full local CI (fmt + clippy + build + test + no_std)
make cli-demo                  # End-to-end CLI demo
make examples                  # Run all examples
```

## Benchmarks

| Operation | Time | Throughput |
|-----------|------|------------|
| `keccak256` | — | — |
| `tagged_hash` | — | — |
| `derive_address` | — | — |
| Tree build (4 leaves) | — | — |
| Proof generation | — | — |
| Proof verification | — | — |
| Full flow (build + prove + verify) | — | — |

> Run `cargo bench` to generate numbers on your machine.

## Security

See [SECURITY.md](SECURITY.md) for the full security policy.

- **Not audited** — this is research-grade software
- Constant-time comparison (`subtle`) in proof verification
- 4 libfuzzer fuzz targets: merkle, proof, witness, RLP
- EVM opcode validator with Berlin gas schedule enforcement
- `#![warn(missing_docs)]` — all public items documented

Report vulnerabilities to **zakaria.saiff@gmail.com** or **[@zacksaif](https://t.me/zacksaif)**.

## Related

- [EIP-8215](https://eips.ethereum.org/EIPS/eip-8215) — Hash-Committed Account specification
- [Ethereum Magicians discussion](https://ethereum-magicians.org/t/eip-8215-hash-committed-account-hca/28094)
- [eth-hca/research](https://github.com/eth-hca/research) — Research documentation

## License

Apache-2.0
