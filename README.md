# hca-rs

**Hash-Committed Account (HCA) — Rust cryptographic primitives**

Reference implementation of the HCA cryptographic core for Ethereum.
Part of the [eth-hca](https://github.com/eth-hca) organization.

> Status: Research / Draft — do not use in production

---

## What is HCA

Hash-Committed Account (HCA) is a proposed new Ethereum account type where the address is derived from a Merkle root of spending conditions — not from a public key.

```
address   = keccak256(tagged_hash("HCAAddr", auth_root))[12:]
auth_root = merkle_root([leaf_0, leaf_1, ..., leaf_n])
leaf_n    = EVM bytecode spending condition
```

No public key enters the address derivation or commitment chain.
Long-exposure quantum attack surface is eliminated by design.

See the full proposal: [github.com/eth-hca/EIP](https://github.com/eth-hca/EIP)

---

## What this library provides

```
address    HCA address derivation from auth_root
merkle     Merkle tree construction, proof generation, verification
witness    Transaction witness builder
hash       Tagged hash domain separation primitives
```

---

## Usage

```rust
use hca_rs::merkle::{Leaf, MerkleTree};
use hca_rs::address::derive_address;

// Define spending conditions
let leaves = vec![
    Leaf::new(0x01, b"OP_CHECKSIG_primary".to_vec(), "Primary key"),
    Leaf::new(0x01, b"OP_CHECKSIG_recovery".to_vec(), "Recovery key"),
];

// Build Merkle tree
let tree = MerkleTree::new(leaves);
let auth_root = tree.auth_root();

// Derive HCA address
let address = derive_address(&auth_root);
println!("HCA address: 0x{}", hex::encode(address));

// Generate proof for leaf 0
let proof = tree.proof(0);
```

---

## Running tests

```bash
cargo test
```

---

## Building for WASM

```bash
wasm-pack build --target web --features wasm
```

---

## Related

- [eth-hca/EIP](https://github.com/eth-hca/EIP) — formal EIP draft
- [eth-hca/research](https://github.com/eth-hca/EIP/tree/main/research) — research documentation
- [eth-hca/hca-go](https://github.com/eth-hca/hca-go) — Go implementation
- [eth-hca/hca-wallet](https://github.com/eth-hca/hca-wallet) — wallet POC

---

## License

Apache-2.0