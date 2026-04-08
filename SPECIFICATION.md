# HCA Protocol Specification

**EIP-8215 | Hash-Committed Account | Reference Implementation Guide**

This document describes the protocol as implemented in `hca-rs`. For the authoritative EIP text see [`_EIP/EIP-draft.md`](_EIP/EIP-draft.md).

---

## 1. Address derivation

```
address = keccak256(tagged_hash("HCAAddr", auth_root))[12:]
```

- `auth_root` is the Merkle root of the account's spending conditions.
- No public key enters the derivation chain.
- The result is a standard 20-byte Ethereum address.

## 2. Tagged hash construction

```
tagged_hash(tag, data) = keccak256(SHA256(tag) || SHA256(tag) || data)
```

BIP-340 style double-prefix provides domain separation. Five tags are defined:

| Tag | Purpose |
|-----|---------|
| `HCAAddr` | Address derivation |
| `HCALeaf` | Leaf hash |
| `HCABranch` | Branch node hash |
| `HCAWitness` | Transaction signing hash |
| `HCARotate` | authRoot rotation authorization |

SHA256(tag) values are precomputed as compile-time constants in `src/hash.rs::tag_hashes`.

## 3. Leaf structure

```
leaf = version_byte || script_bytecode
leaf_hash = tagged_hash("HCALeaf", leaf)
```

| Version | Meaning | Status |
|---------|---------|--------|
| `0x00` | Reserved | MUST reject |
| `0x01` | HCA v1 -- EVM bytecode spending condition | Active |
| `0x02` | EIP-7932 algorithm registry dispatch | Reserved |
| `0x03`--`0x0F` | Future PQ schemes | Reserved |

Leaf scripts MUST NOT exceed `MAX_LEAF_SCRIPT_SIZE` (24 KB). Version `0x00` MUST be rejected at construction time.

### Leaf execution context

Leaf scripts run in a restricted EVM sandbox:

- **Gas cap:** `MAX_LEAF_GAS` = 100,000
- **Banned opcodes:** CREATE, CREATE2, SSTORE, SELFDESTRUCT, DELEGATECALL, CALL (value-bearing), LOG0--LOG4
- **Permitted:** SLOAD, STATICCALL, BALANCE, arithmetic, all read-only opcodes

## 4. Merkle tree

1. Compute `leaf_hash` for each leaf.
2. Pad to the next power of two by repeating the last leaf hash.
3. Build bottom-up: `branch = tagged_hash("HCABranch", left || right)`.
4. Root = `auth_root`.

Maximum depth: `MAX_TREE_DEPTH` = 32 (supports 2^32 leaves).

Domain separation between `HCALeaf` and `HCABranch` makes leaf/branch confusion impossible.

### Duplicate detection

Duplicate leaf hashes within a tree MUST be rejected. The implementation uses a hash set (or BTreeSet in `no_std`) for O(n) detection.

## 5. Merkle proof

A proof for leaf at index `i` consists of the sibling hashes from the leaf level to the root.

Verification:

```
current = leaf_hash
for each (sibling, level) in proof:
    if index_bit == 0:
        current = tagged_hash("HCABranch", current || sibling)
    else:
        current = tagged_hash("HCABranch", sibling || current)
    index >>= 1
assert current == auth_root
```

Proof verification is **static** -- it requires only `leaf_hash`, `proof`, and `auth_root`. No tree instance is needed.

### Batch and compact proofs

- `proofs(indices)` generates multiple proofs from one tree.
- `verify_batch(items, auth_root)` verifies multiple proofs in one call.
- `CompactProofSet` deduplicates shared siblings across multiple proofs.

## 6. Transaction format

EIP-2718 typed transaction, type `0x05`:

```
0x05 || RLP([
    chain_id, nonce, sender, to, value, data,
    max_priority_fee_per_gas, max_fee_per_gas, access_list,
    leaf_version, leaf_script, leaf_index, merkle_proof, witness_data
])
```

`sender` is explicit -- no `ecrecover`.

## 7. Signing hash

```
signing_hash = tagged_hash("HCAWitness",
    chain_id[8] || nonce[8] || from[20] || to[20] || value[16] ||
    gas_limit[8] || max_fee_per_gas[16] || max_priority_fee_per_gas[16] ||
    leaf_hash[32]
)
```

Includes `chain_id` (cross-chain replay), `nonce` (same-chain replay), `from` (cross-account replay), and `leaf_hash` (binds to specific spending condition).

## 8. authRoot rotation

A rotation transaction replaces `authRoot` without changing the address.

```
rotation_hash = tagged_hash("HCARotate",
    chain_id[8] || nonce[8] || from[20] || new_auth_root[32]
)
```

- `new_auth_root` MUST be non-zero.
- Rotation transaction MUST NOT transfer value or execute external calls.
- The `HCARotate` domain tag prevents cross-context replay with regular signing hashes.

## 9. Gas schedule

| Operation | Cost |
|-----------|------|
| Merkle proof base | 200 gas |
| Merkle proof per level | 80 gas |
| Leaf script execution | Metered, capped at 100,000 gas |
| Witness calldata | Standard EIP-2028 rates |

## 10. Constants

All constants are defined in `src/constants.rs`:

| Constant | Value |
|----------|-------|
| `HCA_TX_TYPE` | `0x05` |
| `MAX_TREE_DEPTH` | `32` |
| `MAX_LEAF_GAS` | `100,000` |
| `MAX_LEAF_SCRIPT_SIZE` | `24,576` (24 KB) |
| `MAX_WITNESS_SIZE` | `65,536` (64 KB) |
| `MERKLE_BASE_GAS` | `200` |
| `MERKLE_GAS_PER_LEVEL` | `80` |

## 11. Security properties

| Property | Guarantee |
|----------|-----------|
| Address preimage resistance | ~2^160 classical, ~2^80 Grover |
| Merkle collision resistance | ~2^128 birthday bound |
| Leaf/branch confusion | Impossible by domain separation |
| Cross-chain replay | Prevented by `chain_id` in signing hash |
| Cross-account replay | Prevented by `from` in signing hash |
| Same-chain replay | Prevented by `nonce` in signing hash |
| Cross-context replay (tx vs rotation) | Prevented by distinct domain tags |

The entire commitment structure rests on hash function assumptions only -- no elliptic curve mathematics, no lattice assumptions.
