//! Property-based tests for HCA cryptographic primitives
//!
//! These tests use proptest to verify mathematical properties and invariants
//! that should hold for all valid inputs, not just specific test cases.

use hca_rs::{
    address::derive_address,
    hash::{keccak256, tagged_hash_str as tagged_hash},
    merkle::{Leaf, MerkleTree},
    rlp::{encode_address, encode_bytes, encode_list, encode_uint},
    witness::{RotationRequest, TxMessage},
};
use proptest::prelude::*;

/// Deduplicate leaves by hash — prevents DuplicateLeaf errors in property tests
/// where proptest may generate two leaves with identical scripts.
fn dedup_leaves(leaves: Vec<Leaf>) -> Vec<Leaf> {
    let mut seen = std::collections::HashSet::new();
    leaves
        .into_iter()
        .filter(|l| seen.insert(l.hash()))
        .collect()
}

// ============================================================================
// Hash Function Property Tests (HIGHEST PRIORITY)
// ============================================================================

proptest! {
    /// Property: Keccak256 is deterministic - same input always produces same output
    #[test]
    fn prop_keccak256_deterministic(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let hash1 = keccak256(&data);
        let hash2 = keccak256(&data);
        prop_assert_eq!(hash1, hash2, "Hash should be deterministic");
    }

    /// Property: Keccak256 always produces 32 bytes
    #[test]
    fn prop_keccak256_length(data in prop::collection::vec(any::<u8>(), 0..1024)) {
        let hash = keccak256(&data);
        prop_assert_eq!(hash.len(), 32, "Hash must be 32 bytes");
    }

    /// Property: Different inputs produce different hashes (collision resistance check)
    /// Note: This is probabilistic but should hold for random inputs
    #[test]
    fn prop_keccak256_collision_resistance(
        data1 in prop::collection::vec(any::<u8>(), 1..256),
        data2 in prop::collection::vec(any::<u8>(), 1..256)
    ) {
        prop_assume!(data1 != data2); // Only test when inputs differ
        let hash1 = keccak256(&data1);
        let hash2 = keccak256(&data2);
        prop_assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
    }

    /// Property: Small changes in input produce completely different output (avalanche effect)
    #[test]
    fn prop_keccak256_avalanche(mut data in prop::collection::vec(any::<u8>(), 32..256)) {
        let original_hash = keccak256(&data);

        // Flip one bit in the input
        if !data.is_empty() {
            data[0] ^= 0x01;
            let modified_hash = keccak256(&data);

            // Count differing bits between hashes
            let diff_bits: u32 = original_hash
                .iter()
                .zip(modified_hash.iter())
                .map(|(a, b)| (a ^ b).count_ones())
                .sum();

            // With good avalanche, ~50% of bits should differ (256 bits total, expect ~128)
            // We allow a wide range to avoid false positives
            prop_assert!(diff_bits > 64,
                "Avalanche effect too weak: only {} bits differ (expected ~128)", diff_bits);
        }
    }

    /// Property: Tagged hash is deterministic
    #[test]
    fn prop_tagged_hash_deterministic(
        tag in "[A-Z]{4,10}",
        data in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let hash1 = tagged_hash(&tag, &data);
        let hash2 = tagged_hash(&tag, &data);
        prop_assert_eq!(hash1, hash2, "Tagged hash should be deterministic");
    }

    /// Property: Different tags produce different hashes (domain separation)
    #[test]
    fn prop_tagged_hash_domain_separation(
        tag1 in "[A-Z]{4,10}",
        tag2 in "[A-Z]{4,10}",
        data in prop::collection::vec(any::<u8>(), 0..256)
    ) {
        prop_assume!(tag1 != tag2);
        let hash1 = tagged_hash(&tag1, &data);
        let hash2 = tagged_hash(&tag2, &data);
        prop_assert_ne!(hash1, hash2, "Different tags should produce different hashes");
    }

    /// Property: Tagged hash output is always 32 bytes
    #[test]
    fn prop_tagged_hash_length(
        tag in "[A-Z]{4,10}",
        data in prop::collection::vec(any::<u8>(), 0..512)
    ) {
        let hash = tagged_hash(&tag, &data);
        prop_assert_eq!(hash.len(), 32, "Tagged hash must be 32 bytes");
    }
}

// ============================================================================
// Merkle Tree Property Tests (HIGH PRIORITY)
// ============================================================================

/// Strategy to generate valid leaves
fn arb_leaf() -> impl Strategy<Value = Leaf> {
    (
        prop::collection::vec(any::<u8>(), 1..100), // script
        prop::option::of("[a-z]{0,50}"),            // description
    )
        .prop_map(|(script, desc)| Leaf {
            version: 0x01,
            script,
            description: desc.unwrap_or_default(),
        })
}

proptest! {
    /// Property: Merkle proof verification succeeds for valid proofs
    #[test]
    fn prop_merkle_valid_proof_verifies(
        leaves in prop::collection::vec(arb_leaf(), 1..64)
    ) {
        let leaves = dedup_leaves(leaves);
        prop_assume!(!leaves.is_empty());
        let tree = MerkleTree::new(leaves.clone())?;
        let root = tree.auth_root();

        // Test proof for each leaf
        for (index, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(index)?;
            let leaf_hash = leaf.hash();
            let verified = MerkleTree::verify(&leaf_hash, &proof, &root)?;
            prop_assert!(verified, "Valid proof for leaf {} should verify", index);
        }
    }

    /// Property: Merkle root is deterministic - same leaves produce same root
    #[test]
    fn prop_merkle_root_deterministic(
        leaves in prop::collection::vec(arb_leaf(), 1..32)
    ) {
        let leaves = dedup_leaves(leaves);
        prop_assume!(!leaves.is_empty());
        let tree1 = MerkleTree::new(leaves.clone())?;
        let tree2 = MerkleTree::new(leaves)?;
        prop_assert_eq!(tree1.auth_root(), tree2.auth_root(),
            "Same leaves should produce same root");
    }

    /// Property: Different leaf orders produce different roots
    #[test]
    fn prop_merkle_leaf_order_matters(
        leaves in prop::collection::vec(arb_leaf(), 2..16)
    ) {
        let mut leaves = dedup_leaves(leaves);
        prop_assume!(leaves.len() >= 2);
        let tree1 = MerkleTree::new(leaves.clone())?;
        let root1 = tree1.auth_root();

        // Reverse the order
        leaves.reverse();
        let tree2 = MerkleTree::new(leaves)?;
        let root2 = tree2.auth_root();

        prop_assert_ne!(root1, root2, "Different leaf orders should produce different roots");
    }

    /// Property: Invalid proofs fail verification
    #[test]
    fn prop_merkle_invalid_proof_fails(
        leaves1 in prop::collection::vec(arb_leaf(), 2..32),
        leaves2 in prop::collection::vec(arb_leaf(), 2..32),
        index in 0usize..10
    ) {
        let leaves1 = dedup_leaves(leaves1);
        let leaves2 = dedup_leaves(leaves2);
        prop_assume!(!leaves1.is_empty() && !leaves2.is_empty());
        let tree1 = MerkleTree::new(leaves1.clone())?;
        let tree2 = MerkleTree::new(leaves2.clone())?;

        // Only test if the roots are different
        let root1 = tree1.auth_root();
        let root2 = tree2.auth_root();
        prop_assume!(root1 != root2);

        let idx = index % leaves1.len();
        let proof = tree1.proof(idx)?;
        let leaf_hash = leaves1[idx].hash();

        let verified = MerkleTree::verify(&leaf_hash, &proof, &root2)?;
        prop_assert!(!verified, "Proof from tree1 should not verify against tree2's root");
    }

    /// Property: Merkle root is always 32 bytes
    #[test]
    fn prop_merkle_root_length(
        leaves in prop::collection::vec(arb_leaf(), 1..64)
    ) {
        let leaves = dedup_leaves(leaves);
        prop_assume!(!leaves.is_empty());
        let tree = MerkleTree::new(leaves)?;
        let root = tree.auth_root();
        prop_assert_eq!(root.len(), 32, "Root must be 32 bytes");
    }

    /// Property: Leaf hash is always 32 bytes
    #[test]
    fn prop_leaf_hash_length(leaf in arb_leaf()) {
        let hash = leaf.hash();
        prop_assert_eq!(hash.len(), 32, "Leaf hash must be 32 bytes");
    }

    /// Property: Tree accepts up to 2^20 leaves without panicking
    #[test]
    fn prop_merkle_handles_large_trees(
        leaf_count in 1usize..1024
    ) {
        // Create simple leaves to avoid memory issues
        let leaves: Vec<Leaf> = (0..leaf_count)
            .map(|i| Leaf {
                version: 0x01,
                script: (i as u32).to_be_bytes().to_vec(),
                description: String::new(),
            })
            .collect();

        let result = MerkleTree::new(leaves);
        prop_assert!(result.is_ok(), "Should handle {} leaves", leaf_count);
    }
}

// ============================================================================
// Address Derivation Property Tests (MEDIUM PRIORITY)
// ============================================================================

proptest! {
    /// Property: Address derivation is deterministic
    #[test]
    fn prop_address_deterministic(root in prop::array::uniform32(any::<u8>())) {
        let addr1 = derive_address(&root);
        let addr2 = derive_address(&root);
        prop_assert_eq!(addr1, addr2, "Address derivation should be deterministic");
    }

    /// Property: Address is always 20 bytes
    #[test]
    fn prop_address_length(root in prop::array::uniform32(any::<u8>())) {
        let addr = derive_address(&root);
        prop_assert_eq!(addr.len(), 20, "Address must be 20 bytes");
    }

    /// Property: Different roots produce different addresses (injectivity)
    #[test]
    fn prop_address_injectivity(
        root1 in prop::array::uniform32(any::<u8>()),
        root2 in prop::array::uniform32(any::<u8>())
    ) {
        prop_assume!(root1 != root2);
        let addr1 = derive_address(&root1);
        let addr2 = derive_address(&root2);
        prop_assert_ne!(addr1, addr2, "Different roots should produce different addresses");
    }

    /// Property: Address is not a simple truncation of the root
    #[test]
    fn prop_address_not_truncation(root in prop::array::uniform32(any::<u8>())) {
        let addr = derive_address(&root);
        let truncated = &root[12..]; // Last 20 bytes
        prop_assert_ne!(&addr[..], truncated, "Address should not be simple truncation");
    }
}

// ============================================================================
// RLP Encoding Property Tests (MEDIUM PRIORITY)
// ============================================================================

proptest! {
    /// Property: RLP encoding is deterministic
    #[test]
    fn prop_rlp_uint_deterministic(value in any::<u128>()) {
        let enc1 = encode_uint(value);
        let enc2 = encode_uint(value);
        prop_assert_eq!(enc1, enc2, "RLP uint encoding should be deterministic");
    }

    /// Property: RLP encoded uint is non-empty for non-zero values
    #[test]
    fn prop_rlp_uint_nonempty(value in 1u128..) {
        let encoded = encode_uint(value);
        prop_assert!(!encoded.is_empty(), "Encoded uint should be non-empty");
    }

    /// Property: RLP bytes encoding is deterministic
    #[test]
    fn prop_rlp_bytes_deterministic(data in prop::collection::vec(any::<u8>(), 0..256)) {
        let enc1 = encode_bytes(&data);
        let enc2 = encode_bytes(&data);
        prop_assert_eq!(enc1, enc2, "RLP bytes encoding should be deterministic");
    }

    /// Property: RLP list encoding is deterministic
    #[test]
    fn prop_rlp_list_deterministic(
        items in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..64),
            0..10
        )
    ) {
        let enc1 = encode_list(&items);
        let enc2 = encode_list(&items);
        prop_assert_eq!(enc1, enc2, "RLP list encoding should be deterministic");
    }

    /// Property: RLP address encoding is deterministic and correct length
    #[test]
    fn prop_rlp_address_deterministic(addr in prop::array::uniform20(any::<u8>())) {
        let enc1 = encode_address(&addr);
        let enc2 = encode_address(&addr);

        // Address should be encoded as 0x94 (0x80 + 20) followed by 20 bytes
        prop_assert_eq!(enc1.len(), 21, "Encoded address should be 21 bytes (prefix + 20)");
        prop_assert_eq!(enc1[0], 0x94, "Address prefix should be 0x94");

        prop_assert_eq!(enc1, enc2, "RLP address encoding should be deterministic");
    }

    /// Property: Larger values produce longer or equal-length encodings
    #[test]
    fn prop_rlp_uint_monotonic_length(value1 in 0u128..1000, value2 in 1000u128..100000u128) {
        let enc1 = encode_uint(value1);
        let enc2 = encode_uint(value2);
        prop_assert!(enc2.len() >= enc1.len(),
            "Larger values should produce longer or equal encodings");
    }
}

// ============================================================================
// Transaction Signing Property Tests (MEDIUM PRIORITY)
// ============================================================================

/// Strategy to generate valid TxMessage
fn arb_tx_message() -> impl Strategy<Value = TxMessage> {
    (
        any::<u64>().prop_filter("Valid chain ID", |&id| id > 0),
        any::<u64>(),
        prop::array::uniform20(any::<u8>()),
        prop::array::uniform20(any::<u8>()),
        any::<u64>(),
        any::<u64>().prop_filter("Valid gas limit", |&g| g > 0),
        any::<u64>(),
        any::<u64>(),
        prop::collection::vec(any::<u8>(), 0..256),
    )
        .prop_map(
            |(chain_id, nonce, from, to, value, gas_limit, max_fee, priority_fee, data)| {
                TxMessage {
                    chain_id,
                    nonce,
                    from,
                    to,
                    value: value as u128,
                    data,
                    gas_limit,
                    max_fee_per_gas: max_fee as u128,
                    max_priority_fee_per_gas: priority_fee as u128,
                }
            },
        )
}

proptest! {
    /// Property: Transaction signing hash is deterministic
    #[test]
    fn prop_tx_signing_deterministic(
        tx in arb_tx_message(),
        leaf_hash in prop::array::uniform32(any::<u8>())
    ) {
        let hash1 = tx.signing_hash(&leaf_hash);
        let hash2 = tx.signing_hash(&leaf_hash);
        prop_assert_eq!(hash1, hash2, "Signing hash should be deterministic");
    }

    /// Property: Signing hash is always 32 bytes
    #[test]
    fn prop_tx_signing_length(
        tx in arb_tx_message(),
        leaf_hash in prop::array::uniform32(any::<u8>())
    ) {
        let hash = tx.signing_hash(&leaf_hash);
        prop_assert_eq!(hash.len(), 32, "Signing hash must be 32 bytes");
    }

    /// Property: Different chain IDs produce different signing hashes
    #[test]
    fn prop_tx_chain_separation(
        mut tx in arb_tx_message(),
        leaf_hash in prop::array::uniform32(any::<u8>())
    ) {
        let hash1 = tx.signing_hash(&leaf_hash);
        tx.chain_id = if tx.chain_id == 1 { 2 } else { 1 };
        let hash2 = tx.signing_hash(&leaf_hash);
        prop_assert_ne!(hash1, hash2, "Different chain IDs should produce different hashes");
    }

    /// Property: Different nonces produce different signing hashes
    #[test]
    fn prop_tx_nonce_sensitivity(
        mut tx in arb_tx_message(),
        leaf_hash in prop::array::uniform32(any::<u8>())
    ) {
        let hash1 = tx.signing_hash(&leaf_hash);
        tx.nonce = tx.nonce.wrapping_add(1);
        let hash2 = tx.signing_hash(&leaf_hash);
        prop_assert_ne!(hash1, hash2, "Different nonces should produce different hashes");
    }

    /// Property: Different leaf hashes produce different signing hashes
    #[test]
    fn prop_tx_leaf_binding(
        tx in arb_tx_message(),
        leaf_hash1 in prop::array::uniform32(any::<u8>()),
        leaf_hash2 in prop::array::uniform32(any::<u8>())
    ) {
        prop_assume!(leaf_hash1 != leaf_hash2);
        let hash1 = tx.signing_hash(&leaf_hash1);
        let hash2 = tx.signing_hash(&leaf_hash2);
        prop_assert_ne!(hash1, hash2, "Different leaf hashes should produce different signing hashes");
    }

    /// Property: Different calldata produces different signing hash
    #[test]
    fn prop_tx_calldata_sensitivity(
        tx in arb_tx_message(),
        leaf_hash in prop::array::uniform32(any::<u8>()),
        extra_byte in any::<u8>()
    ) {
        let hash1 = tx.signing_hash(&leaf_hash);
        let mut tx2 = tx.clone();
        tx2.data.push(extra_byte);
        let hash2 = tx2.signing_hash(&leaf_hash);
        prop_assert_ne!(hash1, hash2, "Adding a calldata byte must change the signing hash");
    }

    /// Property: Empty calldata differs from non-empty calldata
    #[test]
    fn prop_tx_empty_vs_nonempty_calldata(
        mut tx in arb_tx_message(),
        leaf_hash in prop::array::uniform32(any::<u8>()),
        nonempty_data in prop::collection::vec(any::<u8>(), 1..128)
    ) {
        tx.data = vec![];
        let hash_empty = tx.signing_hash(&leaf_hash);
        tx.data = nonempty_data;
        let hash_nonempty = tx.signing_hash(&leaf_hash);
        prop_assert_ne!(hash_empty, hash_nonempty, "Empty vs non-empty calldata must produce different hash");
    }
}

// ── Merkle leaf_index property tests ─────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Property: proof generated for index A fails verification with a different leaf hash
    #[test]
    fn prop_merkle_proof_wrong_index_rejected(
        // Use distinct discriminants to produce unique, valid leaf scripts: [0x60, discriminant]
        discriminants in prop::collection::vec(any::<u8>(), 2..8)
    ) {
        // Build leaves with script [0x60, d] (PUSH1 d) — always valid EVM
        let mut leaves: Vec<Leaf> = discriminants
            .into_iter()
            .enumerate()
            .map(|(i, d)| Leaf::new(0x01, vec![0x60, d.wrapping_add(i as u8)], "").unwrap())
            .collect();

        leaves = dedup_leaves(leaves);
        prop_assume!(leaves.len() >= 2);

        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let root = tree.auth_root();

        let proof_for_0 = tree.proof(0).unwrap();
        let leaf_hash_0 = leaves[0].hash();
        let leaf_hash_1 = leaves[1].hash();

        // Correct leaf hash verifies
        prop_assert!(MerkleTree::verify(&leaf_hash_0, &proof_for_0, &root).unwrap());

        // Wrong leaf hash fails — leaf 1's hash does not belong at index 0's position
        prop_assert!(!MerkleTree::verify(&leaf_hash_1, &proof_for_0, &root).unwrap());
    }

    /// Property: tampering with any sibling invalidates proof
    #[test]
    fn prop_merkle_sibling_tamper_rejected(
        discriminants in prop::collection::vec(any::<u8>(), 2..8),
        tamper_byte in any::<u8>()
    ) {
        let mut leaves: Vec<Leaf> = discriminants
            .into_iter()
            .enumerate()
            .map(|(i, d)| Leaf::new(0x01, vec![0x60, d.wrapping_add(i as u8)], "").unwrap())
            .collect();
        leaves = dedup_leaves(leaves);
        prop_assume!(leaves.len() >= 2);

        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let root = tree.auth_root();
        let mut proof = tree.proof(0).unwrap();
        prop_assume!(!proof.siblings.is_empty());

        // Tamper first sibling
        proof.siblings[0][0] ^= tamper_byte | 0x01;
        let result = MerkleTree::verify(&leaves[0].hash(), &proof, &root).unwrap();
        prop_assert!(!result, "Tampered sibling must fail verification");
    }
}

// ── RotationRequest property tests ───────────────────────────────────────────

fn arb_non_zero_root() -> impl Strategy<Value = [u8; 32]> {
    prop::array::uniform32(any::<u8>()).prop_filter("root must be non-zero", |r| r != &[0u8; 32])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Property: signing_hash is deterministic
    #[test]
    fn prop_rotation_deterministic(
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        from in prop::array::uniform20(any::<u8>()),
        root in arb_non_zero_root()
    ) {
        let req = RotationRequest::new(chain_id, nonce, from, root).unwrap();
        prop_assert_eq!(req.signing_hash(), req.signing_hash());
    }

    /// Property: different chain_id produces different hash
    #[test]
    fn prop_rotation_chain_separation(
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        from in prop::array::uniform20(any::<u8>()),
        root in arb_non_zero_root()
    ) {
        let other_chain = chain_id.wrapping_add(1);
        prop_assume!(other_chain != chain_id);
        let req1 = RotationRequest::new(chain_id, nonce, from, root).unwrap();
        let req2 = RotationRequest::new(other_chain, nonce, from, root).unwrap();
        prop_assert_ne!(req1.signing_hash(), req2.signing_hash());
    }

    /// Property: different nonce produces different hash
    #[test]
    fn prop_rotation_nonce_sensitivity(
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        from in prop::array::uniform20(any::<u8>()),
        root in arb_non_zero_root()
    ) {
        let other_nonce = nonce.wrapping_add(1);
        let req1 = RotationRequest::new(chain_id, nonce, from, root).unwrap();
        let req2 = RotationRequest::new(chain_id, other_nonce, from, root).unwrap();
        prop_assert_ne!(req1.signing_hash(), req2.signing_hash());
    }

    /// Property: different new_auth_root produces different hash
    #[test]
    fn prop_rotation_root_sensitivity(
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        from in prop::array::uniform20(any::<u8>()),
        root1 in arb_non_zero_root(),
        root2 in arb_non_zero_root()
    ) {
        prop_assume!(root1 != root2);
        let req1 = RotationRequest::new(chain_id, nonce, from, root1).unwrap();
        let req2 = RotationRequest::new(chain_id, nonce, from, root2).unwrap();
        prop_assert_ne!(req1.signing_hash(), req2.signing_hash());
    }

    /// Property: rotation hash differs from tx signing hash for same fields
    #[test]
    fn prop_rotation_cross_context_separation(
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        from in prop::array::uniform20(any::<u8>()),
        root in arb_non_zero_root()
    ) {
        let rotation_req = RotationRequest::new(chain_id, nonce, from, root).unwrap();
        let tx = TxMessage {
            chain_id,
            nonce,
            from,
            to: from,
            value: 0,
            data: vec![],
            gas_limit: 21000,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
        };
        // Use root as the leaf_hash so the preimage data is as similar as possible
        let rotation_hash = rotation_req.signing_hash();
        let tx_hash = tx.signing_hash(&root);
        prop_assert_ne!(rotation_hash, tx_hash, "Rotation hash must differ from tx hash");
    }

    /// Property: zero new_auth_root is always rejected
    #[test]
    fn prop_rotation_rejects_zero_root(
        chain_id in any::<u64>(),
        nonce in any::<u64>(),
        from in prop::array::uniform20(any::<u8>())
    ) {
        let result = RotationRequest::new(chain_id, nonce, from, [0u8; 32]);
        prop_assert!(result.is_err());
    }
}
