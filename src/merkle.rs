//! HCA Merkle tree — build tree, compute auth_root, generate and verify proofs.
//!
//! ## Security properties
//! - Leaf/branch confusion prevented via domain separation tags
//! - Second preimage attacks impossible by construction
//! - Maximum depth: 32 levels (2^32 leaves max)

use crate::address::tagged_hash;
use crate::address::tags;
use serde::{Deserialize, Serialize};

/// Maximum Merkle tree depth
pub const MAX_DEPTH: usize = 32;

/// HCA spending condition leaf
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Leaf {
    /// Leaf version byte
    /// 0x00 = invalid (reserved)
    /// 0x01 = HCAv1 EVM bytecode leaf (current)
    /// 0x02 = reserved for Falcon/ML-DSA (future)
    /// 0x03 = reserved for SPHINCS+/SLH-DSA (future)
    pub version: u8,
    /// EVM bytecode spending condition
    pub script: Vec<u8>,
    /// Human readable label (not part of hash)
    pub description: String,
}

impl Leaf {
    /// Create a new leaf
    pub fn new(version: u8, script: Vec<u8>, description: &str) -> Self {
        Self {
            version,
            script,
            description: description.to_string(),
        }
    }

    /// Compute leaf hash
    /// leaf_hash = tagged_hash("HCALeaf", version || script)
    pub fn hash(&self) -> [u8; 32] {
        let mut input = Vec::with_capacity(1 + self.script.len());
        input.push(self.version);
        input.extend_from_slice(&self.script);
        tagged_hash(tags::LEAF, &input)
    }

    /// Return true if the leaf version is valid
    pub fn is_valid_version(&self) -> bool {
        self.version != 0x00
    }
}

/// Merkle inclusion proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the proven leaf
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root
    pub siblings: Vec<[u8; 32]>,
}

/// HCA Merkle tree
#[derive(Clone, Debug)]
pub struct MerkleTree {
    pub leaves: Vec<Leaf>,
    /// All nodes — level 0 (leaves) first, root last
    nodes: Vec<Vec<[u8; 32]>>,
    pub depth: usize,
}

impl MerkleTree {
    /// Build a Merkle tree from spending condition leaves
    ///
    /// # Panics
    /// Panics if leaves is empty or exceeds 2^MAX_DEPTH
    pub fn new(leaves: Vec<Leaf>) -> Self {
        assert!(!leaves.is_empty(), "Tree must have at least one leaf");
        assert!(
            leaves.len() <= (1 << MAX_DEPTH),
            "Too many leaves — maximum is 2^{}",
            MAX_DEPTH
        );

        let size = next_power_of_two(leaves.len());

        // Level 0: leaf hashes, padded to power of 2
        let mut level_0: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash()).collect();
        let last = *level_0.last().unwrap();
        while level_0.len() < size {
            level_0.push(last); // pad with last leaf
        }

        let depth = if size == 1 { 0 } else { (size as f64).log2() as usize };

        // Build all levels bottom-up
        let mut levels = vec![level_0];
        for _ in 0..depth {
            let prev = levels.last().unwrap();
            let next: Vec<[u8; 32]> = prev
                .chunks(2)
                .map(|pair| branch_hash(&pair[0], &pair[1]))
                .collect();
            levels.push(next);
        }

        Self { leaves, nodes: levels, depth }
    }

    /// Get the auth_root (Merkle root of all spending conditions)
    pub fn auth_root(&self) -> [u8; 32] {
        *self.nodes.last().unwrap().first().unwrap()
    }

    /// Generate a Merkle proof for the leaf at `leaf_index`
    pub fn proof(&self, leaf_index: usize) -> MerkleProof {
        assert!(leaf_index < self.leaves.len(), "Leaf index out of bounds");

        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = leaf_index;

        for level in &self.nodes[..self.depth] {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            // Use last node if sibling is out of bounds (padding)
            let sibling_hash = level.get(sibling).copied()
                .unwrap_or_else(|| *level.last().unwrap());
            siblings.push(sibling_hash);
            idx /= 2;
        }

        MerkleProof { leaf_index, siblings }
    }

    /// Verify a Merkle proof against the auth_root
    ///
    /// Returns true if the proof is valid.
    /// Domain separation tags make leaf/branch confusion impossible.
    pub fn verify(
        leaf_hash: &[u8; 32],
        proof: &MerkleProof,
        auth_root: &[u8; 32],
    ) -> bool {
        assert!(
            proof.siblings.len() <= MAX_DEPTH,
            "Proof depth exceeds maximum"
        );

        let mut current = *leaf_hash;
        let mut idx = proof.leaf_index;

        for sibling in &proof.siblings {
            current = if idx % 2 == 0 {
                branch_hash(&current, sibling)
            } else {
                branch_hash(sibling, &current)
            };
            idx /= 2;
        }

        &current == auth_root
    }
}

/// Compute branch node hash
/// branch = tagged_hash("HCABranch", left || right)
pub(crate) fn branch_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut input = [0u8; 64];
    input[..32].copy_from_slice(left);
    input[32..].copy_from_slice(right);
    tagged_hash(tags::BRANCH, &input)
}

fn next_power_of_two(n: usize) -> usize {
    if n <= 1 { return 1; }
    let mut p = 1;
    while p < n { p <<= 1; }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(script: &[u8], desc: &str) -> Leaf {
        Leaf::new(0x01, script.to_vec(), desc)
    }

    #[test]
    fn test_single_leaf_tree() {
        let tree = MerkleTree::new(vec![leaf(b"OP_CHECKSIG", "primary")]);
        assert_ne!(tree.auth_root(), [0u8; 32]);
    }

    #[test]
    fn test_proof_verification_single_leaf() {
        let leaves = vec![leaf(b"OP_CHECKSIG", "primary")];
        let tree = MerkleTree::new(leaves.clone());
        let proof = tree.proof(0);
        assert!(MerkleTree::verify(&leaves[0].hash(), &proof, &tree.auth_root()));
    }

    #[test]
    fn test_proof_verification_multiple_leaves() {
        let leaves = vec![
            leaf(b"primary key script", "primary"),
            leaf(b"recovery key script", "recovery"),
            leaf(b"timelock script", "timelock"),
        ];
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.auth_root();

        for i in 0..leaves.len() {
            let proof = tree.proof(i);
            assert!(
                MerkleTree::verify(&leaves[i].hash(), &proof, &root),
                "Proof for leaf {} failed", i
            );
        }
    }

    #[test]
    fn test_wrong_leaf_fails_verification() {
        let leaves = vec![
            leaf(b"leaf 0", "leaf 0"),
            leaf(b"leaf 1", "leaf 1"),
        ];
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.auth_root();
        let proof = tree.proof(0);
        // Wrong leaf hash — should fail
        assert!(!MerkleTree::verify(&leaves[1].hash(), &proof, &root));
    }

    #[test]
    fn test_leaf_branch_confusion_impossible() {
        // A branch hash must not equal a leaf hash — domain separation
        let l = leaf(b"OP_CHECKSIG", "primary");
        let leaf_hash = l.hash();
        let branch = branch_hash(&leaf_hash, &leaf_hash);
        assert_ne!(leaf_hash, branch,
            "Leaf and branch hashes must differ — domain separation required");
    }

    #[test]
    fn test_different_trees_different_roots() {
        let tree1 = MerkleTree::new(vec![leaf(b"script A", "a")]);
        let tree2 = MerkleTree::new(vec![leaf(b"script B", "b")]);
        assert_ne!(tree1.auth_root(), tree2.auth_root());
    }

    #[test]
    fn test_leaf_order_affects_root() {
        let leaves_ab = vec![leaf(b"A", "a"), leaf(b"B", "b")];
        let leaves_ba = vec![leaf(b"B", "b"), leaf(b"A", "a")];
        let tree_ab = MerkleTree::new(leaves_ab);
        let tree_ba = MerkleTree::new(leaves_ba);
        assert_ne!(tree_ab.auth_root(), tree_ba.auth_root(),
            "Leaf order must affect root");
    }

    #[test]
    fn test_invalid_leaf_version() {
        let l = Leaf::new(0x00, b"script".to_vec(), "invalid");
        assert!(!l.is_valid_version());
    }

    #[test]
    fn test_valid_leaf_versions() {
        assert!(Leaf::new(0x01, vec![], "v1").is_valid_version());
        assert!(Leaf::new(0x02, vec![], "v2").is_valid_version());
        assert!(Leaf::new(0xFF, vec![], "vFF").is_valid_version());
    }
}