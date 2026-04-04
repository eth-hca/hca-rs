//! HCA Merkle tree — build tree, compute auth_root, generate and verify proofs.
//!
//! ## Security properties
//! - Leaf/branch confusion prevented via domain separation tags
//! - Second preimage attacks impossible by construction
//! - Maximum depth: 32 levels (2^32 leaves max)

use crate::constants::{MAX_LEAF_SCRIPT_SIZE, MAX_TREE_DEPTH};
use crate::error::{HcaError, HcaResult};
use crate::evm::opcode::validate_leaf_script;
use crate::hash::{tagged_hash, tags};
use serde::{Deserialize, Serialize};

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
    /// Create a new leaf, validating version and script size.
    ///
    /// Returns `HcaError::InvalidLeafVersion` if version is `0x00`.
    /// Returns `HcaError::LeafScriptTooLarge` if script exceeds `MAX_LEAF_SCRIPT_SIZE`.
    pub fn new(version: u8, script: Vec<u8>, description: &str) -> HcaResult<Self> {
        if version == 0x00 {
            return Err(HcaError::InvalidLeafVersion { version });
        }
        if script.len() > MAX_LEAF_SCRIPT_SIZE {
            return Err(HcaError::LeafScriptTooLarge { size: script.len() });
        }
        validate_leaf_script(&script)?;
        Ok(Self {
            version,
            script,
            description: description.to_string(),
        })
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
    /// Returns an error if leaves is empty or exceeds maximum depth.
    pub fn new(leaves: Vec<Leaf>) -> HcaResult<Self> {
        if leaves.is_empty() {
            return Err(HcaError::EmptyTree);
        }

        if leaves.len() > (1 << MAX_TREE_DEPTH) {
            let depth = (leaves.len() as f64).log2().ceil() as usize;
            return Err(HcaError::TreeTooDeep { depth });
        }

        let size = next_power_of_two(leaves.len());

        // Level 0: leaf hashes, padded to power of 2
        let mut level_0: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash()).collect();
        let last = *level_0.last().unwrap();
        while level_0.len() < size {
            level_0.push(last); // pad with last leaf
        }

        let depth = if size == 1 {
            0
        } else {
            (size as f64).log2() as usize
        };

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

        Ok(Self {
            leaves,
            nodes: levels,
            depth,
        })
    }

    /// Get the auth_root (Merkle root of all spending conditions)
    pub fn auth_root(&self) -> [u8; 32] {
        *self.nodes.last().unwrap().first().unwrap()
    }

    /// Generate a Merkle proof for the leaf at `leaf_index`
    pub fn proof(&self, leaf_index: usize) -> HcaResult<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return Err(HcaError::LeafIndexOutOfBounds {
                index: leaf_index,
                count: self.leaves.len(),
            });
        }

        let mut siblings = Vec::with_capacity(self.depth);
        let mut idx = leaf_index;

        for level in &self.nodes[..self.depth] {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            // Use last node if sibling is out of bounds (padding)
            let sibling_hash = level
                .get(sibling)
                .copied()
                .unwrap_or_else(|| *level.last().unwrap());
            siblings.push(sibling_hash);
            idx /= 2;
        }

        Ok(MerkleProof {
            leaf_index,
            siblings,
        })
    }

    /// Verify a Merkle proof against the auth_root
    ///
    /// Returns true if the proof is valid.
    /// Domain separation tags make leaf/branch confusion impossible.
    pub fn verify(
        leaf_hash: &[u8; 32],
        proof: &MerkleProof,
        auth_root: &[u8; 32],
    ) -> HcaResult<bool> {
        if proof.siblings.len() > MAX_TREE_DEPTH {
            return Err(HcaError::TreeTooDeep {
                depth: proof.siblings.len(),
            });
        }

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

        Ok(&current == auth_root)
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
    if n <= 1 {
        return 1;
    }
    let mut p = 1;
    while p < n {
        p <<= 1;
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(script: &[u8], desc: &str) -> Leaf {
        Leaf::new(0x01, script.to_vec(), desc).unwrap()
    }

    #[test]
    fn test_single_leaf_tree() {
        let tree = MerkleTree::new(vec![leaf(b"OP_CHECKSIG", "primary")]).unwrap();
        assert_ne!(tree.auth_root(), [0u8; 32]);
    }

    #[test]
    fn test_proof_verification_single_leaf() {
        let leaves = vec![leaf(b"OP_CHECKSIG", "primary")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let proof = tree.proof(0).unwrap();
        assert!(MerkleTree::verify(&leaves[0].hash(), &proof, &tree.auth_root()).unwrap());
    }

    #[test]
    fn test_proof_verification_multiple_leaves() {
        let leaves = vec![
            leaf(b"primary key script", "primary"),
            leaf(b"recovery key script", "recovery"),
            leaf(b"timelock script", "timelock"),
        ];
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let root = tree.auth_root();

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = tree.proof(i).unwrap();
            assert!(
                MerkleTree::verify(&leaf.hash(), &proof, &root).unwrap(),
                "Proof for leaf {} failed",
                i
            );
        }
    }

    #[test]
    fn test_wrong_leaf_fails_verification() {
        let leaves = vec![leaf(b"leaf 0", "leaf 0"), leaf(b"leaf 1", "leaf 1")];
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let root = tree.auth_root();
        let proof = tree.proof(0).unwrap();
        // Wrong leaf hash — should fail
        assert!(!MerkleTree::verify(&leaves[1].hash(), &proof, &root).unwrap());
    }

    #[test]
    fn test_leaf_branch_confusion_impossible() {
        // A branch hash must not equal a leaf hash — domain separation
        let l = leaf(b"OP_CHECKSIG", "primary");
        let leaf_hash = l.hash();
        let branch = branch_hash(&leaf_hash, &leaf_hash);
        assert_ne!(
            leaf_hash, branch,
            "Leaf and branch hashes must differ — domain separation required"
        );
    }

    #[test]
    fn test_different_trees_different_roots() {
        let tree1 = MerkleTree::new(vec![leaf(b"script A", "a")]).unwrap();
        let tree2 = MerkleTree::new(vec![leaf(b"script B", "b")]).unwrap();
        assert_ne!(tree1.auth_root(), tree2.auth_root());
    }

    #[test]
    fn test_leaf_order_affects_root() {
        let leaves_ab = vec![leaf(b"A", "a"), leaf(b"B", "b")];
        let leaves_ba = vec![leaf(b"B", "b"), leaf(b"A", "a")];
        let tree_ab = MerkleTree::new(leaves_ab).unwrap();
        let tree_ba = MerkleTree::new(leaves_ba).unwrap();
        assert_ne!(
            tree_ab.auth_root(),
            tree_ba.auth_root(),
            "Leaf order must affect root"
        );
    }

    #[test]
    fn test_invalid_leaf_version() {
        let result = Leaf::new(0x00, b"script".to_vec(), "invalid");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            HcaError::InvalidLeafVersion { version: 0x00 }
        );
    }

    #[test]
    fn test_valid_leaf_versions() {
        assert!(Leaf::new(0x01, vec![], "v1").is_ok());
        assert!(Leaf::new(0x02, vec![], "v2").is_ok());
        assert!(Leaf::new(0xFF, vec![], "vFF").is_ok());
    }

    #[test]
    fn test_leaf_script_too_large() {
        use crate::constants::MAX_LEAF_SCRIPT_SIZE;
        let oversized = vec![0x01u8; MAX_LEAF_SCRIPT_SIZE + 1];
        let result = Leaf::new(0x01, oversized.clone(), "oversized");
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            HcaError::LeafScriptTooLarge {
                size: oversized.len()
            }
        );
    }

    #[test]
    fn test_leaf_script_at_max_size() {
        use crate::constants::MAX_LEAF_SCRIPT_SIZE;
        let max_script = vec![0x01u8; MAX_LEAF_SCRIPT_SIZE];
        assert!(Leaf::new(0x01, max_script, "max").is_ok());
    }
}
