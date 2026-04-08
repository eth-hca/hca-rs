//! HCA Merkle tree — build tree, compute auth_root, generate and verify proofs.
//!
//! ## Security properties
//! - Leaf/branch confusion prevented via domain separation tags
//! - Second preimage attacks impossible by construction
//! - Maximum depth: 32 levels (2^32 leaves max)

#[cfg(not(feature = "std"))]
use alloc::collections::BTreeSet;
#[cfg(not(feature = "std"))]
use alloc::{string::String, string::ToString, vec, vec::Vec};
#[cfg(feature = "std")]
use std::collections::HashSet;

use crate::constants::{MAX_LEAF_SCRIPT_SIZE, MAX_TREE_DEPTH};
use crate::error::{HcaError, HcaResult};
use crate::evm::opcode::validate_leaf_script;
use crate::hash::{tagged_hash, tags};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// HCA spending condition leaf
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
        if script.is_empty() {
            return Err(HcaError::EmptyLeafScript);
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
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MerkleProof {
    /// Index of the proven leaf
    pub leaf_index: usize,
    /// Sibling hashes from leaf to root
    pub siblings: Vec<[u8; 32]>,
}

/// Compact proof set — shared siblings deduplicated into a single table.
///
/// When proving multiple leaves from the same tree, many sibling hashes at
/// higher levels are identical. `CompactProofSet` stores each unique sibling
/// once and uses per-leaf index lists to reference them.
///
/// # Wire savings example
/// 4-leaf depth-2 tree, proving all 4 leaves:
/// - Standard: 4 proofs × 2 siblings × 32 bytes = 256 bytes
/// - Compact:  3 unique siblings × 32 bytes + 4 × 2 indices = 104 bytes
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CompactProofSet {
    /// Deduplicated sibling hashes (the shared table)
    pub siblings: Vec<[u8; 32]>,
    /// Per-leaf: (leaf_index, [sibling_table_indices from leaf to root])
    pub proofs: Vec<(usize, Vec<usize>)>,
}

impl CompactProofSet {
    /// Expand one entry back into a standard `MerkleProof`.
    ///
    /// `entry` is the position in `self.proofs` (not the leaf_index).
    pub fn expand(&self, entry: usize) -> HcaResult<MerkleProof> {
        let (leaf_index, ref sib_indices) = self.proofs[entry];
        let siblings = sib_indices
            .iter()
            .map(|&i| {
                self.siblings
                    .get(i)
                    .copied()
                    .ok_or(HcaError::ProofVerificationFailed)
            })
            .collect::<HcaResult<Vec<_>>>()?;
        Ok(MerkleProof {
            leaf_index,
            siblings,
        })
    }

    /// Verify all proofs in the compact set against `auth_root`.
    ///
    /// Returns `Ok(true)` only if every proof is valid.
    pub fn verify_all(&self, leaf_hashes: &[[u8; 32]], auth_root: &[u8; 32]) -> HcaResult<bool> {
        if leaf_hashes.len() != self.proofs.len() {
            return Err(HcaError::ProofVerificationFailed);
        }
        for (i, leaf_hash) in leaf_hashes.iter().enumerate() {
            let proof = self.expand(i)?;
            if !MerkleTree::verify(leaf_hash, &proof, auth_root)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// HCA Merkle tree
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(into = "MerkleTreeSerializable"))]
pub struct MerkleTree {
    /// The original spending-condition leaves (in insertion order)
    pub leaves: Vec<Leaf>,
    /// All nodes — level 0 (leaves) first, root last
    nodes: Vec<Vec<[u8; 32]>>,
    /// Tree depth — 0 for a single-leaf tree, log₂(padded_size) otherwise
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

        if MAX_TREE_DEPTH < usize::BITS as usize && leaves.len() > (1usize << MAX_TREE_DEPTH) {
            let depth = usize::BITS as usize - leaves.len().leading_zeros() as usize;
            return Err(HcaError::TreeTooDeep { depth });
        }

        // Detect duplicate leaves — O(n) with a hash set
        #[cfg(feature = "std")]
        let mut seen = HashSet::new();
        #[cfg(not(feature = "std"))]
        let mut seen = BTreeSet::new();
        for (i, leaf) in leaves.iter().enumerate() {
            if !seen.insert(leaf.hash()) {
                return Err(HcaError::DuplicateLeaf { index: i });
            }
        }

        let size = next_power_of_two(leaves.len());

        // Level 0: leaf hashes, padded to power of 2
        #[cfg(feature = "parallel")]
        let mut level_0: Vec<[u8; 32]> = leaves.par_iter().map(|l| l.hash()).collect();
        #[cfg(not(feature = "parallel"))]
        let mut level_0: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash()).collect();
        let last = *level_0.last().unwrap();
        while level_0.len() < size {
            level_0.push(last); // pad with last leaf
        }

        // Integer log2: number of trailing zeros in a power-of-two equals its log2
        let depth = if size == 1 {
            0
        } else {
            size.trailing_zeros() as usize
        };

        // Build all levels bottom-up
        let mut levels = vec![level_0];
        for _ in 0..depth {
            let prev = levels.last().unwrap();
            #[cfg(feature = "parallel")]
            let next: Vec<[u8; 32]> = prev
                .par_chunks(2)
                .map(|pair| branch_hash(&pair[0], &pair[1]))
                .collect();
            #[cfg(not(feature = "parallel"))]
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

        #[allow(unknown_lints, clippy::manual_is_multiple_of)]
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

        #[allow(unknown_lints, clippy::manual_is_multiple_of)]
        for sibling in &proof.siblings {
            current = if idx % 2 == 0 {
                branch_hash(&current, sibling)
            } else {
                branch_hash(sibling, &current)
            };
            idx /= 2;
        }

        Ok(current.ct_eq(auth_root).into())
    }

    /// Generate proofs for multiple leaf indices in one call.
    ///
    /// Returns proofs in the same order as `indices`.
    /// Fails fast if any index is out of bounds.
    pub fn proofs(&self, indices: &[usize]) -> HcaResult<Vec<MerkleProof>> {
        indices.iter().map(|&i| self.proof(i)).collect()
    }

    /// Generate a compact proof set for multiple leaf indices.
    ///
    /// Siblings shared across proofs are stored once in a deduplicated table.
    /// Use `CompactProofSet::expand()` to recover individual `MerkleProof`s,
    /// or `CompactProofSet::verify_all()` to verify directly.
    pub fn compact_proofs(&self, indices: &[usize]) -> HcaResult<CompactProofSet> {
        let mut table: Vec<[u8; 32]> = Vec::new();
        let mut per_leaf: Vec<(usize, Vec<usize>)> = Vec::with_capacity(indices.len());

        for &leaf_index in indices {
            let proof = self.proof(leaf_index)?;
            let mut sib_indices = Vec::with_capacity(proof.siblings.len());
            for sib in &proof.siblings {
                let idx = table.iter().position(|s| s == sib).unwrap_or_else(|| {
                    table.push(*sib);
                    table.len() - 1
                });
                sib_indices.push(idx);
            }
            per_leaf.push((leaf_index, sib_indices));
        }

        Ok(CompactProofSet {
            siblings: table,
            proofs: per_leaf,
        })
    }

    /// Verify multiple proofs against the same auth_root.
    ///
    /// Returns `Ok(true)` only if every proof is valid.
    /// Returns `Ok(false)` on the first invalid proof.
    /// Returns `Err` if any proof exceeds `MAX_TREE_DEPTH`.
    pub fn verify_batch(
        items: &[(&[u8; 32], &MerkleProof)],
        auth_root: &[u8; 32],
    ) -> HcaResult<bool> {
        for (leaf_hash, proof) in items {
            if !Self::verify(leaf_hash, proof, auth_root)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Compute branch node hash
/// branch = tagged_hash("HCABranch", left || right)
/// Serialization proxy — only the leaves are stored; nodes are recomputed on load.
#[cfg(feature = "serde")]
#[derive(Serialize, Deserialize)]
struct MerkleTreeSerializable {
    leaves: Vec<Leaf>,
}

#[cfg(feature = "serde")]
impl From<MerkleTree> for MerkleTreeSerializable {
    fn from(t: MerkleTree) -> Self {
        Self { leaves: t.leaves }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for MerkleTree {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = MerkleTreeSerializable::deserialize(d)?;
        MerkleTree::new(raw.leaves).map_err(serde::de::Error::custom)
    }
}

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
        assert!(Leaf::new(0x01, b"script".to_vec(), "v1").is_ok());
        assert!(Leaf::new(0x02, b"script".to_vec(), "v2").is_ok());
        assert!(Leaf::new(0xFF, b"script".to_vec(), "vFF").is_ok());
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

    // ── Input validation tests ────────────────────────────────────────────────

    #[test]
    fn test_leaf_rejects_empty_script() {
        let result = Leaf::new(0x01, vec![], "empty");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HcaError::EmptyLeafScript);
    }

    #[test]
    fn test_leaf_rejects_version_zero() {
        let result = Leaf::new(0x00, b"script".to_vec(), "bad version");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HcaError::InvalidLeafVersion { version: 0x00 }
        ));
    }

    #[test]
    fn test_tree_rejects_duplicate_leaves() {
        let leaves = vec![
            leaf(b"same script", "first"),
            leaf(b"same script", "second"),
        ];
        let result = MerkleTree::new(leaves);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HcaError::DuplicateLeaf { .. }
        ));
    }

    #[test]
    fn test_tree_rejects_empty_leaves() {
        let result = MerkleTree::new(vec![]);
        assert_eq!(result.unwrap_err(), HcaError::EmptyTree);
    }

    #[test]
    fn test_verify_rejects_deep_proof() {
        use crate::constants::MAX_TREE_DEPTH;
        let proof = MerkleProof {
            leaf_index: 0,
            siblings: vec![[0u8; 32]; MAX_TREE_DEPTH + 1],
        };
        let result = MerkleTree::verify(&[0u8; 32], &proof, &[0u8; 32]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HcaError::TreeTooDeep { .. }));
    }

    fn make_tree(n: usize) -> (MerkleTree, Vec<Leaf>) {
        let leaves: Vec<Leaf> = (0..n)
            .map(|i| Leaf::new(0x01, vec![0x60, i as u8], &format!("leaf {}", i)).unwrap())
            .collect();
        let tree = MerkleTree::new(leaves.clone()).unwrap();
        (tree, leaves)
    }

    // ── compact proof tests ───────────────────────────────────────────────────

    #[test]
    fn test_compact_proofs_deduplicates_siblings() {
        let (tree, _) = make_tree(4);
        let indices = [0, 1, 2, 3];
        let compact = tree.compact_proofs(&indices).unwrap();

        // 4 leaves at depth 2: 2 siblings per proof = 8 total, but top sibling is shared
        // Unique siblings must be fewer than 4*2 = 8
        assert!(compact.siblings.len() < 8);
        assert_eq!(compact.proofs.len(), 4);
    }

    #[test]
    fn test_compact_proofs_verify_all() {
        let (tree, leaves) = make_tree(4);
        let indices = [0, 1, 2, 3];
        let compact = tree.compact_proofs(&indices).unwrap();
        let root = tree.auth_root();
        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash()).collect();
        assert!(compact.verify_all(&hashes, &root).unwrap());
    }

    #[test]
    fn test_compact_proofs_expand_matches_standard() {
        let (tree, leaves) = make_tree(4);
        let compact = tree.compact_proofs(&[0, 2]).unwrap();
        let root = tree.auth_root();

        // Expand and compare with standard proof
        let expanded_0 = compact.expand(0).unwrap();
        let standard_0 = tree.proof(0).unwrap();
        assert_eq!(expanded_0.leaf_index, standard_0.leaf_index);
        assert_eq!(expanded_0.siblings, standard_0.siblings);
        assert!(MerkleTree::verify(&leaves[0].hash(), &expanded_0, &root).unwrap());

        let expanded_1 = compact.expand(1).unwrap();
        let standard_2 = tree.proof(2).unwrap();
        assert_eq!(expanded_1.leaf_index, standard_2.leaf_index);
        assert_eq!(expanded_1.siblings, standard_2.siblings);
    }

    #[test]
    fn test_compact_proofs_single_leaf_tree() {
        let (tree, leaves) = make_tree(1);
        let compact = tree.compact_proofs(&[0]).unwrap();
        let root = tree.auth_root();
        // Single leaf — no siblings, table is empty
        assert!(compact.siblings.is_empty());
        let hashes = [leaves[0].hash()];
        assert!(compact.verify_all(&hashes, &root).unwrap());
    }

    #[test]
    fn test_compact_proofs_empty_indices() {
        let (tree, _) = make_tree(4);
        let compact = tree.compact_proofs(&[]).unwrap();
        assert!(compact.siblings.is_empty());
        assert!(compact.proofs.is_empty());
        let root = tree.auth_root();
        assert!(compact.verify_all(&[], &root).unwrap());
    }

    #[test]
    fn test_compact_proofs_wrong_leaf_hash_fails() {
        let (tree, leaves) = make_tree(4);
        let compact = tree.compact_proofs(&[0, 1]).unwrap();
        let root = tree.auth_root();
        // Swap hashes — wrong hash for entry 0
        let hashes = [leaves[1].hash(), leaves[0].hash()];
        assert!(!compact.verify_all(&hashes, &root).unwrap());
    }

    #[test]
    fn test_compact_proofs_out_of_bounds_fails() {
        let (tree, _) = make_tree(4);
        assert!(tree.compact_proofs(&[0, 99]).is_err());
    }

    #[test]
    fn test_compact_proofs_eight_leaves_deduplication() {
        let (tree, leaves) = make_tree(8);
        let indices: Vec<usize> = (0..8).collect();
        let compact = tree.compact_proofs(&indices).unwrap();
        let root = tree.auth_root();

        // 8 leaves depth-3: 3 siblings per proof = 24 total raw, deduplicated must be < 24
        assert!(compact.siblings.len() < 24);

        let hashes: Vec<[u8; 32]> = leaves.iter().map(|l| l.hash()).collect();
        assert!(compact.verify_all(&hashes, &root).unwrap());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_merkle_tree_serde_roundtrip() {
        let leaves = vec![
            leaf(b"primary key script", "primary"),
            leaf(b"recovery key script", "recovery"),
            leaf(b"timelock script", "timelock"),
        ];
        let tree = MerkleTree::new(leaves).unwrap();
        let root_before = tree.auth_root();

        let json = serde_json::to_string(&tree).unwrap();
        let tree2: MerkleTree = serde_json::from_str(&json).unwrap();

        assert_eq!(tree2.auth_root(), root_before);
        assert_eq!(tree2.leaves.len(), tree.leaves.len());
        assert_eq!(tree2.depth, tree.depth);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_merkle_tree_serde_only_serializes_leaves() {
        let leaves = vec![leaf(b"script A", "a"), leaf(b"script B", "b")];
        let tree = MerkleTree::new(leaves).unwrap();
        let json = serde_json::to_string(&tree).unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("leaves").is_some());
        assert!(v.get("nodes").is_none());
    }
}
