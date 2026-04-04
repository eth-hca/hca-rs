//! Hash primitives for HCA.
//!
//! Provides:
//! - `keccak256` — standard Keccak-256 hash
//! - `tagged_hash` — domain-separated hash with BIP-340 style tagging
//! - Domain separation tags for different HCA operations

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use tiny_keccak::{Hasher, Keccak};

/// Compute Keccak-256 hash of input data
///
/// Returns a 32-byte hash digest.
///
/// # Examples
///
/// ```
/// use hca_rs::hash::keccak256;
///
/// let data = b"hello world";
/// let hash = keccak256(data);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(data);
    let mut output = [0u8; 32];
    hasher.finalize(&mut output);
    output
}

/// Compute tagged hash with domain separation
///
/// Formula:
/// ```text
/// tagged_hash(tag, data) = keccak256(SHA256(tag) || SHA256(tag) || data)
/// ```
///
/// This follows BIP-340 tagged hash convention adapted for keccak256.
/// The double SHA256(tag) prefix provides domain separation between
/// different uses of the hash function.
///
/// # Domain Separation
///
/// Different tags ensure that:
/// - A leaf hash can never equal a branch hash
/// - An address derivation hash can never collide with a witness hash
/// - Cross-protocol collision attacks are prevented
///
/// # Examples
///
/// ```
/// use hca_rs::hash::{tagged_hash, tags};
///
/// let auth_root = [0u8; 32];
/// let addr_hash = tagged_hash(tags::ADDR, &auth_root);
/// let leaf_hash = tagged_hash(tags::LEAF, &auth_root);
///
/// // Different tags produce different outputs for same input
/// assert_ne!(addr_hash, leaf_hash);
/// ```
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    // Compute SHA256(tag) for domain separation
    let tag_hash = sha256(tag.as_bytes());

    // Build input: SHA256(tag) || SHA256(tag) || data
    let mut input = Vec::with_capacity(64 + data.len());
    input.extend_from_slice(&tag_hash);
    input.extend_from_slice(&tag_hash);
    input.extend_from_slice(data);

    keccak256(&input)
}

/// Compute SHA-256 hash (used internally for tagged hash)
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Domain separation tags for different HCA operations
pub mod tags {
    /// Address derivation: address = keccak256(tagged_hash("HCAAddr", auth_root))[12:]
    pub const ADDR: &str = "HCAAddr";

    /// Leaf hash: leaf_hash = tagged_hash("HCALeaf", version || script)
    pub const LEAF: &str = "HCALeaf";

    /// Branch hash: branch_hash = tagged_hash("HCABranch", left || right)
    pub const BRANCH: &str = "HCABranch";

    /// Witness signing hash: signing_hash = tagged_hash("HCAWitness", tx_data)
    pub const WITNESS: &str = "HCAWitness";

    /// Auth root rotation: rotation_hash = tagged_hash("HCARotate", rotation_data)
    pub const ROTATE: &str = "HCARotate";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        assert_eq!(hash.len(), 32);
        assert_ne!(hash, [0u8; 32]);
    }

    #[test]
    fn test_keccak256_deterministic() {
        let data = b"hello world";
        let hash1 = keccak256(data);
        let hash2 = keccak256(data);
        assert_eq!(hash1, hash2, "keccak256 must be deterministic");
    }

    #[test]
    fn test_keccak256_different_inputs() {
        let hash1 = keccak256(b"input A");
        let hash2 = keccak256(b"input B");
        assert_ne!(
            hash1, hash2,
            "Different inputs must produce different hashes"
        );
    }

    #[test]
    fn test_tagged_hash_domain_separation() {
        let data = [0u8; 32];

        let addr_hash = tagged_hash(tags::ADDR, &data);
        let leaf_hash = tagged_hash(tags::LEAF, &data);
        let branch_hash = tagged_hash(tags::BRANCH, &data);
        let witness_hash = tagged_hash(tags::WITNESS, &data);
        let rotate_hash = tagged_hash(tags::ROTATE, &data);

        // All tags must produce different outputs for same input
        assert_ne!(addr_hash, leaf_hash);
        assert_ne!(addr_hash, branch_hash);
        assert_ne!(addr_hash, witness_hash);
        assert_ne!(addr_hash, rotate_hash);
        assert_ne!(leaf_hash, branch_hash);
        assert_ne!(leaf_hash, witness_hash);
        assert_ne!(leaf_hash, rotate_hash);
        assert_ne!(branch_hash, witness_hash);
        assert_ne!(branch_hash, rotate_hash);
        assert_ne!(witness_hash, rotate_hash);
    }

    #[test]
    fn test_tagged_hash_deterministic() {
        let data = b"test data";
        let hash1 = tagged_hash(tags::ADDR, data);
        let hash2 = tagged_hash(tags::ADDR, data);
        assert_eq!(hash1, hash2, "tagged_hash must be deterministic");
    }

    #[test]
    fn test_tagged_hash_different_from_plain_keccak() {
        let data = b"test data";
        let plain = keccak256(data);
        let tagged = tagged_hash(tags::ADDR, data);
        assert_ne!(
            plain, tagged,
            "Tagged hash must differ from plain keccak256"
        );
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"test";
        let hash1 = sha256(data);
        let hash2 = sha256(data);
        assert_eq!(hash1, hash2);
    }
}
