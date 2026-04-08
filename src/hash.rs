//! Hash primitives for HCA.
//!
//! Provides:
//! - `keccak256` — standard Keccak-256 hash
//! - `tagged_hash` — domain-separated hash with BIP-340 style tagging
//! - Precomputed tag hashes — SHA256(tag) constants computed at compile time
//! - Domain separation tags for different HCA operations
//!
//! ## Performance
//!
//! `SHA256(tag)` is constant for each tag string. Rather than recomputing it
//! on every `tagged_hash()` call, the values are precomputed and stored as
//! `const [u8; 32]` in [`tag_hashes`]. `tagged_hash()` now accepts
//! `&[u8; 32]` directly — zero SHA-256 work per call.

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

/// Compute tagged hash with domain separation using a precomputed tag hash.
///
/// Formula:
/// ```text
/// tagged_hash(tag_hash, data) = keccak256(tag_hash || tag_hash || data)
/// ```
///
/// Pass one of the constants from [`tag_hashes`] as `tag_hash`.
/// This avoids recomputing SHA256(tag) on every call.
///
/// # Examples
///
/// ```
/// use hca_rs::hash::{tagged_hash, tag_hashes};
///
/// let auth_root = [0u8; 32];
/// let addr_hash = tagged_hash(&tag_hashes::ADDR, &auth_root);
/// let leaf_hash = tagged_hash(&tag_hashes::LEAF, &auth_root);
///
/// // Different tags produce different outputs for same input
/// assert_ne!(addr_hash, leaf_hash);
/// ```
pub fn tagged_hash(tag_hash: &[u8; 32], data: &[u8]) -> [u8; 32] {
    // Build input: tag_hash || tag_hash || data
    let mut input = Vec::with_capacity(64 + data.len());
    input.extend_from_slice(tag_hash);
    input.extend_from_slice(tag_hash);
    input.extend_from_slice(data);
    keccak256(&input)
}

/// Compute tagged hash from a raw tag string (computes SHA256(tag) at runtime).
///
/// Use this only when the tag is not one of the known HCA tags.
/// For all protocol operations prefer `tagged_hash` with a [`tag_hashes`] constant.
pub fn tagged_hash_str(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    tagged_hash(&tag_hash, data)
}

/// Compute SHA-256 hash (used internally for tag hash verification in tests)
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Precomputed SHA-256 tag hashes — one constant per HCA domain tag.
///
/// These are `SHA256(tag_string)` computed ahead of time and baked into
/// the binary. `tagged_hash()` uses them directly, saving one SHA-256
/// invocation per hash operation.
///
/// ## How values were derived
/// ```text
/// ADDR    = SHA256("HCAAddr")
/// LEAF    = SHA256("HCALeaf")
/// BRANCH  = SHA256("HCABranch")
/// WITNESS = SHA256("HCAWitness")
/// ROTATE  = SHA256("HCARotate")
/// ```
pub mod tag_hashes {
    /// Precomputed `SHA256("HCAAddr")`
    pub const ADDR: [u8; 32] = [
        0x22, 0x66, 0x89, 0x2b, 0x25, 0x12, 0x6b, 0x72, 0x79, 0x4d, 0xda, 0xb0, 0x79, 0x42, 0x31,
        0xcc, 0x5e, 0x18, 0xd5, 0x28, 0x7d, 0x8c, 0x4c, 0xab, 0xfc, 0x71, 0x26, 0x22, 0x41, 0x00,
        0x87, 0x76,
    ];

    /// Precomputed `SHA256("HCALeaf")`
    pub const LEAF: [u8; 32] = [
        0x63, 0xb4, 0xbf, 0x0b, 0x15, 0x72, 0x10, 0x93, 0x4a, 0x6f, 0x82, 0x6b, 0x9a, 0x65, 0xc3,
        0xeb, 0xa8, 0x8f, 0x09, 0x28, 0x12, 0x99, 0xf2, 0xec, 0xb4, 0x3f, 0x5e, 0x59, 0x74, 0x63,
        0xc6, 0xd8,
    ];

    /// Precomputed `SHA256("HCABranch")`
    pub const BRANCH: [u8; 32] = [
        0xe1, 0x22, 0x9b, 0x7e, 0xf9, 0xc1, 0xb2, 0xac, 0x96, 0x47, 0xc8, 0xa2, 0x1d, 0x13, 0xa8,
        0x74, 0xa3, 0xa3, 0x8c, 0x35, 0x7f, 0xf7, 0xf5, 0xba, 0x25, 0x51, 0xda, 0x28, 0x5b, 0xba,
        0x14, 0x6c,
    ];

    /// Precomputed `SHA256("HCAWitness")`
    pub const WITNESS: [u8; 32] = [
        0x1a, 0x50, 0x46, 0xf2, 0xff, 0x0a, 0x6a, 0x86, 0x32, 0x14, 0x64, 0x7a, 0xd5, 0xf8, 0x12,
        0xd1, 0xcd, 0x73, 0xd7, 0x5c, 0x4e, 0xad, 0x1d, 0x7e, 0x3e, 0x98, 0x25, 0x96, 0x36, 0x2c,
        0xae, 0x8e,
    ];

    /// Precomputed `SHA256("HCARotate")`
    pub const ROTATE: [u8; 32] = [
        0xb6, 0x3f, 0x54, 0xdd, 0xab, 0xfd, 0xf3, 0x2b, 0x2d, 0x40, 0x36, 0x94, 0xd0, 0xa7, 0xbb,
        0x23, 0x53, 0xc2, 0x51, 0x2f, 0x93, 0x22, 0x77, 0xa3, 0xb4, 0x7c, 0x7e, 0x9f, 0x62, 0xac,
        0x8e, 0x09,
    ];
}

/// Domain separation tag strings (kept for documentation and cross-impl compatibility)
pub mod tags {
    /// Address derivation: `address = keccak256(tagged_hash("HCAAddr", auth_root))[12..]`
    pub const ADDR: &str = "HCAAddr";

    /// Leaf hash: `leaf_hash = tagged_hash("HCALeaf", version || script)`
    pub const LEAF: &str = "HCALeaf";

    /// Branch hash: `branch_hash = tagged_hash("HCABranch", left || right)`
    pub const BRANCH: &str = "HCABranch";

    /// Witness signing hash: `signing_hash = tagged_hash("HCAWitness", tx_data)`
    pub const WITNESS: &str = "HCAWitness";

    /// Auth root rotation: `rotation_hash = tagged_hash("HCARotate", rotation_data)`
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
    fn test_tag_hashes_match_sha256() {
        // Verify every precomputed constant equals SHA256(tag_string) at runtime
        assert_eq!(tag_hashes::ADDR, sha256(tags::ADDR.as_bytes()));
        assert_eq!(tag_hashes::LEAF, sha256(tags::LEAF.as_bytes()));
        assert_eq!(tag_hashes::BRANCH, sha256(tags::BRANCH.as_bytes()));
        assert_eq!(tag_hashes::WITNESS, sha256(tags::WITNESS.as_bytes()));
        assert_eq!(tag_hashes::ROTATE, sha256(tags::ROTATE.as_bytes()));
    }

    #[test]
    fn test_tagged_hash_domain_separation() {
        let data = [0u8; 32];

        let addr = tagged_hash(&tag_hashes::ADDR, &data);
        let leaf = tagged_hash(&tag_hashes::LEAF, &data);
        let branch = tagged_hash(&tag_hashes::BRANCH, &data);
        let witness = tagged_hash(&tag_hashes::WITNESS, &data);
        let rotate = tagged_hash(&tag_hashes::ROTATE, &data);

        assert_ne!(addr, leaf);
        assert_ne!(addr, branch);
        assert_ne!(addr, witness);
        assert_ne!(addr, rotate);
        assert_ne!(leaf, branch);
        assert_ne!(leaf, witness);
        assert_ne!(leaf, rotate);
        assert_ne!(branch, witness);
        assert_ne!(branch, rotate);
        assert_ne!(witness, rotate);
    }

    #[test]
    fn test_tagged_hash_deterministic() {
        let data = b"test data";
        let hash1 = tagged_hash(&tag_hashes::ADDR, data);
        let hash2 = tagged_hash(&tag_hashes::ADDR, data);
        assert_eq!(hash1, hash2, "tagged_hash must be deterministic");
    }

    #[test]
    fn test_tagged_hash_different_from_plain_keccak() {
        let data = b"test data";
        let plain = keccak256(data);
        let tagged = tagged_hash(&tag_hashes::ADDR, data);
        assert_ne!(plain, tagged);
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"test";
        let hash1 = sha256(data);
        let hash2 = sha256(data);
        assert_eq!(hash1, hash2);
    }
}
