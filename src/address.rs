//! HCA address derivation.
//!
//! Formula:
//! ```text
//! address = keccak256(tagged_hash("HCAAddr", auth_root))[12..]
//! ```
//!
//! The public key is completely absent from this derivation chain.
//! A quantum computer observing the address has no algebraic
//! structure to run Shor's algorithm against.

use crate::hash::{keccak256, tag_hashes, tagged_hash};

/// Derive a 20-byte HCA address from an auth_root.
///
/// ```text
/// address = keccak256(tagged_hash("HCAAddr", auth_root))[12..]
/// ```
///
/// The outer `keccak256` wraps the tagged hash, matching the structure of
/// Ethereum's EOA derivation (`keccak256(pubkey)[12:]`) while the
/// `tagged_hash` domain separator ensures no cross-type collisions.
pub fn derive_address(auth_root: &[u8; 32]) -> [u8; 20] {
    let inner = tagged_hash(&tag_hashes::ADDR, auth_root);
    let hash = keccak256(&inner);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Format address as hex string with 0x prefix
#[cfg(feature = "std")]
pub fn address_to_hex(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

/// Format auth_root as hex string with 0x prefix
#[cfg(feature = "std")]
pub fn auth_root_to_hex(auth_root: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(auth_root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_is_20_bytes() {
        let auth_root = [1u8; 32];
        let address = derive_address(&auth_root);
        assert_eq!(address.len(), 20);
    }

    #[test]
    fn test_address_deterministic() {
        let auth_root = [42u8; 32];
        let addr1 = derive_address(&auth_root);
        let addr2 = derive_address(&auth_root);
        assert_eq!(
            addr1, addr2,
            "Same auth_root must always produce same address"
        );
    }

    #[test]
    fn test_different_roots_produce_different_addresses() {
        let root1 = [1u8; 32];
        let root2 = [2u8; 32];
        let addr1 = derive_address(&root1);
        let addr2 = derive_address(&root2);
        assert_ne!(
            addr1, addr2,
            "Different auth_roots must produce different addresses"
        );
    }

    #[test]
    fn test_address_not_equal_to_auth_root_truncated() {
        // address is NOT just auth_root`[12..]`
        // it is keccak256(tagged_hash("HCAAddr", auth_root))`[12..]`
        let auth_root = [0xABu8; 32];
        let address = derive_address(&auth_root);
        // If address were just auth_root`[12..]`, all bytes would be 0xAB
        let all_same = address.iter().all(|&b| b == 0xAB);
        assert!(
            !all_same,
            "Address must be a hash of auth_root, not a truncation"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_address_hex_format() {
        let auth_root = [0u8; 32];
        let address = derive_address(&auth_root);
        let hex = address_to_hex(&address);
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 42); // "0x" + 40 hex chars
    }

    #[test]
    fn test_zero_auth_root() {
        // Zero auth_root should still produce a valid address
        let auth_root = [0u8; 32];
        let address = derive_address(&auth_root);
        // Should not panic and should produce non-zero address
        assert_ne!(address, [0u8; 20]);
    }
}
