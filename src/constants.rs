//! Protocol constants for HCA.
//!
//! All protocol-level constants are defined here for consistency
//! across implementations.

/// EIP-2718 transaction type for HCA transactions
/// NOTE: This value is TBD and may change during standardization
pub const HCA_TX_TYPE: u8 = 0x05;

/// Maximum Merkle tree depth (supports up to 2^32 leaves)
pub const MAX_TREE_DEPTH: usize = 32;

/// Maximum gas cost for executing a leaf spending condition
pub const MAX_LEAF_GAS: u64 = 100_000;

/// Gas cost per Merkle tree level during proof verification
pub const MERKLE_GAS_PER_LEVEL: u64 = 80;

/// Base gas cost for Merkle proof verification
pub const MERKLE_BASE_GAS: u64 = 200;

/// Maximum leaf script size in bytes (matches EIP-170 contract size limit)
pub const MAX_LEAF_SCRIPT_SIZE: usize = 24_576; // 24 KB

/// Maximum witness size in bytes
pub const MAX_WITNESS_SIZE: usize = 65_536; // 64 KB

/// Ethereum mainnet chain ID
pub const CHAIN_ID_MAINNET: u64 = 1;

/// Ethereum Sepolia testnet chain ID
pub const CHAIN_ID_SEPOLIA: u64 = 11_155_111;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_reasonable() {
        // Compile-time sanity checks for const values
        const _: () = assert!(MAX_TREE_DEPTH <= 64 && MAX_TREE_DEPTH > 0);
        const _: () = assert!(MAX_LEAF_SCRIPT_SIZE <= 1_000_000);
        const _: () = assert!(MAX_WITNESS_SIZE <= 10_000_000);

        assert_eq!(CHAIN_ID_MAINNET, 1, "Mainnet chain ID is 1");
        assert_eq!(CHAIN_ID_SEPOLIA, 11_155_111, "Sepolia chain ID is 11155111");
    }
}
