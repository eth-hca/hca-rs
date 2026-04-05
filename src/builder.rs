//! Builder pattern APIs for ergonomic construction of HCA types.
//!
//! Builders validate all inputs at `build()` time and return descriptive
//! errors rather than panicking, making them safe for wallet integrations.
//!
//! # Examples
//!
//! ```
//! use hca_rs::builder::{TreeBuilder, TxBuilder};
//!
//! // Build a Merkle tree with two spending conditions
//! let tree = TreeBuilder::new()
//!     .add_leaf(0x01, b"primary_script".to_vec(), "Primary key")
//!     .add_leaf(0x01, b"recovery_script".to_vec(), "Recovery key")
//!     .build()
//!     .unwrap();
//!
//! // Build a transaction message
//! let tx = TxBuilder::new(1)
//!     .nonce(5)
//!     .to([0x02u8; 20])
//!     .value(1_000_000_000_000_000u128)
//!     .gas_limit(21_000)
//!     .max_fee_per_gas(1_000_000_000u128)
//!     .max_priority_fee_per_gas(100_000_000u128)
//!     .build([0x01u8; 20])
//!     .unwrap();
//! ```

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};

#[cfg(feature = "std")]
use std::string::String;

use crate::error::{HcaError, HcaResult};
use crate::merkle::{Leaf, MerkleTree};
use crate::witness::TxMessage;

/// Holds a leaf description as either a borrowed static string or an owned String.
/// This lets TreeBuilder preserve insertion order across add_leaf / add_leaf_owned calls.
enum Desc {
    Static(&'static str),
    Owned(String),
}

impl Desc {
    fn as_str(&self) -> &str {
        match self {
            Desc::Static(s) => s,
            Desc::Owned(s) => s.as_str(),
        }
    }
}

// ── TreeBuilder ───────────────────────────────────────────────────────────────

/// Ergonomic builder for [`MerkleTree`].
///
/// Collects leaves via [`add_leaf`](TreeBuilder::add_leaf) and validates
/// them all at [`build`](TreeBuilder::build) time.
///
/// # Example
///
/// ```
/// use hca_rs::builder::TreeBuilder;
///
/// let tree = TreeBuilder::new()
///     .add_leaf(0x01, b"script_a".to_vec(), "Key A")
///     .add_leaf(0x01, b"script_b".to_vec(), "Key B")
///     .build()
///     .unwrap();
///
/// assert_eq!(tree.leaves.len(), 2);
/// ```
/// Ergonomic builder for [`MerkleTree`].
///
/// Collects leaves via [`add_leaf`](TreeBuilder::add_leaf) and validates
/// them all at [`build`](TreeBuilder::build) time.
///
/// # Example
///
/// ```
/// use hca_rs::builder::TreeBuilder;
///
/// let tree = TreeBuilder::new()
///     .add_leaf(0x01, b"script_a".to_vec(), "Key A")
///     .add_leaf(0x01, b"script_b".to_vec(), "Key B")
///     .build()
///     .unwrap();
///
/// assert_eq!(tree.leaves.len(), 2);
/// ```
#[derive(Default)]
pub struct TreeBuilder {
    pending: Vec<(u8, Vec<u8>, Desc)>,
}

impl TreeBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a leaf with a `'static` description string.
    ///
    /// The leaf is validated (version, script size, banned opcodes) at
    /// [`build`](TreeBuilder::build) time, not here.
    pub fn add_leaf(mut self, version: u8, script: Vec<u8>, description: &'static str) -> Self {
        self.pending
            .push((version, script, Desc::Static(description)));
        self
    }

    /// Add a leaf with an owned description string.
    pub fn add_leaf_owned(mut self, version: u8, script: Vec<u8>, description: String) -> Self {
        self.pending
            .push((version, script, Desc::Owned(description)));
        self
    }

    /// Validate all leaves and build the [`MerkleTree`].
    ///
    /// Returns `Err` if:
    /// - No leaves were added
    /// - Any leaf has an invalid version or oversized script
    /// - Any leaf contains a banned EVM opcode
    /// - Any two leaves are identical (same hash)
    pub fn build(self) -> HcaResult<MerkleTree> {
        if self.pending.is_empty() {
            return Err(HcaError::EmptyTree);
        }

        let mut leaves = Vec::with_capacity(self.pending.len());

        for (version, script, desc) in self.pending {
            leaves.push(Leaf::new(version, script, desc.as_str())?);
        }

        MerkleTree::new(leaves)
    }
}

// ── TxBuilder ─────────────────────────────────────────────────────────────────

/// Ergonomic builder for [`TxMessage`].
///
/// All fields except `chain_id` (set at construction) and `from` (set at
/// [`build`](TxBuilder::build)) are optional and default to zero/empty.
///
/// # Example
///
/// ```
/// use hca_rs::builder::TxBuilder;
///
/// let tx = TxBuilder::new(11155111)
///     .nonce(3)
///     .to([0xAAu8; 20])
///     .value(0)
///     .gas_limit(21_000)
///     .max_fee_per_gas(1_000_000_000u128)
///     .max_priority_fee_per_gas(100_000_000u128)
///     .build([0x01u8; 20])
///     .unwrap();
///
/// assert_eq!(tx.chain_id, 11155111);
/// assert_eq!(tx.nonce, 3);
/// ```
#[derive(Debug)]
pub struct TxBuilder {
    chain_id: u64,
    nonce: u64,
    to: [u8; 20],
    value: u128,
    data: Vec<u8>,
    gas_limit: u64,
    max_fee_per_gas: u128,
    max_priority_fee_per_gas: u128,
}

impl TxBuilder {
    /// Create a new builder for the given `chain_id`.
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            nonce: 0,
            to: [0u8; 20],
            value: 0,
            data: Vec::new(),
            gas_limit: 0,
            max_fee_per_gas: 0,
            max_priority_fee_per_gas: 0,
        }
    }

    /// Set the transaction nonce.
    pub fn nonce(mut self, nonce: u64) -> Self {
        self.nonce = nonce;
        self
    }

    /// Set the recipient address.
    pub fn to(mut self, to: [u8; 20]) -> Self {
        self.to = to;
        self
    }

    /// Set the value to transfer in wei.
    pub fn value(mut self, value: u128) -> Self {
        self.value = value;
        self
    }

    /// Set the calldata.
    pub fn data(mut self, data: Vec<u8>) -> Self {
        self.data = data;
        self
    }

    /// Set the gas limit.
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }

    /// Set the max fee per gas (EIP-1559).
    pub fn max_fee_per_gas(mut self, max_fee_per_gas: u128) -> Self {
        self.max_fee_per_gas = max_fee_per_gas;
        self
    }

    /// Set the max priority fee per gas (EIP-1559 tip).
    pub fn max_priority_fee_per_gas(mut self, max_priority_fee_per_gas: u128) -> Self {
        self.max_priority_fee_per_gas = max_priority_fee_per_gas;
        self
    }

    /// Validate and build the [`TxMessage`].
    ///
    /// `from` is the explicit HCA sender address.
    ///
    /// Returns `Err(HcaError::InvalidAddress)` if `chain_id` is zero.
    pub fn build(self, from: [u8; 20]) -> HcaResult<TxMessage> {
        if self.chain_id == 0 {
            return Err(HcaError::InvalidAddress);
        }
        Ok(TxMessage {
            chain_id: self.chain_id,
            nonce: self.nonce,
            from,
            to: self.to,
            value: self.value,
            data: self.data,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── TreeBuilder tests ─────────────────────────────────────────────────────

    #[test]
    fn test_tree_builder_single_leaf() {
        let tree = TreeBuilder::new()
            .add_leaf(0x01, b"script".to_vec(), "Primary")
            .build()
            .unwrap();
        assert_eq!(tree.leaves.len(), 1);
    }

    #[test]
    fn test_tree_builder_two_leaves() {
        let tree = TreeBuilder::new()
            .add_leaf(0x01, b"script_a".to_vec(), "Key A")
            .add_leaf(0x01, b"script_b".to_vec(), "Key B")
            .build()
            .unwrap();
        assert_eq!(tree.leaves.len(), 2);
        assert_eq!(tree.depth, 1);
    }

    #[test]
    fn test_tree_builder_empty_fails() {
        let result = TreeBuilder::new().build();
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HcaError::EmptyTree);
    }

    #[test]
    fn test_tree_builder_invalid_version_fails() {
        let result = TreeBuilder::new()
            .add_leaf(0x00, b"script".to_vec(), "bad")
            .build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HcaError::InvalidLeafVersion { .. }
        ));
    }

    #[test]
    fn test_tree_builder_banned_opcode_fails() {
        // SSTORE = 0x55
        let result = TreeBuilder::new()
            .add_leaf(0x01, vec![0x55], "banned")
            .build();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), HcaError::BannedOpcode { .. }));
    }

    #[test]
    fn test_tree_builder_duplicate_leaf_fails() {
        let result = TreeBuilder::new()
            .add_leaf(0x01, b"same".to_vec(), "first")
            .add_leaf(0x01, b"same".to_vec(), "second")
            .build();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HcaError::DuplicateLeaf { .. }
        ));
    }

    #[test]
    fn test_tree_builder_add_leaf_owned() {
        let desc = "dynamic".to_string();
        let tree = TreeBuilder::new()
            .add_leaf_owned(0x01, b"script".to_vec(), desc)
            .build()
            .unwrap();
        assert_eq!(tree.leaves.len(), 1);
    }

    #[test]
    fn test_tree_builder_insertion_order_preserved() {
        // Mixing add_leaf and add_leaf_owned must preserve insertion order.
        // Before the fix, static leaves were processed before owned leaves,
        // so A, B(owned), C would produce [A, C, B] — a different auth_root.
        let mixed = TreeBuilder::new()
            .add_leaf(0x01, b"aaa".to_vec(), "A")
            .add_leaf_owned(0x01, b"bbb".to_vec(), "B".to_string())
            .add_leaf(0x01, b"ccc".to_vec(), "C")
            .build()
            .unwrap();

        let ordered = TreeBuilder::new()
            .add_leaf(0x01, b"aaa".to_vec(), "A")
            .add_leaf(0x01, b"bbb".to_vec(), "B")
            .add_leaf(0x01, b"ccc".to_vec(), "C")
            .build()
            .unwrap();

        assert_eq!(
            mixed.auth_root(),
            ordered.auth_root(),
            "insertion order must be preserved when mixing add_leaf and add_leaf_owned"
        );
    }

    #[test]
    fn test_tree_builder_matches_manual_construction() {
        let builder_tree = TreeBuilder::new()
            .add_leaf(0x01, b"primary".to_vec(), "Primary")
            .add_leaf(0x01, b"recovery".to_vec(), "Recovery")
            .build()
            .unwrap();

        let manual_tree = MerkleTree::new(vec![
            Leaf::new(0x01, b"primary".to_vec(), "Primary").unwrap(),
            Leaf::new(0x01, b"recovery".to_vec(), "Recovery").unwrap(),
        ])
        .unwrap();

        assert_eq!(builder_tree.auth_root(), manual_tree.auth_root());
    }

    // ── TxBuilder tests ───────────────────────────────────────────────────────

    #[test]
    fn test_tx_builder_basic() {
        let tx = TxBuilder::new(1)
            .nonce(5)
            .to([0x02u8; 20])
            .value(1000)
            .gas_limit(21_000)
            .max_fee_per_gas(1_000_000_000)
            .max_priority_fee_per_gas(100_000_000)
            .build([0x01u8; 20])
            .unwrap();

        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.nonce, 5);
        assert_eq!(tx.to, [0x02u8; 20]);
        assert_eq!(tx.from, [0x01u8; 20]);
        assert_eq!(tx.value, 1000);
        assert_eq!(tx.gas_limit, 21_000);
    }

    #[test]
    fn test_tx_builder_zero_chain_id_fails() {
        let result = TxBuilder::new(0).build([0x01u8; 20]);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), HcaError::InvalidAddress);
    }

    #[test]
    fn test_tx_builder_defaults() {
        let tx = TxBuilder::new(1).build([0x01u8; 20]).unwrap();
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.value, 0);
        assert_eq!(tx.data, Vec::<u8>::new());
        assert_eq!(tx.gas_limit, 0);
        assert_eq!(tx.max_fee_per_gas, 0);
        assert_eq!(tx.max_priority_fee_per_gas, 0);
    }

    #[test]
    fn test_tx_builder_with_data() {
        let calldata = vec![0xde, 0xad, 0xbe, 0xef];
        let tx = TxBuilder::new(1)
            .data(calldata.clone())
            .build([0x01u8; 20])
            .unwrap();
        assert_eq!(tx.data, calldata);
    }

    #[test]
    fn test_tx_builder_matches_manual_construction() {
        let from = [0x01u8; 20];
        let to = [0x02u8; 20];

        let builder_tx = TxBuilder::new(11155111)
            .nonce(3)
            .to(to)
            .value(500)
            .gas_limit(21_000)
            .max_fee_per_gas(1_000_000_000)
            .max_priority_fee_per_gas(100_000_000)
            .build(from)
            .unwrap();

        let manual_tx = TxMessage {
            chain_id: 11155111,
            nonce: 3,
            from,
            to,
            value: 500,
            data: vec![],
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
        };

        let leaf_hash = [0xAAu8; 32];
        assert_eq!(
            builder_tx.signing_hash(&leaf_hash),
            manual_tx.signing_hash(&leaf_hash),
            "Builder and manual TxMessage must produce same signing hash"
        );
    }

    #[test]
    fn test_tx_builder_sepolia() {
        let tx = TxBuilder::new(11_155_111)
            .nonce(0)
            .to([0xBBu8; 20])
            .gas_limit(100_000)
            .build([0xAAu8; 20])
            .unwrap();
        assert_eq!(tx.chain_id, 11_155_111);
    }
}
