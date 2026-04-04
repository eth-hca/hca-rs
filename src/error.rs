//! Error types for the hca-rs crate.
//!
//! All fallible operations return `HcaResult<T>` for consistent error handling.

use std::fmt;

/// Unified error type for all HCA operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HcaError {
    /// Tree must have at least one leaf
    EmptyTree,

    /// Tree exceeds maximum depth
    TreeTooDeep {
        /// Actual depth attempted
        depth: usize,
    },

    /// Leaf index out of bounds
    LeafIndexOutOfBounds {
        /// Index attempted
        index: usize,
        /// Number of leaves in tree
        count: usize,
    },

    /// Invalid leaf version byte
    InvalidLeafVersion {
        /// Version byte provided
        version: u8,
    },

    /// Leaf script exceeds maximum size
    LeafScriptTooLarge {
        /// Size in bytes
        size: usize,
    },

    /// Merkle proof verification failed
    ProofVerificationFailed,

    /// Witness has not been signed yet
    WitnessNotSigned,

    /// Witness exceeds maximum size
    WitnessTooLarge {
        /// Size in bytes
        size: usize,
    },

    /// authRoot rotation is invalid
    InvalidRotation(String),

    /// Leaf script contains a banned EVM opcode
    BannedOpcode {
        /// The banned opcode byte
        opcode: u8,
        /// Human-readable opcode name
        name: String,
    },

    /// RLP encoding error
    RlpEncodingError(String),

    /// RLP decoding error
    RlpDecodeError(String),

    /// Invalid address format
    InvalidAddress,

    /// Empty leaf script
    EmptyLeafScript,

    /// Duplicate leaf in Merkle tree
    DuplicateLeaf {
        /// Index of the first duplicate found
        index: usize,
    },

    /// Empty witness signature
    EmptySignature,

    /// Leaf script gas limit exceeded during validation
    GasExhausted {
        /// The gas limit in effect
        limit: u64,
        /// Gas consumed before exhaustion
        consumed: u64,
    },
}

impl fmt::Display for HcaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HcaError::EmptyTree => {
                write!(f, "Tree must have at least one leaf")
            }
            HcaError::TreeTooDeep { depth } => {
                write!(f, "Tree depth {} exceeds maximum", depth)
            }
            HcaError::LeafIndexOutOfBounds { index, count } => {
                write!(
                    f,
                    "Leaf index {} out of bounds (tree has {} leaves)",
                    index, count
                )
            }
            HcaError::InvalidLeafVersion { version } => {
                write!(f, "Invalid leaf version: 0x{:02x}", version)
            }
            HcaError::LeafScriptTooLarge { size } => {
                write!(f, "Leaf script size {} exceeds maximum", size)
            }
            HcaError::ProofVerificationFailed => {
                write!(f, "Merkle proof verification failed")
            }
            HcaError::WitnessNotSigned => {
                write!(f, "Witness has not been signed yet")
            }
            HcaError::WitnessTooLarge { size } => {
                write!(f, "Witness size {} exceeds maximum", size)
            }
            HcaError::InvalidRotation(msg) => {
                write!(f, "Invalid authRoot rotation: {}", msg)
            }
            HcaError::BannedOpcode { opcode, name } => {
                write!(
                    f,
                    "Banned opcode in leaf script: {} (0x{:02X})",
                    name, opcode
                )
            }
            HcaError::RlpEncodingError(msg) => {
                write!(f, "RLP encoding error: {}", msg)
            }
            HcaError::RlpDecodeError(msg) => {
                write!(f, "RLP decode error: {}", msg)
            }
            HcaError::InvalidAddress => {
                write!(f, "Invalid address format")
            }
            HcaError::EmptyLeafScript => {
                write!(f, "Leaf script must not be empty")
            }
            HcaError::DuplicateLeaf { index } => {
                write!(f, "Duplicate leaf detected at index {}", index)
            }
            HcaError::EmptySignature => {
                write!(f, "Witness signature must not be empty")
            }
            HcaError::GasExhausted { limit, consumed } => {
                write!(
                    f,
                    "Leaf script gas exhausted: consumed {} of {} limit",
                    consumed, limit
                )
            }
        }
    }
}

impl std::error::Error for HcaError {}

/// Result type for HCA operations
pub type HcaResult<T> = Result<T, HcaError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = HcaError::EmptyTree;
        assert!(err.to_string().contains("at least one leaf"));

        let err = HcaError::TreeTooDeep { depth: 33 };
        assert!(err.to_string().contains("33"));

        let err = HcaError::LeafIndexOutOfBounds { index: 5, count: 3 };
        assert!(err.to_string().contains("5"));
        assert!(err.to_string().contains("3"));
    }

    #[test]
    fn test_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(HcaError::EmptyTree);
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn test_all_error_variants_have_display() {
        let variants: Vec<HcaError> = vec![
            HcaError::EmptyTree,
            HcaError::TreeTooDeep { depth: 33 },
            HcaError::LeafIndexOutOfBounds { index: 1, count: 0 },
            HcaError::InvalidLeafVersion { version: 0x00 },
            HcaError::LeafScriptTooLarge { size: 99999 },
            HcaError::ProofVerificationFailed,
            HcaError::WitnessNotSigned,
            HcaError::WitnessTooLarge { size: 99999 },
            HcaError::InvalidRotation("test".to_string()),
            HcaError::BannedOpcode {
                opcode: 0xFF,
                name: "SELFDESTRUCT".to_string(),
            },
            HcaError::RlpEncodingError("test".to_string()),
            HcaError::RlpDecodeError("test".to_string()),
            HcaError::InvalidAddress,
            HcaError::EmptyLeafScript,
            HcaError::DuplicateLeaf { index: 2 },
            HcaError::EmptySignature,
            HcaError::GasExhausted {
                limit: 100_000,
                consumed: 100_001,
            },
        ];
        for err in variants {
            assert!(!err.to_string().is_empty(), "Display missing for {:?}", err);
        }
    }
}
