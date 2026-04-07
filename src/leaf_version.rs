//! Leaf version registry and validation dispatch (EIP-8215 §Leaf versions).
//!
//! Each leaf version byte maps to a distinct spending condition scheme.
//! The registry validates the script for the declared version and rejects
//! unknown or reserved versions at leaf-construction time.
//!
//! ## Version table
//!
//! | Version | Scheme                              | Status      |
//! |---------|-------------------------------------|-------------|
//! | `0x00`  | Reserved — MUST reject              | Invalid     |
//! | `0x01`  | HCA v1 — EVM bytecode script        | Active      |
//! | `0x02`  | EIP-7932 algorithm registry dispatch| Reserved    |
//! | `0x03`–`0x0F` | Reserved for future PQ schemes | Reserved   |

#[cfg(not(feature = "std"))]
use alloc::string::ToString;

use crate::error::{HcaError, HcaResult};
use crate::evm::opcode::validate_leaf_script;

/// Known leaf version bytes defined by EIP-8215.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LeafVersion {
    /// HCA v1 — EVM bytecode spending condition (active)
    V1 = 0x01,
    /// EIP-7932 algorithm registry dispatch (reserved, not yet active)
    V2 = 0x02,
}

impl LeafVersion {
    /// Parse a raw version byte into a `LeafVersion`.
    ///
    /// Returns `Err(InvalidLeafVersion)` for `0x00` or any unrecognised byte.
    pub fn from_byte(version: u8) -> HcaResult<Self> {
        match version {
            0x00 => Err(HcaError::InvalidLeafVersion { version }),
            0x01 => Ok(LeafVersion::V1),
            0x02 => Ok(LeafVersion::V2),
            _ => Err(HcaError::InvalidLeafVersion { version }),
        }
    }

    /// Return the raw version byte.
    pub fn as_byte(self) -> u8 {
        self as u8
    }

    /// Return true if this version is active (scripts can be executed).
    ///
    /// `V2` is reserved — nodes must reject leaves with this version
    /// until EIP-7932 is activated.
    pub fn is_active(self) -> bool {
        matches!(self, LeafVersion::V1)
    }
}

/// Validate a leaf script for the declared version.
///
/// Dispatch table:
/// - `V1` — runs EVM opcode + gas validation via [`validate_leaf_script`]
/// - `V2` — reserved; always returns `Err(InvalidLeafVersion)`
///
/// Call this from `Leaf::new()` to enforce version-specific constraints
/// before the leaf enters a tree.
pub fn validate_for_version(version: LeafVersion, script: &[u8]) -> HcaResult<()> {
    match version {
        LeafVersion::V1 => validate_leaf_script(script).map(|_| ()),
        LeafVersion::V2 => Err(HcaError::InvalidLeafVersion {
            version: version.as_byte(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_zero_rejected() {
        assert!(LeafVersion::from_byte(0x00).is_err());
    }

    #[test]
    fn test_version_v1_parsed() {
        assert_eq!(LeafVersion::from_byte(0x01).unwrap(), LeafVersion::V1);
    }

    #[test]
    fn test_version_v2_parsed() {
        assert_eq!(LeafVersion::from_byte(0x02).unwrap(), LeafVersion::V2);
    }

    #[test]
    fn test_unknown_version_rejected() {
        for v in [0x03u8, 0x0F, 0x10, 0xFF] {
            assert!(
                LeafVersion::from_byte(v).is_err(),
                "version 0x{:02x} should be rejected",
                v
            );
        }
    }

    #[test]
    fn test_v1_is_active() {
        assert!(LeafVersion::V1.is_active());
    }

    #[test]
    fn test_v2_is_not_active() {
        assert!(!LeafVersion::V2.is_active());
    }

    #[test]
    fn test_as_byte_roundtrip() {
        assert_eq!(LeafVersion::V1.as_byte(), 0x01);
        assert_eq!(LeafVersion::V2.as_byte(), 0x02);
    }

    #[test]
    fn test_validate_v1_valid_script() {
        // PUSH1 0x01 — valid EVM
        assert!(validate_for_version(LeafVersion::V1, &[0x60, 0x01]).is_ok());
    }

    #[test]
    fn test_validate_v1_banned_opcode() {
        // SSTORE (0x55) — banned in leaf context
        assert!(validate_for_version(LeafVersion::V1, &[0x55]).is_err());
    }

    #[test]
    fn test_validate_v2_always_rejected() {
        assert!(validate_for_version(LeafVersion::V2, &[0x60, 0x01]).is_err());
        assert!(validate_for_version(LeafVersion::V2, &[]).is_err());
    }
}
