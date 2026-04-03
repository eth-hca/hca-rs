//! EVM opcode validator for HCA leaf scripts.
//!
//! Leaf scripts execute in a restricted EVM context per EIP-8215.
//! This module parses raw EVM bytecode and rejects scripts containing
//! banned opcodes before they are committed to a Merkle tree.
//!
//! ## Banned opcodes (EIP-8215 §Leaf execution context)
//!
//! | Opcode       | Byte | Reason                                  |
//! |--------------|------|-----------------------------------------|
//! | CREATE       | 0xF0 | No contract deployment during verification |
//! | CREATE2      | 0xF5 | No contract deployment during verification |
//! | SSTORE       | 0x55 | No state mutation                       |
//! | SELFDESTRUCT | 0xFF | No account destruction                  |
//! | DELEGATECALL | 0xF4 | No arbitrary code execution             |
//! | LOG0         | 0xA0 | No event emission                       |
//! | LOG1         | 0xA1 | No event emission                       |
//! | LOG2         | 0xA2 | No event emission                       |
//! | LOG3         | 0xA3 | No event emission                       |
//! | LOG4         | 0xA4 | No event emission                       |
//!
//! ## PUSH data skipping
//!
//! PUSH1–PUSH32 (0x60–0x7F) embed immediate data bytes that must be
//! skipped during scanning to avoid false positives where a banned
//! opcode byte appears as push data, not an instruction.

use crate::error::{HcaError, HcaResult};

/// Banned EVM opcodes per EIP-8215 leaf execution context restrictions.
const BANNED: &[(u8, &str)] = &[
    (0xF0, "CREATE"),
    (0xF5, "CREATE2"),
    (0x55, "SSTORE"),
    (0xFF, "SELFDESTRUCT"),
    (0xF4, "DELEGATECALL"),
    (0xA0, "LOG0"),
    (0xA1, "LOG1"),
    (0xA2, "LOG2"),
    (0xA3, "LOG3"),
    (0xA4, "LOG4"),
];

/// Validate that a leaf script contains no banned EVM opcodes.
///
/// Iterates the bytecode, skipping PUSH immediate data, and checks
/// each opcode against the banned list.
///
/// Returns `Ok(())` if the script is clean.
/// Returns `Err(HcaError::BannedOpcode)` on the first banned opcode found.
///
/// # Examples
///
/// ```
/// use hca_rs::evm::opcode::validate_leaf_script;
///
/// // Clean script: PUSH1 0x01, STOP
/// assert!(validate_leaf_script(&[0x60, 0x01, 0x00]).is_ok());
///
/// // Banned: SSTORE
/// assert!(validate_leaf_script(&[0x55]).is_err());
/// ```
pub fn validate_leaf_script(bytecode: &[u8]) -> HcaResult<()> {
    let mut i = 0;
    while i < bytecode.len() {
        let op = bytecode[i];

        // PUSH1 (0x60) through PUSH32 (0x7F): skip N immediate data bytes
        if (0x60..=0x7F).contains(&op) {
            let push_size = (op - 0x5F) as usize; // PUSH1=1, PUSH2=2, ..., PUSH32=32
            i += 1 + push_size;
            continue;
        }

        if let Some(&(_, name)) = BANNED.iter().find(|&&(byte, _)| byte == op) {
            return Err(HcaError::BannedOpcode {
                opcode: op,
                name: name.to_string(),
            });
        }

        i += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_script_is_valid() {
        assert!(validate_leaf_script(&[]).is_ok());
    }

    #[test]
    fn test_clean_script_is_valid() {
        // PUSH1 0x01, PUSH1 0x02, ADD, STOP
        let script = &[0x60, 0x01, 0x60, 0x02, 0x01, 0x00];
        assert!(validate_leaf_script(script).is_ok());
    }

    #[test]
    fn test_all_banned_opcodes_detected() {
        let banned_bytes = [0xF0, 0xF5, 0x55, 0xFF, 0xF4, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4];
        for &op in &banned_bytes {
            let result = validate_leaf_script(&[op]);
            assert!(result.is_err(), "Opcode 0x{:02X} should be banned", op);
            assert!(matches!(
                result.unwrap_err(),
                HcaError::BannedOpcode { opcode: o, .. } if o == op
            ));
        }
    }

    #[test]
    fn test_banned_opcode_in_push_data_not_flagged() {
        // PUSH1 0xF0 — 0xF0 is CREATE but here it's push data, not an opcode
        let script = &[0x60, 0xF0, 0x00]; // PUSH1 <CREATE_byte>, STOP
        assert!(
            validate_leaf_script(script).is_ok(),
            "Banned byte in PUSH data must not be flagged"
        );
    }

    #[test]
    fn test_push32_data_skipped_correctly() {
        // PUSH32 followed by 32 bytes of 0xFF (SELFDESTRUCT), then STOP
        let mut script = vec![0x7F]; // PUSH32
        script.extend_from_slice(&[0xFF; 32]);
        script.push(0x00); // STOP
        assert!(
            validate_leaf_script(&script).is_ok(),
            "PUSH32 data bytes must be skipped"
        );
    }

    #[test]
    fn test_banned_opcode_after_push_data() {
        // PUSH1 0x01, then SSTORE — SSTORE is an actual opcode
        let script = &[0x60, 0x01, 0x55];
        assert!(matches!(
            validate_leaf_script(script).unwrap_err(),
            HcaError::BannedOpcode { opcode: 0x55, .. }
        ));
    }

    #[test]
    fn test_log0_through_log4_banned() {
        for opcode in 0xA0u8..=0xA4 {
            assert!(
                validate_leaf_script(&[opcode]).is_err(),
                "LOG opcode 0x{:02X} should be banned",
                opcode
            );
        }
    }
}
