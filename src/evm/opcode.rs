//! EVM opcode validator for HCA leaf scripts.
//!
//! Leaf scripts execute in a restricted EVM context per EIP-8215.
//! This module parses raw EVM bytecode, rejects banned opcodes, and
//! enforces the `MAX_LEAF_GAS` cap via a per-opcode gas counter.
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
//! | CALL         | 0xF1 | No external calls                       |
//! | CALLCODE     | 0xF2 | No external calls                       |
//! | STATICCALL   | 0xFA | No external calls                       |
//! | SLOAD        | 0x54 | No state reads                          |
//! | LOG0         | 0xA0 | No event emission                       |
//! | LOG1–LOG4    |0xA1–0xA4| No event emission                   |
//!
//! ## PUSH data skipping
//!
//! PUSH1–PUSH32 (0x60–0x7F) embed immediate data bytes that must be
//! skipped during scanning to avoid false positives.

use crate::constants::MAX_LEAF_GAS;
use crate::error::{HcaError, HcaResult};
use crate::evm::gas::GasCounter;

/// Banned EVM opcodes per EIP-8215 leaf execution context restrictions.
const BANNED: &[(u8, &str)] = &[
    (0xF0, "CREATE"),
    (0xF5, "CREATE2"),
    (0x55, "SSTORE"),
    (0xFF, "SELFDESTRUCT"),
    (0xF4, "DELEGATECALL"),
    (0xF1, "CALL"),
    (0xF2, "CALLCODE"),
    (0xFA, "STATICCALL"),
    (0x54, "SLOAD"),
    (0xA0, "LOG0"),
    (0xA1, "LOG1"),
    (0xA2, "LOG2"),
    (0xA3, "LOG3"),
    (0xA4, "LOG4"),
];

/// Return the base static gas cost for an opcode (EVM Berlin schedule).
fn opcode_gas_cost(op: u8) -> u64 {
    match op {
        // Zero-cost terminals
        0x00 | 0xF3 | 0xFD => 0,
        // Cheap arithmetic / comparison / bitwise (3 gas)
        0x01..=0x0B | 0x10..=0x1D => 3,
        // SHA3 — base cost (30 gas; data cost is dynamic and not counted here)
        0x20 => 30,
        // Stack / memory (2–3 gas)
        0x50 => 2,        // POP
        0x51..=0x53 => 3, // MLOAD, MSTORE, MSTORE8
        0x56 => 8,        // JUMP
        0x57 => 10,       // JUMPI
        0x58..=0x5A => 2, // PC, MSIZE, GAS
        0x5B => 1,        // JUMPDEST
        0x5F => 2,        // PUSH0
        0x60..=0x7F => 3, // PUSH1–PUSH32
        0x80..=0x8F => 3, // DUP1–DUP16
        0x90..=0x9F => 3, // SWAP1–SWAP16
        _ => 3,           // unknown — charge baseline
    }
}

/// Validate a leaf script: check banned opcodes and enforce the gas cap.
///
/// Walks every opcode in `bytecode`, skipping PUSH immediate data, and
/// charges gas per opcode against `MAX_LEAF_GAS`.
///
/// Returns:
/// - `Ok(gas_used)` — script is valid; `gas_used` is the static gas consumed
/// - `Err(HcaError::BannedOpcode)` — script contains a prohibited opcode
/// - `Err(HcaError::GasExhausted)` — script exceeds `MAX_LEAF_GAS`
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
pub fn validate_leaf_script(bytecode: &[u8]) -> HcaResult<u64> {
    let mut counter = GasCounter::new(MAX_LEAF_GAS);
    let mut i = 0;

    while i < bytecode.len() {
        let op = bytecode[i];

        if let Some(&(_, name)) = BANNED.iter().find(|&&(byte, _)| byte == op) {
            return Err(HcaError::BannedOpcode {
                opcode: op,
                name: name.to_string(),
            });
        }

        counter.charge(opcode_gas_cost(op))?;

        // PUSH1 (0x60) through PUSH32 (0x7F): skip N immediate data bytes
        if (0x60..=0x7F).contains(&op) {
            let push_size = (op - 0x5F) as usize; // PUSH1=1, PUSH2=2, ..., PUSH32=32
            i += push_size;
        }

        i += 1;
    }

    Ok(counter.consumed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_LEAF_GAS;

    #[test]
    fn test_empty_script_is_valid() {
        assert_eq!(validate_leaf_script(&[]).unwrap(), 0);
    }

    #[test]
    fn test_clean_script_is_valid() {
        // PUSH1 0x01, PUSH1 0x02, ADD, STOP
        let script = &[0x60, 0x01, 0x60, 0x02, 0x01, 0x00];
        assert!(validate_leaf_script(script).is_ok());
    }

    #[test]
    fn test_all_banned_opcodes_detected() {
        for &(op, _) in BANNED {
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

    #[test]
    fn test_gas_exhaustion_detected() {
        // SHA3 (0x20) = 30 gas; repeat until over MAX_LEAF_GAS
        let count = (MAX_LEAF_GAS / 30 + 100) as usize;
        let script: Vec<u8> = vec![0x20; count];
        let err = validate_leaf_script(&script).unwrap_err();
        assert!(matches!(err, HcaError::GasExhausted { .. }));
    }

    #[test]
    fn test_gas_consumed_returned() {
        // ADD (3) + MUL (3) + STOP (0) = 6
        let script = &[0x01, 0x02, 0x00];
        assert_eq!(validate_leaf_script(script).unwrap(), 6);
    }

    #[test]
    fn test_jumpdest_costs_one_gas() {
        assert_eq!(validate_leaf_script(&[0x5B]).unwrap(), 1);
    }
}
