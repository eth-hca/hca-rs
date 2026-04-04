//! EVM execution context primitives for HCA leaf script validation.
//!
//! Leaf scripts execute in a restricted EVM context per EIP-8215
//! §Leaf execution context:
//!
//! - **[`opcode`]** — static analysis pass: walks bytecode, rejects banned
//!   opcodes (CREATE, SSTORE, SELFDESTRUCT, DELEGATECALL, LOG\*, CALL, SLOAD …),
//!   and returns the static gas consumed.
//! - **[`gas`]** — [`gas::GasCounter`] tracks gas per opcode and enforces
//!   the [`crate::constants::MAX_LEAF_GAS`] cap (100 000 gas).

pub mod gas;
pub mod opcode;
