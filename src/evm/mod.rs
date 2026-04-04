//! EVM execution context primitives for HCA leaf script validation.
//!
//! This module grows alongside the EVM-related PRs:
//!   - PR-03: opcode validator (banned opcode static analysis)
//!   - PR-08: gas metering framework
//!
//! All submodules enforce the restrictions defined in EIP-8215
//! §Leaf execution context.

pub mod gas;
pub mod opcode;
