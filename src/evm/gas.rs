//! Gas counter for HCA leaf script execution.
//!
//! Tracks gas consumed during script validation and enforces the
//! `MAX_LEAF_GAS` cap defined in EIP-8215.

use crate::error::{HcaError, HcaResult};

/// Tracks gas consumed during leaf script execution.
///
/// Every opcode charges gas before executing.  When gas is exhausted
/// `charge()` returns `Err(HcaError::GasExhausted)`.
#[derive(Debug, Clone)]
pub struct GasCounter {
    /// Gas remaining (starts at the limit, decrements on each charge)
    remaining: u64,
    /// Total gas limit this counter was created with
    limit: u64,
}

impl GasCounter {
    /// Create a new counter with the given gas limit.
    pub fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            limit,
        }
    }

    /// Deduct `cost` gas units.
    ///
    /// Returns `Err(HcaError::GasExhausted)` if the remaining gas would go
    /// below zero, leaving the counter unchanged.
    pub fn charge(&mut self, cost: u64) -> HcaResult<()> {
        if cost > self.remaining {
            return Err(HcaError::GasExhausted {
                limit: self.limit,
                consumed: self.limit - self.remaining,
            });
        }
        self.remaining -= cost;
        Ok(())
    }

    /// Gas units consumed so far.
    pub fn consumed(&self) -> u64 {
        self.limit - self.remaining
    }

    /// Gas units remaining.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_counter_full() {
        let c = GasCounter::new(1000);
        assert_eq!(c.remaining(), 1000);
        assert_eq!(c.consumed(), 0);
    }

    #[test]
    fn test_charge_deducts_gas() {
        let mut c = GasCounter::new(1000);
        c.charge(300).unwrap();
        assert_eq!(c.remaining(), 700);
        assert_eq!(c.consumed(), 300);
    }

    #[test]
    fn test_exact_exhaustion_succeeds() {
        let mut c = GasCounter::new(100);
        c.charge(100).unwrap();
        assert_eq!(c.remaining(), 0);
        assert_eq!(c.consumed(), 100);
    }

    #[test]
    fn test_over_limit_returns_error() {
        let mut c = GasCounter::new(100);
        c.charge(50).unwrap();
        let result = c.charge(60);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HcaError::GasExhausted {
                limit: 100,
                consumed: 50
            }
        ));
        // Counter must be unchanged after failed charge
        assert_eq!(c.remaining(), 50);
    }

    #[test]
    fn test_zero_cost_charge() {
        let mut c = GasCounter::new(100);
        c.charge(0).unwrap();
        assert_eq!(c.remaining(), 100);
    }

    #[test]
    fn test_multiple_charges() {
        let mut c = GasCounter::new(1000);
        for _ in 0..10 {
            c.charge(50).unwrap();
        }
        assert_eq!(c.consumed(), 500);
        assert_eq!(c.remaining(), 500);
    }
}
