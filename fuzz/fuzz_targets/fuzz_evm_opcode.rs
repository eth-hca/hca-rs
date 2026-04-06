#![no_main]

use hca_rs::evm::opcode::validate_leaf_script;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Feed arbitrary bytecode — including PUSH data, truncated PUSH at EOF,
    // banned opcodes, and random sequences — into the validator.
    // Must never panic — only return Ok or Err.
    let _ = validate_leaf_script(data);
});
