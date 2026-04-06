#![no_main]

use hca_rs::rlp::{decode_bytes, decode_hca_tx, decode_list, decode_uint};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to select which decoder to fuzz
    let test_type = data[0] % 4;
    let input = &data[1..];

    match test_type {
        0 => {
            // Fuzz decode_bytes: malformed inputs, truncated data, oversized lengths
            let _ = decode_bytes(input);
        }
        1 => {
            // Fuzz decode_uint: should never return a value wider than u128
            let _ = decode_uint(input);
        }
        2 => {
            // Fuzz decode_list: random list prefixes, truncated payloads
            let _ = decode_list(input);
        }
        3 => {
            // Fuzz decode_hca_tx: full transaction decoding with arbitrary bytes
            // Must never panic — only return Ok or Err
            let _ = decode_hca_tx(input);
        }
        _ => unreachable!(),
    }
});
