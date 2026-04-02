#![no_main]

use libfuzzer_sys::fuzz_target;
use hca_rs::rlp::{encode_address, encode_bytes, encode_list, encode_uint};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Use first byte to determine which RLP encoding to test
    let test_type = data[0] % 4;
    let remaining = &data[1..];

    match test_type {
        0 => {
            // Test encode_uint with various values
            if remaining.len() >= 16 {
                let value = u128::from_le_bytes([
                    remaining[0],
                    remaining[1],
                    remaining[2],
                    remaining[3],
                    remaining[4],
                    remaining[5],
                    remaining[6],
                    remaining[7],
                    remaining[8],
                    remaining[9],
                    remaining[10],
                    remaining[11],
                    remaining[12],
                    remaining[13],
                    remaining[14],
                    remaining[15],
                ]);
                let _ = encode_uint(value);
            }
        }
        1 => {
            // Test encode_bytes with arbitrary data
            let _ = encode_bytes(remaining);
        }
        2 => {
            // Test encode_address
            if remaining.len() >= 20 {
                let mut addr = [0u8; 20];
                addr.copy_from_slice(&remaining[0..20]);
                let _ = encode_address(&addr);
            }
        }
        3 => {
            // Test encode_list with multiple items
            let chunk_size = if remaining.len() > 10 {
                remaining.len() / 5
            } else {
                1
            };

            let mut items = Vec::new();
            let mut offset = 0;

            while offset + chunk_size <= remaining.len() && items.len() < 10 {
                items.push(remaining[offset..offset + chunk_size].to_vec());
                offset += chunk_size;
            }

            if !items.is_empty() {
                let _ = encode_list(&items);
            }
        }
        _ => unreachable!(),
    }
});
