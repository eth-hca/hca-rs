//! Integration tests for the `hca` CLI binary.
//!
//! These tests run the compiled binary as a subprocess and verify JSON output.

use std::process::Command;

fn hca(args: &[&str]) -> (String, String, bool) {
    let bin = env!("CARGO_BIN_EXE_hca");
    let out = Command::new(bin)
        .args(args)
        .output()
        .expect("failed to run hca binary");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

const LEAVES: &str = r#"[{"version":"0x01","script":"0x6001","description":"Key A"},{"version":"0x01","script":"0x6002","description":"Key B"}]"#;

#[test]
fn test_cli_create_account() {
    let (stdout, _, ok) = hca(&["create-account", "--leaves", LEAVES]);
    assert!(ok);
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["address"].as_str().unwrap().starts_with("0x"));
    assert_eq!(v["address"].as_str().unwrap().len(), 42);
    assert!(v["auth_root"].as_str().unwrap().starts_with("0x"));
    assert_eq!(v["leaf_count"].as_u64().unwrap(), 2);
    assert_eq!(v["depth"].as_u64().unwrap(), 1);
}

#[test]
fn test_cli_derive_address_roundtrip() {
    // create-account to get auth_root, then derive-address should match
    let (stdout, _, ok) = hca(&["create-account", "--leaves", LEAVES]);
    assert!(ok);
    let created: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let auth_root = created["auth_root"].as_str().unwrap();
    let expected_addr = created["address"].as_str().unwrap();

    let (stdout2, _, ok2) = hca(&["derive-address", "--auth-root", auth_root]);
    assert!(ok2);
    let derived: serde_json::Value = serde_json::from_str(&stdout2).unwrap();
    assert_eq!(derived["address"].as_str().unwrap(), expected_addr);
}

#[test]
fn test_cli_generate_and_verify_proof() {
    // Generate proof for leaf 0
    let (stdout, _, ok) = hca(&["generate-proof", "--leaves", LEAVES, "--index", "0"]);
    assert!(ok);
    let proof_out: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let leaf_hash = proof_out["leaf_hash"].as_str().unwrap();
    let auth_root = proof_out["auth_root"].as_str().unwrap();
    let proof_json = serde_json::json!({
        "leaf_index": proof_out["leaf_index"],
        "siblings": proof_out["siblings"]
    })
    .to_string();

    // Verify it
    let (stdout2, _, ok2) = hca(&[
        "verify-proof",
        "--leaf-hash",
        leaf_hash,
        "--proof",
        &proof_json,
        "--auth-root",
        auth_root,
    ]);
    assert!(ok2);
    let result: serde_json::Value = serde_json::from_str(&stdout2).unwrap();
    assert!(result["valid"].as_bool().unwrap());
}

#[test]
fn test_cli_verify_wrong_leaf_fails() {
    let (stdout, _, ok) = hca(&["generate-proof", "--leaves", LEAVES, "--index", "0"]);
    assert!(ok);
    let proof_out: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    let auth_root = proof_out["auth_root"].as_str().unwrap();
    let proof_json = serde_json::json!({
        "leaf_index": proof_out["leaf_index"],
        "siblings": proof_out["siblings"]
    })
    .to_string();

    // Use wrong leaf hash
    let wrong_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let (stdout2, _, ok2) = hca(&[
        "verify-proof",
        "--leaf-hash",
        wrong_hash,
        "--proof",
        &proof_json,
        "--auth-root",
        auth_root,
    ]);
    assert!(ok2);
    let result: serde_json::Value = serde_json::from_str(&stdout2).unwrap();
    assert!(!result["valid"].as_bool().unwrap());
}

#[test]
fn test_cli_signing_hash_deterministic() {
    let tx = r#"{"chain_id":1,"nonce":0,"from":"0x0000000000000000000000000000000000000001","to":"0x0000000000000000000000000000000000000002","value":"0","gas_limit":21000,"max_fee_per_gas":"1000000000","max_priority_fee_per_gas":"100000000"}"#;
    let leaf_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";

    let (out1, _, ok1) = hca(&["signing-hash", "--tx", tx, "--leaf-hash", leaf_hash]);
    let (out2, _, ok2) = hca(&["signing-hash", "--tx", tx, "--leaf-hash", leaf_hash]);
    assert!(ok1 && ok2);

    let h1: serde_json::Value = serde_json::from_str(&out1).unwrap();
    let h2: serde_json::Value = serde_json::from_str(&out2).unwrap();
    assert_eq!(h1["signing_hash"], h2["signing_hash"]);
}

#[test]
fn test_cli_unknown_command_exits_nonzero() {
    let (_, stderr, ok) = hca(&["foobar"]);
    assert!(!ok);
    // clap prints "unrecognized subcommand" or similar
    assert!(!stderr.is_empty());
}

#[test]
fn test_cli_missing_flag_exits_nonzero() {
    // clap catches missing required args before our code runs
    let (_, stderr, ok) = hca(&["derive-address"]);
    assert!(!ok);
    assert!(stderr.contains("--auth-root"));
}

#[test]
fn test_cli_help() {
    // clap writes --help to stdout with exit 0
    let (stdout, _, ok) = hca(&["--help"]);
    assert!(ok);
    assert!(stdout.contains("create-account"));
    assert!(stdout.contains("derive-address"));
    assert!(stdout.contains("generate-proof"));
    assert!(stdout.contains("verify-proof"));
    assert!(stdout.contains("encode-tx"));
    assert!(stdout.contains("signing-hash"));
}

#[test]
fn test_cli_subcommand_help() {
    // Each subcommand should also have --help
    let (stdout, _, ok) = hca(&["create-account", "--help"]);
    assert!(ok);
    assert!(stdout.contains("--leaves"));
}

#[test]
fn test_cli_version() {
    let (stdout, _, ok) = hca(&["--version"]);
    assert!(ok);
    assert!(stdout.contains("hca"));
}
