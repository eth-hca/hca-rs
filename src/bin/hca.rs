//! hca — Hash-Committed Account command-line tool (EIP-8215)
//!
//! All commands write JSON to stdout.
//! Errors are written to stderr with a non-zero exit code.

use clap::{Parser, Subcommand};
use hca_rs::address::derive_address;
use hca_rs::merkle::{Leaf, MerkleTree};
use hca_rs::rlp::encode_hca_tx;
use hca_rs::witness::{HCAWitness, TxMessage};
use hca_rs::MerkleProof;
use serde_json::{json, Value};
use std::process;

// ── CLI definition ────────────────────────────────────────────────────────────

/// hca — Hash-Committed Account CLI (EIP-8215)
///
/// Cryptographic primitives for quantum-safe Ethereum accounts.
/// All commands output JSON to stdout; errors go to stderr.
#[derive(Parser)]
#[command(
    name = "hca",
    version,
    about = "Hash-Committed Account CLI (EIP-8215)",
    long_about = "Cryptographic primitives for quantum-safe Ethereum accounts.\n\
                  All commands output JSON to stdout; errors go to stderr.\n\n\
                  Repository: https://github.com/eth-hca/hca-rs"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a Merkle tree of spending conditions and derive the HCA address
    ///
    /// Outputs: address, auth_root, depth, leaf_count, leaf_hashes
    CreateAccount {
        /// JSON array of leaf objects: [{"version":"0x01","script":"0x...","description":"..."}]
        #[arg(long, value_name = "JSON")]
        leaves: String,
    },

    /// Derive an HCA address from an auth_root
    ///
    /// Outputs: address
    DeriveAddress {
        /// 32-byte auth_root as 0x-prefixed hex
        #[arg(long, value_name = "HEX")]
        auth_root: String,
    },

    /// Generate a Merkle inclusion proof for a leaf
    ///
    /// Outputs: leaf_index, leaf_hash, auth_root, siblings
    GenerateProof {
        /// JSON array of leaf objects
        #[arg(long, value_name = "JSON")]
        leaves: String,

        /// Leaf index (0-based)
        #[arg(long, value_name = "N")]
        index: usize,
    },

    /// Verify a Merkle inclusion proof against an auth_root
    ///
    /// Outputs: valid (bool)
    VerifyProof {
        /// 32-byte leaf hash as 0x-prefixed hex
        #[arg(long, value_name = "HEX")]
        leaf_hash: String,

        /// Proof JSON: {"leaf_index": N, "siblings": ["0x...", ...]}
        #[arg(long, value_name = "JSON")]
        proof: String,

        /// 32-byte auth_root as 0x-prefixed hex
        #[arg(long, value_name = "HEX")]
        auth_root: String,
    },

    /// RLP-encode a signed HCA transaction (EIP-2718 type 0x05)
    ///
    /// Outputs: encoded (0x-prefixed hex)
    EncodeTx {
        /// Transaction JSON: {chain_id, nonce, from, to, value, gas_limit, max_fee_per_gas, ...}
        #[arg(long, value_name = "JSON")]
        tx: String,

        /// Witness JSON: {leaf_version, leaf_script, leaf_index, siblings, witness_data}
        #[arg(long, value_name = "JSON")]
        witness: String,
    },

    /// Compute the signing hash for a transaction
    ///
    /// Outputs: signing_hash
    SigningHash {
        /// Transaction JSON
        #[arg(long, value_name = "JSON")]
        tx: String,

        /// 32-byte leaf hash as 0x-prefixed hex
        #[arg(long, value_name = "HEX")]
        leaf_hash: String,
    },
}

// ── entry point ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::CreateAccount { leaves } => cmd_create_account(&leaves),
        Commands::DeriveAddress { auth_root } => cmd_derive_address(&auth_root),
        Commands::GenerateProof { leaves, index } => cmd_generate_proof(&leaves, index),
        Commands::VerifyProof {
            leaf_hash,
            proof,
            auth_root,
        } => cmd_verify_proof(&leaf_hash, &proof, &auth_root),
        Commands::EncodeTx { tx, witness } => cmd_encode_tx(&tx, &witness),
        Commands::SigningHash { tx, leaf_hash } => cmd_signing_hash(&tx, &leaf_hash),
    };

    match result {
        Ok(output) => println!("{}", output),
        Err(e) => {
            eprintln!("error: {}", e);
            process::exit(1);
        }
    }
}

// ── commands ──────────────────────────────────────────────────────────────────

fn cmd_create_account(leaves_json: &str) -> Result<String, String> {
    let leaves = parse_leaves(leaves_json)?;
    let tree = MerkleTree::new(leaves).map_err(|e| e.to_string())?;

    let auth_root = tree.auth_root();
    let address = derive_address(&auth_root);

    let out = json!({
        "address":    hex20(&address),
        "auth_root":  hex32(&auth_root),
        "depth":      tree.depth,
        "leaf_count": tree.leaves.len(),
        "leaf_hashes": tree.leaves.iter().map(|l| hex32(&l.hash())).collect::<Vec<_>>()
    });

    Ok(pretty(&out))
}

fn cmd_derive_address(root_hex: &str) -> Result<String, String> {
    let auth_root = decode32(root_hex)?;
    let address = derive_address(&auth_root);
    Ok(pretty(&json!({ "address": hex20(&address) })))
}

fn cmd_generate_proof(leaves_json: &str, index: usize) -> Result<String, String> {
    let leaves = parse_leaves(leaves_json)?;
    let tree = MerkleTree::new(leaves).map_err(|e| e.to_string())?;
    let proof = tree.proof(index).map_err(|e| e.to_string())?;
    let leaf_hash = tree.leaves[index].hash();

    let out = json!({
        "leaf_index": proof.leaf_index,
        "leaf_hash":  hex32(&leaf_hash),
        "auth_root":  hex32(&tree.auth_root()),
        "siblings":   proof.siblings.iter().map(hex32).collect::<Vec<_>>()
    });

    Ok(pretty(&out))
}

fn cmd_verify_proof(
    leaf_hash_hex: &str,
    proof_json: &str,
    auth_root_hex: &str,
) -> Result<String, String> {
    let leaf_hash = decode32(leaf_hash_hex)?;
    let auth_root = decode32(auth_root_hex)?;
    let proof = parse_proof(proof_json)?;

    let valid = MerkleTree::verify(&leaf_hash, &proof, &auth_root).map_err(|e| e.to_string())?;

    Ok(pretty(&json!({ "valid": valid })))
}

fn cmd_encode_tx(tx_json: &str, witness_json: &str) -> Result<String, String> {
    let tx_val: Value =
        serde_json::from_str(tx_json).map_err(|e| format!("invalid tx JSON: {}", e))?;
    let wit_val: Value =
        serde_json::from_str(witness_json).map_err(|e| format!("invalid witness JSON: {}", e))?;

    let tx = parse_tx_message(&tx_val)?;
    let mut witness = parse_witness(&wit_val)?;

    let sig_hex = wit_val["witness_data"].as_str().unwrap_or("0x").to_string();
    let sig = decode_hex(&sig_hex)?;
    if !sig.is_empty() {
        witness.attach_signature(sig).map_err(|e| e.to_string())?;
    }

    if !witness.is_signed() {
        return Err("witness_data is empty — cannot encode unsigned witness".to_string());
    }

    let encoded = encode_hca_tx(&tx, &witness).map_err(|e| e.to_string())?;
    Ok(pretty(
        &json!({ "encoded": format!("0x{}", hex::encode(&encoded)) }),
    ))
}

fn cmd_signing_hash(tx_json: &str, leaf_hash_hex: &str) -> Result<String, String> {
    let tx_val: Value =
        serde_json::from_str(tx_json).map_err(|e| format!("invalid tx JSON: {}", e))?;
    let tx = parse_tx_message(&tx_val)?;
    let leaf_hash = decode32(leaf_hash_hex)?;

    let hash = tx.signing_hash(&leaf_hash);
    Ok(pretty(&json!({ "signing_hash": hex32(&hash) })))
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| format!("invalid hex '{}': {}", s, e))
}

fn decode32(s: &str) -> Result<[u8; 32], String> {
    let v = decode_hex(s)?;
    if v.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", v.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&v);
    Ok(arr)
}

fn hex32(b: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(b))
}

fn hex20(b: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(b))
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap()
}

fn parse_leaves(json_str: &str) -> Result<Vec<Leaf>, String> {
    let arr: Vec<Value> =
        serde_json::from_str(json_str).map_err(|e| format!("invalid leaves JSON: {}", e))?;

    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            let version_str = v["version"]
                .as_str()
                .ok_or_else(|| format!("leaf[{}]: missing 'version'", i))?;
            let version_bytes = decode_hex(version_str)?;
            if version_bytes.len() != 1 {
                return Err(format!("leaf[{}]: version must be 1 byte", i));
            }
            let version = version_bytes[0];

            let script_hex = v["script"]
                .as_str()
                .ok_or_else(|| format!("leaf[{}]: missing 'script'", i))?;
            let script = decode_hex(script_hex)?;

            let description = v["description"].as_str().unwrap_or("");

            Leaf::new(version, script, description).map_err(|e| e.to_string())
        })
        .collect()
}

fn parse_proof(json_str: &str) -> Result<MerkleProof, String> {
    let v: Value =
        serde_json::from_str(json_str).map_err(|e| format!("invalid proof JSON: {}", e))?;

    let leaf_index = v["leaf_index"]
        .as_u64()
        .ok_or("proof: missing 'leaf_index'")? as usize;

    let siblings = v["siblings"]
        .as_array()
        .ok_or("proof: missing 'siblings'")?
        .iter()
        .enumerate()
        .map(|(i, s)| {
            decode32(
                s.as_str()
                    .ok_or_else(|| format!("siblings[{}] must be a string", i))?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MerkleProof {
        leaf_index,
        siblings,
    })
}

fn parse_tx_message(v: &Value) -> Result<TxMessage, String> {
    let from = decode_hex(v["from"].as_str().ok_or("tx: missing 'from'")?)?;
    if from.len() != 20 {
        return Err(format!("tx.from: expected 20 bytes, got {}", from.len()));
    }
    let mut from_arr = [0u8; 20];
    from_arr.copy_from_slice(&from);

    let to = decode_hex(v["to"].as_str().ok_or("tx: missing 'to'")?)?;
    if to.len() != 20 {
        return Err(format!("tx.to: expected 20 bytes, got {}", to.len()));
    }
    let mut to_arr = [0u8; 20];
    to_arr.copy_from_slice(&to);

    let value: u128 = v["value"]
        .as_str()
        .unwrap_or("0")
        .parse()
        .map_err(|_| "tx.value: invalid integer")?;

    let data = v["data"]
        .as_str()
        .map(decode_hex)
        .transpose()?
        .unwrap_or_default();

    Ok(TxMessage {
        chain_id: v["chain_id"].as_u64().ok_or("tx: missing 'chain_id'")?,
        nonce: v["nonce"].as_u64().ok_or("tx: missing 'nonce'")?,
        from: from_arr,
        to: to_arr,
        value,
        data,
        gas_limit: v["gas_limit"].as_u64().ok_or("tx: missing 'gas_limit'")?,
        max_fee_per_gas: v["max_fee_per_gas"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .map_err(|_| "tx.max_fee_per_gas: invalid integer")?,
        max_priority_fee_per_gas: v["max_priority_fee_per_gas"]
            .as_str()
            .unwrap_or("0")
            .parse()
            .map_err(|_| "tx.max_priority_fee_per_gas: invalid integer")?,
    })
}

fn parse_witness(v: &Value) -> Result<HCAWitness, String> {
    let version_bytes = decode_hex(
        v["leaf_version"]
            .as_str()
            .ok_or("witness: missing 'leaf_version'")?,
    )?;
    if version_bytes.len() != 1 {
        return Err("witness.leaf_version must be 1 byte".to_string());
    }
    let leaf_version = version_bytes[0];

    let leaf_script = decode_hex(
        v["leaf_script"]
            .as_str()
            .ok_or("witness: missing 'leaf_script'")?,
    )?;

    let proof = parse_proof(&v.to_string())?;

    let leaf = Leaf::new(leaf_version, leaf_script, "").map_err(|e| e.to_string())?;

    Ok(HCAWitness::build(&leaf, proof))
}
