# Security Policy

## Status

**hca-rs is research-grade software implementing a draft [EIP-8215](https://eips.ethereum.org/EIPS/eip-8215).**

- This library has **not been audited**
- Do **not** use in production or to secure real funds
- The EIP specification is still in draft — breaking changes may occur

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | yes       |
| < 0.3.0 | no        |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report privately via:

- **Email**: zakaria.saiff@gmail.com
- **Telegram**: [@zacksaif](https://t.me/zacksaif)

Once the repository is public, GitHub private vulnerability reporting will be enabled here:
[Report a vulnerability](https://github.com/eth-hca/hca-rs/security/advisories/new)

Include in your report:
- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact

You will receive a response within **72 hours**. If the vulnerability is confirmed, a fix will be issued and you will be credited in the changelog unless you prefer otherwise.

## Scope

Areas of particular concern:

- Hash domain separation (`tagged_hash` — `HCALeaf`, `HCABranch`, `HCAAddr`, `HCAWitness`, `HCARotate`)
- Merkle proof verification (`MerkleTree::verify`)
- Address derivation (`derive_address`)
- Leaf script gas enforcement (`GasCounter`, `validate_leaf_script`)
- RLP encoding correctness for EIP-2718 type `0x05` transactions

## Known Limitations

- No audit has been performed
- EVM leaf script execution is validated statically (opcode + gas), not executed in a real EVM
- Signature verification is out of scope — this library produces signing hashes only
