# Contributing to hca-rs

hca-rs is the Rust reference implementation of [EIP-8215](https://eips.ethereum.org/EIPS/eip-8215) (Hash-Committed Account). Contributions are welcome — bug fixes, test vectors, cross-implementation compatibility, and EIP feedback especially.

## Before You Start

- The EIP spec is the source of truth — contact the author for access
- This is research-grade software, not production-ready
- Open an issue before starting large changes

## Setup

```bash
git clone https://github.com/eth-hca/hca-rs
cd hca-rs
cargo build
make ci        # must pass before every PR
```

**Requirements**: Rust 1.71+ (MSRV), `wasm-pack` for WASM builds, nightly for fuzzing.

## Workflow

1. Branch from `main` — use the naming convention below
2. Make your changes
3. Run `make ci` — all checks must pass locally
4. Open a PR against `main`

### Branch naming

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feat/<name>` | `feat/rotation-leaf` |
| Fix | `fix/<name>` | `fix/proof-depth-check` |
| Test | `test/<name>` | `test/go-vectors` |
| Docs | `docs/<name>` | `docs/rustdoc` |
| Refactor | `refactor/<name>` | `refactor/rlp-encoder` |
| Security | `security/<name>` | `security/gas-metering` |
| Release | `release/<version>` | `release/v0.3.0` |
| Chore | `chore/<name>` | `chore/msrv-bump` |

## Commit Messages

Follow the geth-style format — short, fits in the GitHub commit list:

```
type(scope): short description (#PR)
```

Types: `feat`, `fix`, `test`, `chore`, `docs`, `refactor`, `security`

Examples:
```
feat(merkle): add proof batch verification (#25)
fix(rlp): handle zero-length calldata encoding (#26)
test(vectors): add Go cross-implementation vectors (#27)
```

One logical change per commit. Each file or group of related files gets its own commit.

## CI Requirements

`make ci` runs all of these — they must all pass:

| Check | Command |
|-------|---------|
| Format | `cargo fmt --all -- --check` |
| Lint | `cargo clippy --all-targets --all-features -- -D warnings` |
| Build | `cargo build --all-features` |
| Tests | `cargo test --all-features` |
| no-default | `cargo test --no-default-features` |
| serde-only | `cargo test --no-default-features --features serde` |
| no_std | `cargo build --lib --no-default-features --target thumbv7em-none-eabihf` |

## Testing

- **Unit tests** — inline in each module, test edge cases
- **Property tests** — `tests/property_tests.rs` via proptest
- **Vector tests** — `tests/vector_tests.rs` against `tests/vectors/*.json` for cross-impl compatibility
- **CLI tests** — `tests/cli_tests.rs` integration tests for the `hca` binary
- **Fuzz targets** — `fuzz/` via libfuzzer (requires nightly)

Cross-implementation test vectors (Go, Python, etc.) are especially valuable — add them to `tests/vectors/`.

## Code Style

- No panics in library code — return `HcaResult`
- No `std` assumptions — use `core::` and `alloc::` where possible
- Gate `std`-only code behind `#[cfg(feature = "std")]`
- No new dependencies without discussion — keep the dep tree minimal
- Document all public items (`#![warn(missing_docs)]` is enforced)

## Questions

- Open a GitHub issue for spec questions or implementation discussions
- Reach out to the author: [@zacksaif](https://t.me/zacksaif)
