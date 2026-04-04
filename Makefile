CARGO := $(shell which cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)
CARGO_NIGHTLY := $(shell which cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo) +nightly

.PHONY: all build build-release build-wasm build-wasm-node \
        test test-unit test-property test-vector test-doc test-all test-no-default test-one \
        bench bench-hash bench-merkle bench-address bench-flow \
        fuzz fuzz-merkle fuzz-proof fuzz-witness fuzz-rlp \
        example-create example-spend example-verify \
        cli cli-help cli-demo \
        lint fmt fmt-check check clean

# ─────────────────────────────────────────────
# Build
# ─────────────────────────────────────────────

all: build

build:
	$(CARGO) build

build-release:
	$(CARGO) build --release

build-wasm:
	wasm-pack build --target web --features wasm

build-wasm-node:
	wasm-pack build --target nodejs --features wasm

# ─────────────────────────────────────────────
# Test
# ─────────────────────────────────────────────

test: test-all

test-all:
	$(CARGO) test --all-features

test-unit:
	$(CARGO) test --lib

test-property:
	$(CARGO) test --test property_tests

test-vector:
	$(CARGO) test --test vector_tests

test-doc:
	$(CARGO) test --doc

test-no-default:
	$(CARGO) test --no-default-features

# Run a single test by name: make test-one NAME=test_signing_hash_includes_data
test-one:
	$(CARGO) test -- $(NAME)

# ─────────────────────────────────────────────
# Bench
# ─────────────────────────────────────────────

bench:
	$(CARGO) bench

bench-hash:
	$(CARGO) bench --bench hash_bench

bench-merkle:
	$(CARGO) bench --bench merkle_bench

bench-address:
	$(CARGO) bench --bench address_bench

bench-flow:
	$(CARGO) bench --bench full_flow_bench

# ─────────────────────────────────────────────
# Fuzz (requires nightly)
# ─────────────────────────────────────────────

fuzz: fuzz-merkle fuzz-proof fuzz-witness fuzz-rlp

fuzz-merkle:
	$(CARGO_NIGHTLY) fuzz run fuzz_merkle

fuzz-proof:
	$(CARGO_NIGHTLY) fuzz run fuzz_proof

fuzz-witness:
	$(CARGO_NIGHTLY) fuzz run fuzz_witness

fuzz-rlp:
	$(CARGO_NIGHTLY) fuzz run fuzz_rlp

# ─────────────────────────────────────────────
# Examples
# ─────────────────────────────────────────────

example-create:
	$(CARGO) run --example create_account

example-spend:
	$(CARGO) run --example spend_transaction

example-verify:
	$(CARGO) run --example verify_proof

# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

# Build the hca binary (debug)
cli:
	$(CARGO) build --bin hca

# Show full clap-generated help
cli-help:
	$(CARGO) run --bin hca -- --help

# End-to-end demo: create-account → derive-address → generate-proof → verify-proof → signing-hash
# Runs the full HCA flow in one command. No keys needed.
cli-demo:
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  HCA CLI demo — full flow (EIP-8215)"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	$(eval LEAVES := [{"version":"0x01","script":"0x6001","description":"Primary ECDSA"},{"version":"0x01","script":"0x6002","description":"Recovery key"},{"version":"0x01","script":"0x6003","description":"Timelock 30d"}])
	@echo ""
	@echo "▶ 1. create-account"
	$(eval ACCOUNT := $(shell $(CARGO) run -q --bin hca -- create-account --leaves '$(LEAVES)'))
	@echo '$(ACCOUNT)' | python3 -m json.tool
	$(eval AUTH_ROOT  := $(shell echo '$(ACCOUNT)' | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_root'])"))
	$(eval ADDRESS    := $(shell echo '$(ACCOUNT)' | python3 -c "import sys,json; print(json.load(sys.stdin)['address'])"))
	@echo ""
	@echo "▶ 2. derive-address (roundtrip check)"
	$(CARGO) run -q --bin hca -- derive-address --auth-root $(AUTH_ROOT)
	@echo ""
	@echo "▶ 3. generate-proof (leaf 0)"
	$(eval PROOF_OUT  := $(shell $(CARGO) run -q --bin hca -- generate-proof --leaves '$(LEAVES)' --index 0))
	@echo '$(PROOF_OUT)' | python3 -m json.tool
	$(eval LEAF_HASH  := $(shell echo '$(PROOF_OUT)' | python3 -c "import sys,json; print(json.load(sys.stdin)['leaf_hash'])"))
	$(eval PROOF_JSON := $(shell echo '$(PROOF_OUT)' | python3 -c "import sys,json; d=json.load(sys.stdin); print(json.dumps({'leaf_index':d['leaf_index'],'siblings':d['siblings']}))"))
	@echo ""
	@echo "▶ 4. verify-proof"
	$(CARGO) run -q --bin hca -- verify-proof \
		--leaf-hash $(LEAF_HASH) \
		--proof '$(PROOF_JSON)' \
		--auth-root $(AUTH_ROOT)
	@echo ""
	@echo "▶ 5. signing-hash"
	$(eval TX := {"chain_id":11155111,"nonce":0,"from":"$(ADDRESS)","to":"0x000000000000000000000000000000000000dead","value":"1000000000000000","gas_limit":21000,"max_fee_per_gas":"1000000000","max_priority_fee_per_gas":"100000000"})
	$(CARGO) run -q --bin hca -- signing-hash \
		--tx '$(TX)' \
		--leaf-hash $(LEAF_HASH)
	@echo ""
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
	@echo "  ✓ demo complete"
	@echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ─────────────────────────────────────────────
# Lint & Format
# ─────────────────────────────────────────────

lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

check: fmt-check lint test-all

# ─────────────────────────────────────────────
# Local CI — mirrors GitHub Actions jobs
# Run this before every push / PR
# ─────────────────────────────────────────────

ci: ci-fmt ci-lint ci-build ci-test ci-test-no-default ci-test-serde-only ci-no-std
	@echo "✓ all local CI checks passed"

ci-fmt:
	@echo "[ fmt ]"
	$(CARGO) fmt --all -- --check

ci-lint:
	@echo "[ clippy ]"
	$(CARGO) clippy --all-targets --all-features -- -D warnings

ci-build:
	@echo "[ build ]"
	$(CARGO) build --all-features

ci-test:
	@echo "[ test ]"
	$(CARGO) test --all-features

ci-test-no-default:
	@echo "[ test no-default-features ]"
	$(CARGO) test --no-default-features

ci-test-serde-only:
	@echo "[ test serde only (no std) ]"
	$(CARGO) test --no-default-features --features serde

ci-no-std:
	@echo "[ no_std build ]"
	$(CARGO) build --lib --no-default-features --target thumbv7em-none-eabihf

# ─────────────────────────────────────────────
# Clean
# ─────────────────────────────────────────────

clean:
	$(CARGO) clean
