CARGO := $(shell which cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)
CARGO_NIGHTLY := $(shell which cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo) +nightly

.PHONY: all build build-release build-wasm build-wasm-node \
        test test-unit test-property test-vector test-doc test-all test-no-default test-one \
        bench bench-hash bench-merkle bench-address bench-flow \
        fuzz fuzz-merkle fuzz-proof fuzz-witness fuzz-rlp \
        example-create example-spend example-verify \
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

ci: ci-fmt ci-lint ci-build ci-test ci-test-no-default ci-no-std
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

ci-no-std:
	@echo "[ no_std build ]"
	$(CARGO) build --no-default-features --target thumbv7em-none-eabihf

# ─────────────────────────────────────────────
# Clean
# ─────────────────────────────────────────────

clean:
	$(CARGO) clean
