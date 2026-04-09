SHELL := /bin/sh

CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -fPIC
PYTHON ?= python3
GO ?= go
CARGO ?= $(shell command -v cargo 2>/dev/null || echo $(HOME)/.cargo/bin/cargo)
CARGO_LOCKED_ARGS ?= --locked
GO_MODULE_FLAGS ?= -mod=readonly
SP_DIFFER_BUILD_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.0.0-dev)
BUILD_DEFINES := -DSP_DIFFER_BUILD_VERSION=\"$(SP_DIFFER_BUILD_VERSION)\"
LOCAL_RELEASE_OS = $(shell printf '%s' '$(UNAME_S)' | tr '[:upper:]' '[:lower:]')
LOCAL_RELEASE_ARCH = $(shell uname -m)
LOCAL_RELEASE_NAME = sp-differ-$(SP_DIFFER_BUILD_VERSION)-$(LOCAL_RELEASE_OS)-$(LOCAL_RELEASE_ARCH)
RELEASE_DIST_DIR = $(BUILD_DIR)/dist/$(LOCAL_RELEASE_NAME)
RELEASE_ARCHIVE = $(BUILD_DIR)/$(LOCAL_RELEASE_NAME).tar.gz
RELEASE_KEYS_FILE ?= KEYS
DEFAULT_RELEASE_SIGN_GPG_KEY := $(shell if command -v gpg >/dev/null 2>&1 && [ -f "$(RELEASE_KEYS_FILE)" ]; then key=$$(gpg --show-keys --with-colons "$(RELEASE_KEYS_FILE)" 2>/dev/null | awk -F: '/^pub:/ {print $$5; exit}'); if [ -n "$$key" ] && gpg --list-secret-keys "$$key" >/dev/null 2>&1; then printf '%s' "$$key"; fi; fi)
RELEASE_SIGN_GPG_KEY ?= $(DEFAULT_RELEASE_SIGN_GPG_KEY)

HOST_UNAME_S := $(shell uname -s)

SECP256K1_CFLAGS := $(shell pkg-config --cflags secp256k1 2>/dev/null || pkg-config --cflags libsecp256k1 2>/dev/null)
SECP256K1_LIBS := $(shell pkg-config --libs secp256k1 2>/dev/null || pkg-config --libs libsecp256k1 2>/dev/null)
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)
ifeq ($(HOST_UNAME_S),Darwin)
ifeq ($(strip $(SECP256K1_CFLAGS)),)
	SECP256K1_CFLAGS := -I/opt/homebrew/include
endif
ifeq ($(strip $(SECP256K1_LIBS)),)
	SECP256K1_LIBS := -L/opt/homebrew/lib -lsecp256k1
endif
ifeq ($(strip $(OPENSSL_CFLAGS)),)
	OPENSSL_CFLAGS := -I/opt/homebrew/Cellar/openssl@3/3.6.1/include
endif
ifeq ($(strip $(OPENSSL_LIBS)),)
	OPENSSL_LIBS := -L/opt/homebrew/Cellar/openssl@3/3.6.1/lib -lssl -lcrypto
endif
endif

BUILD_DIR := build
WORKER_SRC := workers/cpp/sp_differ_worker.cpp
RUNNER_SRC := src/runner/sp_differ_runner.cpp
COMPARE_SRC := src/runner/sp_differ_compare.cpp
CLI_SRC := src/cli/main.cpp
WORKER_API_SRC := src/runner/worker.cpp
SEMANTIC_BRIDGE_SRC := src/runner/semantic_bridge.cpp
SEMANTIC_JSON_SRC := src/runner/semantic_json.cpp
SEMANTIC_CONTRACT_SRC := src/runner/semantic_contract.cpp
REPORTER_SRC := src/reporter/reporter.cpp
CORE_SRC := src/core/io.cpp
SEMANTIC_JSON_SRC := src/runner/semantic_json.cpp
SEMANTIC_CONTRACT_SRC := src/runner/semantic_contract.cpp
CORE_SMOKE_SRC := src/core/io_smoke.cpp
CASE_SRC := src/core/case.cpp
CASE_SMOKE_SRC := src/core/case_smoke.cpp
VALIDATE_SRC := src/core/validate.cpp
VALIDATE_SMOKE_SRC := src/core/validate_smoke.cpp
FUZZ_HARNESS_SRC := fuzz/sp_fuzz_harness.cpp
FUZZ_DRIVER_SRC := fuzz/sp_fuzz_driver.cpp

UNAME_S := $(HOST_UNAME_S)
ifeq ($(UNAME_S),Darwin)
  LIB_EXT := dylib
  SHARED_FLAG := -shared
  DL_FLAGS :=
else ifeq ($(OS),Windows_NT)
  LIB_EXT := dll
  SHARED_FLAG := -shared
  DL_FLAGS :=
  THREAD_FLAGS :=
else
  LIB_EXT := so
  SHARED_FLAG := -shared
  DL_FLAGS := -ldl
  THREAD_FLAGS := -pthread
endif
ifeq ($(UNAME_S),Darwin)
  THREAD_FLAGS := -pthread
endif

WORKER_LIB := $(BUILD_DIR)/libsp_differ_worker.$(LIB_EXT)
RUNNER_BIN := $(BUILD_DIR)/sp_differ_runner
COMPARE_BIN := $(BUILD_DIR)/sp_differ_compare
CLI_BIN := $(BUILD_DIR)/sp_differ_cli
CORE_SMOKE_BIN := $(BUILD_DIR)/sp_differ_core_io_smoke
CASE_SMOKE_BIN := $(BUILD_DIR)/sp_differ_core_case_smoke
VALIDATE_SMOKE_BIN := $(BUILD_DIR)/sp_differ_core_validate_smoke
FUZZ_HARNESS_OBJ := $(BUILD_DIR)/sp_fuzz_harness.o
FUZZ_DRIVER_BIN := $(BUILD_DIR)/sp_fuzz_driver
RELEASE_BUILD_DIR := $(BUILD_DIR)/release
RELEASE_CXXFLAGS ?= -std=c++17 -O3 -DNDEBUG -fPIC
RELEASE_STRIP ?= strip
RELEASE_WORKER_LIB := $(RELEASE_BUILD_DIR)/libsp_differ_worker.$(LIB_EXT)
RELEASE_RUNNER_BIN := $(RELEASE_BUILD_DIR)/sp_differ_runner
RELEASE_COMPARE_BIN := $(RELEASE_BUILD_DIR)/sp_differ_compare
RELEASE_CLI_BIN := $(RELEASE_BUILD_DIR)/sp_differ_cli
BUILD_VERSION_STAMP := $(BUILD_DIR)/.build-version
RELEASE_VERSION_STAMP := $(RELEASE_BUILD_DIR)/.build-version
RUST_LIB_NAME := sp_differ_worker_rust
RUST_TARGET_DIR := workers/rust/target/release
ifeq ($(OS),Windows_NT)
  RUST_LIB_FILE := $(RUST_LIB_NAME).$(LIB_EXT)
else
  RUST_LIB_FILE := lib$(RUST_LIB_NAME).$(LIB_EXT)
endif
RUST_LIB_SRC := $(RUST_TARGET_DIR)/$(RUST_LIB_FILE)
RUST_LIB_DST := $(BUILD_DIR)/$(RUST_LIB_FILE)
SPDK_ADAPTER_TARGET_DIR := adapters/spdk_rust/target/debug
SPDK_SEMANTIC_LIB_NAME := sp_differ_semantic_worker_spdk
ifeq ($(OS),Windows_NT)
  SPDK_ADAPTER_BIN_FILE := sp-differ-semantic-adapter-spdk.exe
  SPDK_SEMANTIC_LIB_FILE := $(SPDK_SEMANTIC_LIB_NAME).$(LIB_EXT)
else
  SPDK_ADAPTER_BIN_FILE := sp-differ-semantic-adapter-spdk
  SPDK_SEMANTIC_LIB_FILE := lib$(SPDK_SEMANTIC_LIB_NAME).$(LIB_EXT)
endif
SPDK_ADAPTER_BIN := $(SPDK_ADAPTER_TARGET_DIR)/$(SPDK_ADAPTER_BIN_FILE)
SPDK_SEMANTIC_LIB := $(SPDK_ADAPTER_TARGET_DIR)/$(SPDK_SEMANTIC_LIB_FILE)
SILENT_PAYMENTS_ADAPTER_TARGET_DIR := adapters/silent_payments_rust/target/debug
ifeq ($(OS),Windows_NT)
  SILENT_PAYMENTS_ADAPTER_BIN_FILE := sp-differ-semantic-adapter-silent-payments.exe
else
  SILENT_PAYMENTS_ADAPTER_BIN_FILE := sp-differ-semantic-adapter-silent-payments
endif
SILENT_PAYMENTS_ADAPTER_BIN := $(SILENT_PAYMENTS_ADAPTER_TARGET_DIR)/$(SILENT_PAYMENTS_ADAPTER_BIN_FILE)
SILENT_PAYMENTS_SEMANTIC_LIB_NAME := sp_differ_semantic_worker_silent_payments
ifeq ($(OS),Windows_NT)
  SILENT_PAYMENTS_SEMANTIC_LIB_FILE := $(SILENT_PAYMENTS_SEMANTIC_LIB_NAME).$(LIB_EXT)
else
  SILENT_PAYMENTS_SEMANTIC_LIB_FILE := lib$(SILENT_PAYMENTS_SEMANTIC_LIB_NAME).$(LIB_EXT)
endif
SILENT_PAYMENTS_SEMANTIC_LIB := $(SILENT_PAYMENTS_ADAPTER_TARGET_DIR)/$(SILENT_PAYMENTS_SEMANTIC_LIB_FILE)
BIP352_ADAPTER_TARGET_DIR := adapters/bip352_rust/target/debug
ifeq ($(OS),Windows_NT)
  BIP352_ADAPTER_BIN_FILE := sp-differ-semantic-adapter-bip352.exe
else
  BIP352_ADAPTER_BIN_FILE := sp-differ-semantic-adapter-bip352
endif
BIP352_ADAPTER_BIN := $(BIP352_ADAPTER_TARGET_DIR)/$(BIP352_ADAPTER_BIN_FILE)
BIP352_SEMANTIC_LIB_NAME := sp_differ_semantic_worker_bip352
ifeq ($(OS),Windows_NT)
  BIP352_SEMANTIC_LIB_FILE := $(BIP352_SEMANTIC_LIB_NAME).$(LIB_EXT)
else
  BIP352_SEMANTIC_LIB_FILE := lib$(BIP352_SEMANTIC_LIB_NAME).$(LIB_EXT)
endif
BIP352_SEMANTIC_LIB := $(BIP352_ADAPTER_TARGET_DIR)/$(BIP352_SEMANTIC_LIB_FILE)
GO_BIP352_MODULE_DIR := adapters/go_bip352
ifeq ($(OS),Windows_NT)
  GO_BIP352_ADAPTER_BIN := $(BUILD_DIR)/sp-differ-semantic-adapter-go-bip352.exe
  GO_BIP352_SEMANTIC_LIB := $(BUILD_DIR)/sp_differ_semantic_worker_go_bip352.$(LIB_EXT)
else
  GO_BIP352_ADAPTER_BIN := $(BUILD_DIR)/sp-differ-semantic-adapter-go-bip352
  GO_BIP352_SEMANTIC_LIB := $(BUILD_DIR)/libsp_differ_semantic_worker_go_bip352.$(LIB_EXT)
endif
FUZZ_SEED ?= 352
FUZZ_STRUCTURED_ITERATIONS ?= 8
FUZZ_RAW_ITERATIONS ?= 8
SEMANTIC_TIMEOUT_SECONDS ?= 300.0
BENCH_WARMUP ?= 1
BENCH_ITERATIONS ?= 3
BENCH_TIMEOUT_SECONDS ?= 30.0
BENCH_KIND ?=
BENCH_MAX_CASES ?=
BENCH_SCAN_BLOCKS ?= 1000
BENCH_SCAN_TRANSACTIONS_PER_BLOCK ?= 8
BENCH_SCAN_DENSITY ?= all
BENCH_SCAN_THREADS ?= 0
BENCH_SCAN_SEED ?= 352
BENCH_SCAN_NETWORK ?= mainnet
BENCH_SCAN_VERSION ?= 0
SANITIZE_BUILD_DIR := $(BUILD_DIR)/sanitize
SANITIZE_CXX ?= $(CXX)
SANITIZE_CXXFLAGS ?= -std=c++17 -O1 -g -fPIC -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all
WARN_BUILD_DIR ?= $(BUILD_DIR)/warnings
WARN_CXXFLAGS ?= $(CXXFLAGS) -Wall -Wextra -Wpedantic -Werror
CLANG_TIDY ?= clang-tidy
CLANG_TIDY_SOURCES := $(RUNNER_SRC) $(COMPARE_SRC) $(CLI_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(REPORTER_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(WORKER_SRC)
CLANG_TIDY_CXXFLAGS := -std=c++17 $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS)
UBSAN_OPTIONS ?= print_stacktrace=1:halt_on_error=1
ifeq ($(UNAME_S),Darwin)
ASAN_OPTIONS ?= abort_on_error=1
else
ASAN_OPTIONS ?= detect_leaks=1:abort_on_error=1
endif
SANITIZE_RUN_ENV := ASAN_OPTIONS=$(ASAN_OPTIONS) UBSAN_OPTIONS=$(UBSAN_OPTIONS)
RUSTFMT_MANIFESTS := workers/rust/Cargo.toml adapters/spdk_rust/Cargo.toml adapters/silent_payments_rust/Cargo.toml adapters/bip352_rust/Cargo.toml adapters/bdk_sp_rust/Cargo.toml
GOFMT_SOURCES := $(shell find adapters/go_bip352 -type f -name '*.go' | sort)

SANITIZE_WORKER_LIB := $(SANITIZE_BUILD_DIR)/libsp_differ_worker.$(LIB_EXT)
SANITIZE_RUNNER_BIN := $(SANITIZE_BUILD_DIR)/sp_differ_runner
SANITIZE_COMPARE_BIN := $(SANITIZE_BUILD_DIR)/sp_differ_compare
SANITIZE_CORE_SMOKE_BIN := $(SANITIZE_BUILD_DIR)/sp_differ_core_io_smoke
SANITIZE_CASE_SMOKE_BIN := $(SANITIZE_BUILD_DIR)/sp_differ_core_case_smoke
SANITIZE_VALIDATE_SMOKE_BIN := $(SANITIZE_BUILD_DIR)/sp_differ_core_validate_smoke
BENCH_KIND_ARG :=
ifneq ($(strip $(BENCH_KIND)),)
BENCH_KIND_ARG := --kind $(BENCH_KIND)
endif
BENCH_MAX_CASES_ARG :=
ifneq ($(strip $(BENCH_MAX_CASES)),)
BENCH_MAX_CASES_ARG := --max-cases $(BENCH_MAX_CASES)
endif
LIBFUZZER_FLAGS ?= -fsanitize=fuzzer-no-link,address
VERIFY_PACKAGED_KEYS_ARG :=
ifneq ($(wildcard $(RELEASE_KEYS_FILE)),)
VERIFY_PACKAGED_KEYS_ARG := --keys-file $(RELEASE_KEYS_FILE)
endif
VERIFY_PACKAGED_SIGNATURE_ARG :=
ifneq ($(strip $(RELEASE_SIGN_GPG_KEY)),)
VERIFY_PACKAGED_SIGNATURE_ARG := --require-signature
endif

.PHONY: build test worker runner compare cli smoke sanitize-smoke check clean release lint
.PHONY: check-compile-warnings check-rustfmt check-rust-clippy check-gofmt check-go-vet check-clang-tidy check-abi-symbols fmt fmt-rust fmt-go
.PHONY: worker-rust
.PHONY: smoke-rust
.PHONY: diff
.PHONY: semantic-smoke
.PHONY: check-scripts
.PHONY: check-claims
.PHONY: check-comments
.PHONY: check-workflows
.PHONY: oracle
.PHONY: vectors
.PHONY: vectors-check
.PHONY: vectors-v2
.PHONY: vectors-refresh
.PHONY: adapters
.PHONY: adapter-reference
.PHONY: adapter-spdk
.PHONY: adapter-spdk-ffi
.PHONY: adapter-silent-payments
.PHONY: adapter-silent-payments-ffi
.PHONY: adapter-bip352
.PHONY: adapter-bip352-ffi
.PHONY: adapter-go-bip352
.PHONY: adapter-go-bip352-ffi
.PHONY: adapter-bdk-sp
.PHONY: regressions
.PHONY: regressions-reference
.PHONY: regressions-spdk
.PHONY: regressions-spdk-ffi
.PHONY: regressions-silent-payments
.PHONY: regressions-silent-payments-ffi
.PHONY: regressions-bip352
.PHONY: regressions-bip352-ffi
.PHONY: regressions-go-bip352
.PHONY: regressions-go-bip352-ffi
.PHONY: regressions-bdk-sp
.PHONY: fuzz-corpus
.PHONY: fuzz-harness
.PHONY: fuzz-driver
.PHONY: native-reference-fuzz
.PHONY: fuzz-corpus-refresh
.PHONY: fuzz-minimizer-smoke
.PHONY: fuzz-semantic-spdk
.PHONY: fuzz-semantic-silent-payments
.PHONY: fuzz-semantic-bip352
.PHONY: fuzz-semantic-go-bip352
.PHONY: fuzz-semantic-bdk-sp
.PHONY: fuzz-semantic-workers
.PHONY: fuzz-semantic-adapters
.PHONY: semantic-worker-libs
.PHONY: bench-reference
.PHONY: bench-spdk
.PHONY: bench-spdk-ffi
.PHONY: bench-silent-payments
.PHONY: bench-silent-payments-ffi
.PHONY: bench-bip352
.PHONY: bench-bip352-ffi
.PHONY: bench-go-bip352
.PHONY: bench-go-bip352-ffi
.PHONY: bench-bdk-sp
.PHONY: bench-scan-native
.PHONY: bench-adapters
.PHONY: bench-summary
.PHONY: parity-smoke
.PHONY: cli-smoke
.PHONY: precommit-smoke
.PHONY: research-bip352
.PHONY: research-bip352-deep
.PHONY: release-evidence
.PHONY: release-sign
.PHONY: release-prereqs
.PHONY: package-release
.PHONY: verify-packaged-release
.PHONY: official-release-ready
.PHONY: verify-release-evidence
.PHONY: release-report
.PHONY: maturity-signoff
.PHONY: verify-release
.PHONY: verify-release-live
.PHONY: verify-release-attestation
.PHONY: verify-quick
.PHONY: FORCE

worker: $(WORKER_LIB)

build: worker runner compare cli

FORCE:

check-compile-warnings:
	$(MAKE) BUILD_DIR=$(WARN_BUILD_DIR) CXXFLAGS="$(WARN_CXXFLAGS)" build

check-rustfmt:
	$(CARGO) fmt --manifest-path workers/rust/Cargo.toml --all --check
	$(CARGO) fmt --manifest-path adapters/spdk_rust/Cargo.toml --all --check
	$(CARGO) fmt --manifest-path adapters/silent_payments_rust/Cargo.toml --all --check
	$(CARGO) fmt --manifest-path adapters/bip352_rust/Cargo.toml --all --check
	$(CARGO) fmt --manifest-path adapters/bdk_sp_rust/Cargo.toml --all --check

check-rust-clippy:
	$(CARGO) clippy --manifest-path workers/rust/Cargo.toml $(CARGO_LOCKED_ARGS) --all-targets -- -D warnings
	$(CARGO) clippy --manifest-path adapters/spdk_rust/Cargo.toml $(CARGO_LOCKED_ARGS) --all-targets -- -D warnings
	$(CARGO) clippy --manifest-path adapters/silent_payments_rust/Cargo.toml $(CARGO_LOCKED_ARGS) --all-targets -- -D warnings
	$(CARGO) clippy --manifest-path adapters/bip352_rust/Cargo.toml $(CARGO_LOCKED_ARGS) --all-targets -- -D warnings
	$(CARGO) clippy --manifest-path adapters/bdk_sp_rust/Cargo.toml $(CARGO_LOCKED_ARGS) --all-targets -- -D warnings

check-gofmt:
	@files="$$(gofmt -l $(GOFMT_SOURCES))"; \
	if [ -n "$$files" ]; then \
	  echo "gofmt required for:"; \
	  printf '%s\n' "$$files"; \
	  exit 1; \
	fi

check-go-vet:
	cd $(GO_BIP352_MODULE_DIR) && GOFLAGS="$(GO_MODULE_FLAGS)" $(GO) vet ./...

check-clang-tidy:
	@if ! command -v $(CLANG_TIDY) >/dev/null 2>&1; then \
	  echo "clang-tidy executable not found: $(CLANG_TIDY)" >&2; \
	  exit 1; \
	fi
	@status=0; \
	for source in $(CLANG_TIDY_SOURCES); do \
	  echo "$$ $(CLANG_TIDY) $$source -- $(CLANG_TIDY_CXXFLAGS)"; \
	  $(CLANG_TIDY) "$$source" -- $(CLANG_TIDY_CXXFLAGS) || status=$$?; \
	done; \
	if [ $$status -ne 0 ]; then \
	  echo "clang-tidy failed" >&2; \
	  exit $$status; \
	fi

lint: check-compile-warnings check-rustfmt check-rust-clippy check-gofmt check-go-vet check-claims check-comments check-workflows

fmt: fmt-rust fmt-go

fmt-rust:
	$(CARGO) fmt --manifest-path workers/rust/Cargo.toml --all
	$(CARGO) fmt --manifest-path adapters/spdk_rust/Cargo.toml --all
	$(CARGO) fmt --manifest-path adapters/silent_payments_rust/Cargo.toml --all
	$(CARGO) fmt --manifest-path adapters/bip352_rust/Cargo.toml --all
	$(CARGO) fmt --manifest-path adapters/bdk_sp_rust/Cargo.toml --all

fmt-go:
	gofmt -w $(GOFMT_SOURCES)

$(BUILD_VERSION_STAMP): FORCE
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' "$(SP_DIFFER_BUILD_VERSION)" > $@.tmp
	@if [ ! -f $@ ] || ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm -f $@.tmp; fi

$(RELEASE_VERSION_STAMP): FORCE
	@mkdir -p $(RELEASE_BUILD_DIR)
	@printf '%s\n' "$(SP_DIFFER_BUILD_VERSION)" > $@.tmp
	@if [ ! -f $@ ] || ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm -f $@.tmp; fi

$(WORKER_LIB): $(WORKER_SRC) $(CASE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(SHARED_FLAG) -o $@ $(WORKER_SRC) $(CASE_SRC) $(SECP256K1_CFLAGS) $(SECP256K1_LIBS)

runner: $(RUNNER_BIN)

$(RUNNER_BIN): $(BUILD_VERSION_STAMP) $(RUNNER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(RUNNER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)

compare: $(COMPARE_BIN)

$(COMPARE_BIN): $(BUILD_VERSION_STAMP) $(COMPARE_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(COMPARE_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)

cli: $(CLI_BIN)

$(CLI_BIN): $(BUILD_VERSION_STAMP) $(CLI_SRC) $(REPORTER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(CLI_SRC) $(REPORTER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)

check: $(CORE_SMOKE_BIN) $(CASE_SMOKE_BIN) $(VALIDATE_SMOKE_BIN)
	$(CORE_SMOKE_BIN)
	$(CASE_SMOKE_BIN)
	$(VALIDATE_SMOKE_BIN)
	$(MAKE) check-scripts

test: build
	$(MAKE) check
	$(MAKE) -C workers/cpp clean test_taproot_negation
	./workers/cpp/test_taproot_negation
	$(CARGO) test $(CARGO_LOCKED_ARGS) --manifest-path workers/rust/Cargo.toml
	$(MAKE) vectors-check
	$(MAKE) adapters
	$(MAKE) check-abi-symbols
	$(MAKE) regressions

check-claims:
	$(PYTHON) scripts/check_claim_discipline.py

check-comments:
	$(PYTHON) scripts/check_source_comment_discipline.py

check-workflows:
	$(PYTHON) scripts/check_workflow_hardening.py

check-abi-symbols: worker worker-rust semantic-worker-libs
	$(PYTHON) scripts/check_exported_symbols.py --target cpp-worker --symbol sp_differ_worker_api_version --symbol sp_differ_worker_run --symbol sp_differ_worker_free
	$(PYTHON) scripts/check_exported_symbols.py --target rust-worker --symbol sp_differ_worker_api_version --symbol sp_differ_worker_run --symbol sp_differ_worker_free
	$(PYTHON) scripts/check_exported_symbols.py --target spdk-semantic --symbol sp_differ_semantic_worker_api_version --symbol sp_differ_semantic_worker_run --symbol sp_differ_semantic_worker_free
	$(PYTHON) scripts/check_exported_symbols.py --target silent-payments-semantic --symbol sp_differ_semantic_worker_api_version --symbol sp_differ_semantic_worker_run --symbol sp_differ_semantic_worker_free
	$(PYTHON) scripts/check_exported_symbols.py --target bip352-semantic --symbol sp_differ_semantic_worker_api_version --symbol sp_differ_semantic_worker_run --symbol sp_differ_semantic_worker_free
	$(PYTHON) scripts/check_exported_symbols.py --target go-bip352-semantic --symbol sp_differ_semantic_worker_api_version --symbol sp_differ_semantic_worker_run --symbol sp_differ_semantic_worker_free

check-scripts:
	$(PYTHON) scripts/parse_case.py tests/vectors/example.hex
	$(PYTHON) scripts/parse_case.py tests/vectors/example_v2.hex
	$(PYTHON) scripts/validate_output.py tests/vectors/output_ok.hex
	$(PYTHON) scripts/runner_smoke.py tests/vectors/example.hex
	$(PYTHON) -m py_compile sp_differ_cli.py scripts/check_claim_discipline.py scripts/claim_discipline_smoke.py scripts/check_source_comment_discipline.py scripts/source_comment_discipline_smoke.py scripts/check_workflow_hardening.py scripts/workflow_hardening_smoke.py scripts/check_exported_symbols.py scripts/verify_release_attestation.py scripts/release_attestation_smoke.py scripts/semantic_worker_ffi.py scripts/semantic_case_runner.py scripts/run_semantic_adapter_cases.py scripts/benchmark_semantic_adapter.py scripts/summarize_semantic_benchmarks.py scripts/semantic_benchmark_smoke.py scripts/generate_release_evidence_manifest.py scripts/release_evidence_smoke.py scripts/verify_release_evidence.py scripts/release_verification_smoke.py scripts/intake_semantic_regressions.py scripts/intake_semantic_regressions_smoke.py scripts/run_native_reference_fuzz.py scripts/run_semantic_regressions.py scripts/generate_semantic_fuzz_corpus.py scripts/run_semantic_worker_fuzz.py scripts/run_semantic_adapter_fuzz.py scripts/semantic_fuzz_minimizer.py scripts/semantic_fuzz_minimizer_smoke.py scripts/package_ci_artifacts.py scripts/bip352_external_probe.py scripts/bip352_external_probe_smoke.py scripts/sp_differ_cli_smoke.py scripts/semantic_bridge.py scripts/semantic_runner_smoke.py
	$(MAKE) check-claims PYTHON=$(PYTHON)
	$(MAKE) check-comments PYTHON=$(PYTHON)
	$(MAKE) check-workflows PYTHON=$(PYTHON)
	$(PYTHON) scripts/claim_discipline_smoke.py
	$(PYTHON) scripts/source_comment_discipline_smoke.py
	$(PYTHON) scripts/workflow_hardening_smoke.py
	$(PYTHON) scripts/release_attestation_smoke.py
	bash -n scripts/sign_release.sh
	$(PYTHON) scripts/release_prereqs_smoke.py
	$(PYTHON) scripts/verify_packaged_release_smoke.py
	$(PYTHON) scripts/semantic_fuzz_minimizer_smoke.py
	$(PYTHON) scripts/intake_semantic_regressions_smoke.py
	$(PYTHON) scripts/bip352_external_probe_smoke.py
	$(PYTHON) scripts/semantic_benchmark_smoke.py
	$(PYTHON) scripts/release_evidence_smoke.py
	$(PYTHON) scripts/release_verification_smoke.py
	$(PYTHON) scripts/generate_semantic_fuzz_corpus.py --check
	$(PYTHON) scripts/sp_differ_cli_smoke.py
	$(MAKE) semantic-smoke

oracle:
	$(PYTHON) scripts/run_bip352_reference_oracle.py

vectors-v2:
	$(PYTHON) scripts/generate_bip352_v2_cases.py --check
	$(PYTHON) scripts/run_bip352_v2_oracle_cases.py

adapter-reference: vectors-v2
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name reference --adapter-cmd "$(PYTHON) adapters/reference/semantic_adapter.py" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/reference_semantic_adapter_report.json --markdown-out build/reference_semantic_adapter_report.md --artifact-dir build/reference_semantic_adapter_artifacts

adapter-spdk: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name spdk-rust --adapter-cmd "./$(SPDK_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/spdk_semantic_adapter_report.json --markdown-out build/spdk_semantic_adapter_report.md --artifact-dir build/spdk_semantic_adapter_artifacts

adapter-spdk-ffi: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name spdk-rust-ffi --worker-lib "$(SPDK_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/spdk_semantic_worker_report.json --markdown-out build/spdk_semantic_worker_report.md --artifact-dir build/spdk_semantic_worker_artifacts

adapter-silent-payments: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name silent-payments --adapter-cmd "./$(SILENT_PAYMENTS_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/silent_payments_semantic_adapter_report.json --markdown-out build/silent_payments_semantic_adapter_report.md --artifact-dir build/silent_payments_semantic_adapter_artifacts

adapter-silent-payments-ffi: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name silent-payments-ffi --worker-lib "$(SILENT_PAYMENTS_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/silent_payments_semantic_worker_report.json --markdown-out build/silent_payments_semantic_worker_report.md --artifact-dir build/silent_payments_semantic_worker_artifacts

adapter-bip352: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name bip352 --adapter-cmd "./$(BIP352_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/bip352_semantic_adapter_report.json --markdown-out build/bip352_semantic_adapter_report.md --artifact-dir build/bip352_semantic_adapter_artifacts

adapter-bip352-ffi: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name bip352-ffi --worker-lib "$(BIP352_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/bip352_semantic_worker_report.json --markdown-out build/bip352_semantic_worker_report.md --artifact-dir build/bip352_semantic_worker_artifacts

adapter-go-bip352: vectors-v2
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -o ../../$(GO_BIP352_ADAPTER_BIN) ./cmd/adapter
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name go-bip352 --adapter-cmd "./$(GO_BIP352_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/go_bip352_semantic_adapter_report.json --markdown-out build/go_bip352_semantic_adapter_report.md --artifact-dir build/go_bip352_semantic_adapter_artifacts

adapter-go-bip352-ffi: vectors-v2
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -buildmode=c-shared -o ../../$(GO_BIP352_SEMANTIC_LIB) ./cmd/worker
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name go-bip352-ffi --worker-lib "$(GO_BIP352_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/go_bip352_semantic_worker_report.json --markdown-out build/go_bip352_semantic_worker_report.md --artifact-dir build/go_bip352_semantic_worker_artifacts

adapter-bdk-sp: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bdk_sp_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_cases.py --adapter-name bdk-sp --adapter-cmd "./adapters/bdk_sp_rust/target/debug/sp-differ-semantic-adapter-bdk-sp" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS) --json-out build/bdk_sp_semantic_adapter_report.json --markdown-out build/bdk_sp_semantic_adapter_report.md --artifact-dir build/bdk_sp_semantic_adapter_artifacts

adapters: adapter-reference adapter-spdk adapter-spdk-ffi adapter-silent-payments adapter-silent-payments-ffi adapter-bip352 adapter-bip352-ffi adapter-go-bip352 adapter-go-bip352-ffi adapter-bdk-sp

bench-reference: vectors-v2
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name reference --adapter-cmd "$(PYTHON) adapters/reference/semantic_adapter.py" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/reference_semantic_benchmark.json --markdown-out build/reference_semantic_benchmark.md

bench-spdk: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name spdk-rust --adapter-cmd "./$(SPDK_ADAPTER_BIN)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/spdk_semantic_benchmark.json --markdown-out build/spdk_semantic_benchmark.md

bench-spdk-ffi: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name spdk-rust-ffi --worker-lib "$(SPDK_SEMANTIC_LIB)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/spdk_semantic_worker_benchmark.json --markdown-out build/spdk_semantic_worker_benchmark.md

bench-silent-payments: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name silent-payments --adapter-cmd "./$(SILENT_PAYMENTS_ADAPTER_BIN)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/silent_payments_semantic_benchmark.json --markdown-out build/silent_payments_semantic_benchmark.md

bench-silent-payments-ffi: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name silent-payments-ffi --worker-lib "$(SILENT_PAYMENTS_SEMANTIC_LIB)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/silent_payments_semantic_worker_benchmark.json --markdown-out build/silent_payments_semantic_worker_benchmark.md

bench-bip352: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name bip352 --adapter-cmd "./$(BIP352_ADAPTER_BIN)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/bip352_semantic_benchmark.json --markdown-out build/bip352_semantic_benchmark.md

bench-bip352-ffi: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name bip352-ffi --worker-lib "$(BIP352_SEMANTIC_LIB)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/bip352_semantic_worker_benchmark.json --markdown-out build/bip352_semantic_worker_benchmark.md

bench-go-bip352: vectors-v2
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -o ../../$(GO_BIP352_ADAPTER_BIN) ./cmd/adapter
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name go-bip352 --adapter-cmd "./$(GO_BIP352_ADAPTER_BIN)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/go_bip352_semantic_benchmark.json --markdown-out build/go_bip352_semantic_benchmark.md

bench-go-bip352-ffi: vectors-v2
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -buildmode=c-shared -o ../../$(GO_BIP352_SEMANTIC_LIB) ./cmd/worker
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name go-bip352-ffi --worker-lib "$(GO_BIP352_SEMANTIC_LIB)" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/go_bip352_semantic_worker_benchmark.json --markdown-out build/go_bip352_semantic_worker_benchmark.md

bench-bdk-sp: vectors-v2
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bdk_sp_rust/Cargo.toml
	$(PYTHON) scripts/benchmark_semantic_adapter.py --adapter-name bdk-sp --adapter-cmd "./adapters/bdk_sp_rust/target/debug/sp-differ-semantic-adapter-bdk-sp" --warmup-iterations $(BENCH_WARMUP) --iterations $(BENCH_ITERATIONS) --timeout-seconds $(BENCH_TIMEOUT_SECONDS) $(BENCH_KIND_ARG) $(BENCH_MAX_CASES_ARG) --json-out build/bdk_sp_semantic_benchmark.json --markdown-out build/bdk_sp_semantic_benchmark.md

bench-summary:
	$(PYTHON) scripts/summarize_semantic_benchmarks.py --json-out build/semantic_benchmark_summary.json --markdown-out build/semantic_benchmark_summary.md build/reference_semantic_benchmark.json build/spdk_semantic_benchmark.json build/spdk_semantic_worker_benchmark.json build/silent_payments_semantic_benchmark.json build/silent_payments_semantic_worker_benchmark.json build/bip352_semantic_benchmark.json build/bip352_semantic_worker_benchmark.json build/go_bip352_semantic_benchmark.json build/go_bip352_semantic_worker_benchmark.json build/bdk_sp_semantic_benchmark.json

bench-scan-native: release
	$(RELEASE_CLI_BIN) --benchmark-scan --network $(BENCH_SCAN_NETWORK) --silent-payment-version $(BENCH_SCAN_VERSION) --benchmark-blocks $(BENCH_SCAN_BLOCKS) --benchmark-transactions-per-block $(BENCH_SCAN_TRANSACTIONS_PER_BLOCK) --benchmark-density $(BENCH_SCAN_DENSITY) --benchmark-threads $(BENCH_SCAN_THREADS) --benchmark-seed $(BENCH_SCAN_SEED) --json-out build/native_scan_benchmark.json --markdown-out build/native_scan_benchmark.md

bench-adapters: bench-reference bench-spdk bench-spdk-ffi bench-silent-payments bench-silent-payments-ffi bench-bip352 bench-bip352-ffi bench-go-bip352 bench-go-bip352-ffi bench-bdk-sp bench-summary

regressions-reference:
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name reference --adapter-cmd "$(PYTHON) adapters/reference/semantic_adapter.py" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-spdk:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name spdk-rust --adapter-cmd "./$(SPDK_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-spdk-ffi:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name spdk-rust-ffi --worker-lib "$(SPDK_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-silent-payments:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name silent-payments --adapter-cmd "./$(SILENT_PAYMENTS_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-silent-payments-ffi:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name silent-payments-ffi --worker-lib "$(SILENT_PAYMENTS_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-bip352:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name bip352 --adapter-cmd "./$(BIP352_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-bip352-ffi:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name bip352-ffi --worker-lib "$(BIP352_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-go-bip352:
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -o ../../$(GO_BIP352_ADAPTER_BIN) ./cmd/adapter
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name go-bip352 --adapter-cmd "./$(GO_BIP352_ADAPTER_BIN)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-go-bip352-ffi:
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -buildmode=c-shared -o ../../$(GO_BIP352_SEMANTIC_LIB) ./cmd/worker
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name go-bip352-ffi --worker-lib "$(GO_BIP352_SEMANTIC_LIB)" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions-bdk-sp:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bdk_sp_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_regressions.py --adapter-name bdk-sp --adapter-cmd "./adapters/bdk_sp_rust/target/debug/sp-differ-semantic-adapter-bdk-sp" --timeout-seconds $(SEMANTIC_TIMEOUT_SECONDS)

regressions: regressions-reference regressions-spdk regressions-spdk-ffi regressions-silent-payments regressions-silent-payments-ffi regressions-bip352 regressions-bip352-ffi regressions-go-bip352 regressions-go-bip352-ffi regressions-bdk-sp

fuzz-corpus:
	$(PYTHON) scripts/generate_semantic_fuzz_corpus.py --check

fuzz-harness:
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(LIBFUZZER_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -c -o $(FUZZ_HARNESS_OBJ) $(FUZZ_HARNESS_SRC)

fuzz-driver: $(FUZZ_DRIVER_BIN)

$(FUZZ_DRIVER_BIN): $(BUILD_VERSION_STAMP) $(FUZZ_DRIVER_SRC) $(FUZZ_HARNESS_OBJ) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(WORKER_API_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) -fsanitize=address $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(FUZZ_DRIVER_SRC) $(FUZZ_HARNESS_OBJ) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(WORKER_API_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)

native-reference-fuzz: cli fuzz-harness fuzz-driver
	$(FUZZ_DRIVER_BIN) --iterations 10000 --seed $(FUZZ_SEED)
	$(PYTHON) scripts/run_native_reference_fuzz.py --cli $(CLI_BIN) --iterations 10000 --seed $(FUZZ_SEED)

fuzz-corpus-refresh:
	$(PYTHON) scripts/generate_semantic_fuzz_corpus.py

fuzz-minimizer-smoke:
	$(PYTHON) scripts/semantic_fuzz_minimizer_smoke.py

fuzz-semantic-spdk: fuzz-corpus
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_worker_fuzz.py --worker-lib "$(SPDK_SEMANTIC_LIB)" --seed $(FUZZ_SEED) --structured-iterations $(FUZZ_STRUCTURED_ITERATIONS) --raw-iterations $(FUZZ_RAW_ITERATIONS) --json-out build/spdk_semantic_fuzz_report.json --markdown-out build/spdk_semantic_fuzz_report.md --artifact-dir build/spdk_semantic_fuzz_artifacts

fuzz-semantic-silent-payments: fuzz-corpus
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_worker_fuzz.py --worker-lib "$(SILENT_PAYMENTS_SEMANTIC_LIB)" --seed $(FUZZ_SEED) --structured-iterations $(FUZZ_STRUCTURED_ITERATIONS) --raw-iterations $(FUZZ_RAW_ITERATIONS) --json-out build/silent_payments_semantic_fuzz_report.json --markdown-out build/silent_payments_semantic_fuzz_report.md --artifact-dir build/silent_payments_semantic_fuzz_artifacts

fuzz-semantic-bip352: fuzz-corpus
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_worker_fuzz.py --worker-lib "$(BIP352_SEMANTIC_LIB)" --seed $(FUZZ_SEED) --structured-iterations $(FUZZ_STRUCTURED_ITERATIONS) --raw-iterations $(FUZZ_RAW_ITERATIONS) --json-out build/bip352_semantic_fuzz_report.json --markdown-out build/bip352_semantic_fuzz_report.md --artifact-dir build/bip352_semantic_fuzz_artifacts

fuzz-semantic-go-bip352: fuzz-corpus
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -buildmode=c-shared -o ../../$(GO_BIP352_SEMANTIC_LIB) ./cmd/worker
	$(PYTHON) scripts/run_semantic_worker_fuzz.py --worker-lib "$(GO_BIP352_SEMANTIC_LIB)" --seed $(FUZZ_SEED) --structured-iterations $(FUZZ_STRUCTURED_ITERATIONS) --raw-iterations $(FUZZ_RAW_ITERATIONS) --json-out build/go_bip352_semantic_fuzz_report.json --markdown-out build/go_bip352_semantic_fuzz_report.md --artifact-dir build/go_bip352_semantic_fuzz_artifacts

fuzz-semantic-reference: fuzz-corpus
	$(PYTHON) scripts/run_semantic_adapter_fuzz.py --adapter-name reference --adapter-cmd "$(PYTHON) adapters/reference/semantic_adapter.py" --seed $(FUZZ_SEED) --iterations $(FUZZ_STRUCTURED_ITERATIONS) --json-out build/reference_semantic_adapter_fuzz_report.json --markdown-out build/reference_semantic_adapter_fuzz_report.md --artifact-dir build/reference_semantic_adapter_fuzz_artifacts

fuzz-semantic-spdk-adapter: fuzz-corpus
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_fuzz.py --adapter-name spdk-rust --adapter-cmd "./$(SPDK_ADAPTER_BIN)" --seed $(FUZZ_SEED) --iterations $(FUZZ_STRUCTURED_ITERATIONS) --json-out build/spdk_semantic_adapter_fuzz_report.json --markdown-out build/spdk_semantic_adapter_fuzz_report.md --artifact-dir build/spdk_semantic_adapter_fuzz_artifacts

fuzz-semantic-silent-payments-adapter: fuzz-corpus
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_fuzz.py --adapter-name silent-payments --adapter-cmd "./$(SILENT_PAYMENTS_ADAPTER_BIN)" --seed $(FUZZ_SEED) --iterations $(FUZZ_STRUCTURED_ITERATIONS) --json-out build/silent_payments_semantic_adapter_fuzz_report.json --markdown-out build/silent_payments_semantic_adapter_fuzz_report.md --artifact-dir build/silent_payments_semantic_adapter_fuzz_artifacts

fuzz-semantic-bip352-adapter: fuzz-corpus
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_fuzz.py --adapter-name bip352 --adapter-cmd "./$(BIP352_ADAPTER_BIN)" --seed $(FUZZ_SEED) --iterations $(FUZZ_STRUCTURED_ITERATIONS) --json-out build/bip352_semantic_adapter_fuzz_report.json --markdown-out build/bip352_semantic_adapter_fuzz_report.md --artifact-dir build/bip352_semantic_adapter_fuzz_artifacts

fuzz-semantic-go-bip352-adapter: fuzz-corpus
	@mkdir -p $(BUILD_DIR)
	cd $(GO_BIP352_MODULE_DIR) && $(GO) test $(GO_MODULE_FLAGS) ./...
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -o ../../$(GO_BIP352_ADAPTER_BIN) ./cmd/adapter
	$(PYTHON) scripts/run_semantic_adapter_fuzz.py --adapter-name go-bip352 --adapter-cmd "./$(GO_BIP352_ADAPTER_BIN)" --seed $(FUZZ_SEED) --iterations $(FUZZ_STRUCTURED_ITERATIONS) --json-out build/go_bip352_semantic_adapter_fuzz_report.json --markdown-out build/go_bip352_semantic_adapter_fuzz_report.md --artifact-dir build/go_bip352_semantic_adapter_fuzz_artifacts

fuzz-semantic-bdk-sp: fuzz-corpus
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bdk_sp_rust/Cargo.toml
	$(PYTHON) scripts/run_semantic_adapter_fuzz.py --adapter-name bdk-sp --adapter-cmd "./adapters/bdk_sp_rust/target/debug/sp-differ-semantic-adapter-bdk-sp" --seed $(FUZZ_SEED) --iterations $(FUZZ_STRUCTURED_ITERATIONS) --json-out build/bdk_sp_semantic_adapter_fuzz_report.json --markdown-out build/bdk_sp_semantic_adapter_fuzz_report.md --artifact-dir build/bdk_sp_semantic_adapter_fuzz_artifacts

fuzz-semantic-workers: fuzz-semantic-spdk fuzz-semantic-silent-payments fuzz-semantic-bip352 fuzz-semantic-go-bip352

fuzz-semantic-adapters: fuzz-semantic-reference fuzz-semantic-spdk-adapter fuzz-semantic-silent-payments-adapter fuzz-semantic-bip352-adapter fuzz-semantic-go-bip352-adapter fuzz-semantic-bdk-sp

cli-smoke:
	$(PYTHON) scripts/sp_differ_cli_smoke.py

parity-smoke: worker worker-rust
	$(PYTHON) scripts/byte_worker_parity_smoke.py

precommit-smoke:
	$(PYTHON) -m py_compile scripts/intake_semantic_regressions.py scripts/intake_semantic_regressions_smoke.py scripts/semantic_fuzz_minimizer.py scripts/semantic_fuzz_minimizer_smoke.py
	$(PYTHON) scripts/intake_semantic_regressions_smoke.py
	$(PYTHON) scripts/semantic_fuzz_minimizer_smoke.py

research-bip352:
	$(PYTHON) scripts/bip352_research_scorecard.py --candidates research/bip352_candidates.json --release-readiness build/sp_differ_release_readiness_live.json --json-out build/bip352_impl_research_scorecard.json --markdown-out build/bip352_impl_research_scorecard.md

research-bip352-deep:
	$(PYTHON) scripts/bip352_external_probe.py --candidates research/bip352_candidates.json --json-out build/bip352_external_probe.json --markdown-out build/bip352_external_probe.md
	$(PYTHON) scripts/bip352_research_scorecard.py --candidates research/bip352_candidates.json --release-readiness build/sp_differ_release_readiness_live.json --external-probe build/bip352_external_probe.json --json-out build/bip352_impl_research_scorecard.json --markdown-out build/bip352_impl_research_scorecard.md

release-report:
	$(PYTHON) sp_differ_cli.py status --profile release --json-out build/sp_differ_release_readiness.json --markdown-out build/sp_differ_release_readiness.md --require-green

release-evidence:
	@PROBE_EVIDENCE_ARGS=""; \
	if [ -f build/bip352_external_probe.json ]; then \
		PROBE_EVIDENCE_ARGS="$$PROBE_EVIDENCE_ARGS --path build/bip352_external_probe.json"; \
	fi; \
	if [ -f build/bip352_external_probe.md ]; then \
		PROBE_EVIDENCE_ARGS="$$PROBE_EVIDENCE_ARGS --path build/bip352_external_probe.md"; \
	fi; \
	$(PYTHON) scripts/generate_release_evidence_manifest.py --json-out build/release_evidence_manifest.json --markdown-out build/release_evidence_manifest.md --path build/sp_differ_release_readiness.json --path build/sp_differ_release_readiness.md --path build/sp_differ_release_readiness_live.json --path build/sp_differ_release_readiness_live.md $$PROBE_EVIDENCE_ARGS --path build/semantic_benchmark_summary.json --path build/semantic_benchmark_summary.md

release-sign: release
	./scripts/sign_release.sh --input-dir $(RELEASE_BUILD_DIR) --output-dir $(RELEASE_BUILD_DIR) --gpg-key "$(RELEASE_SIGN_GPG_KEY)"

release-prereqs:
	$(PYTHON) scripts/check_release_prereqs.py --json-out build/release_prereqs.json --markdown-out build/release_prereqs.md

package-release: release
	rm -rf $(RELEASE_DIST_DIR)
	mkdir -p $(RELEASE_DIST_DIR)
	cp $(RELEASE_RUNNER_BIN) $(RELEASE_DIST_DIR)/
	cp $(RELEASE_COMPARE_BIN) $(RELEASE_DIST_DIR)/
	cp $(RELEASE_CLI_BIN) $(RELEASE_DIST_DIR)/
	cp $(RELEASE_WORKER_LIB) $(RELEASE_DIST_DIR)/
	if [ -f $(RELEASE_KEYS_FILE) ]; then cp $(RELEASE_KEYS_FILE) $(RELEASE_DIST_DIR)/; fi
	if [ -f SIGNING.md ]; then cp SIGNING.md $(RELEASE_DIST_DIR)/; fi
	$(RELEASE_CLI_BIN) --check-integrity --json-out $(RELEASE_DIST_DIR)/release_integrity.json --markdown-out $(RELEASE_DIST_DIR)/release_integrity.md
	if [ -n "$(RELEASE_SIGN_GPG_KEY)" ]; then \
		./scripts/sign_release.sh --input-dir $(RELEASE_DIST_DIR) --output-dir $(RELEASE_DIST_DIR) --gpg-key "$(RELEASE_SIGN_GPG_KEY)"; \
	else \
		./scripts/sign_release.sh --input-dir $(RELEASE_DIST_DIR) --output-dir $(RELEASE_DIST_DIR) --allow-unsigned; \
	fi
	tar -czf $(RELEASE_ARCHIVE) -C $(BUILD_DIR)/dist $(LOCAL_RELEASE_NAME)

verify-packaged-release: package-release
	$(PYTHON) scripts/verify_packaged_release.py --archive $(RELEASE_ARCHIVE) $(VERIFY_PACKAGED_KEYS_ARG) $(VERIFY_PACKAGED_SIGNATURE_ARG) --json-out build/packaged_release_verification.json --markdown-out build/packaged_release_verification.md

official-release-ready: release-prereqs package-release
	$(PYTHON) scripts/verify_packaged_release.py --archive $(RELEASE_ARCHIVE) $(VERIFY_PACKAGED_KEYS_ARG) --require-signature --json-out build/packaged_release_verification.json --markdown-out build/packaged_release_verification.md

verify-release-evidence:
	$(PYTHON) scripts/verify_release_evidence.py --manifest build/release_evidence_manifest.json --json-out build/release_evidence_verification.json --markdown-out build/release_evidence_verification.md

maturity-signoff:
	$(MAKE) verify-release-live
	$(MAKE) bench-adapters
	$(MAKE) release-report
	$(MAKE) release-evidence
	$(MAKE) verify-release-evidence

verify-quick:
	$(PYTHON) sp_differ_cli.py verify --profile quick --python $(PYTHON)

verify-release:
	$(PYTHON) sp_differ_cli.py verify --profile release --python $(PYTHON)

verify-release-live:
	$(PYTHON) sp_differ_cli.py verify --profile release --python $(PYTHON) --refresh-external-probe --json-out build/sp_differ_release_readiness_live.json --markdown-out build/sp_differ_release_readiness_live.md

verify-release-attestation:
	$(PYTHON) scripts/verify_release_attestation.py $(RELEASE_ARCHIVE) $(if $(strip $(RELEASE_ATTESTATION_REPO)),--repo $(RELEASE_ATTESTATION_REPO),) $(if $(strip $(RELEASE_ATTESTATION_SOURCE_REF)),--source-ref $(RELEASE_ATTESTATION_SOURCE_REF),)

vectors-check: runner worker worker-rust vectors-v2
	$(PYTHON) scripts/audit_bip352_vectors.py tests/vectors/bip352/official/send_and_receive_test_vectors.json --json-out build/bip352_vector_audit.json
	$(PYTHON) scripts/generate_bip352_projected_cases.py --check
	$(PYTHON) scripts/run_bip352_vector_smoke.py --worker cpp
	$(PYTHON) scripts/run_bip352_vector_smoke.py --worker $(RUST_LIB_DST)

vectors: vectors-check
	$(MAKE) oracle

vectors-refresh:
	$(PYTHON) scripts/fetch_bip352_vectors.py
	$(PYTHON) scripts/generate_bip352_v2_cases.py
	$(PYTHON) scripts/generate_bip352_projected_cases.py

$(CORE_SMOKE_BIN): $(CORE_SMOKE_SRC) $(CORE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(CORE_SMOKE_SRC) $(CORE_SRC)

$(CASE_SMOKE_BIN): $(CASE_SMOKE_SRC) $(CORE_SRC) $(CASE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(CASE_SMOKE_SRC) $(CORE_SRC) $(CASE_SRC)

$(VALIDATE_SMOKE_BIN): $(VALIDATE_SMOKE_SRC) $(CORE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(VALIDATE_SMOKE_SRC) $(CORE_SRC) $(VALIDATE_SRC)

release: $(RELEASE_WORKER_LIB) $(RELEASE_RUNNER_BIN) $(RELEASE_COMPARE_BIN) $(RELEASE_CLI_BIN)

$(RELEASE_WORKER_LIB): $(WORKER_SRC) $(CASE_SRC)
	@mkdir -p $(RELEASE_BUILD_DIR)
	$(CXX) $(RELEASE_CXXFLAGS) $(SHARED_FLAG) -o $@ $(WORKER_SRC) $(CASE_SRC) $(SECP256K1_CFLAGS) $(SECP256K1_LIBS)
	-$(RELEASE_STRIP) -S $@ 2>/dev/null || $(RELEASE_STRIP) $@

$(RELEASE_RUNNER_BIN): $(RELEASE_VERSION_STAMP) $(RUNNER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(RELEASE_BUILD_DIR)
	$(CXX) $(RELEASE_CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(RUNNER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)
	-$(RELEASE_STRIP) -S $@ 2>/dev/null || $(RELEASE_STRIP) $@

$(RELEASE_COMPARE_BIN): $(RELEASE_VERSION_STAMP) $(COMPARE_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(RELEASE_BUILD_DIR)
	$(CXX) $(RELEASE_CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(COMPARE_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)
	-$(RELEASE_STRIP) -S $@ 2>/dev/null || $(RELEASE_STRIP) $@

$(RELEASE_CLI_BIN): $(RELEASE_VERSION_STAMP) $(CLI_SRC) $(REPORTER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(RELEASE_BUILD_DIR)
	$(CXX) $(RELEASE_CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(CLI_SRC) $(REPORTER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)
	-$(RELEASE_STRIP) -S $@ 2>/dev/null || $(RELEASE_STRIP) $@

$(SANITIZE_WORKER_LIB): $(WORKER_SRC) $(CASE_SRC)
	@mkdir -p $(SANITIZE_BUILD_DIR)
	$(SANITIZE_CXX) $(SANITIZE_CXXFLAGS) $(SHARED_FLAG) -o $@ $(WORKER_SRC) $(CASE_SRC) $(SECP256K1_CFLAGS) $(SECP256K1_LIBS)

$(SANITIZE_RUNNER_BIN): $(RUNNER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(SANITIZE_BUILD_DIR)
	$(SANITIZE_CXX) $(SANITIZE_CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(RUNNER_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)

$(SANITIZE_COMPARE_BIN): $(COMPARE_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(SANITIZE_BUILD_DIR)
	$(SANITIZE_CXX) $(SANITIZE_CXXFLAGS) $(BUILD_DEFINES) $(THREAD_FLAGS) $(SECP256K1_CFLAGS) $(OPENSSL_CFLAGS) -o $@ $(COMPARE_SRC) $(WORKER_API_SRC) $(SEMANTIC_BRIDGE_SRC) $(SEMANTIC_JSON_SRC) $(SEMANTIC_CONTRACT_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS) $(THREAD_FLAGS) $(SECP256K1_LIBS) $(OPENSSL_LIBS)

$(SANITIZE_CORE_SMOKE_BIN): $(CORE_SMOKE_SRC) $(CORE_SRC)
	@mkdir -p $(SANITIZE_BUILD_DIR)
	$(SANITIZE_CXX) $(SANITIZE_CXXFLAGS) -o $@ $(CORE_SMOKE_SRC) $(CORE_SRC)

$(SANITIZE_CASE_SMOKE_BIN): $(CASE_SMOKE_SRC) $(CORE_SRC) $(CASE_SRC)
	@mkdir -p $(SANITIZE_BUILD_DIR)
	$(SANITIZE_CXX) $(SANITIZE_CXXFLAGS) -o $@ $(CASE_SMOKE_SRC) $(CORE_SRC) $(CASE_SRC)

$(SANITIZE_VALIDATE_SMOKE_BIN): $(VALIDATE_SMOKE_SRC) $(CORE_SRC) $(VALIDATE_SRC)
	@mkdir -p $(SANITIZE_BUILD_DIR)
	$(SANITIZE_CXX) $(SANITIZE_CXXFLAGS) -o $@ $(VALIDATE_SMOKE_SRC) $(CORE_SRC) $(VALIDATE_SRC)

smoke: worker runner compare cli
	@echo "=== Smoke Test 1: valid fixture produces exit 0 ==="
	$(RUNNER_BIN) tests/smoke/valid_case.json > /tmp/smoke_output_a.json
	@echo "Runner exit: $$?"
	@echo "=== Smoke Test 2: corrupted fixture produces non-zero exit ==="
	$(RUNNER_BIN) tests/smoke/corrupted_case.json > /tmp/smoke_output_b.json; \
	  EXIT=$$?; \
	  if [ $$EXIT -eq 0 ]; then \
	    echo "FAIL: corrupted input returned exit 0 - smoke test is not catching errors"; \
	    exit 1; \
	  else \
	    echo "OK: corrupted input correctly returned exit $$EXIT"; \
	  fi
	@echo "=== Smoke Test 3: comparator catches mismatch ==="
	@echo '{"version":1,"status":"ok","canonical_output":"aabb"}' > /tmp/s_a.json
	@echo '{"version":1,"status":"ok","canonical_output":"ccdd"}' > /tmp/s_b.json
	$(COMPARE_BIN) /tmp/s_a.json /tmp/s_b.json; \
	  EXIT=$$?; \
	  if [ $$EXIT -ne 1 ]; then \
	    echo "FAIL: comparator did not return exit 1 on mismatch (got $$EXIT)"; \
	    exit 1; \
	  else \
	    echo "OK: comparator correctly returned exit 1 on mismatch"; \
	  fi
	@echo "=== Smoke Test 4: comparator passes identical outputs ==="
	$(COMPARE_BIN) /tmp/s_a.json /tmp/s_a.json; \
	  EXIT=$$?; \
	  if [ $$EXIT -ne 0 ]; then \
	    echo "FAIL: comparator returned non-zero on identical inputs (got $$EXIT)"; \
	    exit 1; \
	  else \
	    echo "OK: comparator correctly returned exit 0 on match"; \
	  fi
	@echo "=== Smoke Test 5: comparator ignores nested fixture fields ==="
	@echo '{"nested":{"canonical_output":"aabb"},"canonical_output":"ccdd"}' > /tmp/s_nested_a.json
	@echo '{"nested":{"canonical_output":"aabb"},"canonical_output":"eeff"}' > /tmp/s_nested_b.json
	$(COMPARE_BIN) /tmp/s_nested_a.json /tmp/s_nested_b.json; \
	  EXIT=$$?; \
	  if [ $$EXIT -ne 1 ]; then \
	    echo "FAIL: comparator accepted nested canonical_output instead of the top-level field (got $$EXIT)"; \
	    exit 1; \
	  else \
	    echo "OK: comparator now uses only top-level fixture fields"; \
	  fi
	@echo "=== Smoke Test 6: mixed official suite validates send/receive parity ==="
	$(CLI_BIN) --suite-name official-mixed-smoke \
	  --json-out build/official_mixed_smoke.json \
	  --markdown-out build/official_mixed_smoke.md \
	  --case tests/vectors/bip352/derived/v1/official_case_06_send_00.hex \
	  --case tests/vectors/bip352/derived/v1/official_case_07_send_00.hex \
	  --case tests/vectors/bip352/derived/v2/official_case_19_send_00.hex \
	  --case tests/vectors/bip352/derived/v2/official_case_22_send_00.hex \
	  --case tests/vectors/bip352/derived/v2/official_case_25_send_00.hex \
	  --case tests/vectors/bip352/derived/v2/official_case_26_send_00.hex \
	  --case tests/vectors/bip352/derived/v2/official_case_19_receive_00.hex \
	  --case tests/vectors/bip352/derived/v2/official_case_25_receive_00.hex
	@echo "=== All smoke tests passed ==="

sanitize-smoke: $(SANITIZE_WORKER_LIB) $(SANITIZE_RUNNER_BIN) $(SANITIZE_COMPARE_BIN) $(SANITIZE_CORE_SMOKE_BIN) $(SANITIZE_CASE_SMOKE_BIN) $(SANITIZE_VALIDATE_SMOKE_BIN)
	$(SANITIZE_RUN_ENV) $(SANITIZE_CORE_SMOKE_BIN)
	$(SANITIZE_RUN_ENV) $(SANITIZE_CASE_SMOKE_BIN)
	$(SANITIZE_RUN_ENV) $(SANITIZE_VALIDATE_SMOKE_BIN)
	$(SANITIZE_RUN_ENV) $(SANITIZE_RUNNER_BIN) tests/vectors/example.hex --worker $(SANITIZE_WORKER_LIB)
	@echo '{"version":1,"status":"ok","canonical_output":"aabb"}' > /tmp/sp_differ_sanitize_a.json
	@echo '{"version":1,"status":"ok","canonical_output":"ccdd"}' > /tmp/sp_differ_sanitize_b.json
	$(SANITIZE_RUN_ENV) $(SANITIZE_COMPARE_BIN) /tmp/sp_differ_sanitize_a.json /tmp/sp_differ_sanitize_b.json; \
	  EXIT=$$?; \
	  if [ $$EXIT -ne 1 ]; then \
	    echo "FAIL: sanitized comparator did not return exit 1 on mismatch (got $$EXIT)"; \
	    exit 1; \
	  fi
	@echo '{"nested":{"canonical_output":"aabb"},"canonical_output":"ccdd"}' > /tmp/sp_differ_sanitize_nested_a.json
	@echo '{"nested":{"canonical_output":"aabb"},"canonical_output":"eeff"}' > /tmp/sp_differ_sanitize_nested_b.json
	$(SANITIZE_RUN_ENV) $(SANITIZE_COMPARE_BIN) /tmp/sp_differ_sanitize_nested_a.json /tmp/sp_differ_sanitize_nested_b.json; \
	  EXIT=$$?; \
	  if [ $$EXIT -ne 1 ]; then \
	    echo "FAIL: sanitized comparator accepted nested canonical_output (got $$EXIT)"; \
	    exit 1; \
	  fi
	$(SANITIZE_RUN_ENV) $(PYTHON) scripts/semantic_runner_smoke.py --runner $(SANITIZE_RUNNER_BIN) --compare $(SANITIZE_COMPARE_BIN) --cxx $(SANITIZE_CXX) --cxxflags "$(SANITIZE_CXXFLAGS)"

smoke-rust: check runner worker-rust
	$(RUNNER_BIN) tests/vectors/example.hex --worker $(RUST_LIB_DST)

diff: compare worker-rust check parity-smoke
	$(COMPARE_BIN) tests/vectors/example.hex --left cpp --right rust

semantic-smoke: runner compare
	$(PYTHON) scripts/semantic_runner_smoke.py

semantic-worker-libs:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/spdk_rust/Cargo.toml
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/silent_payments_rust/Cargo.toml
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path adapters/bip352_rust/Cargo.toml
	cd $(GO_BIP352_MODULE_DIR) && $(GO) build $(GO_MODULE_FLAGS) -buildmode=c-shared -o ../../$(GO_BIP352_SEMANTIC_LIB) ./cmd/worker

worker-rust:
	$(CARGO) build $(CARGO_LOCKED_ARGS) --manifest-path workers/rust/Cargo.toml --release
	@mkdir -p $(BUILD_DIR)
	cp $(RUST_LIB_SRC) $(RUST_LIB_DST)

clean:
	rm -rf $(BUILD_DIR)
