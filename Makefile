SHELL := /bin/sh

CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -fPIC

BUILD_DIR := build
WORKER_SRC := workers/cpp/sp_differ_worker.cpp
RUNNER_SRC := src/runner/sp_differ_runner.cpp
COMPARE_SRC := src/runner/sp_differ_compare.cpp
WORKER_API_SRC := src/runner/worker.cpp
CORE_SRC := src/core/io.cpp
CORE_SMOKE_SRC := src/core/io_smoke.cpp
CASE_SRC := src/core/case.cpp
CASE_SMOKE_SRC := src/core/case_smoke.cpp
VALIDATE_SRC := src/core/validate.cpp
VALIDATE_SMOKE_SRC := src/core/validate_smoke.cpp

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LIB_EXT := dylib
  SHARED_FLAG := -shared
  DL_FLAGS :=
else ifeq ($(OS),Windows_NT)
  LIB_EXT := dll
  SHARED_FLAG := -shared
  DL_FLAGS :=
else
  LIB_EXT := so
  SHARED_FLAG := -shared
  DL_FLAGS := -ldl
endif

WORKER_LIB := $(BUILD_DIR)/libsp_differ_worker.$(LIB_EXT)
RUNNER_BIN := $(BUILD_DIR)/sp_differ_runner
COMPARE_BIN := $(BUILD_DIR)/sp_differ_compare
CORE_SMOKE_BIN := $(BUILD_DIR)/sp_differ_core_io_smoke
CASE_SMOKE_BIN := $(BUILD_DIR)/sp_differ_core_case_smoke
VALIDATE_SMOKE_BIN := $(BUILD_DIR)/sp_differ_core_validate_smoke
RUST_LIB_NAME := sp_differ_worker_rust
RUST_TARGET_DIR := workers/rust/target/release
ifeq ($(OS),Windows_NT)
  RUST_LIB_FILE := $(RUST_LIB_NAME).$(LIB_EXT)
else
  RUST_LIB_FILE := lib$(RUST_LIB_NAME).$(LIB_EXT)
endif
RUST_LIB_SRC := $(RUST_TARGET_DIR)/$(RUST_LIB_FILE)
RUST_LIB_DST := $(BUILD_DIR)/$(RUST_LIB_FILE)

.PHONY: worker runner compare smoke check clean
.PHONY: worker-rust
.PHONY: smoke-rust
.PHONY: diff

worker: $(WORKER_LIB)

$(WORKER_LIB): $(WORKER_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(SHARED_FLAG) -o $@ $(WORKER_SRC) $(CASE_SRC)

runner: $(RUNNER_BIN)

$(RUNNER_BIN): $(RUNNER_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(RUNNER_SRC) $(WORKER_API_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS)

compare: $(COMPARE_BIN)

$(COMPARE_BIN): $(COMPARE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(COMPARE_SRC) $(WORKER_API_SRC) $(CORE_SRC) $(CASE_SRC) $(VALIDATE_SRC) $(DL_FLAGS)

check: $(CORE_SMOKE_BIN) $(CASE_SMOKE_BIN) $(VALIDATE_SMOKE_BIN)
	$(CORE_SMOKE_BIN)
	$(CASE_SMOKE_BIN)
	$(VALIDATE_SMOKE_BIN)

$(CORE_SMOKE_BIN): $(CORE_SMOKE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(CORE_SMOKE_SRC) $(CORE_SRC)

$(CASE_SMOKE_BIN): $(CASE_SMOKE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(CASE_SMOKE_SRC) $(CORE_SRC) $(CASE_SRC)

$(VALIDATE_SMOKE_BIN): $(VALIDATE_SMOKE_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $(VALIDATE_SMOKE_SRC) $(CORE_SRC) $(VALIDATE_SRC)

smoke: check worker runner
	$(RUNNER_BIN) tests/vectors/example.hex

smoke-rust: check runner worker-rust
	$(RUNNER_BIN) tests/vectors/example.hex --worker $(RUST_LIB_DST)

diff: compare worker-rust check
	$(COMPARE_BIN) tests/vectors/example.hex --left cpp --right rust

worker-rust:
	cargo build --manifest-path workers/rust/Cargo.toml --release
	@mkdir -p $(BUILD_DIR)
	cp $(RUST_LIB_SRC) $(RUST_LIB_DST)

clean:
	rm -rf $(BUILD_DIR)
