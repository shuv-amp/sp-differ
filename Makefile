SHELL := /bin/sh

CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -fPIC

BUILD_DIR := build
WORKER_SRC := workers/cpp/sp_differ_worker.cpp
RUNNER_SRC := src/runner/sp_differ_runner.cpp

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

.PHONY: worker runner smoke clean

worker: $(WORKER_LIB)

$(WORKER_LIB): $(WORKER_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(SHARED_FLAG) -o $@ $<

runner: $(RUNNER_BIN)

$(RUNNER_BIN): $(RUNNER_SRC)
	@mkdir -p $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $< $(DL_FLAGS)

smoke: worker runner
	$(RUNNER_BIN) tests/vectors/example.hex

clean:
	rm -rf $(BUILD_DIR)
