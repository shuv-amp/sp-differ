HOST_UNAME_S := $(shell uname -s)

CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2

SECP256K1_CFLAGS := $(shell pkg-config --cflags secp256k1 2>/dev/null || pkg-config --cflags libsecp256k1 2>/dev/null)
SECP256K1_LIBS := $(shell pkg-config --libs secp256k1 2>/dev/null || pkg-config --libs libsecp256k1 2>/dev/null)
ifeq ($(HOST_UNAME_S),Darwin)
ifeq ($(strip $(SECP256K1_CFLAGS)),)
SECP256K1_CFLAGS := -I/opt/homebrew/include
endif
ifeq ($(strip $(SECP256K1_LIBS)),)
SECP256K1_LIBS := -L/opt/homebrew/lib -lsecp256k1
endif
endif

TEST_BIN := test_taproot_negation

.PHONY: clean

test_taproot_negation: test_taproot_negation.cpp sp_differ_worker.cpp ../../src/core/case.cpp
	$(CXX) $(CXXFLAGS) -o $@ test_taproot_negation.cpp sp_differ_worker.cpp ../../src/core/case.cpp $(SECP256K1_CFLAGS) $(SECP256K1_LIBS)

clean:
	rm -f $(TEST_BIN)
