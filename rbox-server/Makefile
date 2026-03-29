# Makefile for rbox-server
# Go server with C library bindings (rbox-protocol, shellsplit)

GO := go
GOFLAGS := -tags cgo

# Paths to C libraries
RBOX_PROTO := ../rbox-protocol
SHELLSPLIT := ../shellsplit
C_DFA := ../c-dfa

# CGO environment
export CGO_LDFLAGS = -L$(RBOX_PROTO) -L$(SHELLSPLIT) -lrbox_protocol -lshellsplit -lpthread -lm
export CGO_CFLAGS = -I$(RBOX_PROTO)/include -I$(SHELLSPLIT)/include

# Allow CC override (propagated from mage)
CC ?= gcc
export CC

# Default target - build everything including C libraries
all: libs rbox-server

# Alias for all (used by mage)
build: all

# Build C libraries if needed
libs:
	$(MAKE) -C $(C_DFA) libdfa_eval.a
	$(MAKE) -C $(SHELLSPLIT) libshellsplit.a
	$(MAKE) -C $(RBOX_PROTO) librbox_protocol.a

rbox-server: go.mod go.sum *.go libs
	$(GO) build $(GOFLAGS) -o rbox-server .

# Test target (runs go tests with CGO)
test: libs
	CGO_LDFLAGS="-L$(RBOX_PROTO) -L$(SHELLSPLIT) -lrbox_protocol -lshellsplit -lpthread -lm" \
	CGO_CFLAGS="-I$(RBOX_PROTO)/include -I$(SHELLSPLIT)/include" \
	$(GO) test -v ./...

# Clean
clean:
	rm -f rbox-server
	$(GO) clean
	$(MAKE) -C $(C_DFA) clean 2>/dev/null || true
	$(MAKE) -C $(SHELLSPLIT) clean 2>/dev/null || true
	$(MAKE) -C $(RBOX_PROTO) clean 2>/dev/null || true

# Run without building
run: rbox-server
	./rbox-server

.PHONY: all build clean test run libs
