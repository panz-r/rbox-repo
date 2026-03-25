# Makefile for rbox-server
# Go server with C library bindings (rbox-protocol, shellsplit)

GO := go
GOFLAGS := -tags cgo

# Paths to C libraries
RBOX_PROTO := ../rbox-protocol
SHELLSPLIT := ../shellsplit

# CGO environment
export CGO_LDFLAGS = -L$(RBOX_PROTO) -L$(SHELLSPLIT) -lrbox_protocol -lshellsplit -lpthread -lm
export CGO_CFLAGS = -I$(RBOX_PROTO)/include -I$(SHELLSPLIT)/include

# Allow CC override (propagated from mage)
CC ?= gcc
export CC

# Default target
all: rbox-server

rbox-server: go.mod go.sum *.go
	$(GO) build $(GOFLAGS) -o rbox-server .

# Test target (runs go tests)
test:
	$(GO) test ./...

# Clean
clean:
	rm -f rbox-server

# Run without building
run:
	$(GO) run .

.PHONY: all clean test run
