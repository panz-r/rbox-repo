# Makefile for read-only command wrappers

.PHONY: all build clean install uninstall test unit-test integration-test fmt

all: build

build:
	mkdir -p bin
	go build -o bin/ro-git ./cmd/ro-git
	go build -o bin/ro-find ./cmd/ro-find
	go build -o bin/ro-ls ./cmd/ro-ls
	go build -o bin/ro-cat ./cmd/ro-cat
	go build -o bin/ro-grep ./cmd/ro-grep
	go build -o bin/ro-head ./cmd/ro-head
	go build -o bin/ro-tail ./cmd/ro-tail
	go build -o bin/ro-timeout ./cmd/ro-timeout
	go build -o bin/ro-echo ./cmd/ro-echo
	go build -o bin/ro-date ./cmd/ro-date
	go build -o bin/ro-cd ./cmd/ro-cd
	go build -o bin/ro-bash ./cmd/ro-bash
	go build -o bin/ro-sort ./cmd/ro-sort
	go build -o bin/ro-ulimit ./cmd/ro-ulimit
	go build -o bin/ro-sed ./cmd/ro-sed
	go build -o bin/ro-chmod ./cmd/ro-chmod
	go build -o bin/ro-chown ./cmd/ro-chown
	go build -o bin/ro-mkdir ./cmd/ro-mkdir
	go build -o bin/ro-rmdir ./cmd/ro-rmdir
	go build -o bin/ro-ln ./cmd/ro-ln

clean:
	rm -rf bin

install:
	mkdir -p $(DESTDIR)/usr/local/bin
	install -m 755 bin/ro-git $(DESTDIR)/usr/local/bin/ro-git
	install -m 755 bin/ro-find $(DESTDIR)/usr/local/bin/ro-find
	install -m 755 bin/ro-ls $(DESTDIR)/usr/local/bin/ro-ls
	install -m 755 bin/ro-cat $(DESTDIR)/usr/local/bin/ro-cat
	install -m 755 bin/ro-grep $(DESTDIR)/usr/local/bin/ro-grep
	install -m 755 bin/ro-head $(DESTDIR)/usr/local/bin/ro-head
	install -m 755 bin/ro-tail $(DESTDIR)/usr/local/bin/ro-tail
	install -m 755 bin/ro-timeout $(DESTDIR)/usr/local/bin/ro-timeout
	install -m 755 bin/ro-echo $(DESTDIR)/usr/local/bin/ro-echo
	install -m 755 bin/ro-date $(DESTDIR)/usr/local/bin/ro-date
	install -m 755 bin/ro-cd $(DESTDIR)/usr/local/bin/ro-cd
	install -m 755 bin/ro-bash $(DESTDIR)/usr/local/bin/ro-bash
	install -m 755 bin/ro-sort $(DESTDIR)/usr/local/bin/ro-sort
	install -m 755 bin/ro-ulimit $(DESTDIR)/usr/local/bin/ro-ulimit
	install -m 755 bin/ro-sed $(DESTDIR)/usr/local/bin/ro-sed
	install -m 755 bin/ro-chmod $(DESTDIR)/usr/local/bin/ro-chmod
	install -m 755 bin/ro-chown $(DESTDIR)/usr/local/bin/ro-chown
	install -m 755 bin/ro-mkdir $(DESTDIR)/usr/local/bin/ro-mkdir
	install -m 755 bin/ro-rmdir $(DESTDIR)/usr/local/bin/ro-rmdir
	install -m 755 bin/ro-ln $(DESTDIR)/usr/local/bin/ro-ln

uninstall:
	rm -f $(DESTDIR)/usr/local/bin/ro-git
	rm -f $(DESTDIR)/usr/local/bin/ro-find
	rm -f $(DESTDIR)/usr/local/bin/ro-ls
	rm -f $(DESTDIR)/usr/local/bin/ro-cat
	rm -f $(DESTDIR)/usr/local/bin/ro-grep
	rm -f $(DESTDIR)/usr/local/bin/ro-head
	rm -f $(DESTDIR)/usr/local/bin/ro-tail
	rm -f $(DESTDIR)/usr/local/bin/ro-timeout
	rm -f $(DESTDIR)/usr/local/bin/ro-echo
	rm -f $(DESTDIR)/usr/local/bin/ro-date
	rm -f $(DESTDIR)/usr/local/bin/ro-cd
	rm -f $(DESTDIR)/usr/local/bin/ro-bash
	rm -f $(DESTDIR)/usr/local/bin/ro-sort
	rm -f $(DESTDIR)/usr/local/bin/ro-ulimit
	rm -f $(DESTDIR)/usr/local/bin/ro-sed
	rm -f $(DESTDIR)/usr/local/bin/ro-chmod
	rm -f $(DESTDIR)/usr/local/bin/ro-chown
	rm -f $(DESTDIR)/usr/local/bin/ro-mkdir
	rm -f $(DESTDIR)/usr/local/bin/ro-rmdir
	rm -f $(DESTDIR)/usr/local/bin/ro-ln

# Run all tests
test: unit-test integration-test

# Run unit tests
unit-test:
	@echo "Running unit tests..."
	go test -v ./internal/rogit/...
	go test -v ./internal/rofind/...
	go test -v ./internal/rols/...
	go test -v ./internal/rocat/...
	go test -v ./internal/rogrep/...
	go test -v ./internal/rohead/...
	go test -v ./internal/rotail/...
	go test -v ./internal/rotimeout/...
	go test -v ./internal/roecho/...
	go test -v ./internal/rodate/...
	go test -v ./internal/rocd/...
	go test -v ./internal/robash/...
	go test -v ./internal/rosort/...
	go test -v ./internal/roulimit/...
	go test -v ./internal/rosed/...
	go test -v ./internal/rochmod/...
	go test -v ./internal/rochown/...
	go test -v ./internal/romkdir/...
	go test -v ./internal/rormdir/...
	go test -v ./internal/roln/...

# Run integration tests
integration-test:
	@echo "Running integration tests..."
	go test -v ./test/...

# Quick test (original simple test)
quick-test:
	@echo "Testing ro-git with safe commands..."
	./bin/ro-git --version
	@echo "Testing ro-git with blocked commands..."
	./bin/ro-git add . || echo "Correctly blocked git add"
	@echo "Testing ro-find with safe commands..."
	./bin/ro-find . -name "*.go" -type f
	@echo "Testing ro-find with blocked commands..."
	./bin/ro-find . -name "*.tmp" -exec rm {} \; || echo "Correctly blocked find -exec"
	@echo "Testing ro-ls with safe commands..."
	./bin/ro-ls -la
	@echo "Testing ro-ls with blocked commands..."
	./bin/ro-ls ">output.txt" || echo "Correctly blocked ls redirect"
	@echo "Testing ro-cat with safe commands..."
	./bin/ro-cat Makefile | head -5
	@echo "Testing ro-cat with blocked commands..."
	./bin/ro-cat ">output.txt" || echo "Correctly blocked cat redirect"
	@echo "Testing ro-grep with safe commands..."
	./bin/ro-grep -r "package" . | head -3
	@echo "Testing ro-grep with blocked commands..."
	./bin/ro-grep ">output.txt" || echo "Correctly blocked grep redirect"

fmt:
	gofmt -w .

# Test coverage
coverage:
	@echo "Generating test coverage..."
	go test -coverprofile=coverage.out ./internal/rogit/... ./internal/rofind/... ./internal/rols/... ./internal/rocat/... ./internal/rogrep/... ./internal/rohead/... ./internal/rotail/... ./internal/rotimeout/... ./internal/roecho/... ./internal/rodate/... ./internal/rocd/... ./internal/robash/... ./internal/rosort/... ./internal/roulimit/... ./internal/rosed/... ./internal/rochmod/... ./internal/rochown/... ./internal/romkdir/... ./internal/rormdir/... ./internal/roln/... ./test/...
	go tool cover -html=coverage.out