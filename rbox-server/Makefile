# Makefile for rbox-server
# Delegates to project magefile

.PHONY: all build clean test run

all: build

build:
	cd .. && mage deps && mage BuildBinaries
	cp ../bin/readonlybox-server ./rbox-server

clean:
	rm -f ./rbox-server

test:
	cd .. && mage Test

run: build
	./rbox-server
