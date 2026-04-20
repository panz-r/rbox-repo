# CMake wrapper Makefile - delegates to cmake build
# This exists for backward compatibility with rbox-wrap Makefile which uses "make -C rbox-protocol"

all:
	mkdir -p build
	cmake -S . -B build
	cmake --build build

test:
	cd build && ctest --output-on-failure

clean:
	rm -rf build
	find . -name "*.so*" -type l -delete 2>/dev/null || true

.PHONY: all test clean