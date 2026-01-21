#!/bin/bash
# test.sh
echo "=== Test 1: Allowed command (should work normally) ==="
./security_tracer /bin/ls -la

echo -e "\n=== Test 2: Denied command (should be replaced) ==="
./security_tracer /bin/cat unsafefile.txt

echo -e "\n=== Test 3: Complex command ==="
./security_tracer /bin/bash -c "echo Hello; cat unsafefile.txt; echo World"

echo -e "\n=== Test 4: Check return code ==="
./security_tracer /bin/sh -c "cat unsafefile.txt; echo Exit code: \$?"

echo -e "\n=== Test 5: Pipe chain ==="
./security_tracer /bin/sh -c "cat unsafefile.txt | wc -l"
