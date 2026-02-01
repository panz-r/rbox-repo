#!/bin/bash
# Debug the quantifier pattern parsing

cd /home/panz/osrc/lms-test/readonlybox/c-dfa

echo "=== Building NFA with debug output ==="
./tools/nfa_builder ./tools/alphabet.map ./patterns_acceptance_category_test.txt ./test_accept.nfa 2>&1 | grep -E "(DEBUG|fragment|Looking up|B\]|C\]|D\])" | head -40

echo ""
echo "=== Checking if fragment B is in the NFA ==="
grep -A3 "Fragment:" test_accept.nfa | head -20

echo ""
echo "=== Checking state transitions for pattern a((b))+ ==="
# Look for states that might be related to the a((b))+ pattern
# Pattern index 17 should be around states 80-100
grep -B2 -A5 "PatternId: 17" test_accept.nfa | head -40

echo ""
echo "Done!"

#bash