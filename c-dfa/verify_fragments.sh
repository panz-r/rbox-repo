#!/bin/bash
# Verify fragment lookup is working

cd /home/panz/osrc/lms-test/readonlybox/c-dfa

echo "=== Checking fragment lookup ==="
./tools/nfa_builder ./tools/alphabet.map ./patterns_acceptance_category_test.txt ./test_accept.nfa 2>&1 | grep -E "(Looking up fragment.*b|found|pending_loop_char|DEBUG.*handler)" | head -20

echo ""
echo "=== Checking NFA accepting states ==="
grep -B1 "CategoryMask: 0x01" test_accept.nfa | grep "State" | head -5
grep -B1 "CategoryMask: 0x02" test_accept.nfa | grep "State" | head -5

echo ""
echo "=== Check specific states for a((b))+ pattern ==="
# Pattern a((b))+ should be around states 80-100
grep -A10 "^State 95:" test_accept.nfa

echo ""
echo "Done!"

#bash