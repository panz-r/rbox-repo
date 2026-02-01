#!/bin/bash
# Test the acceptance category fix with detailed debug

cd /home/panz/osrc/lms-test/readonlybox/c-dfa

echo "Building NFA..."
./tools/nfa_builder ./tools/alphabet.map ./patterns_acceptance_category_test.txt ./test_accept.nfa 2>&1 | grep -E "(ACCEPTANCE|Wrote)"

echo ""
echo "Checking NFA states for pattern_id..."
grep -A2 "State 95:" ./test_accept.nfa
grep -A2 "State 96:" ./test_accept.nfa  
grep -A2 "State 97:" ./test_accept.nfa

echo ""
echo "Converting NFA to DFA..."
timeout 10 ./tools/nfa2dfa_advanced ./test_accept.nfa ./test_accept.dfa 2>&1 | grep -E "(Converted|Error|States)" || echo "Conversion may have timed out or had issues"

echo ""
echo "Checking DFA debug for state 32..."
./tools/nfa2dfa_advanced ./test_accept.nfa ./test_accept.dfa 2>&1 | grep "dfa_add_state(32)"

echo ""
echo "Done!"