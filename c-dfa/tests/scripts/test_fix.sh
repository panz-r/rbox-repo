#!/bin/bash
# Test the acceptance category fix

cd "$(dirname "$0")/../.."

echo "Building NFA..."
./tools/nfa_builder ./tools/alphabet.map ./patterns_acceptance_category_test.txt ./test_accept.nfa 2>&1 | grep -v "^//DEBUG"

echo ""
echo "Converting NFA to DFA..."
./tools/nfa2dfa_advanced ./test_accept.nfa ./test_accept.dfa 2>&1

echo ""
echo "Running acceptance tests..."
./dfa_test --acceptance-test ./test_accept.dfa 2>&1

echo ""
echo "Done!"