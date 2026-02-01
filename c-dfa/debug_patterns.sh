cd /home/panz/osrc/lms-test/readonlybox/c-dfa

# Count how many patterns we have and show the ones around pattern 17
head -60 patterns_acceptance_category_test.txt | grep -n "^\["

# Check which pattern is index 17 (0-indexed, so it's the 18th pattern)
echo ""
echo "Pattern at index 17 (0-indexed):"
grep -n "^\[" patterns_acceptance_category_test.txt | head -20 | tail -5

# Show all PatternIds in the NFA file to understand the mapping
echo ""
echo "All PatternIds in NFA (showing unique):"
grep "PatternId:" test_accept.nfa | sort | uniq -c | head -20

#bash