cd /home/panz/osrc/lms-test/readonlybox/c-dfa

echo "=== Pattern at index 17 ==="
grep -n "^\[" patterns_acceptance_category_test.txt | head -20 | tail -5

echo ""
echo "=== All PatternIds in NFA (counting unique) ==="
grep "PatternId:" test_accept.nfa | sort | uniq -c | sort -rn | head -10

echo ""
echo "=== States with PatternId 17 ==="
grep -B2 "PatternId: 17" test_accept.nfa | grep "State" | wc -l
echo "Count above should be 4 (states with PatternId 17)"

#bash