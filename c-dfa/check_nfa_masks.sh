cd /home/panz/osrc/lms-test/readonlybox/c-dfa

echo "=== Check states with PatternId 17 (a((b))+) ==="
grep -B2 "PatternId: 17" test_accept.nfa | grep "State" | head -5

echo ""
echo "=== Check CategoryMask for these states ==="
for i in 83 84 85 86 87; do
    echo "State $i:"
    grep -A3 "^State $i:" test_accept.nfa | grep "CategoryMask"
done

echo ""
echo "=== Check if states from different patterns have different masks ==="
grep -E "(State [0-9]+:|PatternId: 17|CategoryMask:)" test_accept.nfa | grep -A2 "PatternId: 17" | head -20

#bash