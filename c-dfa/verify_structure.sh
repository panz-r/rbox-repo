cd /home/panz/osrc/lms-test/readonlybox/c-dfa

echo "=== Looking for transitions TO state 97 ==="
grep -n "-> 97" test_accept.nfa

echo ""
echo "=== Looking for transitions FROM states with PatternId 18 ==="
# States 93-100 should be pattern 18 (a((b))+)
for i in 93 94 95 96 97 98 99 100; do
    echo "--- State $i ---"
    grep -A10 "^State $i:" test_accept.nfa | grep -E "(Transitions:|Symbol.*->)"
done

echo ""
echo "=== Check if any state transitions to 97 on symbol 6 (b) ==="
grep -B5 "-> 97" test_accept.nfa | grep "Symbol.*6.*-> 97"

echo ""
echo "=== Summary of pattern 18 structure ==="
echo "Pattern 18 should be a((b))+ which means:"
echo "1. State X --'a'(symbol 4)--> State Y"
echo "2. State Y --'b'(symbol 6)--> State Z (accepting)"
echo "3. State Z --'b'(symbol 6)--> State Z (loop)"
echo ""
echo "Looking for these transitions..."

#bash