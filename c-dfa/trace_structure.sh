cd /home/panz/osrc/lms-test/readonlybox/c-dfa

echo "=== States 93-100 to see the pattern structure ==="
for i in 93 94 95 96 97 98 99 100; do
    echo "--- State $i ---"
    grep -A8 "^State $i:" test_accept.nfa
done

echo ""
echo "=== Looking for transitions to accepting states (EosTarget: yes) ==="
grep -B5 "EosTarget: yes" test_accept.nfa | grep -E "(State|Symbol.*->)" | head -30

#bash