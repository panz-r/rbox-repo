cd /home/panz/osrc/lms-test/readonlybox/c-dfa

# Search for states 95, 96, 97
grep -A5 "^State 95:" test_accept.nfa
echo "---"
grep -A5 "^State 96:" test_accept.nfa  
echo "---"
grep -A5 "^State 97:" test_accept.nfa

#bash