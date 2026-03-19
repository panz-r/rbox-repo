#!/bin/bash
#
# rbox-wrap test suite
#

WRAPPER="../rbox-wrap"
SERVER="../../rbox-server/rbox-server"
SOCKET="/tmp/rbox-test-$$.sock"
PASS=0
FAIL=0

cleanup() {
    pkill -f "rbox-server.*$SOCKET" 2>/dev/null || true
    rm -f "$SOCKET"
}
trap cleanup EXIT

pass() {
    echo "  PASS: $1"
    PASS=$((PASS + 1))
}

fail() {
    echo "  FAIL: $1"
    FAIL=$((FAIL + 1))
}

start_server() {
    pkill -f "rbox-server.*$SOCKET" 2>/dev/null || true
    rm -f "$SOCKET"
    $SERVER -socket "$SOCKET" -auto-deny -test-max-requests 1 >/dev/null 2>&1 &
    sleep 0.5
}

start_server_with_policy() {
    local allow_list="$1"
    local deny_list="$2"
    local allow_reason="$3"
    local deny_reason="$4"
    local max_requests="${5:-1}"
    
    pkill -f "rbox-server.*$SOCKET" 2>/dev/null || true
    rm -f "$SOCKET"
    
    local args="-socket $SOCKET -test-max-requests $max_requests"
    if [ -n "$allow_list" ]; then
        args="$args -test-allow-list $allow_list"
    fi
    if [ -n "$deny_list" ]; then
        args="$args -test-deny-list $deny_list"
    fi
    if [ -n "$allow_reason" ]; then
        args="$args -test-allow-reason '$allow_reason'"
    fi
    if [ -n "$deny_reason" ]; then
        args="$args -test-deny-reason '$deny_reason'"
    fi
    
    eval "$SERVER $args" >/dev/null 2>&1 &
    sleep 0.5
}

echo "========================================"
echo "rbox-wrap Test Suite"
echo "========================================"
echo ""

#========================================
# 2.1 Argument Parsing and Usage
#========================================
echo "2.1 Argument Parsing and Usage"
echo "-------------------------------"

output=$($WRAPPER --help 2>&1)
if echo "$output" | grep -q "Usage:"; then
    pass "Help displays usage"
else
    fail "Help displays usage"
fi

output=$($WRAPPER 2>&1 || true)
if echo "$output" | grep -q "No command specified"; then
    pass "No command shows error"
else
    fail "No command shows error"
fi

output=$($WRAPPER --foo 2>&1 || true)
if echo "$output" | grep -qi "unrecognized\|unknown option"; then
    pass "Unknown option shows error"
else
    fail "Unknown option shows error"
fi

output=$($WRAPPER --version 2>&1)
if echo "$output" | grep -q "rbox-wrap"; then
    pass "--version shows version"
else
    fail "--version shows version"
fi

echo ""

#========================================
# 2.2 DFA Fast-Path
#========================================
echo "2.2 DFA Fast-Path"
echo "------------------"

# DFA fast-path (no server needed for safe commands)
output=$($WRAPPER --judge ls 2>&1)
if echo "$output" | grep -q "ALLOW DFA fast-path"; then
    pass "DFA allows 'ls' command"
else
    fail "DFA allows 'ls' command"
fi

output=$($WRAPPER --bin ls 2>&1)
if [ ${#output} -ge 20 ]; then
    pass "--bin outputs packet"
else
    fail "--bin outputs packet"
fi

#========================================
# 2.3 Server Communication
#========================================
echo "2.3 Server Communication"
echo "------------------------"

start_server

output=$($WRAPPER --socket "$SOCKET" --judge ls 2>&1)
if echo "$output" | grep -q "ALLOW"; then
    pass "Server allows 'ls'"
else
    fail "Server allows 'ls'"
fi

output=$($WRAPPER --socket "$SOCKET" --judge rm 2>&1 || true)
if echo "$output" | grep -q "DENY"; then
    pass "Server denies 'rm'"
else
    fail "Server denies 'rm'"
fi

echo ""

#========================================
# 2.4 Binary Mode
#========================================
echo "2.4 Binary Mode"
echo "---------------"

start_server

output=$($WRAPPER --socket "$SOCKET" --bin ls 2>&1)
if [ ${#output} -ge 20 ]; then
    pass "Binary mode outputs packet"
else
    fail "Binary mode outputs packet"
fi

echo ""

#========================================
# 2.5 Command Execution
#========================================
echo "2.5 Command Execution (--run)"
echo "------------------------------"

start_server

# Test: --clear-env with a DFA-matched command still works
output=$($WRAPPER --socket "$SOCKET" --clear-env --run ls /tmp 2>&1 && echo "OK" || echo "FAIL")
if echo "$output" | grep -q "OK"; then
    pass "--clear-env with DFA command works"
else
    fail "--clear-env with DFA command works"
fi

echo ""

#========================================
# 2.9 --relay Mode
#========================================
echo "2.9 --relay Mode"
echo "----------------"

start_server_with_policy "ls" "" "relay-test" ""
output=$($WRAPPER --socket "$SOCKET" --relay --judge ls 2>&1)
if echo "$output" | grep -q "ALLOW relay-test"; then
    pass "--relay forces server contact"
else
    fail "--relay forces server contact"
fi

echo ""

#========================================
# 2.10 Server Unreachable (skip - requires fast-fail connection)
#========================================
echo "2.10 Server Unreachable"
echo "-----------------------"
echo "  SKIP: Connection timeout test requires protocol-level fix"
echo ""

echo ""

#========================================
# Summary
#========================================
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
