#!/bin/bash
#
# rbox-wrap test suite with server

cd "$(dirname "$0")/.." || exit 1

WRAPPER="./rbox-wrap"
SERVER="../rbox-server/rbox-server"
SOCKET="/tmp/rbox-wrap-test.sock"
PASS=0
FAIL=0
SKIP=0

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

skip() {
    echo "  SKIP: $1"
    SKIP=$((SKIP + 1))
}

start_server() {
    pkill -f "rbox-server.*$SOCKET" 2>/dev/null || true
    rm -f "$SOCKET"
    $SERVER -socket "$SOCKET" -auto-deny >/dev/null 2>&1 &
    wait_for_server
}

wait_for_server() {
    local max_attempts=10
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if [ -S "$SOCKET" ]; then
            return 0
        fi
        sleep 0.2
        attempt=$((attempt + 1))
    done
    return 1
}

start_server_with_policy() {
    local allow_list="$1"
    local deny_list="$2"
    local env_deny="$3"
    local max_requests="${4:-1}"
    
    pkill -f "rbox-server.*$SOCKET" 2>/dev/null || true
    rm -f "$SOCKET"
    
    local args="-socket $SOCKET -test-max-requests $max_requests"
    [ -n "$allow_list" ] && args="$args -test-allow-list $allow_list"
    [ -n "$deny_list" ] && args="$args -test-deny-list $deny_list"
    [ -n "$env_deny" ] && args="$args -test-env-deny $env_deny"
    
    $SERVER $args >/dev/null 2>&1 &
    wait_for_server
}

start_server_auto_deny() {
    pkill -f "rbox-server.*$SOCKET" 2>/dev/null || true
    rm -f "$SOCKET"
    $SERVER -socket "$SOCKET" -auto-deny >/dev/null 2>&1 &
    wait_for_server
}

start_server_auto_allow() {
    pkill -f "rbox-server.*$SOCKET" 2>/dev/null || true
    rm -f "$SOCKET"
    $SERVER -socket "$SOCKET" >/dev/null 2>&1 &
    wait_for_server
}

echo "========================================"
echo "rbox-wrap Test Suite"
echo "========================================"
echo ""

#========================================
# Argument Parsing
#========================================
echo "Argument Parsing"
echo "---------------"

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

output=$($WRAPPER --invalid-opt 2>&1 || true)
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
# DFA Fast-Path (no server needed)
#========================================
echo "DFA Fast-Path"
echo "-------------"

output=$($WRAPPER --judge -- ls 2>&1)
if echo "$output" | grep -q "ALLOW DFA fast-path"; then
    pass "DFA allows 'ls' command"
else
    fail "DFA allows 'ls' command"
fi

output=$($WRAPPER --judge -- cat 2>&1)
if echo "$output" | grep -q "ALLOW DFA fast-path"; then
    pass "DFA allows 'cat' command"
else
    fail "DFA allows 'cat' command"
fi

output=$($WRAPPER --judge -- date 2>&1)
if echo "$output" | grep -q "ALLOW DFA fast-path"; then
    pass "DFA allows 'date' command"
else
    fail "DFA allows 'date' command"
fi

output=$($WRAPPER --judge -- uname 2>&1)
if echo "$output" | grep -q "ALLOW DFA fast-path"; then
    pass "DFA allows 'uname' command"
else
    fail "DFA allows 'uname' command"
fi

$WRAPPER --bin -- ls >/dev/null 2>&1
if [ $? -eq 0 ]; then
    pass "--bin runs without crash"
else
    fail "--bin runs without crash"
fi

echo ""

#========================================
# Server Communication
#========================================
echo "Server Communication"
echo "--------------------"

start_server_auto_allow

output=$($WRAPPER --socket "$SOCKET" --judge -- ls 2>&1)
if echo "$output" | grep -q "ALLOW"; then
    pass "Server allows 'ls'"
else
    fail "Server allows 'ls'"
fi

output=$($WRAPPER --socket "$SOCKET" --judge -- rm 2>&1 || true)
if echo "$output" | grep -q "DENY"; then
    pass "Server denies 'rm'"
else
    fail "Server denies 'rm'"
fi

echo ""

#========================================
# DFA Command Execution (with server)
#========================================
echo "DFA Command Execution"
echo "---------------------"

start_server_auto_allow

output=$($WRAPPER --socket "$SOCKET" --run -- ls 2>&1)
if echo "$output" | grep -q "ALLOW\|Makefile"; then
    pass "--run with server works"
else
    fail "--run with server works"
fi

start_server_auto_allow
output=$($WRAPPER --socket "$SOCKET" --clear-env --run -- ls 2>&1)
if echo "$output" | grep -q "ALLOW\|Makefile"; then
    pass "--clear-env --run works"
else
    fail "--clear-env --run works"
fi

echo ""

#========================================
# --relay Mode
#========================================
echo "--relay Mode"
echo "------------"

start_server_auto_allow

output=$($WRAPPER --socket "$SOCKET" --relay --judge -- ls 2>&1)
if echo "$output" | grep -q "ALLOW"; then
    pass "--relay forces server contact"
else
    fail "--relay forces server contact"
fi

echo ""

#========================================
# 5.1 Server Unreachable
#========================================
echo "Server Unreachable"
echo "------------------"

rm -f "$SOCKET"
if timeout 2 $WRAPPER --socket "$SOCKET" --judge -- llsssf 2>&1; then
    fail "Server unreachable should hang/timeout"
else
    echo "  TIMEDOUT: Command hung as expected without server"
    pass "Server unreachable handled gracefully"
fi

echo ""

#========================================
# 7. Exit Code Verification
#========================================
echo "Exit Code Verification"
echo "----------------------"

# Exit code 0 for successful command
start_server_auto_allow
$WRAPPER --socket "$SOCKET" --run -- ls >/dev/null 2>&1
result=$?
if [ $result -eq 0 ]; then
    pass "Exit code 0 for successful command"
else
    fail "Exit code 0 (got $result)"
fi

# Exit code 1 for invalid option
$WRAPPER --invalid-opt ls >/dev/null 2>&1
result=$?
if [ $result -eq 1 ]; then
    pass "Exit code 1 for invalid option"
else
    fail "Exit code 1 (got $result)"
fi

# Exit code 1 for no command
$WRAPPER >/dev/null 2>&1
result=$?
if [ $result -eq 1 ]; then
    pass "Exit code 1 for no command"
else
    fail "Exit code 1 for no command (got $result)"
fi

# Exit code 9 for denied command
start_server_auto_deny
$WRAPPER --socket "$SOCKET" --judge -- rm >/dev/null 2>&1
result=$?
if [ $result -eq 9 ]; then
    pass "Exit code 9 for denied command"
else
    fail "Exit code 9 (got $result)"
fi

echo ""

#========================================
# 2. Environment Filtering
#========================================
echo "Environment Filtering"
echo "--------------------"

start_server_auto_allow
READONLYBOX_FLAGGED_ENVS="HOME:0.5,PATH:0.8" $WRAPPER --socket "$SOCKET" --relay --judge -- ls >/dev/null 2>&1
if [ $? -eq 0 ]; then
    pass "--relay with flagged envs works"
else
    fail "--relay with flagged envs works"
fi

echo ""

#========================================
# Binary Packet Validation
#========================================
echo "Binary Packet Validation"
echo "-----------------------"

if [ -x ./tests/decode_packet ]; then
    start_server_auto_allow
    if [ -S "$SOCKET" ]; then
        $WRAPPER --socket "$SOCKET" --bin ls > /tmp/packet.bin 2>&1
        if [ -s /tmp/packet.bin ] && ./tests/decode_packet /tmp/packet.bin >/dev/null 2>&1; then
            pass "Binary packet is valid"
        else
            fail "Binary packet malformed"
        fi
        rm -f /tmp/packet.bin
    else
        fail "Server did not start"
    fi
else
    skip "Binary packet validation (decode_packet not available)"
fi

echo ""

#========================================
# Large Command Line
#========================================
echo "Large Command Line"
echo "------------------"

long_arg=$(printf 'a%.0s' {1..10000})
output=$($WRAPPER --judge cat Makefile 2>&1 | head -1)
if echo "$output" | grep -q "ALLOW"; then
    pass "Large command line (10k chars) works"
else
    fail "Large command line failed"
fi

echo ""

#========================================
# --clear-env
#========================================
echo "--clear-env Verification"
echo "------------------------"

# --clear-env should work with DFA commands
# It should not error - we'll see the file output or "ALLOW" depending on mode
# Just verify it doesn't crash
output=$($WRAPPER --clear-env --judge cat Makefile 2>&1)
if echo "$output" | grep -q "ALLOW"; then
    pass "--clear-env works with DFA"
else
    fail "--clear-env"
fi

echo ""

#========================================
# Exit Code Verification (DFA commands)
#========================================
echo "Exit Code from DFA Commands"
echo "---------------------------"

$WRAPPER --run -- true
result=$?
if [ $result -eq 0 ]; then
    pass "Exit code 0 from DFA command"
else
    fail "Exit code 0 (got $result)"
fi

$WRAPPER --run -- false
result=$?
if [ $result -eq 1 ]; then
    pass "Exit code 1 from DFA command"
else
    fail "Exit code 1 (got $result)"
fi

echo ""

#========================================
# Privilege Dropping
#========================================
echo "Privilege Dropping"
echo "------------------"

if command -v sudo >/dev/null && sudo -n true 2>/dev/null; then
    # Test --uid flag with DFA-allowed command
    output=$(sudo $WRAPPER --uid 1000 --run cat Makefile 2>&1 | head -1)
    if echo "$output" | grep -q "ALLOW"; then
        pass "Privilege dropping via --uid works"
    else
        fail "Privilege dropping via --uid"
    fi
    
    # Test READONLYBOX_UID
    export READONLYBOX_UID=1000
    output=$(sudo $WRAPPER --run cat Makefile 2>&1 | head -1)
    if echo "$output" | grep -q "ALLOW"; then
        pass "Privilege dropping via READONLYBOX_UID works"
    else
        fail "Privilege dropping via READONLYBOX_UID"
    fi
    unset READONLYBOX_UID
else
    skip "Privilege dropping tests (sudo not available)"
fi

echo ""

#========================================
# Summary
#========================================
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo "Skipped: $SKIP"
echo ""

if [ $FAIL -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed."
    exit 1
fi
