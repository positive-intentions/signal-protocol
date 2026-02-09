#!/bin/bash

# Ensure proverif is available
if ! command -v proverif &> /dev/null; then
    echo "Error: proverif command not found. Please install PROVERIF first."
    echo "See docs/INSTALLATION.md for setup instructions."
    exit 1
fi

# Test script for ProVerif formal proofs

echo "Testing ProVerif models..."
echo ""

PROVERIF_CMD="proverif"
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a single test
run_test() {
    local file=$1
    local name=$2
    
    echo "Testing: $name ($file)"
    
    if $PROVERIF_CMD "$file" > /dev/null 2>&1; then
        echo "  ✓ PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo "  ✗ FAILED"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Run all tests
run_test "proverif/x3dh/x3dh_complete.pv" "X3DH Complete Model"
run_test "proverif/x3dh/x3dh_4dh.pv" "X3DH 4DH Operations"
run_test "proverif/x3dh/x3dh_security.pv" "X3DH Security Properties"
run_test "proverif/double_ratchet/double_ratchet_dr.pv" "Double Ratchet State Transitions"
run_test "proverif/double_ratchet/double_ratchet_key_derivation.pv" "Double Ratchet Key Derivation"
run_test "proverif/double_ratchet/double_ratchet_security.pv" "Double Ratchet Security Properties"
run_test "proverif/signal_protocol_complete.pv" "Complete Signal Protocol"

# Summary
echo ""
echo "========================================"
echo "Test Summary"
echo "========================================"
echo "Passed: $TESTS_PASSED"
echo "Failed: $TESTS_FAILED"
echo "Total:  $((TESTS_PASSED + TESTS_FAILED))"
echo "========================================"

if [ $TESTS_FAILED -eq 0 ]; then
    echo "All tests passed!"
    exit 0
else
    echo "Some tests failed!"
    exit 1
fi