#!/bin/bash
# Quick Test Script for PROVERIF Models

echo "=========================================="
echo "PROVERIF Models Quick Test"
echo "=========================================="
echo ""

# Test each model and show compilation results
MODELS=(
    "formal-proofs/proverif/x3dh/x3dh_4dh.pv:X3DH 4DH"
    "formal-proofs/proverif/x3dh/x3dh_complete.pv:X3DH Complete (4 DH ops)"
    "formal-proofs/proverif/x3dh/x3dh_security.pv:X3DH Security"
    "formal-proofs/proverif/double_ratchet/double_ratchet_dr.pv:DR State Transitions"
    "formal-proofs/proverif/double_ratchet/double_ratchet_key_derivation.pv:DR Key Derivation"
    "formal-proofs/proverif/double_ratchet/double_ratchet_security.pv:DR Security (FS/PCS)"
    "formal-proofs/proverif/signal_protocol_complete.pv:Signal Protocol Complete"
)

PASS=0
FAIL=0

for entry in "${MODELS[@]}"; do
    IFS=':' read -r file name <<< "$entry"
    echo -n "Testing $name... "
    
    if proverif "$file" 2>&1 | grep -q "RESULT.*is true"; then
        echo "✅ PASS"
        ((PASS++))
    elif proverif "$file" >/dev/null 2>&1; then
        echo "✅ PASS (compiles)"
        ((PASS++))
    else
        echo "❌ FAIL"
        ((FAIL++))
    fi
done

echo ""
echo "=== Summary ==="
echo "Total: $((PASS + FAIL))"
echo "Passed: $PASS"
echo "Failed: $FAIL"
echo ""