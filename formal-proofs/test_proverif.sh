#!/bin/bash
#
# formal-proofs/test_proverif.sh
#
# Run every ProVerif model in formal-proofs/proverif and fail if any
# query yields a result other than "is true". Note: queries that are
# *intentionally* expected to be `false` (e.g. attacker(m_phase1) in
# the post-compromise model) are listed in EXPECTED_FALSE below.
#
# This is the script invoked by .github/workflows/verify-proverif.yml
# inside the docker container.

set -euo pipefail

PROVERIF_BIN="${PROVERIF_BIN:-proverif}"

if ! command -v "$PROVERIF_BIN" >/dev/null 2>&1; then
    echo "ERROR: $PROVERIF_BIN not found in PATH"
    exit 2
fi

cd "$(dirname "$0")"

# Set of <file>:<query> pairs whose result is expected to be "false"
# (i.e. ProVerif demonstrates the attack). These are NOT failures of
# the verification effort; they are explicit negative tests that
# confirm a corrupted-state plaintext is reachable as designed.
EXPECTED_FALSE=(
    "double_ratchet.pv:not attacker_p2(m_phase1[]) is false"
)

models=(
    "proverif/x3dh.pv"
    "proverif/x3dh_auth.pv"
    "proverif/double_ratchet.pv"
    "proverif/signal_complete.pv"
)

pass=0
fail=0
total=0

run_model() {
    local file="$1"
    local short
    short="$(basename "$file")"
    total=$((total + 1))

    echo "----------------------------------------------------------------"
    echo "==> $file"

    if [ ! -f "$file" ]; then
        echo "  MISSING: $file"
        fail=$((fail + 1))
        return
    fi

    local out
    out="$("$PROVERIF_BIN" "$file" 2>&1 || true)"

    # Collect result lines.
    local results
    results="$(printf '%s\n' "$out" | grep -E '^RESULT ' || true)"

    if [ -z "$results" ]; then
        echo "  ERROR: ProVerif produced no RESULT lines"
        printf '%s\n' "$out" | tail -20
        fail=$((fail + 1))
        return
    fi

    local model_failed=0
    while IFS= read -r r; do
        if printf '%s' "$r" | grep -q ' is true'; then
            echo "  PASS: $r"
            continue
        fi
        # Check if this is an expected-false query.
        local expected_false=0
        for ef in "${EXPECTED_FALSE[@]}"; do
            local ef_file="${ef%%:*}"
            local ef_query="${ef#*:}"
            if [ "$short" = "$ef_file" ] && \
               printf '%s' "$r" | grep -qF "$ef_query"; then
                echo "  PASS (expected false): $r"
                expected_false=1
                break
            fi
        done
        if [ "$expected_false" -eq 0 ]; then
            echo "  FAIL: $r"
            model_failed=1
        fi
    done <<< "$results"

    if [ "$model_failed" -eq 0 ]; then
        pass=$((pass + 1))
    else
        fail=$((fail + 1))
    fi
}

echo "ProVerif: $($PROVERIF_BIN -help 2>&1 | head -1)"
echo

for m in "${models[@]}"; do
    run_model "$m"
done

echo
echo "================================================================"
echo "Total: $total   Passed: $pass   Failed: $fail"
echo "================================================================"

if [ "$fail" -ne 0 ]; then
    exit 1
fi
exit 0
