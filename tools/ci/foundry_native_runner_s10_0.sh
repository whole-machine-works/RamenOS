#!/usr/bin/env bash
# Foundry gate for S10.0 Native Runner.

set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"
mkdir -p "$ROOT_DIR/out/foundry/selected-tests"
SELECTED_RUN_ROOT="$(mktemp -d "$ROOT_DIR/out/foundry/selected-tests/native-runner.XXXXXX")"

echo "=== S10.0 Native Runner Foundry Gate ==="
echo

PASSED=0
FAILED=0

pass() { echo "PASS: $1"; PASSED=$((PASSED + 1)); }
fail() { echo "FAIL: $1"; FAILED=$((FAILED + 1)); }

echo "Ensuring wasm32-unknown-unknown target is installed..."
rustup target add wasm32-unknown-unknown

# Assertion 1: native_runner binary builds
echo "Asserting native_runner builds..."
if cargo build --locked -p native_runner 2>&1 >/dev/null; then
    pass "native_runner builds"
else
    fail "native_runner builds"
fi

# Assertion 2: hello_wasm.wasm builds
echo
echo "Asserting hello_wasm builds..."
if cargo build --locked -p hello_wasm --target wasm32-unknown-unknown --target-dir "$ROOT_DIR/target" 2>&1 >/dev/null; then
    pass "hello_wasm builds"
else
    fail "hello_wasm builds"
fi

# Assertion 3-5: Run integration tests
echo
echo "Running integration tests..."
if python3 "$ROOT_DIR/tools/ci/selected_test_runner.py" \
    --package native_runner --test integration_test \
    --required-input "$ROOT_DIR/target/wasm32-unknown-unknown/debug/hello_wasm.wasm" \
    --output "$SELECTED_RUN_ROOT/integration"; then
    pass "integration tests pass"
else
    fail "integration tests"
fi

# Exercise the default-off recovery adapter with the locked host engine.
echo
echo "Running bounded recovery adapter controls..."
if python3 "$ROOT_DIR/tools/ci/selected_test_runner.py" \
    --package native_runner --features recovery_decision_v0_dev \
    --filter 'recovery_decision::tests::' --require-filter 'recovery_decision::tests::' \
    --filter 'recovery_decision::q1_tests::controls::' \
    --require-filter 'recovery_decision::q1_tests::controls::' \
    --filter 'recovery_decision::q1_runtime_tests::controls::' \
    --require-filter 'recovery_decision::q1_runtime_tests::controls::' \
    --filter 'recovery_decision::q1_runtime_tests::t2::t2_static_' \
    --require-filter 'recovery_decision::q1_runtime_tests::t2::t2_static_' \
    --filter 'recovery_decision::q1_runtime_tests::t2::runtime_controls::' \
    --require-filter 'recovery_decision::q1_runtime_tests::t2::runtime_controls::' \
    --filter 'recovery_decision::q1_runtime_tests::t2::stage_controls::' \
    --require-filter 'recovery_decision::q1_runtime_tests::t2::stage_controls::' \
    --output "$SELECTED_RUN_ROOT/recovery"; then
    pass "recovery adapter controls pass"
else
    fail "recovery adapter controls"
fi

# Summary
echo
echo "=== S10.0 Summary ==="
echo "PASSED: ${PASSED}"
echo "FAILED: ${FAILED}"

if [[ ${FAILED} -eq 0 ]]; then
    echo
    echo "FOUNDRY_NATIVE_RUNNER_S10_0: METRIC passed=${PASSED} failed=0"
    echo "FOUNDRY_NATIVE_RUNNER_S10_0: ok"
    exit 0
else
    echo
    echo "FOUNDRY_NATIVE_RUNNER_S10_0: METRIC passed=${PASSED} failed=${FAILED}"
    echo "FOUNDRY_NATIVE_RUNNER_S10_0: FAIL"
    exit 1
fi
