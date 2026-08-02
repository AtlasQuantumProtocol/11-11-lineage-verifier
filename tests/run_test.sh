#!/bin/bash
# Conformance run: both independent verifiers over every fixture, including the
# negative cases. Fails the build if any expectation is not met.
#
# Exit codes from both verifiers: 0 verified, 1 usage error, 2 verification failed.
set -u

cd "$(dirname "$0")/.." || exit 1

pass=0
fail=0

expect() {
  local desc="$1" want="$2"; shift 2
  "$@" >/dev/null 2>&1
  local got=$?
  if [ "$got" -eq "$want" ]; then
    echo "  PASS  $desc (exit $got)"
    pass=$((pass + 1))
  else
    echo "  FAIL  $desc (expected exit $want, got $got)"
    fail=$((fail + 1))
  fi
}

echo "11/11 Lineage Conformance"
echo "-------------------------"

echo "JavaScript verifier (src/verifier.js)"
expect "valid governance chain"  0 node src/verifier.js samples/sample-lineage.json
expect "valid retrieval chain"   0 node src/verifier.js samples/sample-retrieval-lineage.json
expect "valid example"           0 node src/verifier.js examples/verified_execution.json
expect "tampered example"        2 node src/verifier.js examples/tampered_execution.json

echo "Python verifier (verifier/verify.py)"
expect "valid governance chain"  0 python3 verifier/verify.py samples/sample-lineage.json
expect "valid retrieval chain"   0 python3 verifier/verify.py samples/sample-retrieval-lineage.json
expect "valid example"           0 python3 verifier/verify.py examples/verified_execution.json
expect "tampered example"        2 python3 verifier/verify.py examples/tampered_execution.json

echo "Cross-implementation agreement"
mkdir -p outputs
js_hash=$(node src/verifier.js samples/sample-retrieval-lineage.json | awk '/Last SHA3/{print $NF}')
py_hash=$(python3 verifier/verify.py samples/sample-retrieval-lineage.json \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["last_hash"])')

if [ "$js_hash" = "$py_hash" ] && [ -n "$js_hash" ]; then
  echo "  PASS  JS and Python agree on terminal chain hash"
  pass=$((pass + 1))
else
  echo "  FAIL  verifier disagreement"
  echo "        JS: $js_hash"
  echo "        PY: $py_hash"
  fail=$((fail + 1))
fi

python3 verifier/verify.py samples/sample-retrieval-lineage.json > outputs/verified_result.json

echo "-------------------------"
echo "passed: $pass  failed: $fail"
[ "$fail" -eq 0 ] || exit 1
echo "Conformance Complete"
