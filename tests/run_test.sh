#!/bin/bash
# Verifies the reference lineage documents with src/verifier.js.
# Passes only if the valid document verifies AND the tampered document is rejected.
set -u

status=0

echo "11/11 Lineage Verification Test"
echo "--------------------------------------"

echo
echo "1. Valid document must PASS"
if node src/verifier.js examples/verified_lineage.json; then
  echo "   OK"
else
  echo "   FAILED: valid document did not verify"
  status=1
fi

echo
echo "2. Tampered document must FAIL"
if node src/verifier.js examples/tampered_lineage.json; then
  echo "   FAILED: tampered document verified, tamper detection is not working"
  status=1
else
  echo "   OK: rejected as expected"
fi

echo
if [ "$status" -eq 0 ]; then
  echo "Verification test complete: both outcomes correct"
else
  echo "Verification test FAILED"
fi
exit "$status"
