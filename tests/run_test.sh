#!/bin/bash

echo "Running 11/11 Lineage Verification Test"
echo "--------------------------------------"

python3 verifier/verify.py examples/verified_execution.json > outputs/verified_result.json

echo ""
echo "Verification Output:"
cat outputs/verified_result.json

echo ""
echo "Verification Complete"
