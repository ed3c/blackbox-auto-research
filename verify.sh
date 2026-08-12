#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
python3 -m unittest discover -s "$ROOT/tests"
python3 "$ROOT/scripts/check_experiment_ledger.py" "$ROOT/examples/ledger.json"
if python3 "$ROOT/scripts/check_experiment_ledger.py" "$ROOT/tests/fixtures/ledger-hollow.json"; then
  echo "VERIFY FAIL: hollow experiment ledger unexpectedly passed" >&2
  exit 2
fi
python3 "$ROOT/scripts/check_public_surface.py" "$ROOT"
python3 "$ROOT/scripts/gates/check_delivery_receipt.py"
echo "VERIFY PASS"
