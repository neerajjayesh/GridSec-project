#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ./scripts/python-runtime.sh
export QT_QPA_PLATFORM=offscreen
export PYTHONPATH="$PWD"
"$GRIDSEC_PYTHON" -m compileall -q core gui protocols main.py
for module in protocols.c37118 protocols.dnp3 protocols.goose protocols.modbus protocols.iec104 core.attack_engine core.traffic_filter core.packet_parser; do
    "$GRIDSEC_PYTHON" -m "$module"
done
"$GRIDSEC_PYTHON" test_regression.py
"$GRIDSEC_PYTHON" -m unittest discover -s tests -v
