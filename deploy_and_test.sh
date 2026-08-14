#!/bin/bash
SRC="/mnt/c/Users/Whai/.gemini/antigravity-ide/scratch/GridSecSim"
DST="$HOME/GridSecSim"

echo "Deploying GridSec Sim files..."

cp "$SRC/protocols/goose.py"         "$DST/protocols/"
cp "$SRC/protocols/dnp3.py"          "$DST/protocols/"
cp "$SRC/protocols/modbus.py"        "$DST/protocols/"
cp "$SRC/core/goose_simulator.py"    "$DST/core/"
cp "$SRC/core/dnp3_simulator.py"     "$DST/core/"
cp "$SRC/core/modbus_simulator.py"   "$DST/core/"
cp "$SRC/gui/main_window.py"         "$DST/gui/"
cp "$SRC/gui/node_types.py"          "$DST/gui/"

echo "All 8 files deployed OK"

echo ""
echo "Running protocol self-tests..."
cd "$DST"
source venv/bin/activate
export PYTHONPATH="$DST"

echo ""
echo "=== GOOSE Protocol ==="
python3 protocols/goose.py

echo ""
echo "=== DNP3 Protocol ==="
python3 protocols/dnp3.py

echo ""
echo "=== Modbus/TCP Protocol ==="
python3 protocols/modbus.py

echo ""
echo "ALL PROTOCOL TESTS DONE"
