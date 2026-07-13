#!/bin/bash
cd ~/GridSecSim
source venv/bin/activate

PROJECT_ROOT=$(pwd)
export PYTHONPATH="$PROJECT_ROOT"

echo "=== Import Check ==="
python3 -c "
import PyQt6
import matplotlib
import numpy
import pyqtgraph
import cryptography
print('ALL IMPORTS OK')
print('  PyQt6:', PyQt6.QtCore.PYQT_VERSION_STR)
print('  matplotlib:', matplotlib.__version__)
print('  numpy:', numpy.__version__)
"

echo ""
echo "=== C37.118 Codec Test ==="
python3 protocols/c37118.py

echo ""
echo "=== Attack Engine Test ==="
python3 core/attack_engine.py

echo ""
echo "=== Traffic Filter Test ==="
python3 core/traffic_filter.py

echo ""
echo "=== Packet Parser Test ==="
python3 core/packet_parser.py

echo ""
echo "ALL CORE TESTS DONE"
