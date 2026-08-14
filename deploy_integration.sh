#!/bin/bash
# Deploy all integration layer files from Windows to WSL2
set -e
SRC="/mnt/c/Users/Whai/.gemini/antigravity-ide/scratch/GridSecSim"
DST="$HOME/GridSecSim"

echo "=== Deploying GridSec Sim Integration Layer ==="

# Core files
cp "$SRC/core/pcap_writer.py"          "$DST/core/"
cp "$SRC/core/rest_api.py"             "$DST/core/"
# integration_manager.py was patched in-place in WSL, don't overwrite
cp "$SRC/core/goose_simulator.py"      "$DST/core/"
cp "$SRC/core/dnp3_simulator.py"       "$DST/core/"
cp "$SRC/core/modbus_simulator.py"     "$DST/core/"

# GUI files
cp "$SRC/gui/integration_panel.py"     "$DST/gui/"
cp "$SRC/gui/main_window.py"           "$DST/gui/"
cp "$SRC/gui/node_types.py"            "$DST/gui/"

# Protocol files
cp "$SRC/protocols/goose.py"           "$DST/protocols/"
cp "$SRC/protocols/dnp3.py"            "$DST/protocols/"
cp "$SRC/protocols/modbus.py"          "$DST/protocols/"

echo "All files deployed."
echo ""
echo "=== Running integration tests ==="
cd "$DST"
source venv/bin/activate
export PYTHONPATH="$DST"

echo ""
echo "--- pcap writer test ---"
python3 core/pcap_writer.py

echo ""
echo "--- REST API import test ---"
python3 -c "
from core.rest_api import GridSecRESTServer, APIState
s = GridSecRESTServer('127.0.0.1', 18080)
ok = s.start()
import time; time.sleep(0.3)
import urllib.request
resp = urllib.request.urlopen('http://127.0.0.1:18080/api/v1/status')
data = resp.read().decode()
assert 'GridSec Sim' in data, 'Bad response'
s.stop()
print('REST API: OK ->', data[:80])
"

echo ""
echo "--- Integration Manager import test ---"
python3 -c "
from core.integration_manager import IntegrationManager, generate_stix_bundle, Incident
mgr = IntegrationManager()
# Create fake incidents
for i in range(5):
    from core.pdc_proxy import PacketRecord
    import time
    rec = type('R', (), {
        'timestamp': time.time(),
        'status': 'attacked' if i % 2 == 0 else 'clean',
        'attack_type': 'NOISE',
        'original': {'freq': 50.0, 'phasors': [[120.0, 0.0]]},
        'modified': {'freq': 51.5, 'phasors': [[150.0, 0.0]]},
    })()
    mgr.record_packet(rec, b'test', protocol='C37.118')
assert mgr.incident_count == 5
stix = mgr._api_stix()
assert stix['type'] == 'bundle'
assert stix['spec_version'] == '2.1'
csv = mgr._api_csv()
assert 'NOISE' in csv
print(f'IntegrationManager: OK — {mgr.incident_count} incidents, STIX objects: {len(stix[\"objects\"])}, CSV lines: {len(csv.splitlines())}')
"

echo ""
echo "--- GUI panel import test ---"
python3 -c "
import sys
sys.argv = ['test']
# Just test imports (no display needed)
from gui.integration_panel import IntegrationPanel, CaptureTab, SyslogTab, RestAPITab, ExportTab, GuidesTab
print('GUI integration_panel: imports OK')
"

echo ""
echo "=== ALL INTEGRATION TESTS PASSED ==="
