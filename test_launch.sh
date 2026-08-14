#!/bin/bash
set -e
cp /mnt/c/Users/Whai/.gemini/antigravity-ide/scratch/GridSecSim/gui/main_window.py ~/GridSecSim/gui/
cp /mnt/c/Users/Whai/.gemini/antigravity-ide/scratch/GridSecSim/gui/integration_panel.py ~/GridSecSim/gui/

cd ~/GridSecSim
source venv/bin/activate
export PYTHONPATH=$(pwd)

echo "=== Testing main_window import ==="
python3 -c "from gui.main_window import MainWindow; print('MainWindow: OK')"

echo "=== Testing full app startup (headless) ==="
python3 -c "
import sys, os
os.environ['QT_QPA_PLATFORM'] = 'offscreen'
from PyQt6.QtWidgets import QApplication
app = QApplication(sys.argv)
from gui.main_window import MainWindow
w = MainWindow()
w.show()
# Check integration tab exists
right = w._h_splitter.widget(2)
from PyQt6.QtWidgets import QTabWidget
tabs = right.findChild(QTabWidget)
tab_names = [tabs.tabText(i) for i in range(tabs.count())]
print('Tabs:', tab_names)
assert 'Integrations' in tab_names, 'Integration tab missing!'
assert hasattr(w, '_integration'), 'IntegrationManager missing!'
print('Integration panel wired: OK')
app.quit()
print('LAUNCH TEST PASSED')
"
