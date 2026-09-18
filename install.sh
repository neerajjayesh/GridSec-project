#!/bin/bash
# GridSec Sim — One-command installer for Ubuntu 22.04 (WSL2 / VM)
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║      GridSec Sim — Installer v1.0       ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Check Python 3.10+ ────────────────────────────────────────────────────
echo -e "${YELLOW}[1/5] Checking Python version...${NC}"
PYTHON_BIN=""
for bin in python3.12 python3.11 python3.10 python3; do
    if command -v "$bin" &>/dev/null; then
        VER=$("$bin" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        MAJOR=$(echo "$VER" | cut -d. -f1)
        MINOR=$(echo "$VER" | cut -d. -f2)
        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
            PYTHON_BIN="$bin"
            echo -e "  ${GREEN}✔ Found Python $VER at $(which $bin)${NC}"
            break
        fi
    fi
done

if [ -z "$PYTHON_BIN" ]; then
    echo -e "${RED}✘ Python 3.10+ not found. Installing...${NC}"
    sudo apt-get update -qq
    sudo apt-get install -y python3.10 python3.10-venv python3.10-dev
    PYTHON_BIN="python3.10"
fi

# ── 2. System dependencies ────────────────────────────────────────────────────
echo -e "${YELLOW}[2/5] Installing system dependencies...${NC}"
sudo apt-get update -qq
sudo apt-get install -y \
    python3-pip \
    python3-venv \
    libxcb-xinerama0 \
    libxcb-cursor0 \
    libgl1 \
    libglib2.0-0 \
    libfontconfig1 \
    libdbus-1-3 \
    libegl1 \
    net-tools
echo -e "  ${GREEN}✔ System packages installed${NC}"

# ── 3. Create virtual environment ─────────────────────────────────────────────
echo -e "${YELLOW}[3/5] Creating virtual environment...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -d "venv" ]; then
    echo -e "  ${YELLOW}⚠ Virtual environment already exists — skipping creation${NC}"
else
    "$PYTHON_BIN" -m venv venv
    echo -e "  ${GREEN}✔ Virtual environment created at $SCRIPT_DIR/venv${NC}"
fi

# ── 4. Install Python dependencies ────────────────────────────────────────────
echo -e "${YELLOW}[4/5] Installing Python dependencies...${NC}"
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q
echo -e "  ${GREEN}✔ Python packages installed${NC}"

# ── 5. Verify installation ────────────────────────────────────────────────────
echo -e "${YELLOW}[5/5] Verifying installation...${NC}"
python -c "from PyQt6.QtWidgets import QApplication; import matplotlib; import numpy; import scapy; print('  All imports OK')"
echo -e "  ${GREEN}✔ All modules verified${NC}"

deactivate

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Setup Complete!                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "To run GridSec Sim:"
echo -e "  ${CYAN}cd $(pwd)${NC}"
echo -e "  ${CYAN}source venv/bin/activate${NC}"
echo -e "  ${CYAN}python main.py${NC}"
echo ""
echo -e "For headless/WSL2 environments without a display server, set:"
echo -e "  ${CYAN}export DISPLAY=:0  # or use VcXsrv / WSLg${NC}"
echo ""
