# GridSec Sim

A **Smart Grid Cybersecurity Simulation Tool** — a Man-in-the-Middle attack simulator for IEEE C37.118 synchrophasor protocols, inspired by NetSim Cyber.

---

## What It Does

GridSec Sim lets you:
- **Simulate a PMU** (Phasor Measurement Unit) generating real IEEE C37.118 binary frames
- **Intercept the data stream** with a built-in MitM proxy
- **Apply cyberattack modules** (noise injection, frequency override, replay attacks, packet drop, and more)
- **Visualize the attack** in real-time via a waveform viewer
- **Forward tampered data to openPDC** (or any C37.118-compatible PDC)
- **Design network topologies** on a Cisco Packet Tracer–style drag-and-drop canvas

---

## Requirements

- **OS**: Ubuntu 22.04 (WSL2 on Windows or bare Linux VM)
- **Python**: 3.10 or higher
- **Display**: Required for the GUI (use WSLg, VcXsrv, or X410 for WSL2)

---

## Installation (Linux / WSL2)

```bash
# Clone or copy the project to your Linux environment
cd GridSecSim

# Run the one-command installer
bash install.sh
```

The installer will:
1. Verify Python 3.10+
2. Install system packages (`libxcb`, `libgl1`, etc.)
3. Create a Python virtual environment (`venv/`)
4. Install all Python dependencies

---

## Running the App

```bash
cd GridSecSim
source venv/bin/activate
python main.py
```

### WSL2 Display Setup (if needed)

**Option A — WSLg** (Windows 11 with WSL2, auto-configured):
```bash
# Just run python main.py — WSLg handles display automatically
```

**Option B — VcXsrv** (Windows 10):
1. Install [VcXsrv](https://sourceforge.net/projects/vcxsrv/)
2. Launch XLaunch → "Multiple windows" → Disable access control
3. In WSL2: `export DISPLAY=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}'):0`
4. Then run `python main.py`

---

## Quick Start — End-to-End Simulation

1. Launch the app: `python main.py`
2. **Drag a PMU node** onto the canvas → right-click → set IP=`127.0.0.1`, Port=`4712`
3. **Drag a PDC node** → right-click → set IP=`127.0.0.1`, Port=`4713`
4. **Draw a link** between PMU and PDC (click Connect, then click each node)
5. **Drag a Threat Agent** onto the link (it becomes the MitM)
6. Open **Attack Panel** (right side) → select "Noise Attack" → set std_dev=`2.0`
7. Click **Run Simulation** (toolbar)
8. Watch the **waveform viewer** — green = clean signal, red = tampered signal
9. Read the **packet log** — attacked packets shown in red

### Guided scenarios and safer runs

- Use **File → Load MitM Demo** (or `python main.py --demo`) to load a ready-to-run PMU → MitM → PDC topology.
- Use the **Scenarios** menu to apply a clean baseline, noise, GPS spoofing, false-data, packet-loss, or replay setup in one click.
- Use **Validate Topology** before running. It blocks missing PMU/PDC setups and highlights unattached Threat Agents, missing C37.118 links, and single-stream port conflicts.
- Attack schedules can delay an enabled attack until a selected packet frame and optionally stop it after a selected duration.
- Saved topologies use the portable **v2** schema, with stable node IDs and retained MitM attachments. Legacy topology files remain supported.

---

## openPDC Integration

openPDC listens for C37.118 data on a configurable port (default: **TCP 4712**).

To forward the tampered stream to openPDC:
1. Ensure openPDC is running on your Windows host or Linux VM
2. In the PDC node properties, set the IP to your openPDC host (e.g., `192.168.1.100`) and Port=`4712`
3. Run the simulation — GridSec Sim's proxy will forward each (possibly modified) frame to openPDC

You can verify the tampered data by observing the openPDC waveform display showing corrupted voltage/frequency readings.

---

## Attack Modules

| Attack | Description |
|--------|-------------|
| **Noise** | Gaussian random noise on phasor magnitudes |
| **Ramp** | Linear drift of magnitude or frequency over time |
| **Pulse** | Periodic sudden spike in a field |
| **Frequency Override** | Force FREQ field to a specific value (45–65 Hz) |
| **Magnitude Override** | Force a specific phasor's magnitude |
| **Angle Override** | Force a specific phasor's angle |
| **Replay** | Record N frames and loop-replay them (freeze attack) |
| **Delay** | Inject latency (milliseconds) before forwarding |
| **Drop** | Randomly discard X% of packets |
| **Scale** | Multiply all phasor magnitudes by a scale factor |

---

## Project Structure

```
GridSecSim/
├── main.py                  # App entry point
├── requirements.txt         # Python dependencies
├── install.sh               # One-command Linux installer
├── README.md                # This file
│
├── core/
│   ├── pmu_simulator.py     # IEEE C37.118 PMU data generator thread
│   ├── pdc_proxy.py         # MitM proxy (PMU → attack → openPDC)
│   ├── packet_parser.py     # C37.118 binary frame parser/rebuilder
│   ├── attack_engine.py     # All 10 attack modules
│   └── traffic_filter.py   # Packet filter rules
│
├── protocols/
│   ├── c37118.py            # Full IEEE C37.118-2011 encoder/decoder
│   ├── dnp3.py              # DNP3 stub
│   ├── modbus.py            # Modbus TCP stub
│   └── iec104.py            # IEC 60870-5-104 stub
│
├── gui/
│   ├── main_window.py       # Main window (Packet Tracer layout)
│   ├── canvas.py            # Drag-and-drop topology canvas
│   ├── node_types.py        # PMU, PDC, Switch, ThreatAgent, Virtual nodes
│   ├── properties_panel.py  # Node/link configuration panel
│   ├── attack_panel.py      # Attack configuration panel
│   ├── waveform_viewer.py   # Live matplotlib signal viewer
│   └── styles.qss           # Dark theme Qt stylesheet
│
└── assets/icons/            # Node icon images
```

---

## Protocol Reference

- **IEEE C37.118-2011**: Primary simulated protocol. Synchrophasor data standard.
- **DNP3**: Stub implementation — structure only, no live simulation yet.
- **Modbus TCP**: Stub implementation.
- **IEC 60870-5-104**: Stub implementation.

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `cannot connect to X server` | Set `DISPLAY` env var — see WSL2 Display Setup above |
| `Address already in use` | Port 4712 is busy — change proxy port in node properties |
| `No module named PyQt6` | Run `source venv/bin/activate` first |
| `openPDC not receiving data` | Check firewall rules; ensure openPDC listens on correct port |
| GUI freezes | All network ops run in threads — if it freezes, report as bug |

---

## License

MIT License — For educational and research purposes only.

> ⚠️ **Warning**: This tool is for authorized cybersecurity research and education only. Unauthorized use against real power grid infrastructure is illegal and dangerous.
