# GridSec Sim — Smart Grid Cybersecurity Simulation Tool

> A Packet Tracer-style man-in-the-middle attack simulator for ICS/SCADA protocols.

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-green?style=flat-square)
![Protocols](https://img.shields.io/badge/Protocols-C37.118%20%7C%20DNP3%20%7C%20Modbus%20%7C%20GOOSE-orange?style=flat-square)

## Overview

GridSec Sim simulates real-world cyberattacks on smart grid infrastructure. It generates genuine IEEE C37.118 synchrophasor data, intercepts it via a man-in-the-middle proxy, applies attack modules, and sends the modified data to openPDC — all while generating real network traffic visible in Wireshark, Zeek, and commercial OT security tools.

## Features

- **Drag-and-drop topology canvas** (Cisco Packet Tracer style) — PMU, PDC, Switch, Threat Agent nodes  
- **PMU Simulator** — generates real IEEE C37.118 frames at 30 fps with 3-phase phasors  
- **MitM Proxy Engine** — intercepts, modifies, and forwards packets  
- **10 Attack Modules** mapped to MITRE ATT&CK for ICS  
- **4 Protocol Simulators** — C37.118, DNP3, Modbus/TCP, IEC 61850 GOOSE  
- **Live Waveform Viewer** — real-time voltage and frequency plots  
- **Professional OT Integrations** — Wireshark, Zeek, Dragos, Claroty, Splunk, REST API, STIX 2.1  

## Protocols

| Protocol | Port | Transport | Wireshark Filter |
|----------|------|-----------|-----------------|
| IEEE C37.118 (Synchrophasor) | 4712 | UDP | `udp.port == 4712` |
| DNP3 | 20000 | UDP | `dnp3` |
| Modbus/TCP | 502 | TCP | `modbus` |
| IEC 61850 GOOSE | — | Raw Ethernet | `goose` |

## Attack Modules

| Attack | MITRE ATT&CK ICS | What it does |
|--------|-----------------|-------------|
| Noise Injection | T0815 | Adds Gaussian noise to phasor/frequency values |
| Replay Attack | T0830 | Re-sends old captured frames instead of live data |
| Data Delay | T0830 | Buffers and delays packets by a configurable time |
| Packet Drop | T0800 | Silently drops packets (availability attack) |
| Frequency Override | T0836 | Forces a false fixed frequency value |
| Magnitude Override | T0836 | Forces a false voltage magnitude |
| Angle Override | T0836 | Manipulates phase angles |
| Ramp Attack | T0831 | Gradually drifts all values upward |
| Pulse Attack | T0801 | Injects periodic spikes |
| Scale Attack | T0836 | Multiplies all measurements by a factor |

## External Integrations

| Tool | Integration Method | Format |
|------|--------------------|--------|
| Wireshark, Zeek, Arkime | libpcap file + live FIFO pipe | `.pcap` |
| Security Onion | `so-import-pcap` | `.pcap` |
| Dragos, Claroty, Nozomi | Syslog/CEF (RFC 5424) + REST API | CEF, JSON |
| Splunk, QRadar, Sentinel | Syslog/CEF | CEF |
| OpenCTI, MISP | STIX 2.1 export | STIX 2.1 bundle |
| Custom / SOAR | REST API (11 endpoints + SSE) | JSON |

## Installation

```bash
git clone https://github.com/neerajjayesh/GridSec-project.git
cd GridSec-project
bash install.sh
source venv/bin/activate
python main.py
```

For GOOSE (requires raw Ethernet socket):
```bash
sudo python main.py
# OR (one-time capability grant):
sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
python main.py
```

## Project Structure

```
GridSec-project/
├── main.py                    # Application entry point
├── install.sh                 # Auto-installer (Python deps + venv)
├── core/
│   ├── attack_engine.py       # 10 MitM attack modules
│   ├── pmu_simulator.py       # IEEE C37.118 PMU simulator
│   ├── pdc_proxy.py           # Man-in-the-middle proxy engine
│   ├── dnp3_simulator.py      # DNP3 outstation simulator
│   ├── goose_simulator.py     # IEC 61850 GOOSE publisher
│   ├── modbus_simulator.py    # Modbus TCP server + polling master
│   ├── pcap_writer.py         # libpcap file writer
│   ├── rest_api.py            # REST API server (11 endpoints)
│   ├── integration_manager.py # Central OT tool integration hub
│   └── traffic_filter.py      # Packet filtering rules
├── gui/
│   ├── main_window.py         # Main PyQt6 window
│   ├── canvas.py              # Drag-and-drop topology canvas
│   ├── attack_panel.py        # Attack configuration UI
│   ├── integration_panel.py   # External integrations UI (5 tabs)
│   ├── waveform_viewer.py     # Live matplotlib waveform plots
│   ├── properties_panel.py    # Node properties panel
│   └── node_types.py          # Node definitions and icons
└── protocols/
    ├── c37118.py              # IEEE C37.118.2 encoder/decoder
    ├── dnp3.py                # DNP3 Data Link + CRC-16/DNP
    ├── modbus.py              # Modbus/TCP MBAP header + FCs
    └── goose.py               # IEC 61850 GOOSE ASN.1 BER encoder
```

## REST API Quick Reference

```bash
# Health check (no auth required)
curl http://localhost:8080/api/v1/status

# Get incident log
curl -H "Authorization: Bearer <key>" http://localhost:8080/api/v1/incidents

# Enable attack remotely
curl -X POST -H "Authorization: Bearer <key>" \
     -H "Content-Type: application/json" \
     -d '{"type":"NOISE","params":{"std_dev":5.0}}' \
     http://localhost:8080/api/v1/attack/enable

# Export STIX 2.1 threat intelligence
curl -H "Authorization: Bearer <key>" \
     http://localhost:8080/api/v1/export/stix -o threats.json

# Live event stream (Server-Sent Events)
curl --no-buffer -H "Authorization: Bearer <key>" \
     http://localhost:8080/api/v1/events
```

## Requirements

- Ubuntu 22.04+ or WSL2
- Python 3.10+
- PyQt6, matplotlib, numpy, scipy

## License

MIT License

## About

Built as a university cybersecurity project demonstrating ICS/SCADA protocol vulnerabilities and the critical need for IEC 62351 cryptographic authentication in smart grid deployments.
