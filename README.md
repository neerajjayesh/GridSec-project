# GridSec Sim

**Smart grid cybersecurity simulation and protocol analysis for research, teaching, and controlled laboratory experiments.**

GridSec Sim is a Python desktop application for creating substation topologies, generating synchrophasor measurements, applying controlled changes to a C37.118 stream, and comparing original and modified signals. Its PyQt6 interface combines a topology canvas, attack controls, waveform plots, packet records, and integration panels.

**Project GitHub:** [neerajjayesh/GridSec-project](https://github.com/neerajjayesh/GridSec-project)

The application reports version **1.0.0**. This documentation describes implemented behavior, including incomplete features. It does not claim production readiness or protocol certification.

## Documentation

**[Download the complete PDF manual](output/pdf/GridSec_Sim_Documentation.pdf)** - includes clickable contents, architecture diagrams, full worked examples, and embedded reference files.

**[Download the Overleaf project](output/overleaf/GridSec_Sim_Overleaf.zip)** - editable LaTeX chapters, figures, and examples; compile `main.tex` with pdfLaTeX.

| Your task | Read |
|---|---|
| Install and run your first experiment | [Getting started](docs/getting-started.md) |
| Learn the interface and scenarios | [User guide](docs/user-guide.md) |
| Understand project capabilities | [Product overview](docs/overview.md) |
| Understand the implementation | [Architecture](docs/architecture.md) |
| Configure attacks and scheduling | [Attack reference](docs/attacks.md) |
| Use protocols, APIs, and exports | [Protocols](docs/protocols.md), [REST API](docs/api-reference.md), [Integrations](docs/integrations.md) |
| Maintain or extend the project | [Development](docs/development.md), [Testing](docs/testing.md), [Contributing](CONTRIBUTING.md) |
| Browse everything | **[Full documentation index](docs/index.md)** |

## Quick start

Run from the directory containing `main.py`. Create a fresh environment for your operating system.

### Windows PowerShell

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe main.py --demo
```

### Linux or WSL

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py --demo
```

Python 3.10 or later and a working Qt display environment are required. See [Getting started](docs/getting-started.md) for platform details.

Choose **Scenarios → Clean Baseline**, then **Run** (`F5`). Use **Stop** (`F6`) before selecting another scenario. Choose **Noisy Sensor**, run again, and compare the waveforms.

## Current capabilities

- Thirteen node types across process, bay, station, and state levels.
- Topology editing, protocol labels, validation, and version 2 JSON saves.
- One active PMU-to-proxy C37.118 stream in the desktop runtime.
- Ten attack modules, packet-based scheduling, and original/modified plots.
- Auxiliary DNP3 and Modbus simulators; a Linux raw Ethernet GOOSE publisher.
- Incident JSON/CSV export and experimental STIX export.
- Core libraries for PCAP, Syslog/CEF, and a local REST API.

The first PMU and Local PDC determine the desktop stream. Canvas links do not create independent routes or attack engines. Some integration buttons call missing manager methods, and the GUI capture callback does not supply packet bytes. Read [Known limitations](docs/known-limitations.md) before relying on these workflows.

## Verification

```powershell
.\.venv\Scripts\python.exe test_regression.py
```

On Linux, use `.venv/bin/python test_regression.py`. The existing suite passed **201/201 checks** during this review. See [Testing](docs/testing.md) for coverage and verification boundaries.

## Repository layout

```text
main.py                 Desktop entry point
core/                   Simulators, proxy, attacks, filters, integrations
protocols/              Binary codecs and frame helpers
gui/                    Qt windows, canvas, panels, and plots
docs/                   User, reference, and maintenance documentation
requirements.txt        Direct dependencies with minimum versions
test_regression.py      Offscreen regression suite
mitm-demo-topology.json  Small demonstration topology
hard-topology.json       Larger topology illustration
SCENARIOS.md            Earlier extended scenario workbook
```

## Project use and licensing

Use GridSec Sim within an authorized, isolated laboratory. Starting a simulation attempts to start auxiliary protocol services as well as C37.118; see [Operations](docs/operations.md).

Earlier project text identifies the license as MIT, but this checkout contains no `LICENSE` file. The maintainer must supply the authoritative license and copyright notice before licensing status can be confirmed. See [Security](SECURITY.md) for the current security model.
