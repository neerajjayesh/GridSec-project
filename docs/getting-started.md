# Getting started

[Documentation index](index.md)

## Obtain the source

The project repository is [neerajjayesh/GridSec-project](https://github.com/neerajjayesh/GridSec-project).

```text
git clone https://github.com/neerajjayesh/GridSec-project.git
cd GridSec-project
```

If you already have the source, open the directory containing `main.py` and continue with the installation steps below.

## Requirements

| Requirement | Details |
|---|---|
| Python | Project baseline: 3.10+. Review environment: Windows with Python 3.14.6. |
| Display | Qt-compatible desktop; minimum window 1200 × 700, initial size 1600 × 950 |
| Packages | Install all entries in `requirements.txt` |
| Source | Keep `core/`, `gui/`, `protocols/`, stylesheet, and demo beside `main.py` |
| Network | Local UDP/TCP sockets; isolated laboratory for external receivers |
| Optional tools | Wireshark/capture reader and an independently configured PDC |

Windows supports the Qt interface and main UDP workflow. GOOSE uses Linux `AF_PACKET`; native Windows does not support that publisher. Linux/WSL GOOSE also depends on raw socket permissions and the interface. The core experiment does not require elevating the desktop application.

## Windows installation

Open PowerShell in the directory containing `main.py`:

```powershell
py -3 --version
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -c "import PyQt6, numpy, matplotlib; print('Core imports OK')"
.\.venv\Scripts\python.exe main.py --demo
```

Calling the interpreter directly avoids a PowerShell activation-policy change. Use an existing working environment if you already have one. Do not reuse an environment copied from another OS or machine.

## Linux or WSL installation

```bash
python3 --version
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -c "import PyQt6, numpy, matplotlib; print('Core imports OK')"
.venv/bin/python main.py --demo
```

If environment creation fails, install your distribution's Python virtual-environment package. Qt may also need XCB, OpenGL, EGL, font, and D-Bus libraries.

The bundled `install.sh` targets Ubuntu 22.04 and creates `venv/`. It invokes `sudo apt-get`, selects Python, installs system packages, and installs requirements. Review it for other distributions. Its system-package block suppresses failures with `|| true`; a success banner alone does not verify the installation.

```bash
bash install.sh
venv/bin/python main.py --demo
```

## Display setup

On Windows, use a normal desktop session. Under WSL, use an available WSLg display or a configured display server. Preserve working `DISPLAY` and `WAYLAND_DISPLAY` values.

On Linux, `main.py` sets `QT_QPA_PLATFORM=offscreen` when neither display variable exists, unless a platform was already set. Offscreen mode supports checks but produces no visible window. It is not a headless simulation service.

## First experiment

1. Launch with `--demo`; it loads a topology without starting simulation.
2. Choose **Scenarios → Clean Baseline**.
3. Click **Validate**; the demo has a PMU, Local PDC, and attached Threat Agent.
4. Click **Run** (`F5`). Check packet totals and proxy status.
5. Inspect magnitude, frequency, and angle. Clean values overlap, apart from possible startup/configuration-record artifacts.
6. Click **Stop** (`F6`).
7. Choose **Scenarios → Noisy Sensor**, then run again. Modified magnitude varies around the original.
8. Stop, save the topology, and export incident JSON/CSV from the Integrations export tab.

The demo forwards UDP to `127.0.0.1:4713`. A Local PDC node represents a destination; it does not launch a PDC receiver. The GUI can display proxy results with no listener. See [Integrations](integrations.md) for receipt verification.

## Installation verification

Windows:

```powershell
.\.venv\Scripts\python.exe test_regression.py
.\.venv\Scripts\python.exe docs/examples/inspect_frame.py
```

Linux/WSL:

```bash
.venv/bin/python test_regression.py
.venv/bin/python docs/examples/inspect_frame.py
```

The regression suite uses offscreen Qt. The documentation example verifies a deterministic transformation without network traffic. See [Testing](testing.md) for results and coverage limits, then [User guide](user-guide.md) to build an experiment.

Source: [entry point](../main.py), [requirements](../requirements.txt), [installer](../install.sh), [demo](../mitm-demo-topology.json).
