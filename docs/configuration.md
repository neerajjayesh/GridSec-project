# Configuration reference

[Documentation index](index.md)

## Launch options and environment

| Setting | Default | Effect |
|---|---|---|
| `python main.py` | Empty canvas | Starts the desktop application |
| `python main.py --demo` | Opt-in | Loads bundled diagram after startup; does not start traffic |
| `GRIDSEC_LOG_LEVEL` | `INFO` | Python logging level, uppercased; unknown names fall back to INFO |
| `DISPLAY`, `WAYLAND_DISPLAY` | Environment-dependent | Linux/WSL display discovery |
| `QT_QPA_PLATFORM` | Qt/platform-dependent | Can select offscreen Qt for automated checks |

There is no project CLI parser exposing endpoint, attack, API, capture, config-file, or headless-run flags. `--demo` is detected directly in `sys.argv`.

PowerShell logging example:

```powershell
$env:GRIDSEC_LOG_LEVEL = 'DEBUG'
.\.venv\Scripts\python.exe main.py --demo
```

Linux example:

```bash
GRIDSEC_LOG_LEVEL=DEBUG .venv/bin/python main.py --demo
```

## Dependency declaration

| Package | Declared minimum | Role |
|---|---|---|
| PyQt6 | 6.4.0 | Desktop UI and signals |
| matplotlib | 3.7.0 | Embedded waveform plots |
| numpy | 1.24.0 | Plot data arrays |
| scapy | 2.5.0 | Declared packet-tooling dependency; core PCAP writer uses standard-library code |
| pyqtgraph | 0.13.0 | Declared dependency; current waveform implementation uses matplotlib |
| cryptography | 41.0.0 | Declared dependency; its presence does not enable TLS/authentication on protocol streams |

No exact lockfile or package metadata is supplied. Record installed versions for repeatable experiments. Startup explicitly checks only PyQt6, matplotlib, and numpy.

## Desktop runtime settings

| Setting | Actual runtime value/source | Notes |
|---|---|---|
| PMU destination host | `127.0.0.1` | Editable PMU IP is not used as the socket destination |
| Proxy bind host | `127.0.0.1` | Fixed by main window |
| Proxy listen port | First PMU node's `port`; default 4712 | Stop and restart after edits |
| Proxy destination | First Local PDC node's `ip` and `port`; defaults `127.0.0.1:4713` | Represents an independently running receiver |
| Main transport | UDP | Saved node `proto=TCP` does not switch the desktop runtime |
| Reporting rate | 30 frames/s | PMU node `reporting_rate` is not passed through |
| PMU ID | 1 | Node `idcode` is not passed through |
| Measurements | Three phasors, one analog, one digital word at generation | Parser digital-word mismatch is documented separately |
| Nominal frequency/magnitude | 50 Hz / 120 V | Constructor arguments fixed by main window |
| GOOSE | App ID `0x0001`, IED name `GridSecSim`, 1 Hz, autodetected interface | Started independently of diagram node counts |
| DNP3 | Destination `127.0.0.1:20000`, requested bind port 20000, 1 Hz | Bind host is `0.0.0.0`; may fall back to an ephemeral port |
| Modbus | Server `127.0.0.1:502`, 1 Hz master polling | On bind failure attempts port 10502 |

## Saved properties versus live behavior

Node labels, positions, levels, protocol labels, breaker state, switch port count, PDC buffer settings, regional uplink state, and Threat Agent metadata are stored in the diagram. Only the runtime fields identified above determine the desktop sockets.

Editing a property while running does not rebuild active components. `_on_config_applied()` logs the change; it does not reconfigure the proxy. Stop, edit, validate, and restart.

Threat Agent attack type, parameters, and schedule may be recorded when toggling attacks through the panel. Loading them restores metadata, not engine execution. The one active engine remains global to the stream; selected-link scope is not enforced.

## Core constructors

| Interface | Useful defaults and controls |
|---|---|
| `PMUSimulator` | `dst_host='127.0.0.1'`, `dst_port=4712`, `idcode=1`, `fps=30` clamped to 1–120, `nom_freq=50.0`, `nom_voltage=120.0` |
| `PDCProxy` | `listen_host='0.0.0.0'`, `listen_port=4712`, `target_host='127.0.0.1'`, `target_port=4713`, `proto='UDP'`; core also has TCP mode |
| `C37118Codec` | `idcode=1`, three phasors, one analog, zero digital words unless explicitly set |
| `GridSecRESTServer` | `host='127.0.0.1'`, `port=8080`; bearer auth enabled in shared API state |
| `IntegrationManager.configure_rest_api` | Defaults to `host='0.0.0.0'`, `port=8080`; explicitly pass loopback for local use |
| `configure_syslog` | `host='127.0.0.1'`, `port=514`, `protocol='UDP'` |
| `configure_pcap` | `/tmp/gridsec_capture.pcap`, regular file by default; choose a native path on Windows |

Constructors expose more flexibility than the desktop. These Python interfaces are not a promise of complete interoperability or thread-safe multi-instance use.

## Persistence and reset

| State | Saved/recovered? |
|---|---|
| Topology nodes, links, attachment IDs | Explicit JSON save/load |
| Attack metadata on agents | May be saved; not automatically armed on load |
| Engine counters, ramp/replay state | Memory only; retained across stop/start until reset |
| Incident history | Memory only, last 10,000 records |
| Recent packet summaries | Memory only, last 1,000 records |
| API token | Generated in module state per process; explicit setter available |
| Integration host/path settings | Memory only; no automatic settings file |
| Logs | Console by default; file persistence requires explicit redirection |

Source: [requirements](../requirements.txt), [entry](../main.py), [main window](../gui/main_window.py), [PMU](../core/pmu_simulator.py), [manager](../core/integration_manager.py).
