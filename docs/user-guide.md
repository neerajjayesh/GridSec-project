# User guide

[Documentation index](index.md)

## Workspace and editing

The left panel contains the hierarchical node palette and protocol selection. The center contains the topology canvas; the right panel contains Properties, Attacks, and Integrations. Lower panels show waveforms and packet records. The toolbar provides simulation, file, editing, and zoom controls.

1. Drag a palette node onto the canvas, double-click a palette item, or use a toolbar node shortcut.
2. Drag nodes to arrange them. Select a node for properties; right-click for its configuration menu.
3. Choose **Connect**, click source, then destination. `Escape` cancels an unfinished link.
4. Select or right-click a link to inspect/change its protocol.
5. Move a Threat Agent onto a link to record interception visually.
6. Use **Delete** mode or select items and press `Delete`/`Backspace` to remove them.
7. Save with `Ctrl+S`.

The canvas is a diagram editor. A drawn switch does not create packet-switching behavior, and every link does not launch a network connection.

## Node palette

| Level | Nodes | Current meaning |
|---|---|---|
| L0 Process | CT/VT Sensor, Circuit Breaker | Diagram assets with sensor/breaker metadata |
| L1 Bay | PMU, Protection IED, Bay Control Unit | PMU selects the stream; IED/BCU illustrate bay devices |
| L2 Station | Local PDC, Station Switch, Station HMI, Engineering Workstation, Gateway/RTU | Local PDC selects destination; other nodes retain station metadata |
| L3 State | State PDC | Regional diagram and uplink indicator |
| Unassigned | Threat Agent, Virtual Node | Interception annotation and generic device |

Breaker/uplink toggles update configuration and visuals; they do not actuate physical devices or connect a regional PDC.

Link defaults are GOOSE for L0–L1; C37.118 for PMU links between L1–L2 and GOOSE for other L1–L2 links; DNP3 for Gateway/RTU links between L2–L3 and C37.118 for other L2–L3 links. Other combinations keep the selected canvas protocol. Explicit link choices override defaults.

## Validate and run

**Validate** (`Ctrl+Shift+V`) blocks startup for missing PMU or Local PDC nodes. State PDC does not substitute for Local PDC. Missing direct C37.118 PMU–PDC links, unattached agents, and duplicate PMU ports produce warnings. Run asks whether to continue when warnings exist.

The first PMU sets the proxy listen port. The first Local PDC sets destination IP/port. Desktop runtime uses UDP, 30 frames/s, 50 Hz, and 120 V nominal magnitude regardless of several editable node fields.

Stop before loading another topology, changing endpoints, or selecting a scenario. Ordinary Open does not consistently enforce this, and a scenario can change attack state even when loading its demo is blocked during a run.

## Guided scenarios

| Scenario | Module | Preset |
|---|---|---|
| Clean Baseline | Disable current attack | No transformation |
| Noisy Sensor | `NOISE` | `noise_std=5.0` |
| GPS Frequency Spoofing | `FREQUENCY_OVERRIDE` | `target_freq=60.0` |
| Voltage False Data | `MAGNITUDE_OVERRIDE` | `phasor_idx=0`, `value=0.0` |
| Packet Loss Drill | `DROP` | `drop_percent=50.0` |
| Replay Drill | `REPLAY` | `buffer_size=90` |

Each loads the bundled diagram. GPS Frequency Spoofing changes a measurement field; it does not simulate GPS hardware. Presets are not complete run checkpoints. Reset attack statistics/state and review Schedule before comparing experiments; stop/start does not automatically reset them.

## Manual attacks

In **Attacks**, disable the current module, select the desired dropdown entry, adjust parameters, and enable it. Confirm the active module in the panel. Parameter edits are synchronized through the enable/disable action; changing the dropdown alone need not change the engine.

Use the dropdown as the authoritative selector. The top-level Attacks menu currently opens/synchronizes the panel without selecting its requested module. The selected-link scope option does not implement per-link execution.

Enable **Schedule attack by packet frame** to set Start after and Duration. Zero duration has no scheduled end. Read [Attack scheduling](attacks.md) for exact frame indexing.

**Reset Stats** clears engine counters and module state, including replay buffers and ramp/pulse counters. It does not clear integration incident history or remove the schedule.

## Interpret results

### Waveforms

Plots compare original and modified phase-A magnitude, frequency, and phase-A angle. Each retains 120 samples; the active tab refreshes at 10 Hz. At 30 data frames/s this is approximately four seconds.

The horizontal axis uses local processing time, not the frame timestamp. Dropped and configuration records can reach the plots. A plotted value does not prove delivery, and packet loss need not appear as a gap. Replay retains old frame timestamps but appears at the current display time.

### Packet classifications

| Status | Meaning |
|---|---|
| `clean` | Unchanged, filter bypass, inactive schedule, or no content modification |
| `attacked` | Engine marked content modified and proxy attempted re-encoding |
| `dropped` | Attack selected the frame for non-forwarding |
| `invalid` | Parser rejected or did not recognize the frame |

Delay preserves bytes and remains `clean`. Dashboard counters count matching data frames passed to the engine; proxy and incident totals also include other records.

### Exports

The Integrations export tab provides JSON and CSV. JSON retains original/modified frame fields; CSV summarizes events. STIX is experimental. PCAP needs an active writer and packet bytes; the current desktop capture path is incomplete. See [Integrations](integrations.md).

## Keyboard reference

| Action | Shortcut |
|---|---|
| New / Open / Save | `Ctrl+N` / `Ctrl+O` / `Ctrl+S` |
| Run / Stop | `F5` / `F6` |
| Validate | `Ctrl+Shift+V` |
| Zoom in / out / fit | `Ctrl+=` / `Ctrl+-` / `Ctrl+0` |
| Fit with canvas focus | `F` |
| Pan | Middle-button drag or hold `Space` and drag |
| Zoom around pointer | Mouse wheel |
| Cancel link / select | `Escape` |
| Delete selection | `Delete` / `Backspace` |
| Exit | `Ctrl+Q` |

## Record an experiment

Record source revision, package versions, topology, actual endpoints, module parameters, schedule, reset procedure, duration, and counters. Export before closing. For receiver tests, record transport/configuration and independent receipt evidence. Noise/drop results vary because the GUI has no random-seed setting.

Source: [main window](../gui/main_window.py), [canvas](../gui/canvas.py), [nodes](../gui/node_types.py), [attack panel](../gui/attack_panel.py), [viewer](../gui/waveform_viewer.py).
