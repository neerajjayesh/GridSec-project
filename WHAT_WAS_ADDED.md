# What Was Added to GridSec Sim

This file lists the enhancements added during the current improvement pass and shows where to find them in the application.

## Quick way to see the additions

1. Start the app from Windows:

   ```powershell
   py -3 main.py --demo
   ```

2. The bundled **PMU-Demo → MitM-Demo → PDC-Demo** topology opens automatically.
3. Look for the following UI items:

   | Where | What to use |
   |---|---|
   | Toolbar | **Load Demo**, **Save**, and **Validate** |
   | File menu | **Load MitM Demo** and **Validate Topology** |
   | Scenarios menu | One-click training scenarios |
   | Attacks tab | New **Schedule** section |
   | Packet Log header | Live simulation summary |

## Added features

### 1. Bundled MitM demo topology

- New file: `mitm-demo-topology.json`
- Contains a PMU, an active Threat Agent, and a PDC connected with an intercepted C37.118 link.
- Load it from **File → Load MitM Demo**, the **Load Demo** toolbar button, or with:

  ```powershell
  py -3 main.py --demo
  ```

### 2. Guided scenarios

Open the **Scenarios** menu and choose one of:

- Clean Baseline
- Noisy Sensor
- GPS Frequency Spoofing
- Voltage False Data
- Packet Loss Drill
- Replay Drill

Each scenario loads the demo topology and applies a suitable attack configuration. Start the simulation with **Run** or `F5`.

### 3. Topology validation

Use **Validate** in the toolbar, or **File → Validate Topology**.

It checks for:

- missing PMU or Local PDC nodes (blocks simulation)
- a missing direct C37.118 PMU-to-PDC link
- Threat Agents that are not attached to a link
- duplicate PMU ports, which are not supported by the present single-stream runtime

The same validation runs before a simulation starts.

### 4. Live run dashboard

The header of the **Packet Log** now shows:

- simulation state: Ready or Running
- total packets
- modified packets
- dropped packets
- current active attack

### 5. Attack scheduling

Open the **Attacks** tab and use the **Schedule** section.

- Enable **Schedule attack by packet frame**.
- Set **Start after** to delay the attack.
- Set **Duration** to a number of frames, or leave it at `0` to continue until stopped.

This is useful for multi-stage demonstrations: run clean traffic first, then activate an attack at a predictable time.

### 6. Safer, portable topology files

New saves use topology schema **v2**:

- stable UUID-based node identifiers
- saved MitM/Threat Agent link attachments
- retained attacker settings on active Threat Agents
- backward compatibility with legacy topology files

This fixes the earlier issue where a loaded topology could lose its intercepted-link state.

### 7. Better attacker configuration groundwork

When an attack is enabled, its type, parameters, and schedule are recorded on active Threat Agent nodes. This makes the configuration visible in saved topology data and establishes the foundation for future per-link execution.

## Current limitations

- The runtime currently simulates one active PMU/proxy stream. Multiple Threat Agents can be drawn and configured, but true simultaneous per-link attack execution requires a multi-stream proxy redesign.
- Creating an EXE/installer and connecting to external production systems are separate packaging/deployment tasks.

## Verification

After these additions, the regression suite reports:

```text
201/201 passed, 0 failed
```

Run it with:

```powershell
py -3 test_regression.py
```
