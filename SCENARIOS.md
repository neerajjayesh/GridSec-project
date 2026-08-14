# GridSecSim — Complete Scenario Playbook

> **15 hands-on scenarios** you can run yourself. No coding needed.  
> Each scenario tells you exactly: what to build, what buttons to click, and what to look for.

---

## Table of Contents

| #  | Scenario | Difficulty | Attack Used |
|----|----------|-----------|-------------|
| 1  | Your First Simulation | 🟢 Easy | None (clean baseline) |
| 2  | Noisy Sensor | 🟢 Easy | NOISE |
| 3  | GPS Spoofing | 🟢 Easy | FREQUENCY_OVERRIDE |
| 4  | Voltage Lie | 🟢 Easy | MAGNITUDE_OVERRIDE |
| 5  | Angle Manipulation | 🟢 Easy | ANGLE_OVERRIDE |
| 6  | Slow Drift Attack | 🟡 Medium | RAMP |
| 7  | Spike Injection | 🟡 Medium | PULSE |
| 8  | Data Replay (Stuxnet-style) | 🟡 Medium | REPLAY |
| 9  | Latency Bomb | 🟡 Medium | DELAY |
| 10 | Packet Black Hole | 🟡 Medium | DROP |
| 11 | Scaling Deception | 🟡 Medium | SCALE |
| 12 | Full Substation Topology | 🟡 Medium | None (architecture) |
| 13 | Multi-Phase APT Attack | 🔴 Hard | REPLAY → MAG_OVERRIDE → REPLAY |
| 14 | Coordinated Dual-Bay Attack | 🔴 Hard | SCALE on two links |
| 15 | State-Level Blackout Simulation | 🔴 Hard | Multiple attacks chained |

---

## How to Launch the App

```
python main.py
```

You'll see this layout:

```
┌──────────────────────────────────────────────────────┐
│  Toolbar: Run | Stop | Select | Connect | Delete     │
├────────────┬──────────────────────┬──────────────────┤
│ Node       │                      │ Properties tab   │
│ Palette    │   Canvas             │ Attacks tab      │
│ (drag      │   (your diagram)     │ (enable attacks) │
│  nodes)    │                      │                  │
├────────────┴───────────┬──────────┴──────────────────┤
│ Waveform Viewer        │ Packet Log                  │
├────────────────────────┴─────────────────────────────┤
│ Status Bar: PMU status | Proxy | Sent | Modified     │
└──────────────────────────────────────────────────────┘
```

### Controls Cheat Sheet

| What you want to do | How to do it |
|---------------------|-------------|
| Place a node | Drag it from the left palette onto the canvas |
| Select something | Left-click it |
| Connect two nodes | Click "Connect" button → click Node A → click Node B |
| Go back to normal | Click "Select" button (or press Escape) |
| Delete something | Select it → press Delete key |
| Move a node | Click and drag it |
| Zoom in/out | Scroll wheel |
| Pan the canvas | Middle-mouse-button drag |
| Run simulation | Press F5 (or click Run) |
| Stop simulation | Press F6 (or click Stop) |
| Save your work | Ctrl+S |

---

## The 4 Levels (What the Canvas Lanes Mean)

The canvas has 4 horizontal lanes. Each represents a level of a real power substation:

```
┌─────────────────────────────────────────────────┐
│  L3 — State     (top)    State/Regional PDC     │  ← Sends data to grid operator
├─────────────────────────────────────────────────┤
│  L2 — Station            PDC, Switch, HMI, RTU  │  ← Station-level equipment
├─────────────────────────────────────────────────┤
│  L1 — Bay                PMU, IED, BCU           │  ← Bay-level devices
├─────────────────────────────────────────────────┤
│  L0 — Process  (bottom)  CT/VT, Breaker         │  ← Physical equipment
└─────────────────────────────────────────────────┘
```

When you drag a node onto the canvas, it **automatically snaps** to the correct lane.

---

# 🟢 EASY SCENARIOS (1–5)

These use a simple 2-node topology. Perfect for learning the basics.

---

## Scenario 1: Your First Simulation

**Goal**: See clean synchrophasor data flowing. No attacks. This is your baseline.

### Step 1 — Build

1. In the left palette, expand **"L1 — Bay"**
2. Drag **PMU** onto the canvas → it lands in the Bay lane
3. Expand **"L2 — Station"**
4. Drag **Local PDC** onto the canvas → it lands in the Station lane
5. Click **"Connect"** button in the toolbar (top)
6. Click the **PMU node** on the canvas
7. Click the **PDC node** on the canvas
8. A purple line appears between them labeled **"C37.118"** — that's the link!
9. Click **"Select"** button to go back to normal mode

### Step 2 — Run

10. Press **F5** (or click **Run** in toolbar)
11. Look at the **bottom-left** → Waveform Viewer shows:
    - Green line bouncing = voltage magnitude (~120V)
    - Switch tabs to see Frequency (~50Hz) and Angle
12. Look at the **bottom-right** → Packet Log shows:
    - Lines appearing rapidly, all marked **CLEAN** in green
13. Look at the **status bar** (very bottom):
    - "PMU: ● Running" with a counter going up
    - "Sent: 1, 2, 3..." counting packets
    - "Modified: 0" and "Dropped: 0" — nothing is being attacked

### Step 3 — Stop

14. Press **F6** to stop

### What you learned
> This is what NORMAL looks like. Every future scenario will show you how attacks change this baseline.

---

## Scenario 2: Noisy Sensor (NOISE Attack)

**Goal**: Add random noise to voltage measurements — like a sensor going bad.

### Step 1 — Build (same as Scenario 1)

1. PMU → PDC connected with C37.118 link (use your saved topology or rebuild)
2. Drag a **Threat Agent** (red triangle, from "Utility" section at bottom of palette) and drop it **on top of the purple link** between PMU and PDC
3. The link turns **red and dashed** — it's intercepted!
4. Right-click the Threat Agent → click **"Set as Active Attacker"**

### Step 2 — Configure the Attack

5. Click the **"Attacks" tab** on the right panel
6. Select attack type: **NOISE**
7. Set **noise_std = 5.0** (this means ±5 volts of random noise)
8. Click **Enable**

### Step 3 — Run and Observe

9. Press **F5** to start simulation
10. **Waveform Viewer** now shows TWO lines:
    - 🟢 Green = original clean signal (smooth)
    - 🔴 Red = attacked signal (jittery, noisy)
11. **Packet Log** shows entries marked **ATTACKED [NOISE]** in red
12. **Status bar** shows "Modified: 1, 2, 3..." counting attacked packets

### Step 4 — Experiment

13. While running, change **noise_std to 50.0** → click **Apply**
14. The red line gets MUCH noisier — huge voltage swings
15. Change it to **0.5** → barely visible difference (subtle attack)

### Step 5 — Stop

16. Click **Disable** in the Attacks tab
17. Press **F6** to stop

### What you learned
> A noise attack adds random jitter. High noise is obvious, low noise is sneaky. Real attackers use low noise to avoid detection.

---

## Scenario 3: GPS Spoofing (FREQUENCY_OVERRIDE Attack)

**Goal**: Force the reported frequency to a wrong value — simulating GPS spoofing on a PMU.

### Build

1. Same PMU → Threat Agent → PDC setup as Scenario 2

### Configure

2. Attacks tab → select **FREQUENCY_OVERRIDE**
3. Set **target_freq = 60.0** (real grid is 50Hz, we're forcing it to say 60Hz)
4. Click **Enable**

### Run and Observe

5. Press **F5**
6. Click the **"Frequency"** tab in the Waveform Viewer
7. You'll see:
    - 🟢 Green line = real frequency at ~50Hz
    - 🔴 Red line = attacked frequency locked at exactly 60Hz
8. Packet Log shows **ATTACKED [FREQUENCY_OVERRIDE]** entries
9. The reported frequency jump from 50→60 is a **10Hz error** — in a real grid, this would trigger emergency load shedding!

### Experiment

10. Try **target_freq = 49.5** — a subtle 0.5Hz drift. Much harder to detect but still dangerous over time.
11. Try **target_freq = 0.0** — complete frequency blackout

### What you learned
> GPS spoofing can make a PMU report wrong frequency. The grid operator sees 60Hz when reality is 50Hz. This can cause generators to trip offline.

---

## Scenario 4: Voltage Lie (MAGNITUDE_OVERRIDE Attack)

**Goal**: Force a voltage phasor to zero — making it look like a line is dead when it isn't.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → select **MAGNITUDE_OVERRIDE**
3. Set **phasor_idx = 0** (this targets the first voltage phasor, Va)
4. Set **value = 0.0** (force it to zero volts)
5. Click **Enable**

### Run and Observe

6. Press **F5**
7. **Waveform Viewer** (Voltage tab):
    - 🟢 Green = real voltage at ~120V
    - 🔴 Red = attacked voltage flat at 0V
8. This is a **false data injection** — the operator thinks the line is dead (0V) but it's actually live (120V). Extremely dangerous.

### Experiment

9. Try **value = 240.0** — opposite lie: makes it look like overvoltage. Operator might disconnect a healthy line.
10. Try **phasor_idx = 1** — targets the second phasor (Vb) instead of Va.

### What you learned
> Magnitude override is the most dangerous FDI attack. The operator makes decisions based on lies. Zero voltage = "line is dead" = operator might energize it while workers are on it.

---

## Scenario 5: Angle Manipulation (ANGLE_OVERRIDE Attack)

**Goal**: Force a phasor angle to a wrong value — disrupting power flow calculations.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → select **ANGLE_OVERRIDE**
3. Set **phasor_idx = 0** (target Va)
4. Set **angle_deg = 90.0** (force angle to 90° instead of real ~0°)
5. Click **Enable**

### Run and Observe

6. Press **F5**
7. Click the **"Angle"** tab in Waveform Viewer:
    - 🟢 Green = real angle near 0°
    - 🔴 Red = forced to 90°
8. In a real grid, **angle difference between buses** determines power flow direction. A 90° error would make the state estimator think power is flowing the wrong way.

### Experiment

9. Try **angle_deg = 180.0** — this is the "anti-phase" attack. Maximum disruption.
10. Try **angle_deg = 5.0** — subtle 5° shift. Hard to detect but accumulates errors over time.

### What you learned
> Angle attacks mess up power flow calculations. Even small angle errors compound across the grid, leading to wrong dispatch decisions.

---

# 🟡 MEDIUM SCENARIOS (6–11)

These introduce more complex attacks and larger topologies.

---

## Scenario 6: Slow Drift Attack (RAMP)

**Goal**: Gradually increase voltage readings over time — like boiling a frog slowly.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → **RAMP**
3. Set **ramp_rate = 0.5** (add 0.5V per frame)
4. Set **direction = up**
5. Set **target = magnitude**
6. Click **Enable**

### Run and Observe

7. Press **F5**
8. Watch the **Voltage** waveform:
    - 🟢 Green stays flat at ~120V
    - 🔴 Red slowly climbs: 120 → 121 → 122 → 130 → 140...
9. After 30 seconds, the attacked value might be 500V+ while reality is still 120V

### Why this matters

- The attack is **invisible at first** — both lines start at the same place
- Anomaly detectors that check for sudden jumps will MISS this
- By the time the drift is noticeable, the state estimator has been poisoned for minutes

### Experiment

10. Try **direction = down** — voltage slowly drops toward zero
11. Try **target = frequency** — frequency drifts instead of voltage
12. Try **ramp_rate = 0.01** — super slow, almost undetectable

### What you learned
> Ramp attacks are stealth attacks. They change values so slowly that threshold-based alarms don't trigger. This is how sophisticated attackers operate.

---

## Scenario 7: Spike Injection (PULSE)

**Goal**: Inject periodic voltage spikes — simulating equipment faults or trigger false protection trips.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → **PULSE**
3. Set **amplitude = 100.0** (100V spike above normal)
4. Set **interval = 10** (spike every 10 frames)
5. Set **duration_frames = 2** (each spike lasts 2 frames)
6. Click **Enable**

### Run and Observe

7. Press **F5**
8. **Waveform Viewer**: Red line has periodic tall spikes, green stays flat
9. **Packet Log**: You'll see clusters of `ATTACKED [PULSE]` entries every ~10 packets, with `CLEAN` entries between them

### Why this matters

- Periodic spikes can **trigger protection relays** to trip breakers
- If spikes match the relay's pickup time, they cause false disconnections
- This is a **denial-of-service through false protection operation**

### Experiment

10. Try **interval = 3** — very frequent spikes (hammering)
11. Try **amplitude = 5.0** — subtle spikes that might fool averaging algorithms
12. Try **duration_frames = 10** — long sustained spikes

### What you learned
> Pulse attacks can cause cascading failures. If a protection relay sees "overvoltage" for enough consecutive frames, it trips the breaker — disconnecting a healthy line.

---

## Scenario 8: Data Replay — Stuxnet Style (REPLAY)

**Goal**: Record normal data, then loop it forever — hiding any physical changes. This is exactly what Stuxnet did to Iran's centrifuges.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → **REPLAY**
3. Set **buffer_size = 60** (records 60 frames = 2 seconds at 30fps)
4. Click **Enable**

### Run and Observe

5. Press **F5**
6. **First 2 seconds**: The attack is recording. Both lines look the same.
7. **After 2 seconds**: The red line starts **looping** — it replays the same 2-second pattern over and over
8. The green line keeps showing real-time data, but the operator only sees the red (replayed) data
9. **Even if the physical system changes completely**, the operator's screen shows the old "normal" recording

### Why this is terrifying

- The operator sees "everything is fine" while the attacker does whatever they want
- Stuxnet used this exact technique: showed operators normal centrifuge speeds while actually spinning them to destruction
- Detection requires comparing across multiple independent data sources

### Experiment

10. Try **buffer_size = 10** — shorter loop, more obvious repetition
11. Try **buffer_size = 300** — 10-second recording, very hard to detect

### What you learned
> Replay attacks are the ultimate stealth tool. The operator sees a perfect copy of "normal" while reality could be a disaster. This is why redundant, independent monitoring matters.

---

## Scenario 9: Latency Bomb (DELAY)

**Goal**: Add artificial delay to data packets — making real-time control impossible.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → **DELAY**
3. Set **delay_ms = 200** (200 millisecond delay per packet)
4. Click **Enable**

### Run and Observe

5. Press **F5**
6. Watch the **Packet Log** — entries appear noticeably slower than before
7. **Status bar**: "Sent" counter still goes up, but packets arrive at the PDC 200ms late
8. In a real system, PMU data must arrive within **20-50ms** for real-time control. A 200ms delay makes the data useless for protection.

### Why this matters

- Synchrophasor-based protection systems need data in **real-time** (<50ms)
- Adding 200ms delay means the protection system is always looking at **old data**
- If a fault happens, the protection relay sees it 200ms too late — potentially causing equipment damage

### Experiment

9. Try **delay_ms = 50** — just enough to cross the "too late" threshold
10. Try **delay_ms = 1000** — 1 full second of delay. Data is completely useless.
11. Try **delay_ms = 10** — very subtle, might not be noticed but still degrades accuracy

### What you learned
> Timing attacks don't change the data — they just deliver it too late. This is harder to detect because the values look correct, they're just stale.

---

## Scenario 10: Packet Black Hole (DROP)

**Goal**: Randomly destroy packets — simulating a DoS attack on the communication link.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → **DROP**
3. Set **drop_percent = 50.0** (destroy half of all packets)
4. Click **Enable**

### Run and Observe

5. Press **F5**
6. **Packet Log**: Mix of `CLEAN` (green) and `DROPPED` (yellow) entries
7. **Status bar**: "Dropped" counter climbing. "Sent" counter is about half of what it was in Scenario 1
8. **Waveform Viewer**: Gaps and stuttering in the signal — the PDC is missing data

### What happens at different drop rates

| Drop % | Effect |
|--------|--------|
| 10% | Barely noticeable — PDC interpolates |
| 30% | PDC starts showing data quality warnings |
| 50% | Significant gaps — real-time protection unreliable |
| 75% | Mostly blind — operator has no situational awareness |
| 95% | Near-total communication blackout |
| 100% | Complete denial of service |

### Experiment

9. Try each percentage above and watch the waveform degrade

### What you learned
> Packet dropping is the simplest DoS attack. Even 30% packet loss makes synchrophasor-based protection unreliable.

---

## Scenario 11: Scaling Deception (SCALE)

**Goal**: Multiply all voltages by a factor — everything looks proportionally wrong.

### Build

1. Same PMU → Threat Agent → PDC setup

### Configure

2. Attacks tab → **SCALE**
3. Set **scale_factor = 2.0** (double all voltages)
4. Click **Enable**

### Run and Observe

5. Press **F5**
6. **Waveform Viewer**:
    - 🟢 Green = ~120V (real)
    - 🔴 Red = ~240V (doubled!)
7. The operator sees dangerous overvoltage and might **disconnect the line** — when it's actually fine!

### The clever version

8. Try **scale_factor = 0.95** — everything reads 5% low
9. This makes the operator think voltage is sagging. They might **boost generation** — causing actual overvoltage on a healthy line.
10. Try **scale_factor = 1.01** — just 1% off. Almost impossible to detect, but over time it corrupts state estimation across the entire grid.

### What you learned
> Scaling attacks preserve the shape of the signal (same noise pattern, same trends) — only the magnitude changes. This makes them harder to detect than other attacks because statistical properties like variance remain proportional.

---

## Scenario 12: Full Substation Topology (No Attack)

**Goal**: Build a complete 4-level substation to understand the architecture before running advanced attacks.

### Build This Topology

```
L3 — State:     [SPDC-1]
                  ↑        ↑
L2 — Station:   [PDC-1] [RTU-1]  [HMI-1]  [EW-1]
                  ↑        ↑        ↑        ↑
                 [SW-1] ──────────────────────┘
                  ↑
L1 — Bay:       [PMU-1]  [IED-1]  [BCU-1]
                  ↑        ↑
L0 — Process:   [CT-1]   [CB-1]
```

### Step by Step

**Level 0 — Process (bottom lane):**
1. Drag **CT/VT Sensor** from "L0 — Process" → it snaps to the bottom lane
2. Drag **Circuit Breaker** next to it

**Level 1 — Bay:**
3. Drag **PMU** from "L1 — Bay"
4. Drag **Protection IED** next to it
5. Drag **Bay Control Unit** next to it

**Level 2 — Station:**
6. Drag **Station Switch** from "L2 — Station"
7. Drag **Local PDC** next to it
8. Drag **Gateway / RTU** next to it
9. Drag **Station HMI** next to it
10. Drag **Eng. Workstation** next to it

**Level 3 — State:**
11. Drag **State PDC** from "L3 — State"

**Connect everything (use "Connect" mode):**
12. CT-1 → PMU-1 (link auto-selects **GOOSE**)
13. CB-1 → IED-1 (link auto-selects **GOOSE**)
14. PMU-1 → SW-1 (link auto-selects **C37.118**)
15. IED-1 → SW-1 (link auto-selects **GOOSE**)
16. BCU-1 → SW-1
17. SW-1 → PDC-1
18. SW-1 → HMI-1
19. SW-1 → EW-1
20. PDC-1 → SPDC-1 (link auto-selects **C37.118**)
21. RTU-1 → SPDC-1 (link auto-selects **DNP3**)

### Explore

22. Click each node and read the **Properties panel** on the right:
    - **CT/VT**: Read-only sensor info
    - **Breaker**: Click the toggle button to switch between 🟢 CLOSED and 🔴 OPEN
    - **PMU**: See reporting rate (30 fps) and C37.118 ID code
    - **IED**: Shows "Protection Relay — GOOSE protocol"
    - **HMI**: Dropdown to set status: Active / Idle / Down
    - **Eng. WS**: See the big yellow **⚠ HIGH-RISK ASSET** badge
    - **RTU**: Dropdown for uplink protocol: DNP3 or IEC104
    - **State PDC**: Toggle **Regional Uplink** on/off (watch the packet log for status messages)

23. **Right-click a link** → Change Protocol to see options (C37.118, DNP3, Modbus, IEC104, GOOSE)

24. **Save this topology** with Ctrl+S — you'll reuse it for Scenarios 13-15

### What you learned
> You now understand the full substation architecture. Data flows from physical sensors (L0) up through bay devices (L1), station equipment (L2), to the state-level PDC (L3) that reports to grid operators.

---

# 🔴 HARD SCENARIOS (13–15)

These combine multiple attacks and use the full substation topology from Scenario 12.

---

## Scenario 13: Multi-Phase APT Attack (Industroyer Simulation)

**Goal**: Simulate a real-world APT (Advanced Persistent Threat) attack in 4 phases — just like the 2016 Ukraine power grid attack.

### Setup

1. Load your Scenario 12 topology (or rebuild it)
2. Drop a **Threat Agent** on the **PMU-1 → SW-1** link
3. Right-click Threat Agent → "Set as Active Attacker"

### Phase 1 — Reconnaissance (REPLAY)

> *The attacker observes normal patterns before acting.*

4. Attacks tab → **REPLAY**
5. Set **buffer_size = 90** (3 seconds of "normal" data)
6. Click **Enable**
7. Press **F5** — let it run for 5 seconds
8. The attacker is now recording baseline data
9. **Disable** the attack (but keep simulation running)

### Phase 2 — False Data Injection (MAGNITUDE_OVERRIDE)

> *The attacker hides the real state from the operator.*

10. Switch to **MAGNITUDE_OVERRIDE**
11. Set **phasor_idx = 0, value = 0.0**
12. Click **Enable**
13. Watch the waveform: operator sees 0V (dead line) while reality is 120V (live line)
14. In the real attack, this is when the attacker would send switching commands

### Phase 3 — Physical Action (Breaker Trip)

> *The attacker opens a circuit breaker.*

15. Right-click **CB-1** (Circuit Breaker) → **"Open Breaker"**
16. The breaker node turns red with 🔴 indicator
17. In reality, this disconnects a section of the power grid

### Phase 4 — Cover Tracks (REPLAY)

> *The attacker replays old "normal" data to hide what happened.*

18. Switch attack to **REPLAY**
19. Set **buffer_size = 90**
20. Click **Enable**
21. The operator now sees the old "normal" recording — they don't know the breaker was opened
22. Check the packet log: entries show `ATTACKED [REPLAY]` but the VALUES look normal

### Stop and Review

23. Press **F6**
24. Look at the status bar: "Modified" counter shows how many packets were tampered with

### What you learned
> This is exactly the Industroyer/CrashOverride attack pattern: observe → blind the operator → take action → cover tracks. The key insight is that attacks are SEQUENTIAL, not just single events.

---

## Scenario 14: Coordinated Dual-Bay Attack

**Goal**: Attack two PMU feeds simultaneously to corrupt state estimation.

### Setup — Build Two Bays

1. Build two parallel paths:
   ```
   Bay A:  CT-1 → PMU-1 → SW-1 → PDC-1 → SPDC-1
   Bay B:  CT-2 → PMU-2 → SW-2 → PDC-2 → SPDC-1 (same State PDC!)
   ```
2. Drop **Threat Agent #1** on the **PMU-1 → SW-1** link
3. Drop **Threat Agent #2** on the **PMU-2 → SW-2** link

### Attack A — Make Bay A Read High

4. Select Threat Agent #1 (click it)
5. Right-click → "Set as Active Attacker"
6. Attacks tab → **SCALE**, set **scale_factor = 1.5** (50% higher)
7. Click **Enable**

### Run

8. Press **F5**
9. The State PDC now receives:
    - Bay A: 180V (fake — scaled up 50%)
    - Bay B: 120V (real)
10. The **state estimator** sees a 60V difference between two bays that should be similar
11. It might flag Bay B as "bad data" and remove it — trusting the wrong one!

### Make It Sneaky

12. Change **scale_factor to 1.02** — only 2% difference
13. Now Bay A says 122.4V and Bay B says 120V
14. This is within normal variation — the state estimator won't flag it
15. But over time, it introduces systematic bias into grid-wide calculations

### What you learned
> When attackers control multiple measurement points, they can fool the state estimator — the algorithm that grid operators rely on for situational awareness. Even small coordinated errors compound into dangerous decisions.

---

## Scenario 15: State-Level Blackout Simulation

**Goal**: Chain multiple attacks to simulate a cascading blackout — the worst-case scenario.

### Setup

1. Build the full Scenario 12 topology
2. Add a second bay (PMU-2, CT-2, IED-2) connected through SW-1

### Phase 1 — Infiltrate via Engineering Workstation

3. Drop a **Threat Agent** on the **EW-1 → SW-1** link
4. This represents the attacker gaining access through the Engineering Workstation (USB malware, phishing, etc.)
5. Click EW-1 and note the **⚠ HIGH-RISK ASSET** warning in Properties

### Phase 2 — Blind the Operator

6. Set Active Attacker on the Threat Agent
7. Enable **REPLAY** attack (buffer_size = 120 = 4 seconds)
8. Press **F5** — let it record for 5 seconds
9. The HMI now shows looped "normal" data

### Phase 3 — Deny Communication

10. Switch to **DROP** attack, set **drop_percent = 90**
11. Enable it
12. 90% of packets from the PMU to the PDC are destroyed
13. The PDC and State PDC are now nearly blind

### Phase 4 — Trip the Breakers

14. Right-click **CB-1** → "Open Breaker" (first breaker opens)
15. Change HMI-1 status to **"Down"** in Properties (simulates HMI crash)
16. Toggle State PDC **Regional Uplink** off (simulates cutting state-level communication)
17. Check the packet log — you'll see:
    - `State PDC → Regional: link down`
    - `ATTACKED [DROP]` entries with yellow `DROPPED` markers

### Phase 5 — Review the Damage

18. Press **F6** to stop
19. Status bar shows:
    - "Dropped" counter = high (most packets destroyed)
    - "Modified" counter = the replay/drop attack count
20. The topology now shows:
    - Breaker open (red dot)
    - HMI down
    - Regional uplink disconnected
    - Attack link red and dashed

### What you learned
> A full blackout attack combines: entry (EW compromise) → stealth (replay) → disruption (packet drop) → action (breaker trip) → isolation (cut uplink). Defense requires protection at EVERY layer, not just one.

---

## What to Do Next

### Save Your Topologies
- **Ctrl+S** after each scenario to keep your work
- **Ctrl+O** to reload them later

### Try Combining Attacks
- Build Scenario 12 topology
- Place Threat Agents on DIFFERENT links simultaneously  
- Run different attacks on each — how does the system behave?

### Challenge Yourself
- Can you build a topology with 3 bays and 2 State PDCs?
- Can you find an attack that's completely invisible to the waveform viewer?
- What's the smallest `ramp_rate` that eventually causes a visible difference?
- What happens if you scale by exactly 1.0? (Hint: nothing — it's a no-op)

---

## Quick Reference: All 10 Attacks

| Attack | What It Changes | Key Parameter | Real-World Analogy |
|--------|----------------|---------------|-------------------|
| **NOISE** | Adds random noise to voltage | `noise_std` (volts) | Bad sensor / EMI interference |
| **RAMP** | Gradual drift up or down | `ramp_rate` (V/frame) | Slow sensor degradation |
| **PULSE** | Periodic voltage spikes | `amplitude`, `interval` | Equipment fault / relay trigger |
| **FREQ_OVERRIDE** | Forces frequency value | `target_freq` (Hz) | GPS spoofing on PMU |
| **MAG_OVERRIDE** | Forces voltage value | `value` (volts) | False Data Injection |
| **ANGLE_OVERRIDE** | Forces phasor angle | `angle_deg` (degrees) | Phase angle manipulation |
| **REPLAY** | Loops old recorded data | `buffer_size` (frames) | Stuxnet-style masking |
| **DELAY** | Adds latency to packets | `delay_ms` (milliseconds) | Timing attack / congestion |
| **DROP** | Randomly destroys packets | `drop_percent` (%) | DoS / communication jamming |
| **SCALE** | Multiplies all voltages | `scale_factor` (×) | Measurement scaling error |

---

*GridSec Sim — For educational and authorized research purposes only.*
