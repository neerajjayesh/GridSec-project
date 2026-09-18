# Attack engine reference

[Documentation index](index.md)

## Execution contract

`AttackEngine` holds one instance of each module and selects one active type. `set_attack(AttackType, params)` disables the previous module and enables the selected one. Module parameters and internal state generally persist between selections. `NONE` is the default passthrough state.

`apply(frame_dict)` returns `(frame_dict, was_modified, was_dropped)`. Modules operate on decoded C37.118 data frames. They do not intercept GOOSE/DNP3/Modbus traffic, transmit exploit payloads to unrelated devices, or implement packet-routing policies.

Phasor indices are zero-based: `0` is phase A in the default generator. Magnitudes use the generator's voltage units, frequency is Hz, angles in decoded frames are radians, and the angle-override parameter is degrees.

## Parameters

These are **engine parameter names**, accepted by `set_params()`. Unknown keys are generally ignored, not rejected. UI ranges may be narrower than core setters.

| Type | Parameters and defaults | Behavior and core constraints |
|---|---|---|
| `NOISE` | `noise_std=1.0`, `add_freq_noise=false`, `freq_std=0.05` | Independent Gaussian noise on all magnitudes; optional frequency noise. Uses `noise_std`, not `std_dev`. Magnitudes are not clamped to zero. |
| `RAMP` | `ramp_rate=0.05`, `target='magnitude'`, `direction='up'`, `phasor_idx=-1` | Adds/subtracts rate × module frame count. Target: magnitude/frequency; negative index selects all phasors. Magnitudes are clamped at zero. |
| `PULSE` | `amplitude=30.0`, `interval=30`, `duration_frames=3`, `target='magnitude'`, `phasor_idx=-1` | Spike when `frame_count % interval < duration_frames`. Interval/duration are clamped to at least 1. Amplitude units follow target. |
| `FREQUENCY_OVERRIDE` | `target_freq=60.0` | Replaces FREQ; setter clamps to 45–65 Hz. |
| `MAGNITUDE_OVERRIDE` | `phasor_idx=0`, `value=0.0` | Replaces one magnitude; out-of-range index passes unchanged. |
| `ANGLE_OVERRIDE` | `phasor_idx=0`, `angle_deg=0.0` | Replaces one angle after degree-to-radian conversion; invalid index passes unchanged. |
| `REPLAY` | `buffer_size=30` | Records N eligible frames unchanged, then loops deep copies including old timestamps. Buffer size is at least 1. `recording` and `buffered` are readback fields, not writable parameters. |
| `DELAY` | `delay_ms=100.0` | Sleeps on the proxy thread for each eligible data frame. Setter clamps to 0–5000 ms. No content change/drop flag. |
| `DROP` | `drop_percent=20.0` | Independent random drop decision; setter clamps to 0–100%. |
| `SCALE` | `scale_factor=1.5`, `also_scale_freq=false` | Multiplies all magnitudes and optionally frequency. Core setter does not enforce the 0–10 range mentioned in its docstring. |

## Timing and state

Ramp is measured per module invocation, not per wall-clock second. Pulse starts with module frame count 1, so its first window is not a zero-based sequence. A duration at least as large as its interval makes every eligible invocation a pulse.

Replay requires N frames to fill before modifications begin. At an uninterrupted 30 eligible frames/s, a 90-frame buffer takes approximately three seconds. Restarting the simulation does not automatically clear the engine's buffer. Applying a new `buffer_size` recreates it; `reset_attack_state()` clears all module state.

Delay reduces proxy throughput because it blocks that stream's processing worker. The PMU may continue generating faster than processing, creating socket backlog or loss. Delay does not increment `modified_packets` or produce attacked incidents by itself.

## Scheduling

```python
engine.set_attack(AttackType.SCALE, {"scale_factor": 2.0})
engine.reset_stats()
engine.reset_attack_state()
engine.set_schedule(start_frame=2, duration_frames=2)
```

The engine increments `total_packets` before checking the window. For a positive duration, the active condition is:

```text
start_frame <= total_packets < start_frame + duration_frames
```

A duration of zero removes the upper bound. `start_frame=0, duration_frames=0` is immediate and indefinite. With start 2 and duration 2, calls 1–4 produce modification flags `[false, true, true, false]`. To get N complete clean eligible frames first, use start `N+1`.

Counters are cumulative since the last statistics reset. Arming a schedule during a run uses that existing counter, not a delay relative to the moment you clicked Enable. Disabled/schedule-inactive behavior and module-specific counters also mean a ramp's local frame count is distinct from the engine counter. Use both resets for a controlled repeat.

Start/stop does not reset scheduling. The GUI may show “Waiting” after a finite window has ended. A selected attack shown in the dashboard can be enabled but outside its active window.

## Traffic filtering

`TrafficFilter` decides whether data enters the engine; nonmatching data is still forwarded unchanged. It is not a firewall.

```python
from core.traffic_filter import TrafficFilter

traffic_filter = TrafficFilter()
traffic_filter.add_rule(dst_ip="127.0.0.1", dst_port=4713, proto="UDP")
```

Rule fields are `src_ip`, `dst_ip`, `src_port`, `dst_port`, `proto`, `label`, and `enabled`. `None` is a wildcard. Specified fields combine with AND; enabled rules combine with OR. Empty rule list matches everything; a nonempty list containing only disabled rules matches nothing. IP matching is string equality, not CIDR/subnet matching.

In UDP proxy metadata, destination means the proxy's **forwarding destination**, not its listen address. The generated PMU source port is an ephemeral socket port. The desktop constructs an empty filter and does not expose a working rule editor or connect selected-link scope to these rules.

## Counters and interpretation

`total_packets` counts engine calls. `modified_packets` increments when a result is modified; `dropped_packets` increments when dropped. Non-data frames and filter bypasses do not enter the engine. Reset Stats clears these and module state through the GUI, but does not clear incident history.

A modification flag expresses module behavior, not necessarily a numerical difference: overriding a value with the same value can still count as modified. Rebuild failures and downstream send errors require separate inspection.

Use [inspect_frame.py](examples/inspect_frame.py) for a deterministic example. Source: [engine](../core/attack_engine.py), [filter](../core/traffic_filter.py), [proxy](../core/pdc_proxy.py), [panel](../gui/attack_panel.py).
