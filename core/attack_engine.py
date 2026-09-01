"""
core/attack_engine.py
=====================
All 10 cyberattack modules for IEEE C37.118 synchrophasor streams.

Each attack module:
  - Has an enable/disable toggle
  - Accepts configurable parameters
  - Takes a decoded frame dict (from packet_parser.parse_frame)
  - Returns (modified_dict, was_modified: bool, was_dropped: bool)

The AttackEngine class wires them all together and is used by pdc_proxy.

Available attacks:
  1. NOISE            — Gaussian noise on phasor magnitudes
  2. RAMP             — Linear drift of magnitude or frequency
  3. PULSE            — Periodic spike injection
  4. FREQUENCY_OVERRIDE — Force FREQ field to fixed value
  5. MAGNITUDE_OVERRIDE — Force a specific phasor's magnitude
  6. ANGLE_OVERRIDE   — Force a specific phasor's angle
  7. REPLAY           — Record N frames, loop-replay instead of live data
  8. DELAY            — Sleep N ms before forwarding (latency injection)
  9. DROP             — Randomly discard X% of packets
  10. SCALE           — Multiply all magnitudes by a scale factor
"""

import copy
import math
import random
import time
import logging
from collections import deque
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Attack type enum
# ─────────────────────────────────────────────────────────────────────────────

class AttackType(str, Enum):
    NONE               = "NONE"
    NOISE              = "NOISE"
    RAMP               = "RAMP"
    PULSE              = "PULSE"
    FREQUENCY_OVERRIDE = "FREQUENCY_OVERRIDE"
    MAGNITUDE_OVERRIDE = "MAGNITUDE_OVERRIDE"
    ANGLE_OVERRIDE     = "ANGLE_OVERRIDE"
    REPLAY             = "REPLAY"
    DELAY              = "DELAY"
    DROP               = "DROP"
    SCALE              = "SCALE"


# ─────────────────────────────────────────────────────────────────────────────
# Attack result
# ─────────────────────────────────────────────────────────────────────────────

class AttackResult:
    """Result of applying one attack to one frame."""
    def __init__(
        self,
        frame_dict:   dict,
        was_modified: bool = False,
        was_dropped:  bool = False,
        attack_type:  AttackType = AttackType.NONE,
        description:  str = "",
    ):
        self.frame_dict   = frame_dict
        self.was_modified = was_modified
        self.was_dropped  = was_dropped
        self.attack_type  = attack_type
        self.description  = description


# ─────────────────────────────────────────────────────────────────────────────
# Base attack class
# ─────────────────────────────────────────────────────────────────────────────

class BaseAttack:
    """Abstract base class for all attack modules."""

    attack_type: AttackType = AttackType.NONE
    display_name: str = "No Attack"
    description:  str = ""

    def __init__(self):
        self.enabled     = False
        self.frame_count = 0         # increments each time apply() is called

    def enable(self)  -> None: self.enabled = True
    def disable(self) -> None: self.enabled = False
    def toggle(self)  -> None: self.enabled = not self.enabled

    def get_params(self) -> dict:
        """Return current parameter dict (for UI binding)."""
        return {}

    def set_params(self, params: dict) -> None:
        """Update parameters from a dict."""
        pass

    def reset(self) -> None:
        """Reset internal state (frame counter, buffers, etc.)."""
        self.frame_count = 0

    def apply(self, frame_dict: dict) -> AttackResult:
        """
        Apply this attack to a parsed frame dict.
        Subclasses must override _apply_attack().
        """
        self.frame_count += 1
        if not self.enabled or frame_dict.get("frame_type") != "data":
            return AttackResult(frame_dict, False, False, self.attack_type)
        return self._apply_attack(frame_dict)

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        raise NotImplementedError

    @staticmethod
    def _copy(frame_dict: dict) -> dict:
        """Deep copy a frame dict, preserving nested lists."""
        d = dict(frame_dict)
        d["phasors"] = [list(p) for p in frame_dict.get("phasors", [])]
        d["analog"]  = list(frame_dict.get("analog", []))
        d["digital"] = list(frame_dict.get("digital", []))
        return d


# ─────────────────────────────────────────────────────────────────────────────
# 1. NOISE attack
# ─────────────────────────────────────────────────────────────────────────────

class NoiseAttack(BaseAttack):
    """
    Add Gaussian random noise to all phasor magnitudes.

    Parameters:
      noise_std (float): standard deviation of the noise in Volts (default 1.0)
      add_freq_noise (bool): also add noise to FREQ field
      freq_std (float): std deviation for frequency noise in Hz (default 0.05)
    """
    attack_type  = AttackType.NOISE
    display_name = "Noise Injection"
    description  = "Adds Gaussian white noise to phasor magnitudes"

    def __init__(self):
        super().__init__()
        self.noise_std     = 1.0
        self.add_freq_noise = False
        self.freq_std      = 0.05

    def get_params(self) -> dict:
        return {
            "noise_std":      self.noise_std,
            "add_freq_noise": self.add_freq_noise,
            "freq_std":       self.freq_std,
        }

    def set_params(self, params: dict) -> None:
        if "noise_std"      in params: self.noise_std      = float(params["noise_std"])
        if "add_freq_noise" in params: self.add_freq_noise = bool(params["add_freq_noise"])
        if "freq_std"       in params: self.freq_std       = float(params["freq_std"])

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        f = self._copy(frame_dict)
        for i, (mag, ang) in enumerate(f["phasors"]):
            f["phasors"][i] = [mag + random.gauss(0, self.noise_std), ang]
        if self.add_freq_noise:
            f["freq"] = f["freq"] + random.gauss(0, self.freq_std)
        desc = f"NOISE std={self.noise_std:.3f}V"
        return AttackResult(f, True, False, self.attack_type, desc)


# ─────────────────────────────────────────────────────────────────────────────
# 2. RAMP attack
# ─────────────────────────────────────────────────────────────────────────────

class RampAttack(BaseAttack):
    """
    Linearly drift a target value each frame.

    Parameters:
      ramp_rate  (float): change per frame (e.g. 0.1 V/frame or 0.01 Hz/frame)
      target     (str):   "magnitude" | "frequency"
      direction  (str):   "up" | "down"
      phasor_idx (int):   which phasor to ramp (for magnitude mode; -1 = all)
    """
    attack_type  = AttackType.RAMP
    display_name = "Ramp Drift"
    description  = "Linearly drifts magnitude or frequency over time"

    def __init__(self):
        super().__init__()
        self.ramp_rate  = 0.05
        self.target     = "magnitude"   # "magnitude" or "frequency"
        self.direction  = "up"          # "up" or "down"
        self.phasor_idx = -1            # -1 = all phasors

    def get_params(self) -> dict:
        return {
            "ramp_rate":  self.ramp_rate,
            "target":     self.target,
            "direction":  self.direction,
            "phasor_idx": self.phasor_idx,
        }

    def set_params(self, params: dict) -> None:
        if "ramp_rate"  in params: self.ramp_rate  = float(params["ramp_rate"])
        if "target"     in params: self.target      = str(params["target"])
        if "direction"  in params: self.direction   = str(params["direction"])
        if "phasor_idx" in params: self.phasor_idx  = int(params["phasor_idx"])

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        f   = self._copy(frame_dict)
        sign = 1 if self.direction == "up" else -1
        delta = sign * self.ramp_rate * self.frame_count

        if self.target == "magnitude":
            indices = range(len(f["phasors"])) if self.phasor_idx < 0 else [self.phasor_idx]
            for i in indices:
                if i < len(f["phasors"]):
                    mag, ang = f["phasors"][i]
                    f["phasors"][i] = [max(0.0, mag + delta), ang]
        elif self.target == "frequency":
            f["freq"] = f["freq"] + delta

        desc = f"RAMP {self.direction} {self.target} rate={self.ramp_rate} frame={self.frame_count}"
        return AttackResult(f, True, False, self.attack_type, desc)


# ─────────────────────────────────────────────────────────────────────────────
# 3. PULSE attack
# ─────────────────────────────────────────────────────────────────────────────

class PulseAttack(BaseAttack):
    """
    Inject a sudden spike at regular intervals.

    Parameters:
      amplitude      (float): spike magnitude in Volts
      interval       (int):   frames between spikes
      duration_frames(int):   how many frames the spike lasts
      target         (str):   "magnitude" | "frequency"
      phasor_idx     (int):   which phasor (-1 = all)
    """
    attack_type  = AttackType.PULSE
    display_name = "Pulse Injection"
    description  = "Injects sudden spikes at regular intervals"

    def __init__(self):
        super().__init__()
        self.amplitude       = 30.0
        self.interval        = 30     # every 30 frames ≈ 1 second at 30fps
        self.duration_frames = 3
        self.target          = "magnitude"
        self.phasor_idx      = -1

    def get_params(self) -> dict:
        return {
            "amplitude":       self.amplitude,
            "interval":        self.interval,
            "duration_frames": self.duration_frames,
            "target":          self.target,
            "phasor_idx":      self.phasor_idx,
        }

    def set_params(self, params: dict) -> None:
        if "amplitude"       in params: self.amplitude       = float(params["amplitude"])
        if "interval"        in params: self.interval        = max(1, int(params["interval"]))
        if "duration_frames" in params: self.duration_frames = max(1, int(params["duration_frames"]))
        if "target"          in params: self.target          = str(params["target"])
        if "phasor_idx"      in params: self.phasor_idx      = int(params["phasor_idx"])

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        # Is this frame inside a spike?
        pos_in_interval = self.frame_count % self.interval
        if pos_in_interval >= self.duration_frames:
            return AttackResult(frame_dict, False, False, self.attack_type, "PULSE (quiet)")

        f   = self._copy(frame_dict)
        amp = self.amplitude

        if self.target == "magnitude":
            indices = range(len(f["phasors"])) if self.phasor_idx < 0 else [self.phasor_idx]
            for i in indices:
                if i < len(f["phasors"]):
                    mag, ang = f["phasors"][i]
                    f["phasors"][i] = [mag + amp, ang]
        elif self.target == "frequency":
            f["freq"] += amp

        desc = f"PULSE amp={amp} frame={self.frame_count}"
        return AttackResult(f, True, False, self.attack_type, desc)


# ─────────────────────────────────────────────────────────────────────────────
# 4. FREQUENCY_OVERRIDE attack
# ─────────────────────────────────────────────────────────────────────────────

class FrequencyOverrideAttack(BaseAttack):
    """
    Force the FREQ field to a fixed value.

    Parameters:
      target_freq (float): Hz value to inject (e.g. 60.0 — the "wrong" nominal)
    """
    attack_type  = AttackType.FREQUENCY_OVERRIDE
    display_name = "Frequency Override"
    description  = "Forces FREQ field to a fixed value regardless of real data"

    def __init__(self):
        super().__init__()
        self.target_freq = 60.0

    def get_params(self) -> dict:
        return {"target_freq": self.target_freq}

    def set_params(self, params: dict) -> None:
        if "target_freq" in params:
            v = float(params["target_freq"])
            self.target_freq = max(45.0, min(65.0, v))

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        f = self._copy(frame_dict)
        f["freq"] = self.target_freq
        desc = f"FREQ_OVERRIDE → {self.target_freq} Hz"
        return AttackResult(f, True, False, self.attack_type, desc)


# ─────────────────────────────────────────────────────────────────────────────
# 5. MAGNITUDE_OVERRIDE attack
# ─────────────────────────────────────────────────────────────────────────────

class MagnitudeOverrideAttack(BaseAttack):
    """
    Force a specific phasor's magnitude to an exact value.

    Parameters:
      phasor_idx (int):   0-based index of the phasor to override
      value      (float): magnitude in Volts to inject
    """
    attack_type  = AttackType.MAGNITUDE_OVERRIDE
    display_name = "Magnitude Override"
    description  = "Forces a specific phasor magnitude to an exact value"

    def __init__(self):
        super().__init__()
        self.phasor_idx = 0
        self.value      = 0.0

    def get_params(self) -> dict:
        return {"phasor_idx": self.phasor_idx, "value": self.value}

    def set_params(self, params: dict) -> None:
        if "phasor_idx" in params: self.phasor_idx = int(params["phasor_idx"])
        if "value"      in params: self.value       = float(params["value"])

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        f = self._copy(frame_dict)
        idx = self.phasor_idx
        if 0 <= idx < len(f["phasors"]):
            _, ang = f["phasors"][idx]
            f["phasors"][idx] = [self.value, ang]
            desc = f"MAG_OVERRIDE phasor[{idx}] → {self.value} V"
            return AttackResult(f, True, False, self.attack_type, desc)
        return AttackResult(frame_dict, False, False, self.attack_type, "MAG_OVERRIDE (index out of range)")


# ─────────────────────────────────────────────────────────────────────────────
# 6. ANGLE_OVERRIDE attack
# ─────────────────────────────────────────────────────────────────────────────

class AngleOverrideAttack(BaseAttack):
    """
    Force a specific phasor's angle to an exact value.

    Parameters:
      phasor_idx (int):   0-based phasor index
      angle_deg  (float): angle in degrees (converted to radians for encoding)
    """
    attack_type  = AttackType.ANGLE_OVERRIDE
    display_name = "Angle Override"
    description  = "Forces a specific phasor angle to an exact value"

    def __init__(self):
        super().__init__()
        self.phasor_idx = 0
        self.angle_deg  = 0.0

    def get_params(self) -> dict:
        return {"phasor_idx": self.phasor_idx, "angle_deg": self.angle_deg}

    def set_params(self, params: dict) -> None:
        if "phasor_idx" in params: self.phasor_idx = int(params["phasor_idx"])
        if "angle_deg"  in params: self.angle_deg  = float(params["angle_deg"])

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        f = self._copy(frame_dict)
        idx = self.phasor_idx
        if 0 <= idx < len(f["phasors"]):
            mag, _ = f["phasors"][idx]
            ang_rad = math.radians(self.angle_deg)
            f["phasors"][idx] = [mag, ang_rad]
            desc = f"ANGLE_OVERRIDE phasor[{idx}] → {self.angle_deg}°"
            return AttackResult(f, True, False, self.attack_type, desc)
        return AttackResult(frame_dict, False, False, self.attack_type, "ANGLE_OVERRIDE (index out of range)")


# ─────────────────────────────────────────────────────────────────────────────
# 7. REPLAY attack
# ─────────────────────────────────────────────────────────────────────────────

class ReplayAttack(BaseAttack):
    """
    Record N frames, then loop-replay them instead of forwarding live data.

    This simulates a "freeze" attack — the PDC receives valid but stale data
    and cannot detect the grid anomaly because measurements appear frozen.

    Parameters:
      buffer_size (int): number of frames to record before replaying
    """
    attack_type  = AttackType.REPLAY
    display_name = "Replay (Freeze)"
    description  = "Records frames then replays them in a loop instead of live data"

    def __init__(self):
        super().__init__()
        self.buffer_size   = 30
        self._buffer: deque = deque(maxlen=self.buffer_size)
        self._recording    = True   # True = still filling buffer
        self._replay_idx   = 0

    def get_params(self) -> dict:
        return {
            "buffer_size": self.buffer_size,
            "recording":   self._recording,
            "buffered":    len(self._buffer),
        }

    def set_params(self, params: dict) -> None:
        if "buffer_size" in params:
            self.buffer_size = max(1, int(params["buffer_size"]))
            self._buffer = deque(maxlen=self.buffer_size)
            self._recording = True

    def reset(self) -> None:
        super().reset()
        self._buffer.clear()
        self._recording  = True
        self._replay_idx = 0

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        if self._recording:
            self._buffer.append(copy.deepcopy(frame_dict))
            if len(self._buffer) >= self.buffer_size:
                self._recording = False
                self._replay_idx = 0
                logger.info(f"REPLAY: buffer full ({self.buffer_size} frames) — starting replay")
            return AttackResult(frame_dict, False, False, self.attack_type,
                                f"REPLAY recording {len(self._buffer)}/{self.buffer_size}")

        # Replay from buffer
        replay_frame = copy.deepcopy(self._buffer[self._replay_idx % len(self._buffer)])
        self._replay_idx += 1
        desc = f"REPLAY frame {self._replay_idx % self.buffer_size}/{self.buffer_size}"
        return AttackResult(replay_frame, True, False, self.attack_type, desc)


# ─────────────────────────────────────────────────────────────────────────────
# 8. DELAY attack
# ─────────────────────────────────────────────────────────────────────────────

class DelayAttack(BaseAttack):
    """
    Inject artificial latency before forwarding.

    Parameters:
      delay_ms (float): milliseconds to sleep per packet (0–5000)

    Note: This sleep happens on the proxy worker thread — it slows down
    the entire stream. Real Delay attacks also affect the PDC's timestamp
    validity window.
    """
    attack_type  = AttackType.DELAY
    display_name = "Delay / Latency"
    description  = "Injects artificial latency before each packet is forwarded"

    def __init__(self):
        super().__init__()
        self.delay_ms = 100.0

    def get_params(self) -> dict:
        return {"delay_ms": self.delay_ms}

    def set_params(self, params: dict) -> None:
        if "delay_ms" in params:
            self.delay_ms = max(0.0, min(5000.0, float(params["delay_ms"])))

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        time.sleep(self.delay_ms / 1000.0)
        desc = f"DELAY {self.delay_ms:.1f} ms"
        return AttackResult(frame_dict, False, False, self.attack_type, desc)


# ─────────────────────────────────────────────────────────────────────────────
# 9. DROP attack
# ─────────────────────────────────────────────────────────────────────────────

class DropAttack(BaseAttack):
    """
    Randomly discard packets to simulate packet loss.

    Parameters:
      drop_percent (float): 0–100 — percentage of packets to discard
    """
    attack_type  = AttackType.DROP
    display_name = "Packet Drop"
    description  = "Randomly discards a percentage of packets"

    def __init__(self):
        super().__init__()
        self.drop_percent = 20.0

    def get_params(self) -> dict:
        return {"drop_percent": self.drop_percent}

    def set_params(self, params: dict) -> None:
        if "drop_percent" in params:
            self.drop_percent = max(0.0, min(100.0, float(params["drop_percent"])))

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        if random.random() * 100 < self.drop_percent:
            desc = f"DROP ({self.drop_percent:.0f}%)"
            return AttackResult(frame_dict, False, True, self.attack_type, desc)
        return AttackResult(frame_dict, False, False, self.attack_type, "DROP (passed)")


# ─────────────────────────────────────────────────────────────────────────────
# 10. SCALE attack
# ─────────────────────────────────────────────────────────────────────────────

class ScaleAttack(BaseAttack):
    """
    Multiply all phasor magnitudes by a scale factor.

    Can simulate:
      scale < 1.0  → voltage sag
      scale > 1.0  → voltage swell
      scale = 0.0  → complete blackout (all zeros)

    Parameters:
      scale_factor (float): multiplier (0.0–10.0, default 1.5)
      also_scale_freq (bool): also scale the FREQ field
    """
    attack_type  = AttackType.SCALE
    display_name = "Scale (Sag/Swell)"
    description  = "Multiplies all phasor magnitudes by a scale factor"

    def __init__(self):
        super().__init__()
        self.scale_factor    = 1.5
        self.also_scale_freq = False

    def get_params(self) -> dict:
        return {
            "scale_factor":    self.scale_factor,
            "also_scale_freq": self.also_scale_freq,
        }

    def set_params(self, params: dict) -> None:
        if "scale_factor"    in params: self.scale_factor    = float(params["scale_factor"])
        if "also_scale_freq" in params: self.also_scale_freq = bool(params["also_scale_freq"])

    def _apply_attack(self, frame_dict: dict) -> AttackResult:
        f = self._copy(frame_dict)
        for i, (mag, ang) in enumerate(f["phasors"]):
            f["phasors"][i] = [mag * self.scale_factor, ang]
        if self.also_scale_freq:
            f["freq"] *= self.scale_factor
        desc = f"SCALE ×{self.scale_factor:.3f}"
        return AttackResult(f, True, False, self.attack_type, desc)


# ─────────────────────────────────────────────────────────────────────────────
# Attack registry
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_CLASSES: Dict[AttackType, type] = {
    AttackType.NOISE:              NoiseAttack,
    AttackType.RAMP:               RampAttack,
    AttackType.PULSE:              PulseAttack,
    AttackType.FREQUENCY_OVERRIDE: FrequencyOverrideAttack,
    AttackType.MAGNITUDE_OVERRIDE: MagnitudeOverrideAttack,
    AttackType.ANGLE_OVERRIDE:     AngleOverrideAttack,
    AttackType.REPLAY:             ReplayAttack,
    AttackType.DELAY:              DelayAttack,
    AttackType.DROP:               DropAttack,
    AttackType.SCALE:              ScaleAttack,
}


# ─────────────────────────────────────────────────────────────────────────────
# Attack Engine
# ─────────────────────────────────────────────────────────────────────────────

class AttackEngine:
    """
    Manages the active attack and applies it to each packet.

    Only ONE attack is active at a time (the currently selected type).
    All 10 attack instances are kept alive so their state/params persist
    between switches.
    """

    def __init__(self):
        # Instantiate all attack objects
        self._attacks: Dict[AttackType, BaseAttack] = {
            t: cls() for t, cls in ATTACK_CLASSES.items()
        }
        self._active_type = AttackType.NONE
        self._none_attack = BaseAttack()   # always-passthrough

        # Statistics
        self.stats = {
            "total_packets":    0,
            "modified_packets": 0,
            "dropped_packets":  0,
        }
        # Optional packet-frame schedule.  A duration of 0 means remain active
        # until the simulation stops.
        self._schedule_start_frame = 0
        self._schedule_duration_frames = 0

    # ── Attack selection ──────────────────────────────────────────────────────

    def set_attack(self, attack_type: AttackType, params: Optional[dict] = None) -> None:
        """
        Select the active attack type and optionally set its parameters.
        Also enables the selected attack (and disables the previous one).
        """
        # Disable old
        old = self._attacks.get(self._active_type)
        if old:
            old.disable()

        self._active_type = attack_type

        # Enable new
        new = self._attacks.get(attack_type)
        if new:
            new.enable()
            if params:
                new.set_params(params)

        logger.info(f"AttackEngine: switched to {attack_type.value}")

    def get_attack(self, attack_type: Optional[AttackType] = None) -> BaseAttack:
        """Return the attack instance for the given type (or active type)."""
        t = attack_type or self._active_type
        return self._attacks.get(t, self._none_attack)

    @property
    def active_attack(self) -> BaseAttack:
        return self._attacks.get(self._active_type, self._none_attack)

    @property
    def active_type(self) -> AttackType:
        return self._active_type

    def enable(self)  -> None: self.active_attack.enable()
    def disable(self) -> None: self.active_attack.disable()

    @property
    def is_enabled(self) -> bool:
        return self.active_attack.enabled

    def set_params(self, params: dict) -> None:
        self.active_attack.set_params(params)

    def get_params(self) -> dict:
        return self.active_attack.get_params()

    def set_schedule(self, start_frame: int = 0, duration_frames: int = 0) -> None:
        """Arm the active attack for a packet-frame window."""
        self._schedule_start_frame = max(0, int(start_frame))
        self._schedule_duration_frames = max(0, int(duration_frames))

    @property
    def schedule(self) -> dict:
        return {
            "start_frame": self._schedule_start_frame,
            "duration_frames": self._schedule_duration_frames,
        }

    @property
    def is_scheduled_active(self) -> bool:
        frame = self.stats["total_packets"]
        if frame < self._schedule_start_frame:
            return False
        return (self._schedule_duration_frames == 0 or
                frame < self._schedule_start_frame + self._schedule_duration_frames)

    def reset_stats(self) -> None:
        self.stats = {"total_packets": 0, "modified_packets": 0, "dropped_packets": 0}

    def reset_attack_state(self) -> None:
        for attack in self._attacks.values():
            attack.reset()

    # ── Apply ──────────────────────────────────────────────────────────────────

    def apply(self, frame_dict: dict) -> Tuple[dict, bool, bool]:
        """
        Apply the active attack to a parsed frame dict.

        Parameters
        ----------
        frame_dict : dict from packet_parser.parse_frame()

        Returns
        -------
        (modified_frame_dict, was_modified, was_dropped)
        """
        self.stats["total_packets"] += 1

        if self.is_enabled and not self.is_scheduled_active:
            result = AttackResult(frame_dict, False, False, self.active_type,
                                  "Attack schedule inactive")
        else:
            result = self.active_attack.apply(frame_dict)

        if result.was_dropped:
            self.stats["dropped_packets"] += 1
        elif result.was_modified:
            self.stats["modified_packets"] += 1

        return result.frame_dict, result.was_modified, result.was_dropped

    def all_attacks_info(self) -> List[dict]:
        """Return a list of info dicts for all available attacks (for UI)."""
        info = []
        for atype, attack in self._attacks.items():
            info.append({
                "type":         atype.value,
                "display_name": attack.display_name,
                "description":  attack.description,
                "enabled":      attack.enabled,
                "params":       attack.get_params(),
                "is_active":    atype == self._active_type,
            })
        return info


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import math
    from protocols.c37118 import C37118Codec

    print("=" * 60)
    print("  AttackEngine Self-Test — all 10 attacks")
    print("=" * 60)

    codec = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=0)
    TWO_PI = 2 * math.pi

    def make_frame(freq=50.0, mag=120.0) -> dict:
        phasors = [
            (mag, 0.0),
            (mag, -TWO_PI/3),
            (mag,  TWO_PI/3),
        ]
        raw = codec.encode_data_frame(phasors, freq, 0.0, [1.0], [])
        d   = codec.decode_data_frame(raw).to_dict()
        d["frame_type"] = "data"
        return d

    engine = AttackEngine()

    # ── NOISE ─────────────────────────────────────────────────────────────────
    print("\n[1] NOISE")
    engine.set_attack(AttackType.NOISE, {"noise_std": 5.0})
    frame = make_frame()
    orig_mag = frame["phasors"][0][0]
    f2, modified, dropped = engine.apply(frame)
    assert modified, "NOISE should modify"
    assert not dropped
    diff = abs(f2["phasors"][0][0] - orig_mag)
    print(f"  Original mag: {orig_mag:.3f}  →  Modified: {f2['phasors'][0][0]:.3f}  (diff={diff:.3f})")
    assert diff < 50, "Noise diff unexpectedly large"
    print("  ✔ NOISE OK")

    # ── RAMP ──────────────────────────────────────────────────────────────────
    print("\n[2] RAMP")
    engine.set_attack(AttackType.RAMP, {"ramp_rate": 1.0, "direction": "up", "target": "magnitude"})
    frame = make_frame()
    results = []
    for _ in range(5):
        f2, m, d = engine.apply(frame)
        results.append(f2["phasors"][0][0])
    print(f"  Magnitudes over 5 frames: {[round(x,2) for x in results]}")
    assert results[-1] > results[0], "RAMP up should increase"
    print("  ✔ RAMP OK")

    # ── PULSE ─────────────────────────────────────────────────────────────────
    print("\n[3] PULSE")
    engine.set_attack(AttackType.PULSE, {"amplitude": 50.0, "interval": 5, "duration_frames": 2})
    frame = make_frame()
    pulse_results = []
    for _ in range(10):
        f2, m, d = engine.apply(frame)
        pulse_results.append((m, f2["phasors"][0][0]))
    spikes = [v for m, v in pulse_results if m]
    no_spikes = [v for m, v in pulse_results if not m]
    print(f"  Spike frames: {len(spikes)}, quiet frames: {len(no_spikes)}")
    assert spikes, "Should have at least one spike"
    assert all(s > 120.0 for s in spikes), "Spike should increase magnitude"
    print("  ✔ PULSE OK")

    # ── FREQUENCY_OVERRIDE ────────────────────────────────────────────────────
    print("\n[4] FREQUENCY_OVERRIDE")
    engine.set_attack(AttackType.FREQUENCY_OVERRIDE, {"target_freq": 60.0})
    frame = make_frame(freq=50.0)
    f2, m, d = engine.apply(frame)
    assert abs(f2["freq"] - 60.0) < 0.01, f"Expected 60.0 got {f2['freq']}"
    print(f"  Injected freq: {f2['freq']} Hz (was 50.0)")
    print("  ✔ FREQUENCY_OVERRIDE OK")

    # ── MAGNITUDE_OVERRIDE ────────────────────────────────────────────────────
    print("\n[5] MAGNITUDE_OVERRIDE")
    engine.set_attack(AttackType.MAGNITUDE_OVERRIDE, {"phasor_idx": 0, "value": 0.0})
    frame = make_frame()
    f2, m, d = engine.apply(frame)
    assert abs(f2["phasors"][0][0] - 0.0) < 0.01
    print(f"  Va magnitude forced to: {f2['phasors'][0][0]} V")
    print("  ✔ MAGNITUDE_OVERRIDE OK")

    # ── ANGLE_OVERRIDE ────────────────────────────────────────────────────────
    print("\n[6] ANGLE_OVERRIDE")
    engine.set_attack(AttackType.ANGLE_OVERRIDE, {"phasor_idx": 0, "angle_deg": 90.0})
    frame = make_frame()
    f2, m, d = engine.apply(frame)
    expected_rad = math.radians(90.0)
    assert abs(f2["phasors"][0][1] - expected_rad) < 0.001
    print(f"  Va angle forced to: {math.degrees(f2['phasors'][0][1]):.1f}° (was 0°)")
    print("  ✔ ANGLE_OVERRIDE OK")

    # ── REPLAY ────────────────────────────────────────────────────────────────
    print("\n[7] REPLAY")
    engine.set_attack(AttackType.REPLAY, {"buffer_size": 5})
    # Fill buffer
    for freq in [50.0, 50.1, 50.2, 50.3, 50.4]:
        engine.apply(make_frame(freq=freq))
    # Now replaying — should loop through buffered frames
    replayed_freqs = []
    for _ in range(5):
        frame = make_frame(freq=51.0)   # new "live" data
        f2, m, d = engine.apply(frame)
        replayed_freqs.append(round(f2["freq"], 2))
    print(f"  Replayed freqs: {replayed_freqs}  (should be ~50.0–50.4, not 51.0)")
    # Note: small float encode/decode rounding is expected
    assert not any(abs(f - 51.0) < 0.05 for f in replayed_freqs), "Should not have live freq 51.0"
    print("  ✔ REPLAY OK")

    # ── DELAY ─────────────────────────────────────────────────────────────────
    print("\n[8] DELAY")
    engine.set_attack(AttackType.DELAY, {"delay_ms": 50.0})
    frame = make_frame()
    t0 = time.time()
    f2, m, d = engine.apply(frame)
    elapsed_ms = (time.time() - t0) * 1000
    print(f"  Elapsed: {elapsed_ms:.1f} ms (expected ≥50 ms)")
    assert elapsed_ms >= 45, f"Delay too short: {elapsed_ms}"
    print("  ✔ DELAY OK")

    # ── DROP ──────────────────────────────────────────────────────────────────
    print("\n[9] DROP")
    engine.set_attack(AttackType.DROP, {"drop_percent": 50.0})
    frame  = make_frame()
    drops  = sum(1 for _ in range(200) if engine.apply(frame)[2])
    pct    = drops / 200 * 100
    print(f"  Dropped {drops}/200 packets = {pct:.1f}%  (target 50%)")
    assert 30 < pct < 70, f"Drop rate {pct}% outside expected range 30–70%"
    print("  ✔ DROP OK")

    # ── SCALE ─────────────────────────────────────────────────────────────────
    print("\n[10] SCALE")
    engine.set_attack(AttackType.SCALE, {"scale_factor": 2.0})
    frame = make_frame(mag=100.0)
    f2, m, d = engine.apply(frame)
    assert abs(f2["phasors"][0][0] - 200.0) < 1.0, f"Expected 200.0, got {f2['phasors'][0][0]}"
    print(f"  100.0 V × 2.0 = {f2['phasors'][0][0]:.1f} V")
    print("  ✔ SCALE OK")

    # ── Stats ─────────────────────────────────────────────────────────────────
    print(f"\nEngine stats: {engine.stats}")
    print("\n" + "=" * 60)
    print("  ALL 10 ATTACKS PASSED ✔")
    print("=" * 60)
