"""
core/pmu_simulator.py
=====================
IEEE C37.118 PMU (Phasor Measurement Unit) simulator.

Generates realistic 3-phase synchrophasor data and transmits it as
properly encoded C37.118 binary frames via UDP to a configurable port
(typically the MitM proxy port).

Architecture:
  - Runs as a daemon thread (QThread-compatible — emits via callback)
  - Generates data at a configurable frame rate (default 30 fps)
  - Supports live parameter changes (frequency, magnitude) while running
  - Sends a CFG-2 frame first, then DATA frames continuously

Phasor model:
  - 3 voltage phasors: Va (0°), Vb (-120°), Vc (+120°) at configurable magnitude
  - Frequency varies sinusoidally around nominal (simulates realistic drift)
  - Analog channel: active power (P) estimate
"""

import math
import socket
import threading
import time
import logging
from typing import Callable, List, Optional, Tuple

from protocols.c37118 import C37118Codec, CMD_TURN_ON_TX

logger = logging.getLogger(__name__)

TWO_PI = 2 * math.pi


class PMUSimulator(threading.Thread):
    """
    IEEE C37.118 PMU simulator thread.

    Sends UDP packets containing C37.118-compliant binary frames to
    dst_host:dst_port at the configured frame rate.

    Parameters
    ----------
    dst_host    : destination IP (proxy listen address)
    dst_port    : destination UDP port
    idcode      : PMU station ID code
    fps         : frames per second (1–120)
    nom_freq    : nominal frequency in Hz (50 or 60)
    nom_voltage : nominal voltage magnitude in Volts (phase-neutral)
    on_frame    : optional callback(raw_bytes, frame_dict) called each frame
    """

    def __init__(
        self,
        dst_host:    str   = "127.0.0.1",
        dst_port:    int   = 4712,
        idcode:      int   = 1,
        fps:         int   = 30,
        nom_freq:    float = 50.0,
        nom_voltage: float = 120.0,
        on_frame:    Optional[Callable[[bytes, dict], None]] = None,
    ):
        super().__init__(daemon=True, name="PMUSimulator")

        self.dst_host    = dst_host
        self.dst_port    = dst_port
        self.idcode      = idcode
        self.fps         = max(1, min(120, fps))
        self.nom_freq    = nom_freq
        self.nom_voltage = nom_voltage
        self.on_frame    = on_frame

        # Runtime-adjustable parameters (thread-safe via threading.Lock)
        self._lock        = threading.Lock()
        self._freq_offset = 0.0     # Hz offset from nominal (set by attack panel, etc.)
        self._mag_scale   = 1.0     # voltage magnitude scale factor
        self._manual_freq: Optional[float] = None  # if set, override automatic freq

        # Internal state
        self._running    = False
        self._stop_event = threading.Event()
        self._frame_count = 0
        self._last_frame: Optional[dict] = None
        self._last_raw:   Optional[bytes] = None

        # Codec
        self._codec = C37118Codec(
            idcode=idcode,
            num_phasors=3,
            num_analog=1,
            num_digital=1,
            station_name=f"PMU-{idcode:04d}   ",
            nominal_freq=0x0001 if nom_freq <= 50 else 0x0000,
        )

        # UDP socket (created in run())
        self._sock: Optional[socket.socket] = None

        # Statistics
        self.packets_sent  = 0
        self.packets_error = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the PMU simulator thread."""
        if self._running:
            logger.warning("PMUSimulator: already running")
            return
        self._stop_event.clear()
        self._running = True
        self._frame_count = 0
        self.packets_sent = 0
        self.packets_error = 0
        super().start()
        logger.info(f"PMUSimulator: started → {self.dst_host}:{self.dst_port} @ {self.fps} fps")

    def stop(self) -> None:
        """Stop the PMU simulator thread gracefully."""
        self._stop_event.set()
        self._running = False
        logger.info("PMUSimulator: stop requested")

    def set_frequency(self, freq: float) -> None:
        """Override the simulated frequency (Hz). Pass None to restore automatic."""
        with self._lock:
            if freq is None:
                self._manual_freq = None
            else:
                self._manual_freq = max(45.0, min(65.0, float(freq)))

    def set_magnitude(self, magnitude: float) -> None:
        """Set the voltage magnitude scale factor (1.0 = nominal)."""
        with self._lock:
            self._mag_scale = max(0.0, float(magnitude))

    def set_freq_offset(self, offset: float) -> None:
        """Add an offset in Hz to the nominal frequency."""
        with self._lock:
            self._freq_offset = float(offset)

    def get_current_frame(self) -> Optional[dict]:
        """Return the most recently generated frame dict (thread-safe)."""
        return self._last_frame

    def get_current_raw(self) -> Optional[bytes]:
        """Return the most recently generated raw frame bytes (thread-safe)."""
        return self._last_raw

    @property
    def is_running(self) -> bool:
        return self._running and self.is_alive()

    # ── Thread entry point ────────────────────────────────────────────────────

    def run(self) -> None:
        """Main simulation loop — runs in its own thread."""
        # Create UDP socket
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
        except OSError as exc:
            logger.error(f"PMUSimulator: cannot create socket: {exc}")
            self._running = False
            return

        # Send CFG-2 frame first so the receiver knows the data format
        try:
            cfg_frame = self._codec.encode_config_frame(data_rate=self.fps)
            self._sock.sendto(cfg_frame, (self.dst_host, self.dst_port))
            logger.info(f"PMUSimulator: sent CFG-2 frame ({len(cfg_frame)} bytes)")
        except OSError as exc:
            logger.warning(f"PMUSimulator: could not send CFG-2: {exc}")

        interval = 1.0 / self.fps
        next_send = time.perf_counter()

        while not self._stop_event.is_set():
            now = time.perf_counter()
            if now < next_send:
                # Precise sleep — sleep in small chunks to stay responsive
                remaining = next_send - now
                if remaining > 0.002:
                    time.sleep(remaining - 0.001)
                while time.perf_counter() < next_send:
                    pass  # busy-wait for last sub-ms
            next_send += interval

            self._frame_count += 1
            t = time.time()

            # Build phasor data
            raw_bytes, frame_dict = self._generate_frame(t)
            self._last_frame = frame_dict
            self._last_raw   = raw_bytes

            # Send UDP packet
            try:
                self._sock.sendto(raw_bytes, (self.dst_host, self.dst_port))
                self.packets_sent += 1
            except OSError as exc:
                self.packets_error += 1
                if self.packets_error % 100 == 1:
                    logger.warning(f"PMUSimulator: send error: {exc}")

            # Callback for GUI updates
            if self.on_frame is not None:
                try:
                    self.on_frame(raw_bytes, frame_dict)
                except Exception as exc:
                    logger.debug(f"PMUSimulator: on_frame callback error: {exc}")

        # Cleanup
        if self._sock:
            self._sock.close()
            self._sock = None
        self._running = False
        logger.info(f"PMUSimulator: stopped after {self.packets_sent} packets")

    # ── Frame generation ──────────────────────────────────────────────────────

    def _generate_frame(self, t: float) -> Tuple[bytes, dict]:
        """
        Generate a realistic 3-phase IEEE C37.118 data frame at time t.

        Voltage model:
          Va = V_nom × sin(2π × freq × t + 0°)
          Vb = V_nom × sin(2π × freq × t - 120°)
          Vc = V_nom × sin(2π × freq × t + 120°)

        In polar form (as required by C37.118):
          magnitude = V_nom (peak or RMS — we use RMS ÷ √2 here: 120 V ≈ RMS)
          angle_a   = 0 (reference)
          angle_b   = -2π/3
          angle_c   = +2π/3

        Frequency modulation:
          Slow drift: ±0.05 Hz sinusoidal variation over 10s period
          Plus any manual offset.
        """
        with self._lock:
            mag_scale   = self._mag_scale
            freq_offset = self._freq_offset
            manual_freq = self._manual_freq

        # Frequency with realistic slow drift
        drift = 0.05 * math.sin(TWO_PI * t / 10.0)   # ±0.05 Hz over 10s
        freq  = self.nom_freq + drift + freq_offset
        if manual_freq is not None:
            freq = manual_freq
        freq = max(45.0, min(65.0, freq))

        # ROCOF (df/dt) — finite difference approximation
        drift_rate = 0.05 * (TWO_PI / 10.0) * math.cos(TWO_PI * t / 10.0)
        dfreq = drift_rate + 0.0   # Hz/s

        # Voltage magnitude (RMS phase-to-neutral)
        base_mag = self.nom_voltage * mag_scale

        # Small imbalance to make it realistic (±0.2%)
        imbalance_a =  base_mag * (1 + 0.002 * math.sin(TWO_PI * t * 0.3))
        imbalance_b =  base_mag * (1 - 0.001 * math.sin(TWO_PI * t * 0.5))
        imbalance_c =  base_mag * (1 + 0.001 * math.sin(TWO_PI * t * 0.7))

        # Phase angles (in radians, referenced to Va = 0°)
        angle_a = 0.0
        angle_b = -TWO_PI / 3    # -120°
        angle_c =  TWO_PI / 3   #  +120°

        phasors = [
            (imbalance_a, angle_a),
            (imbalance_b, angle_b),
            (imbalance_c, angle_c),
        ]

        # Analog channel 1: estimated active power (MW) — simplified
        # P ≈ V × I × cos(φ) → we fake a slow variation
        power = 50.0 + 5.0 * math.sin(TWO_PI * t / 7.0)
        analog = [power]

        # Digital channel: PMU status word (bit 0 = GPS locked)
        digital = [0x0001]

        # SOC + FRACSEC from current time
        soc     = int(t)
        fracsec = int((t - soc) * 1_000_000) & 0x00FFFFFF

        raw_bytes = self._codec.encode_data_frame(
            phasors=phasors,
            freq=freq,
            dfreq=dfreq,
            analog=analog,
            digital=digital,
            soc=soc,
            fracsec=fracsec,
        )

        frame_dict = {
            "frame_type": "data",
            "idcode":     self.idcode,
            "soc":        soc,
            "fracsec":    fracsec,
            "stat":       0x0000,
            "phasors":    [list(p) for p in phasors],
            "freq":       freq,
            "dfreq":      dfreq,
            "analog":     analog,
            "digital":    digital,
            "raw":        raw_bytes,
        }

        return raw_bytes, frame_dict


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import struct

    print("PMUSimulator self-test — listen for 3 seconds of UDP packets")

    # Listen on a free port
    listen_port = 19876
    received    = []

    def listener():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(4.0)
        sock.bind(("127.0.0.1", listen_port))
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                received.append(data)
        except socket.timeout:
            pass
        finally:
            sock.close()

    t = threading.Thread(target=listener, daemon=True)
    t.start()

    time.sleep(0.1)  # let listener start

    pmu = PMUSimulator(
        dst_host="127.0.0.1",
        dst_port=listen_port,
        fps=30,
        nom_freq=50.0,
        nom_voltage=120.0,
    )
    pmu.start()

    time.sleep(3.0)
    pmu.stop()
    t.join()

    print(f"\nReceived {len(received)} packets in ~3 seconds")
    print(f"Expected ~90 DATA + 1 CFG-2 = ~91 packets at 30 fps")

    # Verify first non-CFG2 packet is a valid DATA frame
    data_pkts = [p for p in received if p[:2] == bytes([0xAA, 0x01])]
    cfg2_pkts = [p for p in received if p[:2] == bytes([0xAA, 0x31])]

    print(f"DATA frames:  {len(data_pkts)}")
    print(f"CFG-2 frames: {len(cfg2_pkts)}")
    assert cfg2_pkts, "Should have at least one CFG-2 frame"
    assert len(data_pkts) >= 80, f"Too few DATA frames: {len(data_pkts)}"

    codec = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=1)
    sample = codec.decode_data_frame(data_pkts[10])
    assert sample is not None, "DATA frame decode failed"
    print(f"\nSample decoded frame:")
    print(f"  FREQ:    {sample.freq:.4f} Hz")
    print(f"  PHASORS: {[(round(m,2), round(math.degrees(a),2)) for m,a in sample.phasors]}")
    print(f"  ANALOG:  {sample.analog}")
    assert 48.0 < sample.freq < 52.0, f"Frequency out of range: {sample.freq}"
    assert abs(sample.phasors[0][0] - 120.0) < 2.0, "Va magnitude out of range"
    print("\nPMUSimulator ALL TESTS PASSED ✔")
