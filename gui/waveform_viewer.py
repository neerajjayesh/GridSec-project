"""
gui/waveform_viewer.py
======================
Live matplotlib-embedded waveform viewer.

Shows BEFORE (clean, green) and AFTER (attacked, red) signals on the same
chart for three measurement tabs:
  1. Voltage Magnitude (V)
  2. Frequency (Hz)
  3. Angle (degrees)

Updates at 10 fps via QTimer.
Uses a rolling 2-second buffer.
"""

import math
import time
from collections import deque
from typing import Optional, List, Tuple

import numpy as np

from PyQt6.QtCore import QTimer, Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QTabWidget, QLabel,
    QHBoxLayout, QPushButton, QFrame
)

try:
    import matplotlib
    matplotlib.use("QtAgg")
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Buffer size: 2 seconds × 30 fps = 60 samples
BUFFER_MAXLEN = 120   # 2 seconds at 60fps (generous)
UPDATE_FPS    = 10


class WaveformChannel:
    """Rolling buffer for one measurement channel."""

    def __init__(self, maxlen: int = BUFFER_MAXLEN):
        self.times:    deque = deque(maxlen=maxlen)
        self.original: deque = deque(maxlen=maxlen)   # clean signal
        self.attacked: deque = deque(maxlen=maxlen)   # attacked signal

    def push(self, t: float, orig_val: float, atk_val: float) -> None:
        self.times.append(t)
        self.original.append(orig_val)
        self.attacked.append(atk_val)

    def clear(self) -> None:
        self.times.clear()
        self.original.clear()
        self.attacked.clear()

    def arrays(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        if not self.times:
            return np.array([]), np.array([]), np.array([])
        t0 = self.times[0]
        t  = np.array(self.times) - t0
        return t, np.array(self.original), np.array(self.attacked)


class WaveformPlot(QWidget):
    """Single matplotlib chart embedded in a QWidget."""

    def __init__(
        self,
        title: str,
        y_label: str,
        y_min: float,
        y_max: float,
        parent=None,
    ):
        super().__init__(parent)
        self._title  = title
        self._y_label = y_label
        self._y_min  = y_min
        self._y_max  = y_max
        self._channel = WaveformChannel()
        self._attack_active = False

        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if not HAS_MATPLOTLIB:
            lbl = QLabel("⚠ matplotlib not installed. Run: pip install matplotlib")
            lbl.setStyleSheet("color: #f59e0b; padding: 20px;")
            lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(lbl)
            self._canvas = None
            return

        # Figure with dark background
        self._fig = Figure(figsize=(6, 2.2), dpi=90, facecolor="#13131f")
        self._ax  = self._fig.add_subplot(111)
        self._fig.subplots_adjust(left=0.10, right=0.98, top=0.88, bottom=0.18)
        self._setup_axes()

        # Create line objects (initially empty)
        self._line_orig, = self._ax.plot([], [], color="#10b981", linewidth=1.5,
                                          label="Clean", zorder=3)
        self._line_atk,  = self._ax.plot([], [], color="#ef4444", linewidth=1.5,
                                          linestyle="--", label="Attacked", zorder=4)
        self._ax.legend(loc="upper right", fontsize=7, framealpha=0.3,
                        facecolor="#1e1e2e", edgecolor="#3d3d5c",
                        labelcolor=["#10b981", "#ef4444"])

        self._canvas = FigureCanvas(self._fig)
        self._canvas.setStyleSheet("background: #13131f;")
        layout.addWidget(self._canvas)

    def _setup_axes(self):
        ax = self._ax
        ax.set_facecolor("#0d0d1a")
        ax.set_title(self._title, color="#a78bfa", fontsize=10, pad=4,
                     fontfamily="monospace")
        ax.set_xlabel("Time (s)", color="#64748b", fontsize=8)
        ax.set_ylabel(self._y_label, color="#64748b", fontsize=8)
        ax.tick_params(colors="#64748b", labelsize=7)
        ax.set_xlim(0, 2.0)
        ax.set_ylim(self._y_min, self._y_max)
        ax.grid(True, color="#1e2a3a", linewidth=0.5, linestyle="--")
        ax.spines["bottom"].set_color("#2d2d44")
        ax.spines["top"].set_color("#2d2d44")
        ax.spines["left"].set_color("#2d2d44")
        ax.spines["right"].set_color("#2d2d44")

    def push(self, t: float, orig: float, attacked: float) -> None:
        self._channel.push(t, orig, attacked)

    def refresh(self) -> None:
        if self._canvas is None:
            return
        times, orig, atk = self._channel.arrays()
        if len(times) < 2:
            return

        t_window = 2.0
        t_end    = times[-1]
        t_start  = max(0.0, t_end - t_window)

        # Update line data
        self._line_orig.set_data(times, orig)
        self._line_atk.set_data(times, atk)

        # Slide x window
        self._ax.set_xlim(t_start, t_end)

        # Auto y-range with padding
        all_vals = np.concatenate([orig, atk])
        if len(all_vals):
            vmin = min(all_vals.min(), self._y_min)
            vmax = max(all_vals.max(), self._y_max)
            pad  = (vmax - vmin) * 0.05 or 1.0
            self._ax.set_ylim(vmin - pad, vmax + pad)

        self._canvas.draw_idle()

    def clear(self) -> None:
        self._channel.clear()
        if self._canvas:
            self._line_orig.set_data([], [])
            self._line_atk.set_data([], [])
            self._canvas.draw_idle()


class WaveformViewer(QWidget):
    """
    Tabbed waveform viewer with three channels:
      1. Voltage Magnitude (Va)
      2. Frequency
      3. Angle (Va)

    Call push_frame(original_dict, modified_dict) each time a packet
    is processed by the proxy.
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._start_time = time.time()
        self._build_ui()
        self._setup_timer()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header bar
        header = QFrame()
        header.setFixedHeight(32)
        header.setStyleSheet("background: #1a1a2e; border-bottom: 1px solid #2d2d44;")
        hdr_layout = QHBoxLayout(header)
        hdr_layout.setContentsMargins(10, 0, 10, 0)

        title = QLabel("Live Waveform")
        title.setStyleSheet("color: #a78bfa; font-weight: 600; font-size: 12px;")
        hdr_layout.addWidget(title)
        hdr_layout.addStretch()

        self._fps_label = QLabel("0.0 fps")
        self._fps_label.setStyleSheet("color: #64748b; font-size: 11px;")
        hdr_layout.addWidget(self._fps_label)

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.setFixedSize(50, 22)
        self._clear_btn.setStyleSheet(
            "font-size: 11px; padding: 0; border-radius: 3px;"
            "background: #2d2d44; color: #94a3b8; border: 1px solid #3d3d5c;"
        )
        self._clear_btn.clicked.connect(self.clear)
        hdr_layout.addWidget(self._clear_btn)
        layout.addWidget(header)

        # Tab widget
        self._tabs = QTabWidget()
        self._tabs.setDocumentMode(True)
        layout.addWidget(self._tabs)

        # Voltage Magnitude
        self._mag_plot = WaveformPlot(
            title="Va — Voltage Magnitude",
            y_label="Volts (V)",
            y_min=80.0, y_max=170.0,
        )
        self._tabs.addTab(self._mag_plot,   "Voltage Mag")

        # Frequency
        self._freq_plot = WaveformPlot(
            title="Frequency",
            y_label="Frequency (Hz)",
            y_min=48.0, y_max=52.0,
        )
        self._tabs.addTab(self._freq_plot, "Frequency")

        # Angle
        self._angle_plot = WaveformPlot(
            title="Va - Phase Angle",
            y_label="Angle (degrees)",
            y_min=-10.0, y_max=10.0,
        )
        self._tabs.addTab(self._angle_plot, "Angle")

        # Frame counter for fps tracking
        self._frame_count = 0
        self._fps_t0      = time.time()

    def _setup_timer(self):
        self._timer = QTimer(self)
        self._timer.setInterval(1000 // UPDATE_FPS)   # 100 ms = 10 fps
        self._timer.timeout.connect(self._refresh_all)

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self) -> None:
        self._start_time = time.time()
        self._frame_count = 0
        self._fps_t0 = time.time()
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def clear(self) -> None:
        self._mag_plot.clear()
        self._freq_plot.clear()
        self._angle_plot.clear()

    def push_frame(self, original: Optional[dict], modified: Optional[dict]) -> None:
        """
        Push one frame pair to all channels.

        original : parsed frame dict (before attack)
        modified : parsed frame dict (after attack, may be same object if unmodified)
        """
        if original is None:
            return

        t = time.time() - self._start_time

        # Voltage magnitude — use Va (phasor[0])
        orig_phasors = original.get("phasors", [])
        mod_phasors  = modified.get("phasors", []) if modified else orig_phasors

        orig_mag = orig_phasors[0][0] if orig_phasors else 0.0
        mod_mag  = mod_phasors[0][0]  if mod_phasors  else orig_mag

        orig_freq = original.get("freq", 50.0)
        mod_freq  = modified.get("freq", orig_freq) if modified else orig_freq

        orig_angle = math.degrees(orig_phasors[0][1]) if orig_phasors else 0.0
        mod_angle  = math.degrees(mod_phasors[0][1])  if mod_phasors  else orig_angle

        self._mag_plot.push(t, orig_mag, mod_mag)
        self._freq_plot.push(t, orig_freq, mod_freq)
        self._angle_plot.push(t, orig_angle, mod_angle)

        self._frame_count += 1

    def push_frame_from_record(self, record) -> None:
        """Convenience — push from a PDCProxy PacketRecord."""
        if record.original.get("frame_type") != "data":
            return
        if not record.forwarded:
            missing = {"phasors": [(float("nan"), float("nan"))], "freq": float("nan")}
            self.push_frame(record.original, missing)
        else:
            self.push_frame(record.original, record.modified)

    # ── Private ───────────────────────────────────────────────────────────────

    def _refresh_all(self) -> None:
        # Only refresh the active tab to save CPU
        active = self._tabs.currentIndex()
        plots  = [self._mag_plot, self._freq_plot, self._angle_plot]
        if 0 <= active < len(plots):
            plots[active].refresh()

        # Update fps display
        now = time.time()
        elapsed = now - self._fps_t0
        if elapsed >= 1.0:
            fps = self._frame_count / elapsed
            self._fps_label.setText(f"{fps:.1f} fps")
            self._frame_count = 0
            self._fps_t0 = now
