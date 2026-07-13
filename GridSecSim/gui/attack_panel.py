"""
gui/attack_panel.py
===================
Attack configuration panel for GridSec Sim.

Features:
  - Dropdown to select active attack type
  - QStackedWidget with attack-specific parameter controls
  - Enable/Disable toggle button
  - Scope radio buttons (all links / selected link)
  - Real-time packet counters (total, modified, dropped)
  - Reset button to clear attack state and counters

The panel communicates with AttackEngine via direct method calls.
GUI signals notify the main window when the attack configuration changes.
"""

from typing import Optional, Dict

from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QComboBox, QPushButton, QCheckBox,
    QSlider, QDoubleSpinBox, QSpinBox, QStackedWidget,
    QFrame, QGroupBox, QRadioButton, QButtonGroup,
    QSizePolicy
)

from core.attack_engine import AttackEngine, AttackType, ATTACK_CLASSES


# ─────────────────────────────────────────────────────────────────────────────
# Attack type display info
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_ORDER = [
    AttackType.NONE,
    AttackType.NOISE,
    AttackType.RAMP,
    AttackType.PULSE,
    AttackType.FREQUENCY_OVERRIDE,
    AttackType.MAGNITUDE_OVERRIDE,
    AttackType.ANGLE_OVERRIDE,
    AttackType.REPLAY,
    AttackType.DELAY,
    AttackType.DROP,
    AttackType.SCALE,
]

ATTACK_ICONS = {
    AttackType.NONE:               "⬜",
    AttackType.NOISE:              "〰",
    AttackType.RAMP:               "📈",
    AttackType.PULSE:              "⚡",
    AttackType.FREQUENCY_OVERRIDE: "🔁",
    AttackType.MAGNITUDE_OVERRIDE: "📐",
    AttackType.ANGLE_OVERRIDE:     "🔄",
    AttackType.REPLAY:             "⏪",
    AttackType.DELAY:              "⏱",
    AttackType.DROP:               "🗑",
    AttackType.SCALE:              "✕",
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sep() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setStyleSheet("border: none; background: #3d3d5c; max-height: 1px;")
    return f


def _title(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setStyleSheet("color:#64748b; font-size:10px; font-weight:600; letter-spacing:0.05em;")
    return lbl


# ─────────────────────────────────────────────────────────────────────────────
# Attack-specific parameter pages (one per attack type)
# ─────────────────────────────────────────────────────────────────────────────

class NoParamPage(QWidget):
    def __init__(self, msg="No parameters"):
        super().__init__()
        lbl = QLabel(f"<center><span style='color:#3d3d5c'>{msg}</span></center>")
        lbl.setTextFormat(Qt.TextFormat.RichText)
        lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        QVBoxLayout(self).addWidget(lbl)

    def get_params(self): return {}
    def set_params(self, p): pass


class NoisePage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)
        self._std = QDoubleSpinBox()
        self._std.setRange(0.01, 100.0)
        self._std.setSingleStep(0.1)
        self._std.setValue(1.0)
        self._std.setSuffix(" V")
        form.addRow("Std Deviation:", self._std)

        self._freq_noise = QCheckBox("Also add frequency noise")
        form.addRow("", self._freq_noise)

        self._freq_std = QDoubleSpinBox()
        self._freq_std.setRange(0.001, 5.0)
        self._freq_std.setSingleStep(0.01)
        self._freq_std.setValue(0.05)
        self._freq_std.setSuffix(" Hz")
        form.addRow("Freq Noise Std:", self._freq_std)

    def get_params(self):
        return {
            "noise_std":      self._std.value(),
            "add_freq_noise": self._freq_noise.isChecked(),
            "freq_std":       self._freq_std.value(),
        }
    def set_params(self, p):
        if "noise_std"      in p: self._std.setValue(float(p["noise_std"]))
        if "add_freq_noise" in p: self._freq_noise.setChecked(bool(p["add_freq_noise"]))
        if "freq_std"       in p: self._freq_std.setValue(float(p["freq_std"]))


class RampPage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._rate = QDoubleSpinBox()
        self._rate.setRange(0.001, 100.0)
        self._rate.setSingleStep(0.01)
        self._rate.setValue(0.05)
        form.addRow("Ramp Rate:", self._rate)

        self._target = QComboBox()
        self._target.addItems(["magnitude", "frequency"])
        form.addRow("Target:", self._target)

        self._dir = QComboBox()
        self._dir.addItems(["up", "down"])
        form.addRow("Direction:", self._dir)

        self._idx = QSpinBox()
        self._idx.setRange(-1, 10)
        self._idx.setValue(-1)
        self._idx.setToolTip("-1 = all phasors")
        form.addRow("Phasor Index:", self._idx)

    def get_params(self):
        return {
            "ramp_rate":  self._rate.value(),
            "target":     self._target.currentText(),
            "direction":  self._dir.currentText(),
            "phasor_idx": self._idx.value(),
        }
    def set_params(self, p):
        if "ramp_rate"  in p: self._rate.setValue(float(p["ramp_rate"]))
        if "target"     in p: self._target.setCurrentText(str(p["target"]))
        if "direction"  in p: self._dir.setCurrentText(str(p["direction"]))
        if "phasor_idx" in p: self._idx.setValue(int(p["phasor_idx"]))


class PulsePage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._amp = QDoubleSpinBox()
        self._amp.setRange(0.1, 1000.0)
        self._amp.setSingleStep(1.0)
        self._amp.setValue(30.0)
        self._amp.setSuffix(" V")
        form.addRow("Amplitude:", self._amp)

        self._interval = QSpinBox()
        self._interval.setRange(1, 1000)
        self._interval.setValue(30)
        self._interval.setSuffix(" frames")
        form.addRow("Interval:", self._interval)

        self._duration = QSpinBox()
        self._duration.setRange(1, 100)
        self._duration.setValue(3)
        self._duration.setSuffix(" frames")
        form.addRow("Duration:", self._duration)

        self._target = QComboBox()
        self._target.addItems(["magnitude", "frequency"])
        form.addRow("Target:", self._target)

    def get_params(self):
        return {
            "amplitude":       self._amp.value(),
            "interval":        self._interval.value(),
            "duration_frames": self._duration.value(),
            "target":          self._target.currentText(),
        }
    def set_params(self, p):
        if "amplitude"       in p: self._amp.setValue(float(p["amplitude"]))
        if "interval"        in p: self._interval.setValue(int(p["interval"]))
        if "duration_frames" in p: self._duration.setValue(int(p["duration_frames"]))
        if "target"          in p: self._target.setCurrentText(str(p["target"]))


class FreqOverridePage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._freq = QDoubleSpinBox()
        self._freq.setRange(45.0, 65.0)
        self._freq.setSingleStep(0.1)
        self._freq.setValue(60.0)
        self._freq.setSuffix(" Hz")
        form.addRow("Target Frequency:", self._freq)

        info = QLabel("<i>Normal range: 49.5–50.5 Hz<br>Attack: force to wrong value</i>")
        info.setTextFormat(Qt.TextFormat.RichText)
        info.setStyleSheet("color: #64748b; font-size: 11px;")
        form.addRow("", info)

    def get_params(self): return {"target_freq": self._freq.value()}
    def set_params(self, p):
        if "target_freq" in p: self._freq.setValue(float(p["target_freq"]))


class MagOverridePage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._idx = QSpinBox()
        self._idx.setRange(0, 5)
        self._idx.setValue(0)
        self._idx.setToolTip("0=Va, 1=Vb, 2=Vc")
        form.addRow("Phasor Index:", self._idx)

        self._val = QDoubleSpinBox()
        self._val.setRange(0.0, 10000.0)
        self._val.setSingleStep(1.0)
        self._val.setValue(0.0)
        self._val.setSuffix(" V")
        form.addRow("Magnitude:", self._val)

    def get_params(self):
        return {"phasor_idx": self._idx.value(), "value": self._val.value()}
    def set_params(self, p):
        if "phasor_idx" in p: self._idx.setValue(int(p["phasor_idx"]))
        if "value"      in p: self._val.setValue(float(p["value"]))


class AngleOverridePage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._idx = QSpinBox()
        self._idx.setRange(0, 5)
        self._idx.setValue(0)
        form.addRow("Phasor Index:", self._idx)

        self._angle = QDoubleSpinBox()
        self._angle.setRange(-180.0, 180.0)
        self._angle.setSingleStep(1.0)
        self._angle.setValue(0.0)
        self._angle.setSuffix("°")
        form.addRow("Angle:", self._angle)

    def get_params(self):
        return {"phasor_idx": self._idx.value(), "angle_deg": self._angle.value()}
    def set_params(self, p):
        if "phasor_idx" in p: self._idx.setValue(int(p["phasor_idx"]))
        if "angle_deg"  in p: self._angle.setValue(float(p["angle_deg"]))


class ReplayPage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._buf = QSpinBox()
        self._buf.setRange(1, 300)
        self._buf.setValue(30)
        self._buf.setSuffix(" frames")
        form.addRow("Buffer Size:", self._buf)

        self._status = QLabel("Status: Not recording")
        self._status.setStyleSheet("color: #64748b; font-size: 11px;")
        form.addRow("", self._status)

    def get_params(self): return {"buffer_size": self._buf.value()}
    def set_params(self, p):
        if "buffer_size" in p: self._buf.setValue(int(p["buffer_size"]))
        if "buffered" in p and "buffer_size" in p:
            rec = p.get("recording", True)
            buffered = p.get("buffered", 0)
            buf_size = p.get("buffer_size", 30)
            if rec:
                self._status.setText(f"Recording: {buffered}/{buf_size}")
                self._status.setStyleSheet("color: #f59e0b; font-size: 11px;")
            else:
                self._status.setText("Replaying ⏪")
                self._status.setStyleSheet("color: #ef4444; font-size: 11px;")


class DelayPage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._delay = QDoubleSpinBox()
        self._delay.setRange(0.0, 5000.0)
        self._delay.setSingleStep(10.0)
        self._delay.setValue(100.0)
        self._delay.setSuffix(" ms")
        form.addRow("Delay:", self._delay)

        warn = QLabel("⚠ High delay will slow the entire stream")
        warn.setStyleSheet("color: #f59e0b; font-size: 11px;")
        form.addRow("", warn)

    def get_params(self): return {"delay_ms": self._delay.value()}
    def set_params(self, p):
        if "delay_ms" in p: self._delay.setValue(float(p["delay_ms"]))


class DropPage(QWidget):
    def __init__(self):
        super().__init__()
        vbox = QVBoxLayout(self)
        vbox.setSpacing(6)

        vbox.addWidget(QLabel("Drop Percentage:"))

        self._slider = QSlider(Qt.Orientation.Horizontal)
        self._slider.setRange(0, 100)
        self._slider.setValue(20)
        self._slider.setTickInterval(10)
        self._slider.setTickPosition(QSlider.TickPosition.TicksBelow)
        vbox.addWidget(self._slider)

        self._pct_label = QLabel("20%")
        self._pct_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._pct_label.setStyleSheet("color: #ef4444; font-size: 16px; font-weight: 700;")
        vbox.addWidget(self._pct_label)
        self._slider.valueChanged.connect(lambda v: self._pct_label.setText(f"{v}%"))

    def get_params(self): return {"drop_percent": float(self._slider.value())}
    def set_params(self, p):
        if "drop_percent" in p:
            self._slider.setValue(int(p["drop_percent"]))


class ScalePage(QWidget):
    def __init__(self):
        super().__init__()
        form = QFormLayout(self)
        form.setSpacing(8)

        self._scale = QDoubleSpinBox()
        self._scale.setRange(0.0, 10.0)
        self._scale.setSingleStep(0.1)
        self._scale.setValue(1.5)
        self._scale.setDecimals(3)
        form.addRow("Scale Factor:", self._scale)

        info = QLabel("<1.0 = voltage sag  |  >1.0 = voltage swell<br>0.0 = blackout")
        info.setTextFormat(Qt.TextFormat.RichText)
        info.setStyleSheet("color: #64748b; font-size: 11px;")
        form.addRow("", info)

        self._also_freq = QCheckBox("Also scale frequency")
        form.addRow("", self._also_freq)

    def get_params(self):
        return {
            "scale_factor":    self._scale.value(),
            "also_scale_freq": self._also_freq.isChecked(),
        }
    def set_params(self, p):
        if "scale_factor"    in p: self._scale.setValue(float(p["scale_factor"]))
        if "also_scale_freq" in p: self._also_freq.setChecked(bool(p["also_scale_freq"]))


PARAM_PAGES: Dict[AttackType, type] = {
    AttackType.NONE:               lambda: NoParamPage("No attack selected"),
    AttackType.NOISE:              NoisePage,
    AttackType.RAMP:               RampPage,
    AttackType.PULSE:              PulsePage,
    AttackType.FREQUENCY_OVERRIDE: FreqOverridePage,
    AttackType.MAGNITUDE_OVERRIDE: MagOverridePage,
    AttackType.ANGLE_OVERRIDE:     AngleOverridePage,
    AttackType.REPLAY:             ReplayPage,
    AttackType.DELAY:              DelayPage,
    AttackType.DROP:               DropPage,
    AttackType.SCALE:              ScalePage,
}


# ─────────────────────────────────────────────────────────────────────────────
# Attack Panel
# ─────────────────────────────────────────────────────────────────────────────

class AttackPanel(QWidget):
    """
    Attack configuration panel widget.

    Signals:
      attack_changed(attack_type: str, params: dict)
      attack_toggled(enabled: bool)
    """

    attack_changed = pyqtSignal(str, dict)
    attack_toggled = pyqtSignal(bool)

    def __init__(self, engine: AttackEngine, parent=None):
        super().__init__(parent)
        self._engine = engine
        self._pages: Dict[AttackType, QWidget] = {}
        self._build_ui()
        self._setup_stats_timer()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # ── Title ────────────────────────────────────────────────────────────
        title_row = QHBoxLayout()
        skull = QLabel("💀")
        skull.setStyleSheet("font-size: 18px;")
        title = QLabel("Attack Configuration")
        title.setStyleSheet("color: #ef4444; font-weight: 700; font-size: 13px;")
        title_row.addWidget(skull)
        title_row.addWidget(title)
        title_row.addStretch()
        layout.addLayout(title_row)
        layout.addWidget(_sep())

        # ── Attack selector ───────────────────────────────────────────────────
        layout.addWidget(_title("Attack Type"))
        self._type_combo = QComboBox()
        for at in ATTACK_ORDER:
            icon = ATTACK_ICONS.get(at, "")
            cls  = ATTACK_CLASSES.get(at)
            name = cls.display_name if cls else "No Attack"
            self._type_combo.addItem(f"{icon}  {name}", at)
        self._type_combo.currentIndexChanged.connect(self._on_type_changed)
        layout.addWidget(self._type_combo)

        # Description label
        self._desc_label = QLabel("")
        self._desc_label.setStyleSheet("color: #64748b; font-size: 11px;")
        self._desc_label.setWordWrap(True)
        layout.addWidget(self._desc_label)

        layout.addWidget(_sep())

        # ── Parameter pages (one per attack) ──────────────────────────────────
        layout.addWidget(_title("Parameters"))
        self._stack = QStackedWidget()
        for at in ATTACK_ORDER:
            page_cls = PARAM_PAGES.get(at, lambda: NoParamPage())
            page     = page_cls()
            self._pages[at] = page
            self._stack.addWidget(page)
        layout.addWidget(self._stack)

        layout.addWidget(_sep())

        # ── Enable/Disable toggle ─────────────────────────────────────────────
        self._enable_btn = QPushButton("⚡  Enable Attack")
        self._enable_btn.setObjectName("btn_attack_enable")
        self._enable_btn.setCheckable(True)
        self._enable_btn.setChecked(False)
        self._enable_btn.setMinimumHeight(36)
        self._enable_btn.toggled.connect(self._on_enable_toggled)
        layout.addWidget(self._enable_btn)

        # Apply params button
        apply_btn = QPushButton("Apply Parameters")
        apply_btn.clicked.connect(self._apply_params)
        layout.addWidget(apply_btn)

        layout.addWidget(_sep())

        # ── Scope ─────────────────────────────────────────────────────────────
        layout.addWidget(_title("Apply To"))
        scope_grp = QGroupBox()
        scope_grp.setStyleSheet("QGroupBox { border: none; padding: 0; margin: 0; }")
        scope_layout = QHBoxLayout(scope_grp)
        scope_layout.setContentsMargins(0, 0, 0, 0)
        self._scope_all  = QRadioButton("All Links")
        self._scope_sel  = QRadioButton("Selected Link")
        self._scope_all.setChecked(True)
        scope_layout.addWidget(self._scope_all)
        scope_layout.addWidget(self._scope_sel)
        layout.addWidget(scope_grp)

        layout.addWidget(_sep())

        # ── Statistics counters ───────────────────────────────────────────────
        layout.addWidget(_title("Statistics"))
        stats_frame = QFrame()
        stats_frame.setObjectName("sectionFrame")
        stats_frame.setStyleSheet("""
            QFrame#sectionFrame {
                background: #13131f;
                border: 1px solid #2d2d44;
                border-radius: 8px;
            }
        """)
        sg = QVBoxLayout(stats_frame)
        sg.setContentsMargins(10, 8, 10, 8)
        sg.setSpacing(4)

        def stat_row(label, attr):
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setStyleSheet("color: #64748b; font-size: 11px;")
            val = QLabel("0")
            val.setStyleSheet("color: #a78bfa; font-weight: 700; font-size: 13px;")
            val.setAlignment(Qt.AlignmentFlag.AlignRight)
            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val)
            setattr(self, attr, val)
            return row

        sg.addLayout(stat_row("Total Packets:", "_stat_total"))
        sg.addLayout(stat_row("Modified:", "_stat_modified"))
        sg.addLayout(stat_row("Dropped:", "_stat_dropped"))
        layout.addWidget(stats_frame)

        # Reset button
        reset_btn = QPushButton("Reset Stats")
        reset_btn.setFixedHeight(28)
        reset_btn.setStyleSheet("font-size: 11px; padding: 0;")
        reset_btn.clicked.connect(self._reset_stats)
        layout.addWidget(reset_btn)

        layout.addStretch()

        # Trigger initial state
        self._on_type_changed(0)

    # ── Timer for stats ───────────────────────────────────────────────────────

    def _setup_stats_timer(self):
        self._stats_timer = QTimer(self)
        self._stats_timer.setInterval(500)   # update every 500ms
        self._stats_timer.timeout.connect(self._update_stats)
        self._stats_timer.start()

    # ── Slots ─────────────────────────────────────────────────────────────────

    def _on_type_changed(self, idx: int) -> None:
        at = self._type_combo.itemData(idx)
        if at is None:
            return

        # Switch page
        page_idx = ATTACK_ORDER.index(at)
        self._stack.setCurrentIndex(page_idx)

        # Update description
        cls = ATTACK_CLASSES.get(at)
        if cls:
            self._desc_label.setText(cls.description)
        else:
            self._desc_label.setText("No attack — packets pass through unmodified.")

        # Restore params from engine
        page = self._pages.get(at)
        if page and hasattr(page, "set_params"):
            eng_attack = self._engine.get_attack(at)
            page.set_params(eng_attack.get_params())

    def _on_enable_toggled(self, checked: bool) -> None:
        at = self._get_active_type()
        self._apply_params()   # sync params first

        if checked:
            self._engine.set_attack(at)
            self._engine.enable()
            self._enable_btn.setText("🛑  Disable Attack")
            self._enable_btn.setStyleSheet(
                "background: #ef4444; color: white; border: none; border-radius: 6px;"
                "font-weight: 700; font-size: 13px;"
            )
        else:
            self._engine.disable()
            self._enable_btn.setText("⚡  Enable Attack")
            self._enable_btn.setStyleSheet("")   # revert to QSS

        self.attack_toggled.emit(checked)
        self.attack_changed.emit(at.value, self._get_current_params())

    def _apply_params(self) -> None:
        at   = self._get_active_type()
        page = self._pages.get(at)
        if page and hasattr(page, "get_params"):
            params = page.get_params()
            eng_attack = self._engine.get_attack(at)
            eng_attack.set_params(params)

    def _reset_stats(self) -> None:
        self._engine.reset_stats()
        self._engine.reset_attack_state()
        self._stat_total.setText("0")
        self._stat_modified.setText("0")
        self._stat_dropped.setText("0")

    def _update_stats(self) -> None:
        stats = self._engine.stats
        self._stat_total.setText(f"{stats['total_packets']:,}")
        self._stat_modified.setText(f"{stats['modified_packets']:,}")
        self._stat_dropped.setText(f"{stats['dropped_packets']:,}")

        # Update replay page status if active
        at = self._get_active_type()
        if at == AttackType.REPLAY:
            replay_atk = self._engine.get_attack(AttackType.REPLAY)
            page = self._pages.get(AttackType.REPLAY)
            if page and hasattr(page, "set_params"):
                page.set_params(replay_atk.get_params())

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _get_active_type(self) -> AttackType:
        return self._type_combo.currentData() or AttackType.NONE

    def _get_current_params(self) -> dict:
        page = self._pages.get(self._get_active_type())
        if page and hasattr(page, "get_params"):
            return page.get_params()
        return {}

    # ── Public API ─────────────────────────────────────────────────────────

    def is_attack_enabled(self) -> bool:
        return self._enable_btn.isChecked()

    def get_scope(self) -> str:
        return "all" if self._scope_all.isChecked() else "selected"

    def sync_from_engine(self) -> None:
        """Pull current engine state into the UI (e.g., after loading a topology)."""
        at    = self._engine.active_type
        idx   = ATTACK_ORDER.index(at) if at in ATTACK_ORDER else 0
        self._type_combo.setCurrentIndex(idx)
        self._enable_btn.setChecked(self._engine.is_enabled)
