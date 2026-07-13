"""
gui/main_window.py
==================
GridSec Sim — Main Application Window.

Layout (Cisco Packet Tracer style):
  ┌──────────────────────────────────────────────────────────────┐
  │  Menu Bar + Toolbar                                          │
  ├──────────────┬─────────────────────────────┬────────────────┤
  │  Node Palette│                             │  Properties    │
  │  + Protocol  │   Topology Canvas           │  Panel         │
  │  selector    │   (QGraphicsView)           │  + Attack      │
  │              │                             │  Panel         │
  ├──────────────┴────────────────┬────────────┴────────────────┤
  │  Waveform Viewer              │  Packet Log                 │
  ├───────────────────────────────┴─────────────────────────────┤
  │  Status Bar                                                  │
  └──────────────────────────────────────────────────────────────┘

Threading model:
  - PMUSimulator runs in a daemon thread
  - PDCProxy runs in a daemon thread
  - Both emit data via callbacks → bridged to Qt signals
    via a QObject relay to avoid threading violations
  - GUI updates happen in the main thread only
"""

import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Optional, List

from PyQt6.QtCore import (
    Qt, QTimer, pyqtSignal, QObject, QThread, QMutex
)
from PyQt6.QtGui import (
    QAction, QFont, QColor, QKeySequence, QIcon
)
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QApplication,
    QVBoxLayout, QHBoxLayout, QSplitter,
    QLabel, QPushButton, QFrame, QComboBox,
    QListWidget, QListWidgetItem, QTextEdit,
    QFileDialog, QMessageBox, QToolBar, QStatusBar,
    QTabWidget, QScrollBar, QSizePolicy, QMenu,
    QDialog, QFormLayout, QLineEdit, QSpinBox,
)

from core.attack_engine import AttackEngine, AttackType
from core.pdc_proxy import PDCProxy, PacketRecord
from core.pmu_simulator import PMUSimulator
from core.traffic_filter import TrafficFilter
from protocols.c37118 import C37118Codec

from gui.attack_panel import AttackPanel
from gui.canvas import TopologyCanvas
from gui.node_types import (
    NodeType, NODE_DISPLAY_NAMES, NODE_ICON_TEXT,
    BaseNode, PMUNode, PDCNode, ThreatAgentNode,
)
from gui.properties_panel import PropertiesPanel
from gui.waveform_viewer import WaveformViewer

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Thread-safe signal relay
# ─────────────────────────────────────────────────────────────────────────────

class WorkerRelay(QObject):
    """
    Relay object that lives in the main thread and emits signals.
    Worker threads call emit_* methods which are thread-safe.
    """
    pmu_frame_received  = pyqtSignal(bytes, dict)
    proxy_packet        = pyqtSignal(object)   # PacketRecord
    simulation_error    = pyqtSignal(str)

    def emit_pmu_frame(self, raw: bytes, frame_dict: dict) -> None:
        try:
            self.pmu_frame_received.emit(raw, frame_dict)
        except Exception:
            pass

    def emit_proxy_packet(self, record: PacketRecord) -> None:
        try:
            self.proxy_packet.emit(record)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Node palette item
# ─────────────────────────────────────────────────────────────────────────────

PALETTE_NODES = [
    (NodeType.PMU,          "📡  PMU",          "Phasor Measurement Unit"),
    (NodeType.PDC,          "🖥  PDC",           "Data Concentrator / openPDC"),
    (NodeType.SWITCH,       "🔀  Switch",        "Network switch"),
    (NodeType.THREAT_AGENT, "💀  Threat Agent",  "Man-in-the-Middle attacker"),
    (NodeType.VIRTUAL,      "⚙  Virtual Node",  "Generic virtual device"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    """GridSec Sim main application window."""

    def __init__(self):
        super().__init__()

        # Core components
        self._codec  = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=1)
        self._engine = AttackEngine()
        self._filter = TrafficFilter()
        self._relay  = WorkerRelay()

        self._pmu:   Optional[PMUSimulator] = None
        self._proxy: Optional[PDCProxy]     = None
        self._sim_running = False

        # Packet log buffer (for performance — batch-update)
        self._log_buffer:  List[str]   = []
        self._log_mutex    = QMutex()
        self._log_max_lines = 500

        self._build_ui()
        self._build_menus()
        self._build_toolbar()
        self._build_status_bar()
        self._connect_signals()

        # Log flush timer (batch GUI updates)
        self._log_flush_timer = QTimer(self)
        self._log_flush_timer.setInterval(200)
        self._log_flush_timer.timeout.connect(self._flush_log)
        self._log_flush_timer.start()

        self.setWindowTitle("GridSec Sim — Smart Grid Cybersecurity Simulation Tool")
        self.resize(1600, 950)
        self._apply_stylesheet()
        self.setMinimumSize(1200, 700)

        logger.info("GridSec Sim: main window initialized")

    # ── UI Construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Main horizontal splitter: left | center | right ─────────────────
        self._h_splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left panel (node palette) ────────────────────────────────────────
        left_panel = self._build_left_panel()
        self._h_splitter.addWidget(left_panel)
        self._h_splitter.setStretchFactor(0, 0)

        # ── Center+bottom vertical splitter ──────────────────────────────────
        center_splitter = QSplitter(Qt.Orientation.Vertical)

        # Canvas
        self._canvas = TopologyCanvas()
        center_splitter.addWidget(self._canvas)

        # Bottom: waveform | log
        bottom_splitter = QSplitter(Qt.Orientation.Horizontal)
        self._waveform  = WaveformViewer()
        self._log_panel = self._build_log_panel()
        bottom_splitter.addWidget(self._waveform)
        bottom_splitter.addWidget(self._log_panel)
        bottom_splitter.setSizes([700, 500])
        center_splitter.addWidget(bottom_splitter)
        center_splitter.setSizes([600, 280])

        self._h_splitter.addWidget(center_splitter)
        self._h_splitter.setStretchFactor(1, 1)

        # ── Right panel (properties + attack) ────────────────────────────────
        right_panel = self._build_right_panel()
        self._h_splitter.addWidget(right_panel)
        self._h_splitter.setStretchFactor(2, 0)
        self._h_splitter.setSizes([200, 1000, 300])

        main_layout.addWidget(self._h_splitter)

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(180)
        panel.setMaximumWidth(220)
        panel.setStyleSheet("background: #252535; border-right: 1px solid #2d2d44;")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 10, 8, 8)
        layout.setSpacing(6)

        # Title
        title = QLabel("🗂  Node Palette")
        title.setStyleSheet("color: #a78bfa; font-weight: 700; font-size: 12px; padding: 4px 0;")
        layout.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("border: none; background: #3d3d5c; max-height: 1px;")
        layout.addWidget(sep)

        # Help text
        help_lbl = QLabel("Drag to canvas →")
        help_lbl.setStyleSheet("color: #4a5568; font-size: 11px; padding: 2px 0;")
        layout.addWidget(help_lbl)

        # Palette list
        self._palette = QListWidget()
        self._palette.setDragEnabled(True)
        self._palette.setStyleSheet("QListWidget { border: none; background: transparent; }")
        for node_type, display_name, tooltip in PALETTE_NODES:
            item = QListWidgetItem(display_name)
            item.setData(Qt.ItemDataRole.UserRole, node_type)
            item.setToolTip(tooltip)
            self._palette.addItem(item)

        self._palette.itemDoubleClicked.connect(self._on_palette_double_click)
        self._palette.setDragDropMode(QListWidget.DragDropMode.DragOnly)
        layout.addWidget(self._palette)

        # Protocol selector
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setStyleSheet("border: none; background: #3d3d5c; max-height: 1px;")
        layout.addWidget(sep2)

        proto_title = QLabel("🔗  Link Protocol")
        proto_title.setStyleSheet("color: #a78bfa; font-weight: 700; font-size: 11px; padding: 4px 0;")
        layout.addWidget(proto_title)

        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["C37.118", "DNP3", "Modbus", "IEC104"])
        self._proto_combo.currentTextChanged.connect(
            lambda p: self._canvas.set_protocol(p)
        )
        layout.addWidget(self._proto_combo)

        layout.addStretch()

        return panel

    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(280)
        panel.setMaximumWidth(340)
        panel.setStyleSheet("background: #252535; border-left: 1px solid #2d2d44;")

        tabs = QTabWidget()
        tabs.setDocumentMode(True)

        self._props_panel = PropertiesPanel()
        tabs.addTab(self._props_panel, "🔧 Properties")

        self._attack_panel = AttackPanel(self._engine)
        tabs.addTab(self._attack_panel, "💀 Attacks")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(tabs)
        return panel

    def _build_log_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        header = QFrame()
        header.setFixedHeight(32)
        header.setStyleSheet("background: #1a1a2e; border-bottom: 1px solid #2d2d44;")
        hdr_layout = QHBoxLayout(header)
        hdr_layout.setContentsMargins(10, 0, 10, 0)
        lbl = QLabel("📋 Packet Log")
        lbl.setStyleSheet("color: #a78bfa; font-weight: 600; font-size: 12px;")
        hdr_layout.addWidget(lbl)
        hdr_layout.addStretch()
        clear_btn = QPushButton("Clear")
        clear_btn.setFixedSize(50, 22)
        clear_btn.setStyleSheet(
            "font-size: 11px; padding: 0; border-radius: 3px;"
            "background: #2d2d44; color: #94a3b8; border: 1px solid #3d3d5c;"
        )
        clear_btn.clicked.connect(self._clear_log)
        hdr_layout.addWidget(clear_btn)
        layout.addWidget(header)

        self._log_text = QTextEdit()
        self._log_text.setReadOnly(True)
        self._log_text.setStyleSheet("""
            QTextEdit {
                background: #0d0d1a;
                color: #94a3b8;
                font-family: "Cascadia Code", Consolas, monospace;
                font-size: 11px;
                border: none;
            }
        """)
        layout.addWidget(self._log_text)
        return panel

    # ── Menu ──────────────────────────────────────────────────────────────────

    def _build_menus(self):
        mb = self.menuBar()

        # File menu
        file_menu = mb.addMenu("&File")
        act_new    = QAction("New Topology", self, shortcut="Ctrl+N")
        act_open   = QAction("Open Topology…", self, shortcut="Ctrl+O")
        act_save   = QAction("Save Topology…", self, shortcut="Ctrl+S")
        act_exit   = QAction("Exit", self, shortcut="Ctrl+Q")
        act_new.triggered.connect(self._new_topology)
        act_open.triggered.connect(self._open_topology)
        act_save.triggered.connect(self._save_topology)
        act_exit.triggered.connect(self.close)
        file_menu.addActions([act_new, act_open, act_save])
        file_menu.addSeparator()
        file_menu.addAction(act_exit)

        # Simulation menu
        sim_menu = mb.addMenu("&Simulation")
        self._act_run  = QAction("▶  Run Simulation", self, shortcut="F5")
        self._act_stop = QAction("■  Stop Simulation", self, shortcut="F6")
        self._act_run.triggered.connect(self._start_simulation)
        self._act_stop.triggered.connect(self._stop_simulation)
        self._act_stop.setEnabled(False)
        sim_menu.addActions([self._act_run, self._act_stop])

        # Attacks menu
        atk_menu = mb.addMenu("&Attacks")
        for at in AttackType:
            if at == AttackType.NONE:
                continue
            cls  = __import__("core.attack_engine", fromlist=[""]).ATTACK_CLASSES.get(at)
            name = cls.display_name if cls else at.value
            act  = QAction(f"{name}", self)
            act.triggered.connect(lambda checked, a=at: self._select_attack(a))
            atk_menu.addAction(act)

        # View menu
        view_menu = mb.addMenu("&View")
        act_zoom_in  = QAction("Zoom In",  self, shortcut="Ctrl+=")
        act_zoom_out = QAction("Zoom Out", self, shortcut="Ctrl+-")
        act_zoom_fit = QAction("Fit View", self, shortcut="Ctrl+0")
        act_zoom_in.triggered.connect(self._canvas.zoom_in)
        act_zoom_out.triggered.connect(self._canvas.zoom_out)
        act_zoom_fit.triggered.connect(self._canvas.zoom_fit)
        view_menu.addActions([act_zoom_in, act_zoom_out, act_zoom_fit])

        # Help menu
        help_menu = mb.addMenu("&Help")
        act_about = QAction("About GridSec Sim", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_about)

    # ── Toolbar ───────────────────────────────────────────────────────────────

    def _build_toolbar(self):
        tb = QToolBar("Main Toolbar")
        tb.setMovable(False)
        tb.setObjectName("mainToolbar")
        self.addToolBar(tb)

        # Run / Stop
        self._tb_run  = tb.addAction("▶  Run")
        self._tb_stop = tb.addAction("■  Stop")
        self._tb_run.triggered.connect(self._start_simulation)
        self._tb_stop.triggered.connect(self._stop_simulation)
        self._tb_stop.setEnabled(False)

        tb.addSeparator()

        # Canvas modes
        self._tb_select  = tb.addAction("↖  Select")
        self._tb_connect = tb.addAction("🔗  Connect")
        self._tb_delete  = tb.addAction("🗑  Delete")
        self._tb_select.setCheckable(True)
        self._tb_select.setChecked(True)
        self._tb_connect.setCheckable(True)
        self._tb_delete.setCheckable(True)
        self._tb_select.triggered.connect(lambda: self._set_canvas_mode("select"))
        self._tb_connect.triggered.connect(lambda: self._set_canvas_mode("connect"))
        self._tb_delete.triggered.connect(lambda: self._set_canvas_mode("delete"))

        tb.addSeparator()

        # Zoom
        tb.addAction("🔍+", self._canvas.zoom_in)
        tb.addAction("🔍−", self._canvas.zoom_out)
        tb.addAction("⊡  Fit",  self._canvas.zoom_fit)

        tb.addSeparator()

        # Clear
        act_clear = tb.addAction("🗑  Clear Canvas")
        act_clear.triggered.connect(self._confirm_clear)

        tb.addSeparator()

        # Quick node buttons
        for node_type, label, _ in PALETTE_NODES[:4]:
            icon = NODE_ICON_TEXT.get(node_type, "?")
            act  = tb.addAction(f"{icon} +{label.split()[1]}")
            act.triggered.connect(lambda checked, t=node_type: self._canvas.add_node(t))

    def _set_canvas_mode(self, mode: str) -> None:
        self._canvas.set_mode(mode)
        self._tb_select.setChecked(mode == "select")
        self._tb_connect.setChecked(mode == "connect")
        self._tb_delete.setChecked(mode == "delete")

    # ── Status Bar ────────────────────────────────────────────────────────────

    def _build_status_bar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)

        def _lbl(text, obj_name=""):
            l = QLabel(text)
            if obj_name: l.setObjectName(obj_name)
            l.setStyleSheet("padding: 0 8px; font-size: 12px;")
            return l

        def _sep():
            f = QFrame()
            f.setFrameShape(QFrame.Shape.VLine)
            f.setStyleSheet("color: #3d3d5c;")
            return f

        self._sb_pmu   = _lbl("PMU: ●  Stopped", "status_pmu_stopped")
        self._sb_proxy = _lbl("Proxy: ●  Idle",   "status_proxy_idle")
        self._sb_sent  = _lbl("Sent: 0")
        self._sb_atk   = _lbl("Modified: 0", "status_attack_off")
        self._sb_drop  = _lbl("Dropped: 0")

        for w in [self._sb_pmu, _sep(), self._sb_proxy, _sep(),
                  self._sb_sent, _sep(), self._sb_atk, _sep(), self._sb_drop]:
            sb.addPermanentWidget(w)

        # Update timer
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_timer.start()

    def _update_status_bar(self) -> None:
        if self._pmu and self._pmu.is_running:
            self._sb_pmu.setText(f"PMU: ●  Running ({self._pmu.packets_sent:,})")
            self._sb_pmu.setObjectName("status_pmu_running")
        else:
            self._sb_pmu.setText("PMU: ●  Stopped")
            self._sb_pmu.setObjectName("status_pmu_stopped")

        if self._proxy and self._proxy.is_running:
            self._sb_proxy.setText(f"Proxy: ●  Active")
            self._sb_proxy.setObjectName("status_proxy_active")
        else:
            self._sb_proxy.setText("Proxy: ●  Idle")
            self._sb_proxy.setObjectName("status_proxy_idle")

        stats = self._engine.stats
        self._sb_sent.setText(f"Sent: {stats['total_packets']:,}")
        modified = stats['modified_packets']
        if modified > 0:
            self._sb_atk.setText(f"Modified: {modified:,}")
            self._sb_atk.setObjectName("status_attack_on")
        else:
            self._sb_atk.setText(f"Modified: 0")
            self._sb_atk.setObjectName("status_attack_off")
        self._sb_drop.setText(f"Dropped: {stats['dropped_packets']:,}")

    # ── Signal connections ────────────────────────────────────────────────────

    def _connect_signals(self):
        # Canvas → properties panel
        self._canvas.signals.node_selected.connect(self._on_node_selected)
        self._canvas.signals.link_selected.connect(self._on_link_selected)
        self._canvas.signals.node_config_changed.connect(self._on_node_config_changed)

        # Properties panel → canvas
        self._props_panel.config_applied.connect(self._on_config_applied)

        # Relay (background threads → main thread)
        self._relay.pmu_frame_received.connect(self._on_pmu_frame)
        self._relay.proxy_packet.connect(self._on_proxy_packet)
        self._relay.simulation_error.connect(self._on_simulation_error)

        # Palette drag
        self._palette.startDrag = self._palette_start_drag

    def _palette_start_drag(self, supported_actions):
        item = self._palette.currentItem()
        if item:
            from PyQt6.QtGui import QDrag
            from PyQt6.QtCore import QMimeData
            mime = QMimeData()
            mime.setText(item.data(Qt.ItemDataRole.UserRole))
            drag = QDrag(self._palette)
            drag.setMimeData(mime)
            drag.exec(Qt.DropAction.CopyAction)

    # ── Simulation control ────────────────────────────────────────────────────

    def _start_simulation(self) -> None:
        if self._sim_running:
            return

        # Determine PMU and PDC settings from canvas
        pmu_nodes = self._canvas.get_pmu_nodes()
        pdc_nodes = self._canvas.get_pdc_nodes()

        pmu_ip   = pmu_nodes[0].ip   if pmu_nodes else "127.0.0.1"
        pmu_port = pmu_nodes[0].port if pmu_nodes else 4712
        pdc_ip   = pdc_nodes[0].ip   if pdc_nodes else "127.0.0.1"
        pdc_port = pdc_nodes[0].port if pdc_nodes else 4713

        # Proxy listens on PMU's port; PMU sends to proxy
        proxy_port = pmu_port
        pmu_target = proxy_port

        self._log(f"[SIM] Starting simulation: PMU→{pmu_ip}:{pmu_target}  Proxy→{pdc_ip}:{pdc_port}", "system")

        # Create proxy
        self._proxy = PDCProxy(
            listen_host="127.0.0.1",
            listen_port=proxy_port,
            target_host=pdc_ip,
            target_port=pdc_port,
            proto="UDP",
            codec=self._codec,
            attack_engine=self._engine,
            traffic_filter=self._filter,
            on_packet=self._relay.emit_proxy_packet,
        )
        self._proxy.start()

        # Give proxy a moment to bind
        time.sleep(0.15)

        # Create PMU
        self._pmu = PMUSimulator(
            dst_host="127.0.0.1",
            dst_port=proxy_port,
            fps=30,
            nom_freq=50.0,
            nom_voltage=120.0,
            on_frame=self._relay.emit_pmu_frame,
        )
        self._pmu.start()

        self._sim_running = True
        self._waveform.start()
        self._canvas.set_simulation_running(True)

        # Update toolbar
        self._tb_run.setEnabled(False)
        self._tb_stop.setEnabled(True)
        self._act_run.setEnabled(False)
        self._act_stop.setEnabled(True)

        self._log("[SIM] Simulation running ▶", "system")

    def _stop_simulation(self) -> None:
        if not self._sim_running:
            return

        if self._pmu:
            self._pmu.stop()
            self._pmu = None

        if self._proxy:
            self._proxy.stop()
            self._proxy = None

        self._sim_running = False
        self._waveform.stop()
        self._canvas.set_simulation_running(False)

        self._tb_run.setEnabled(True)
        self._tb_stop.setEnabled(False)
        self._act_run.setEnabled(True)
        self._act_stop.setEnabled(False)

        self._log("[SIM] Simulation stopped ■", "system")

    # ── Callbacks from background threads ─────────────────────────────────────

    def _on_pmu_frame(self, raw: bytes, frame_dict: dict) -> None:
        """Called in main thread via relay when PMU generates a frame."""
        pass   # waveform is updated from proxy_packet instead

    def _on_proxy_packet(self, record: PacketRecord) -> None:
        """Called in main thread via relay for each processed packet."""
        # Feed waveform viewer
        self._waveform.push_frame_from_record(record)

        # Build log line with color
        line_html = self._format_log_line(record)
        self._log_buffer_append(line_html)

    def _log_buffer_append(self, html: str) -> None:
        self._log_mutex.lock()
        self._log_buffer.append(html)
        self._log_mutex.unlock()

    def _flush_log(self) -> None:
        """Batch-flush log buffer to QTextEdit (runs in main thread via timer)."""
        self._log_mutex.lock()
        lines = list(self._log_buffer)
        self._log_buffer.clear()
        self._log_mutex.unlock()

        if not lines:
            return

        # Batch insert
        cursor = self._log_text.textCursor()
        from PyQt6.QtGui import QTextCursor
        cursor.movePosition(QTextCursor.MoveOperation.End)

        for html in lines:
            self._log_text.append(html)

        # Keep log bounded
        doc = self._log_text.document()
        while doc.blockCount() > self._log_max_lines:
            cursor = self._log_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            cursor.select(QTextCursor.SelectionType.BlockUnderCursor)
            cursor.removeSelectedText()
            cursor.deleteChar()  # remove the block separator

        # Scroll to bottom
        sb = self._log_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _format_log_line(self, record: PacketRecord) -> str:
        ts     = time.strftime("%H:%M:%S", time.localtime(record.timestamp))
        ms     = int((record.timestamp % 1) * 1000)
        status = record.status

        if status == "attacked":
            color = "#ef4444"
            badge = f"<span style='color:#ef4444;font-weight:700'>ATTACKED</span>"
        elif status == "dropped":
            color = "#f59e0b"
            badge = f"<span style='color:#f59e0b;font-weight:700'>DROPPED </span>"
        elif status == "invalid":
            color = "#64748b"
            badge = f"<span style='color:#64748b'>INVALID </span>"
        else:
            color = "#10b981"
            badge = f"<span style='color:#10b981'>CLEAN   </span>"

        orig = record.original or {}
        freq  = orig.get("freq", 0.0)
        ph    = orig.get("phasors", [[0, 0]])
        mag   = ph[0][0] if ph else 0.0

        line = (
            f"<span style='color:#4a5568'>[{ts}.{ms:03d}]</span> "
            f"{badge} "
            f"<span style='color:#64748b'>freq={freq:.3f}Hz</span> "
            f"<span style='color:#64748b'>Va={mag:.1f}V</span>"
        )

        if status == "attacked" and record.modified:
            mod   = record.modified
            mfreq = mod.get("freq", freq)
            mph   = mod.get("phasors", [[0, 0]])
            mmag  = mph[0][0] if mph else mag
            line += (
                f" → <span style='color:#ef4444'>freq={mfreq:.3f}Hz Va={mmag:.1f}V</span>"
                f" <span style='color:#7c3aed;font-size:10px'>[{record.attack_type}]</span>"
            )

        return line

    def _log(self, text: str, style: str = "info") -> None:
        """Add a plain text message to the log."""
        colors = {
            "system": "#a78bfa",
            "info":   "#64748b",
            "error":  "#ef4444",
            "warn":   "#f59e0b",
        }
        color = colors.get(style, "#64748b")
        self._log_buffer_append(f"<span style='color:{color}'>{text}</span>")

    def _clear_log(self) -> None:
        self._log_text.clear()
        self._log_mutex.lock()
        self._log_buffer.clear()
        self._log_mutex.unlock()

    # ── Panel signal handlers ─────────────────────────────────────────────────

    def _on_node_selected(self, node) -> None:
        if node:
            self._props_panel.show_node(node)

    def _on_link_selected(self, link) -> None:
        if link:
            self._props_panel.show_link(link)

    def _on_node_config_changed(self, node: BaseNode) -> None:
        self._props_panel.show_node(node)

    def _on_config_applied(self, node: BaseNode, cfg: dict) -> None:
        self._log(f"[CFG] {node.label} configured: {cfg['ip']}:{cfg['port']} {cfg['proto']}", "system")

    def _on_simulation_error(self, msg: str) -> None:
        QMessageBox.critical(self, "Simulation Error", msg)

    # ── Palette double-click (add node) ───────────────────────────────────────

    def _on_palette_double_click(self, item) -> None:
        node_type = item.data(Qt.ItemDataRole.UserRole)
        self._canvas.add_node(node_type)

    # ── Attack selection ──────────────────────────────────────────────────────

    def _select_attack(self, attack_type: AttackType) -> None:
        """Select attack from menu — switch attack panel tab."""
        from PyQt6.QtWidgets import QTabWidget
        # Find right panel tabs
        right = self._h_splitter.widget(2)
        tabs  = right.findChild(QTabWidget)
        if tabs:
            tabs.setCurrentIndex(1)   # Attack tab
        self._attack_panel.sync_from_engine()

    # ── File operations ───────────────────────────────────────────────────────

    def _new_topology(self) -> None:
        if self._sim_running:
            QMessageBox.warning(self, "Warning", "Stop simulation before clearing topology.")
            return
        reply = QMessageBox.question(self, "New Topology",
            "Clear the canvas and start a new topology?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self._canvas.clear_canvas()

    def _save_topology(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Topology", "topology.json",
            "JSON files (*.json);;All files (*)"
        )
        if path:
            data = self._canvas.save_topology()
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            self._log(f"[FILE] Topology saved to {path}", "system")

    def _open_topology(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Topology", "",
            "JSON files (*.json);;All files (*)"
        )
        if path:
            try:
                with open(path) as f:
                    data = json.load(f)
                self._canvas.load_topology(data)
                self._log(f"[FILE] Topology loaded from {path}", "system")
            except Exception as exc:
                QMessageBox.critical(self, "Load Error", f"Failed to load topology:\n{exc}")

    def _confirm_clear(self) -> None:
        reply = QMessageBox.question(
            self, "Clear Canvas", "Remove all nodes and links?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._canvas.clear_canvas()

    # ── About ─────────────────────────────────────────────────────────────────

    def _show_about(self) -> None:
        QMessageBox.about(self, "About GridSec Sim",
            "<h3>GridSec Sim v1.0</h3>"
            "<p>Smart Grid Cybersecurity Simulation Tool</p>"
            "<p>IEEE C37.118 Man-in-the-Middle Attack Simulator</p>"
            "<br>"
            "<p><b>Protocols:</b> IEEE C37.118-2011, DNP3, Modbus TCP, IEC 60870-5-104</p>"
            "<p><b>Attacks:</b> Noise, Ramp, Pulse, Override, Replay, Delay, Drop, Scale</p>"
            "<br>"
            "<p style='color: #94a3b8; font-size: 11px;'>"
            "For educational and authorized research purposes only.<br>"
            "Unauthorized use against real infrastructure is illegal.</p>"
        )

    # ── Stylesheet ────────────────────────────────────────────────────────────

    def _apply_stylesheet(self) -> None:
        """Load and apply the QSS stylesheet."""
        # Find styles.qss relative to this file
        base   = Path(__file__).parent
        qss_path = base / "styles.qss"
        if qss_path.exists():
            with open(qss_path, "r") as f:
                self.setStyleSheet(f.read())
        else:
            logger.warning(f"styles.qss not found at {qss_path}")

    # ── Window close ─────────────────────────────────────────────────────────

    def closeEvent(self, event) -> None:
        if self._sim_running:
            self._stop_simulation()
        event.accept()
