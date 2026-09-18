"""
gui/main_window.py
==================
GridSec Sim — Main Application Window.

Layout (Cisco Packet Tracer style):
  ┌──────────────────────────────────────────────────────────────┐
  │  Menu Bar + Toolbar                                          │
  ├──────────────┬─────────────────────────────┬────────────────┤
  │  Node Palette│                             │  Properties    │
  │  (4 levels)  │   Topology Canvas           │  Panel         │
  │  + Protocol  │   (QGraphicsView)           │  + Attack      │
  │  selector    │   with level lanes          │  Panel         │
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
import ipaddress
from html import escape
from pathlib import Path
from typing import Optional, List

from PyQt6.QtCore import (
    Qt, QTimer, pyqtSignal, QObject, QThread, QMutex, QSaveFile, QIODevice, QSignalBlocker
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
    QTabWidget, QScrollBar, QSizePolicy, QMenu, QScrollArea,
    QDialog, QFormLayout, QLineEdit, QSpinBox,
    QTreeWidget, QTreeWidgetItem,
)

from core.attack_engine import AttackEngine, AttackType
from core.pdc_proxy import PDCProxy, PacketRecord
from core.pmu_simulator import PMUSimulator
from core.traffic_filter import TrafficFilter
from core.goose_simulator import GOOSESimulator
from core.dnp3_simulator import DNP3Simulator
from core.modbus_simulator import ModbusSimulator
from core.integration_manager import IntegrationManager
from protocols.c37118 import C37118Codec

from gui.attack_panel import AttackPanel
from gui.canvas import TopologyCanvas
from gui.integration_panel import IntegrationPanel
from gui.node_types import (
    NodeType, NODE_DISPLAY_NAMES, NODE_ICON_TEXT, NODE_COLORS,
    NODE_LEVEL, LEVEL_LABELS,
    BaseNode, PMUNode, PDCNode, ThreatAgentNode,
    CTVTNode, BreakerNode, ProtectionIEDNode, BCUNode,
    SwitchNode, StationHMINode, EngineeringWSNode,
    GatewayRTUNode, StatePDCNode, VirtualNode,
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
    attack_state_changed = pyqtSignal()

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
# Node palette — hierarchical level groups
# ─────────────────────────────────────────────────────────────────────────────

PALETTE_LEVELS = [
    ("L0 — Process", [
        (NodeType.CT_VT,    "CT/VT Sensor",        "Current/Voltage transformer sensor"),
        (NodeType.BREAKER,  "Circuit Breaker",      "Binary open/closed switching device"),
    ]),
    ("L1 — Bay", [
        (NodeType.PMU,            "PMU",              "Phasor Measurement Unit"),
        (NodeType.PROTECTION_IED, "Protection IED",   "GOOSE-speaking protection relay"),
        (NodeType.BCU,            "Bay Control Unit",  "Bay-level switching control"),
    ]),
    ("L2 — Station", [
        (NodeType.PDC,            "Local PDC",          "Data Concentrator / openPDC"),
        (NodeType.SWITCH,         "Station Switch",     "Network switch"),
        (NodeType.STATION_HMI,    "Station HMI",        "HMI / SCADA Server"),
        (NodeType.ENGINEERING_WS, "Eng. Workstation",    "⚠ High-risk asset"),
        (NodeType.GATEWAY_RTU,    "Gateway / RTU",       "DNP3/IEC104 uplink to state"),
    ]),
    ("L3 — State", [
        (NodeType.STATE_PDC,  "State PDC",  "Regional PDC — aggregates from local PDCs"),
    ]),
]

PALETTE_UTILITY = [
    (NodeType.THREAT_AGENT, "Threat Agent",  "Man-in-the-Middle attacker"),
    (NodeType.VIRTUAL,      "Virtual Node",  "Generic virtual device"),
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

        self._pmu:    Optional[PMUSimulator]   = None
        self._proxy:  Optional[PDCProxy]        = None
        self._goose:  Optional[GOOSESimulator]  = None
        self._dnp3:   Optional[DNP3Simulator]   = None
        self._modbus: Optional[ModbusSimulator] = None
        self._sim_running = False
        self._selected_link = None
        self._run_started_at = 0.0

        # Integration manager (Wireshark/pcap, Syslog/CEF, REST API)
        self._integration = IntegrationManager()
        self._integration.set_attack_hooks(self._api_enable_attack, self._api_disable_attack)

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
        self._h_splitter.setSizes([220, 1000, 300])

        main_layout.addWidget(self._h_splitter)

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(200)
        panel.setMaximumWidth(260)
        panel.setStyleSheet("background: #252535; border-right: 1px solid #2d2d44;")

        layout = QVBoxLayout(panel)
        layout.setContentsMargins(8, 10, 8, 8)
        layout.setSpacing(6)

        # Title
        title = QLabel("Node Palette")
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

        # ── Vertical splitter: tree widget | protocol section ────────────────
        left_splitter = QSplitter(Qt.Orientation.Vertical)
        left_splitter.setHandleWidth(6)
        left_splitter.setStyleSheet("""
            QSplitter::handle {
                background: #3d3d5c;
                border-radius: 2px;
                margin: 2px 30px;
                min-height: 4px;
            }
            QSplitter::handle:hover {
                background: #7c3aed;
            }
        """)

        # ── Top: Hierarchical palette tree ───────────────────────────────────
        self._palette_tree = QTreeWidget()
        self._palette_tree.setHeaderHidden(True)
        self._palette_tree.setDragEnabled(True)
        self._palette_tree.setDragDropMode(QTreeWidget.DragDropMode.DragOnly)
        self._palette_tree.setRootIsDecorated(True)
        self._palette_tree.setAnimated(True)
        self._palette_tree.setIndentation(16)
        self._palette_tree.setStyleSheet("""
            QTreeWidget {
                border: none;
                background: transparent;
                outline: 0;
            }
            QTreeWidget::item {
                padding: 4px 4px;
                border-radius: 4px;
                margin: 1px 0;
            }
            QTreeWidget::item:hover {
                background: #2d2d44;
            }
            QTreeWidget::item:selected {
                background: #3d3d5c;
            }
            QTreeWidget::branch {
                background: transparent;
            }
            QTreeWidget::branch:has-children:!has-siblings:closed,
            QTreeWidget::branch:closed:has-children:has-siblings {
                image: none;
                border-image: none;
            }
            QTreeWidget::branch:open:has-children:!has-siblings,
            QTreeWidget::branch:open:has-children:has-siblings {
                image: none;
                border-image: none;
            }
        """)

        # Build level groups
        for level_label, nodes in PALETTE_LEVELS:
            level_item = QTreeWidgetItem(self._palette_tree, [level_label])
            level_item.setFlags(level_item.flags() & ~Qt.ItemFlag.ItemIsDragEnabled)
            level_item.setExpanded(True)
            font = level_item.font(0)
            font.setBold(True)
            font.setPointSize(10)
            level_item.setFont(0, font)
            level_item.setForeground(0, QColor("#a78bfa"))

            for node_type, display_name, tooltip in nodes:
                icon_text = NODE_ICON_TEXT.get(node_type, "?")
                color = NODE_COLORS.get(node_type, "#8b5cf6")
                child = QTreeWidgetItem(level_item, [f"{icon_text}  {display_name}"])
                child.setData(0, Qt.ItemDataRole.UserRole, node_type)
                child.setToolTip(0, tooltip)
                child.setForeground(0, QColor(color))

        # Utility separator
        sep_item = QTreeWidgetItem(self._palette_tree, ["── Utility ──"])
        sep_item.setFlags(sep_item.flags() & ~Qt.ItemFlag.ItemIsDragEnabled)
        sep_item.setForeground(0, QColor("#3d3d5c"))
        font = sep_item.font(0)
        font.setPointSize(9)
        sep_item.setFont(0, font)

        for node_type, display_name, tooltip in PALETTE_UTILITY:
            icon_text = NODE_ICON_TEXT.get(node_type, "?")
            color = NODE_COLORS.get(node_type, "#8b5cf6")
            child = QTreeWidgetItem(self._palette_tree, [f"{icon_text}  {display_name}"])
            child.setData(0, Qt.ItemDataRole.UserRole, node_type)
            child.setToolTip(0, tooltip)
            child.setForeground(0, QColor(color))

        self._palette_tree.itemDoubleClicked.connect(self._on_palette_double_click)

        # ── Drag support for tree items ──────────────────────────────────────
        self._palette_tree.startDrag = self._palette_tree_start_drag

        left_splitter.addWidget(self._palette_tree)

        # ── Bottom: Protocol selector section ────────────────────────────────
        proto_section = QWidget()
        proto_layout = QVBoxLayout(proto_section)
        proto_layout.setContentsMargins(0, 6, 0, 4)
        proto_layout.setSpacing(6)

        proto_title = QLabel("Link Protocol")
        proto_title.setStyleSheet("color: #a78bfa; font-weight: 700; font-size: 11px; padding: 4px 0;")
        proto_layout.addWidget(proto_title)

        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["C37.118", "DNP3", "Modbus", "IEC104", "GOOSE"])
        self._proto_combo.currentTextChanged.connect(
            lambda p: self._canvas.set_protocol(p)
        )
        proto_layout.addWidget(self._proto_combo)

        # Protocol info label
        proto_info = QLabel(
            "<small style='color:#4a5568'>"
            "Auto-selected by node types.<br>"
            "Override here if needed.</small>"
        )
        proto_info.setTextFormat(Qt.TextFormat.RichText)
        proto_info.setWordWrap(True)
        proto_layout.addWidget(proto_info)

        proto_layout.addStretch()

        left_splitter.addWidget(proto_section)

        # Default split: tree gets most space, protocol section gets ~100px
        left_splitter.setSizes([500, 120])
        left_splitter.setCollapsible(0, False)  # tree can't be collapsed
        left_splitter.setCollapsible(1, False)  # protocol section can't be collapsed

        layout.addWidget(left_splitter)

        return panel


    def _palette_tree_start_drag(self, supported_actions):
        """Custom drag handler for the palette tree widget."""
        item = self._palette_tree.currentItem()
        if item and item.data(0, Qt.ItemDataRole.UserRole):
            from PyQt6.QtGui import QDrag
            from PyQt6.QtCore import QMimeData
            mime = QMimeData()
            mime.setText(item.data(0, Qt.ItemDataRole.UserRole))
            drag = QDrag(self._palette_tree)
            drag.setMimeData(mime)
            drag.exec(Qt.DropAction.CopyAction)

    def _build_right_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(360)
        panel.setMaximumWidth(520)
        panel.setStyleSheet("background: #252535; border-left: 1px solid #2d2d44;")

        tabs = QTabWidget()
        tabs.setDocumentMode(True)

        self._props_panel = PropertiesPanel()
        tabs.addTab(self._props_panel, "Properties")

        self._attack_panel = AttackPanel(self._engine)
        attack_scroll = QScrollArea()
        attack_scroll.setWidgetResizable(True)
        attack_scroll.setFrameShape(QFrame.Shape.NoFrame)
        attack_scroll.setWidget(self._attack_panel)
        tabs.addTab(attack_scroll, "Attacks")

        self._integration_panel = IntegrationPanel(self._integration)
        tabs.addTab(self._integration_panel, "Integrations")

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
        lbl = QLabel("Packet Log")
        lbl.setStyleSheet("color: #a78bfa; font-weight: 600; font-size: 12px;")
        hdr_layout.addWidget(lbl)
        self._dash_label = QLabel("● Ready  |  0 packets")
        self._dash_label.setWordWrap(True)
        self._dash_label.setMinimumWidth(0)
        self._dash_label.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self._dash_label.setStyleSheet("color: #64748b; font-size: 11px;")
        hdr_layout.addWidget(self._dash_label)
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
        act_demo   = QAction("Load MitM Demo", self)
        act_validate = QAction("Validate Topology", self, shortcut="Ctrl+Shift+V")
        act_exit   = QAction("Exit", self, shortcut="Ctrl+Q")
        act_new.triggered.connect(self._new_topology)
        act_open.triggered.connect(self._open_topology)
        act_save.triggered.connect(self._save_topology)
        act_demo.triggered.connect(self._load_mitm_demo)
        act_validate.triggered.connect(self._show_topology_validation)
        act_exit.triggered.connect(self.close)
        file_menu.addActions([act_new, act_open, act_save, act_demo, act_validate])
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
        sim_menu.addSeparator()
        self._adapter_actions = {}
        for name in ("GOOSE", "DNP3", "Modbus"):
            action = QAction(f"Enable {name} adapter on next Run", self, checkable=True)
            action.setToolTip("Optional protocol traffic. GOOSE publishes on the local network interface and needs raw-socket permission.")
            sim_menu.addAction(action)
            self._adapter_actions[name] = action

        scenario_menu = mb.addMenu("&Scenarios")
        for name, attack_type, params in [
            ("Clean Baseline", AttackType.NONE, {}),
            ("Noisy Sensor", AttackType.NOISE, {"noise_std": 5.0}),
            ("GPS Frequency Spoofing", AttackType.FREQUENCY_OVERRIDE, {"target_freq": 60.0}),
            ("Voltage False Data", AttackType.MAGNITUDE_OVERRIDE, {"phasor_idx": 0, "value": 0.0}),
            ("Packet Loss Drill", AttackType.DROP, {"drop_percent": 50.0}),
            ("Replay Drill", AttackType.REPLAY, {"buffer_size": 90}),
        ]:
            action = QAction(name, self)
            action.triggered.connect(
                lambda checked=False, at=attack_type, p=params, n=name: self._load_quick_scenario(n, at, p)
            )
            scenario_menu.addAction(action)

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
        self._tb_run  = tb.addAction("Run")
        self._tb_stop = tb.addAction("Stop")
        self._tb_run.triggered.connect(self._start_simulation)
        self._tb_stop.triggered.connect(self._stop_simulation)
        self._tb_stop.setEnabled(False)

        # Keep the three most frequent file actions in immediate reach.
        tb.addSeparator()
        tb.addAction("Save", self._save_topology)
        tb.addAction("Load Demo", self._load_mitm_demo)
        tb.addAction("Validate", self._show_topology_validation)

        tb.addSeparator()

        # Canvas modes
        self._tb_select  = tb.addAction("Select")
        self._tb_connect = tb.addAction("Connect")
        self._tb_delete  = tb.addAction("Delete")
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

        # Quick node buttons — key types from each level
        quick_nodes = [
            (NodeType.PMU,       "PMU"),
            (NodeType.PDC,       "PDC"),
            (NodeType.SWITCH,    "SW"),
            (NodeType.STATE_PDC, "SPDC"),
            (NodeType.THREAT_AGENT, "Threat"),
        ]
        for node_type, short in quick_nodes:
            icon = NODE_ICON_TEXT.get(node_type, "?")
            act  = tb.addAction(f"{icon} +{short}")
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
        self._sb_extra = _lbl("GOOSE:--  DNP3:--  Modbus:--")

        for w in [self._sb_pmu, _sep(), self._sb_proxy, _sep(),
                  self._sb_sent, _sep(), self._sb_atk, _sep(),
                  self._sb_drop, _sep(), self._sb_extra]:
            sb.addPermanentWidget(w)

        # Update timer
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self._update_status_bar)
        self._status_timer.start()

    def _update_status_bar(self) -> None:
        self._integration.sim_running = self._sim_running
        self._integration.attack_data = self._engine.snapshot()
        if self._sim_running and ((self._pmu and not self._pmu.is_running) or
                                  (self._proxy and not self._proxy.is_running)):
            reason = ((self._pmu.last_error if self._pmu else "") or
                      (self._proxy.last_error if self._proxy else "") or "Worker stopped unexpectedly")
            self._stop_simulation()
            self._log(f"[ERROR] {reason}", "warn")
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
        if hasattr(self, "_dash_label"):
            state = "Running" if self._sim_running else "Ready"
            attack = self._engine.active_type.value if self._engine.is_enabled else "None"
            color = "#10b981" if self._sim_running else "#64748b"
            self._dash_label.setText(
                f"● {state} | {stats['total_packets']:,} packets | "
                f"{stats['modified_packets']:,} modified | {stats['dropped_packets']:,} dropped | Attack: {attack}"
            )
            self._dash_label.setStyleSheet(f"color: {color}; font-size: 11px;")

        # GOOSE / DNP3 / Modbus status dots
        goose_state = "ON" if (self._goose and self._goose.is_active) else "--"
        dnp3_state  = f"{self._dnp3.frames_sent}" if self._dnp3 else "--"
        modbus_port = self._modbus.active_port if self._modbus else "--"
        self._sb_extra.setText(
            f"GOOSE:{goose_state}  DNP3:{dnp3_state}  Modbus:{modbus_port}"
        )

    # ── Signal connections ────────────────────────────────────────────────────

    def _connect_signals(self):
        # Canvas → properties panel
        self._canvas.signals.node_selected.connect(self._on_node_selected)
        self._canvas.signals.link_selected.connect(self._on_link_selected)
        self._canvas.signals.node_config_changed.connect(self._on_node_config_changed)

        # Properties panel → canvas
        self._props_panel.config_applied.connect(self._on_config_applied)
        self._props_panel.regional_uplink_toggled.connect(self._on_regional_uplink_toggled)
        self._attack_panel.attack_changed.connect(self._on_attack_configured)

        # Relay (background threads → main thread)
        self._relay.pmu_frame_received.connect(self._on_pmu_frame)
        self._relay.proxy_packet.connect(self._on_proxy_packet)
        self._relay.simulation_error.connect(self._on_simulation_error)
        self._relay.attack_state_changed.connect(self._sync_attack_ui)
        self._canvas.signals.topology_changed.connect(self._topology_changed)

    # ── Simulation control ────────────────────────────────────────────────────

    def _start_simulation(self) -> None:
        if self._sim_running:
            return

        errors, warnings = self._topology_validation_messages()
        if errors:
            QMessageBox.warning(self, "Topology Needs Attention", "\n".join(f"• {item}" for item in errors))
            return
        if warnings:
            reply = QMessageBox.question(
                self, "Topology Warnings",
                "The simulation can still run, but review these warnings:\n\n" +
                "\n".join(f"• {item}" for item in warnings) + "\n\nContinue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        # Determine PMU and PDC settings from canvas
        pmu_nodes = self._canvas.get_pmu_nodes()
        pdc_nodes = self._canvas.get_pdc_nodes()

        pmu_ip   = pmu_nodes[0].ip   if pmu_nodes else "127.0.0.1"
        pmu_port = pmu_nodes[0].port if pmu_nodes else 4712
        pdc_ip   = pdc_nodes[0].ip   if pdc_nodes else "127.0.0.1"
        pdc_port = pdc_nodes[0].port if pdc_nodes else 4713
        config = pmu_nodes[0].get_config()
        transport = pmu_nodes[0].proto.upper()
        self._codec = C37118Codec(idcode=int(config.get("idcode", 1)), num_digital=1)
        self._engine.reset_stats()
        self._engine.reset_attack_state()
        self._run_started_at = time.time()

        # Proxy listens on PMU's port; PMU sends to proxy
        proxy_port = pmu_port
        pmu_target = proxy_port

        self._log(f"[SIM] Starting simulation: PMU→{pmu_ip}:{pmu_target}  Proxy→{pdc_ip}:{pdc_port}", "system")

        # Create proxy
        self._proxy = PDCProxy(
            listen_host=pmu_ip,
            listen_port=proxy_port,
            target_host=pdc_ip,
            target_port=pdc_port,
            proto=transport,
            codec=self._codec,
            attack_engine=self._engine,
            traffic_filter=self._filter,
            on_packet=self._relay.emit_proxy_packet,
        )
        self._update_attack_scope()
        self._proxy.start()

        # Give proxy a moment to bind
        if not self._proxy.ready.wait(2) or self._proxy.last_error or not self._proxy.is_running:
            reason = self._proxy.last_error or "Proxy did not become ready"
            self._stop_simulation()
            QMessageBox.critical(self, "Startup Error", reason)
            return

        # Create PMU
        self._pmu = PMUSimulator(
            dst_host="127.0.0.1" if pmu_ip == "0.0.0.0" else pmu_ip,
            dst_port=proxy_port,
            idcode=int(config.get("idcode", 1)),
            fps=int(config.get("reporting_rate", 30)),
            nom_freq=float(config.get("nom_freq", 50.0)),
            nom_voltage=float(config.get("nom_voltage", 120.0)),
            proto=transport,
            on_frame=self._relay.emit_pmu_frame,
        )
        self._pmu.start()
        if not self._pmu.ready.wait(2) or self._pmu.last_error or not self._pmu.is_running:
            reason = self._pmu.last_error or "PMU did not become ready"
            self._stop_simulation()
            QMessageBox.critical(self, "Startup Error", reason)
            return

        self._sim_running = True
        self._integration.sim_running = True
        self._integration.topology_data = self._serialize_topology()
        self._props_panel.setEnabled(False)
        self._waveform.clear()
        self._waveform.start()
        self._canvas.set_simulation_running(True)

        # ── Start GOOSE simulator ───────────────────────────────────────────
        if self._adapter_actions["GOOSE"].isChecked():
            try:
                self._goose = GOOSESimulator(
                    interface  = "",   # auto-detect (eth0 or similar)
                    appid      = 0x0001,
                    ied_name   = "GridSecSim",
                    fps        = 1.0,
                    callback   = None,
                )
                self._goose.start()
                if self._goose.is_active:
                    self._log("[GOOSE] Publisher started on raw Ethernet ✔", "system")
                elif self._goose.error:
                    self._log(f"[GOOSE] {self._goose.error}", "warn")
                    self._log("[GOOSE] Run with: sudo python main.py", "warn")
            except Exception as e:
                self._log(f"[GOOSE] Failed to start: {e}", "warn")
                self._goose = None

        # ── Start DNP3 simulator ────────────────────────────────────────────
        if self._adapter_actions["DNP3"].isChecked():
            try:
                self._dnp3 = DNP3Simulator(
                    target_ip   = "127.0.0.1",
                    target_port = 20000,
                    bind_port   = 20000,
                    fps         = 1.0,
                )
                self._dnp3.start()
                self._log("[DNP3] Outstation started on UDP port 20000 ✔", "system")
            except Exception as e:
                self._log(f"[DNP3] Failed to start: {e}", "warn")
                self._dnp3 = None

        # ── Start Modbus simulator ──────────────────────────────────────────
        if self._adapter_actions["Modbus"].isChecked():
            try:
                self._modbus = ModbusSimulator(
                    host         = "127.0.0.1",
                    port         = 502,
                    poll_rate_hz = 1.0,
                )
                self._modbus.start()
                self._log(f"[Modbus] Server started on TCP port {self._modbus.active_port} ✔", "system")
            except Exception as e:
                self._log(f"[Modbus] Failed to start: {e}", "warn")
                self._modbus = None

        # Update toolbar
        self._tb_run.setEnabled(False)
        for action in self._adapter_actions.values():
            action.setEnabled(False)
        self._tb_stop.setEnabled(True)
        self._act_run.setEnabled(False)
        self._act_stop.setEnabled(True)

        self._log("[SIM] Simulation running ▶", "system")

    def _stop_simulation(self) -> None:
        self._sim_running = False
        self._integration.sim_running = False
        self._engine.cancel_event.set()

        if self._pmu:
            self._pmu.stop()
            self._pmu.join(timeout=2)
            self._pmu = None

        if self._proxy:
            self._proxy.stop()
            self._proxy.join(timeout=2)
            self._proxy = None

        if self._goose:
            self._goose.stop()
            self._goose = None

        if self._dnp3:
            self._dnp3.stop()
            self._dnp3 = None

        if self._modbus:
            self._modbus.stop()
            self._modbus = None

        self._sim_running = False
        self._waveform.stop()
        self._canvas.set_simulation_running(False)
        self._props_panel.setEnabled(True)

        self._tb_run.setEnabled(True)
        for action in self._adapter_actions.values():
            action.setEnabled(True)
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
        if not self._sim_running or record.timestamp < self._run_started_at:
            return
        # Feed waveform viewer
        self._waveform.push_frame_from_record(record)

        # Forward values to GOOSE / DNP3 / Modbus simulators
        orig = record.modified if record.forwarded else {}
        ph   = orig.get("phasors", [[120.0, 0.0], [119.5, 0.0], [120.5, 0.0]])
        va   = ph[0][0] if len(ph) > 0 else 120.0
        vb   = ph[1][0] if len(ph) > 1 else 119.5
        vc   = ph[2][0] if len(ph) > 2 else 120.5
        freq = orig.get("freq", 50.0)

        if self._goose and orig.get("frame_type") == "data":
            self._goose.update_values(va=va, vb=vb, vc=vc, freq=freq)
        if self._dnp3 and orig.get("frame_type") == "data":
            self._dnp3.update_values(va=va, vb=vb, vc=vc, freq=freq)
        if self._modbus and orig.get("frame_type") == "data":
            self._modbus.update_values(va=va, vb=vb, vc=vc, freq=freq)

        # Record to integration manager (pcap, syslog, REST API)
        try:
            raw_bytes = getattr(record, 'raw_bytes', b'') or b''
            self._integration.record_packet(
                record,
                raw_bytes  = raw_bytes,
                protocol   = "C37.118",
                src_ip     = record.src_addr[0],
                dst_ip     = record.dst_addr[0],
                src_port   = record.src_addr[1],
                dst_port   = record.dst_addr[1],
                transport  = record.transport,
            )
            # Keep integration manager in sync with sim state
            self._integration.attack_data = self._engine.snapshot()
        except Exception:
            logger.exception("Integration update failed")

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
        elif status == "forward_error":
            color = "#ef4444"
            badge = "<span style='color:#ef4444'>SEND ERROR</span>"
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

        if record.description and record.status != "clean":
            line += f" <span style='color:#94a3b8'>{escape(record.description)}</span>"
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
        self._log_buffer_append(f"<span style='color:{color}'>{escape(text)}</span>")

    def _clear_log(self) -> None:
        self._log_text.clear()
        self._log_mutex.lock()
        self._log_buffer.clear()
        self._log_mutex.unlock()

    # ── Panel signal handlers ─────────────────────────────────────────────────

    def _on_node_selected(self, node) -> None:
        if node:
            self._props_panel.show_node(node)
        else:
            self._props_panel.clear()

    def _on_link_selected(self, link) -> None:
        self._selected_link = link
        self._update_attack_scope()
        if link:
            self._props_panel.show_link(link)

    def _on_node_config_changed(self, node: BaseNode) -> None:
        self._props_panel.show_node(node)

    def _on_config_applied(self, node: BaseNode, cfg: dict) -> None:
        self._log(f"[CFG] {node.label} configured: {cfg}", "system")

    def _on_attack_configured(self, attack_type: str, params: dict) -> None:
        """Store the selected setup on active attackers for topology review/export.

        The current runtime has one PMU/proxy stream, so these assignments are
        recorded per attacker now and become executable per-link policies when
        the multi-stream proxy is introduced.
        """
        active_agents = [agent for agent in self._canvas.get_threat_agents()
                         if agent._config.get("active")]
        for agent in active_agents:
            agent._config["attack_type"] = attack_type
            agent._config["attack_params"] = dict(params)
            agent._config["attack_schedule"] = self._engine.schedule
            agent._config["attack_enabled"] = self._engine.is_enabled
        self._update_attack_scope()
        self._integration.attack_data = self._engine.snapshot()
        if active_agents:
            self._log(f"[ATTACK] {attack_type} configured for " +
                      ", ".join(agent.label for agent in active_agents), "system")

    def _on_regional_uplink_toggled(self, node: BaseNode, connected: bool) -> None:
        """Handle regional uplink toggle from Properties panel."""
        ts = time.strftime("%H:%M:%S")
        status = "link up" if connected else "link down"
        self._log(
            f"[{ts}] State PDC → Regional: {status} (C37.118, hardcoded)",
            "system"
        )

    def _on_simulation_error(self, msg: str) -> None:
        QMessageBox.critical(self, "Simulation Error", msg)

    # ── Palette double-click (add node) ───────────────────────────────────────

    def _on_palette_double_click(self, item, column) -> None:
        node_type = item.data(0, Qt.ItemDataRole.UserRole)
        if node_type:
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
        self._attack_panel.select_attack(attack_type)

    # ── File operations ───────────────────────────────────────────────────────

    def _api_enable_attack(self, attack_type, params):
        # HTTP workers only touch the locked engine; all widgets stay on Qt's thread.
        self._engine.set_attack(AttackType(attack_type), params)
        self._integration.attack_data = self._engine.snapshot()
        self._relay.attack_state_changed.emit()
        return True

    def _api_disable_attack(self):
        self._engine.disable()
        self._integration.attack_data = self._engine.snapshot()
        self._relay.attack_state_changed.emit()
        return True

    def _sync_attack_ui(self):
        self._attack_panel.sync_from_engine()
        self._on_attack_configured(self._engine.active_type.value, self._engine.get_params())

    def _update_attack_scope(self):
        if not self._proxy:
            return
        if self._attack_panel.get_scope() == "all":
            self._proxy.attack_enabled = True
            return
        pmus, pdcs = self._canvas.get_pmu_nodes(), self._canvas.get_pdc_nodes()
        link = self._selected_link
        self._proxy.attack_enabled = bool(
            pmus and pdcs and link in self._canvas.get_all_links() and
            link.protocol == "C37.118" and
            {link.src_node, link.dst_node} == {pmus[0], pdcs[0]})

    def _topology_changed(self):
        if self._selected_link not in self._canvas.get_all_links():
            self._selected_link = None
        self._props_panel.clear()
        self._integration.topology_data = self._serialize_topology()

    def _serialize_topology(self):
        data = self._canvas.save_topology()
        state = self._engine.snapshot()
        state.pop("stats", None)
        state["scope"] = self._attack_panel.get_scope()
        link = self._selected_link
        state["selected_link"] = ([link.src_node._topology_id, link.dst_node._topology_id]
                                  if link in self._canvas.get_all_links() else None)
        data["simulation"] = state
        return data

    def save_topology_to(self, path):
        """Atomic save: an interrupted or failed write leaves the old file intact."""
        payload = json.dumps(self._serialize_topology(), indent=2, allow_nan=False).encode("utf-8")
        target = QSaveFile(str(path))
        if not target.open(QIODevice.OpenModeFlag.WriteOnly):
            raise OSError(target.errorString())
        if target.write(payload) != len(payload) or not target.commit():
            target.cancelWriting()
            raise OSError(target.errorString())

    def _load_topology_data(self, data):
        if self._sim_running:
            raise ValueError("Stop before loading a topology")
        self._canvas.validate_topology(data)
        state = data.get("simulation")
        if state is None:
            agent = next((n for n in data["nodes"]
                          if n["node_type"] == NodeType.THREAT_AGENT and n.get("active")
                          and n.get("attack_type")), {})
            state = {"type": agent.get("attack_type", "NONE"),
                     "params": agent.get("attack_params", {}),
                     "enabled": agent.get("attack_enabled", bool(agent)),
                     "schedule": agent.get("attack_schedule", {})}
        if not isinstance(state, dict) or state.get("scope", "all") not in ("all", "selected"):
            raise ValueError("Invalid simulation settings")
        candidate = AttackEngine()
        candidate.set_attack(AttackType(state.get("type", "NONE")), state.get("params", {}))
        schedule = state.get("schedule", {})
        if not isinstance(schedule, dict):
            raise ValueError("Invalid schedule")
        start, duration = schedule.get("start_frame", 0), schedule.get("duration_frames", 0)
        if any(not isinstance(v, int) or isinstance(v, bool) or not 0 <= v <= 1000000
               for v in (start, duration)):
            raise ValueError("Schedule values must be integers from 0 to 1000000")
        if not isinstance(state.get("enabled", False), bool):
            raise ValueError("Attack enabled must be boolean")
        selected = state.get("selected_link")
        if selected is not None and (not isinstance(selected, list) or len(selected) != 2):
            raise ValueError("Invalid selected link")
        self._canvas.load_topology(data)
        self._engine.set_attack(candidate.active_type, candidate.get_params())
        self._engine.set_schedule(start, duration)
        self._engine.reset_stats()
        self._engine.reset_attack_state()
        if not state.get("enabled", False):
            self._engine.disable()
        self._selected_link = next((link for link in self._canvas.get_all_links()
                                   if [link.src_node._topology_id, link.dst_node._topology_id] == selected), None)
        self._attack_panel._scope_all.setChecked(state.get("scope", "all") == "all")
        self._attack_panel._scope_sel.setChecked(state.get("scope", "all") == "selected")
        self._attack_panel.sync_from_engine()
        self._integration.topology_data = self._serialize_topology()

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
            try:
                self.save_topology_to(path)
                self._log(f"[FILE] Topology saved to {path}", "system")
            except Exception as exc:
                QMessageBox.critical(self, "Save Error", f"Could not save topology:\n{exc}")

    def _open_topology(self) -> None:
        if self._sim_running:
            QMessageBox.warning(self, "Simulation Running", "Stop before opening a topology.")
            return
        path, _ = QFileDialog.getOpenFileName(
            self, "Open Topology", "",
            "JSON files (*.json);;All files (*)"
        )
        if path:
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                self._load_topology_data(data)
                self._log(f"[FILE] Topology loaded from {path}", "system")
            except Exception as exc:
                QMessageBox.critical(self, "Load Error", f"Failed to load topology:\n{exc}")

    def _load_mitm_demo(self) -> None:
        """Load the bundled PMU → MitM → PDC example topology."""
        if self._sim_running:
            QMessageBox.warning(self, "Simulation Running", "Stop the simulation before loading a topology.")
            return False
        path = Path(__file__).resolve().parent.parent / "mitm-demo-topology.json"
        try:
            with open(path, encoding="utf-8") as f:
                self._load_topology_data(json.load(f))
            self._canvas.zoom_fit()
            self._log("[FILE] MitM demo topology loaded", "system")
            return True
        except Exception as exc:
            QMessageBox.critical(self, "Demo Load Error", f"Could not load the bundled demo:\n{exc}")
            return False

    def _load_quick_scenario(self, name: str, attack_type: AttackType, params: dict) -> None:
        """Load the local demo and configure one guided training scenario."""
        if not self._load_mitm_demo():
            return
        self._engine.set_schedule()
        self._engine.reset_stats()
        self._engine.reset_attack_state()
        self._engine.set_attack(attack_type, params)
        if attack_type == AttackType.NONE:
            self._engine.disable()
        else:
            self._engine.set_attack(attack_type, params)
            self._engine.enable()
        self._attack_panel.sync_from_engine()
        self._on_attack_configured(attack_type.value, self._engine.get_params())
        self._log(f"[SCENARIO] Loaded: {name}", "system")

    def _topology_validation_messages(self) -> tuple[list[str], list[str]]:
        """Return blocking errors and non-blocking warnings for the canvas."""
        errors: list[str] = []
        warnings: list[str] = []
        pmus = self._canvas.get_pmu_nodes()
        pdcs = self._canvas.get_pdc_nodes()
        links = self._canvas.get_all_links()
        if not pmus:
            errors.append("Add at least one PMU before running a simulation.")
        if not pdcs:
            errors.append("Add at least one Local PDC before running a simulation.")
        if len(pmus) > 1 or len(pdcs) > 1:
            warnings.append("Runtime currently uses only the first PMU and first Local PDC; other nodes are diagram assets.")
        for node in pmus[:1] + pdcs[:1]:
            try:
                ipaddress.IPv4Address(node.ip)
                if not 1 <= node.port <= 65535:
                    raise ValueError("port must be from 1 to 65535")
                if node.proto.upper() not in ("UDP", "TCP"):
                    raise ValueError("transport must be UDP or TCP")
            except (ValueError, TypeError, AttributeError) as exc:
                errors.append(f"{node.label}: invalid endpoint ({exc})")
        if pmus and pdcs:
            if pmus[0].proto.upper() != pdcs[0].proto.upper():
                errors.append("PMU and PDC must use the same transport.")
            if pmus[0].port == pdcs[0].port and (
                    pmus[0].ip in (pdcs[0].ip, "0.0.0.0") or
                    {pmus[0].ip, pdcs[0].ip} <= {"127.0.0.1", "0.0.0.0"}):
                errors.append("Proxy input and PDC output must use different local endpoints (prevents a packet loop).")
            cfg = pmus[0].get_config()
            for key, default, low, high in (("reporting_rate", 30, 1, 120),
                                           ("idcode", 1, 1, 65535)):
                value = cfg.get(key, default)
                if not isinstance(value, int) or not low <= value <= high:
                    errors.append(f"PMU {key} must be an integer from {low} to {high}.")
            for key, default, low, high in (("nom_freq", 50, 45, 65),
                                           ("nom_voltage", 120, 0, 1000000)):
                value = cfg.get(key, default)
                if not isinstance(value, (int, float)) or not low <= value <= high:
                    errors.append(f"PMU {key} must be a number from {low} to {high}.")
        if self._attack_panel.get_scope() == "selected" and self._selected_link not in links:
            warnings.append("Selected Link scope has no target; packets will pass through unchanged.")
        if pmus and pdcs:
            pmu_pdc_link = any(
                link.protocol == "C37.118" and
                ((link.src_node in pmus and link.dst_node in pdcs) or
                 (link.dst_node in pmus and link.src_node in pdcs))
                for link in links
            )
            if not pmu_pdc_link:
                warnings.append("No direct C37.118 PMU-to-PDC link was found; the runtime uses the first PMU and PDC.")
        loose_agents = [a.label for a in self._canvas.get_threat_agents()
                        if not any(a in link._threat_agents for link in links)]
        if loose_agents:
            warnings.append("Threat Agent not attached to a link: " + ", ".join(loose_agents))
        pmu_ports = [node.port for node in pmus]
        if len(pmu_ports) != len(set(pmu_ports)):
            warnings.append("Multiple PMUs share a listen port; the current runtime simulates one active PMU stream.")
        return errors, warnings

    def _show_topology_validation(self) -> None:
        errors, warnings = self._topology_validation_messages()
        if not errors and not warnings:
            QMessageBox.information(self, "Topology Validation", "✓ Topology is ready to run.")
            return
        message = []
        if errors:
            message.append("<b>Must fix</b><br>" + "<br>".join(f"• {item}" for item in errors))
        if warnings:
            message.append("<b>Warnings</b><br>" + "<br>".join(f"• {item}" for item in warnings))
        QMessageBox.warning(self, "Topology Validation", "<br><br>".join(message))

    def _confirm_clear(self) -> None:
        if self._sim_running:
            QMessageBox.warning(self, "Simulation Running", "Stop before clearing the topology.")
            return
        reply = QMessageBox.question(
            self, "Clear Canvas", "Remove all nodes and links?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self._canvas.clear_canvas()

    # ── About ─────────────────────────────────────────────────────────────────

    def _show_about(self) -> None:
        QMessageBox.about(self, "About GridSec Sim",
            "<h3>GridSec Sim v2.0</h3>"
            "<p>Smart Grid Cybersecurity Simulation Tool</p>"
            "<p>Hierarchical Substation Automation Model</p>"
            "<br>"
            "<p><b>Levels:</b> Process (L0) → Bay (L1) → Station (L2) → State (L3)</p>"
            "<p><b>Protocols:</b> IEEE C37.118-2011, DNP3, Modbus TCP, IEC 60870-5-104, GOOSE</p>"
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
        self._stop_simulation()
        self._integration.stop()
        event.accept()
