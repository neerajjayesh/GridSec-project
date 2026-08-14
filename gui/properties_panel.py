"""
gui/properties_panel.py
=======================
Right-panel node/link configuration and properties display.

Shows type-specific property schemas for each node type:
  - PMU: reporting rate, ID code, level
  - PDC: buffer timeout, PMU input count
  - State PDC: connected PDC count, regional uplink toggle
  - Switch: port count, connected nodes
  - Station HMI: status (Active/Idle/Down)
  - Engineering Workstation: high-risk badge
  - Gateway/RTU: protocol selector (DNP3/IEC104)
  - CT/VT: subtype, read-only sensor
  - Breaker: state toggle (open/closed)
  - Protection IED: subtype
  - BCU: subtype
  - Threat Agent: target link info
  - Virtual Node: subtype

For a selected LinkItem:
  - Shows src → dst with protocol label
  - Protocol selector
  - Intercepted indicator
"""

import time
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QSpinBox, QComboBox, QPushButton,
    QFrame, QGroupBox, QScrollArea, QSizePolicy,
    QDoubleSpinBox,
)

from gui.node_types import (
    BaseNode, LinkItem, NodeType, NODE_DISPLAY_NAMES,
    NODE_COLORS, NODE_ICON_TEXT, NODE_LEVEL, LEVEL_LABELS,
)


class PropertiesPanel(QWidget):
    """
    Properties panel — shown in the right sidebar.

    Signals:
      config_applied(node, config_dict) — user clicked Apply
      regional_uplink_toggled(node, connected: bool) — uplink toggle
    """

    config_applied = pyqtSignal(object, dict)
    regional_uplink_toggled = pyqtSignal(object, bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_node: Optional[BaseNode] = None
        self._current_link: Optional[LinkItem] = None
        self._field_widgets = {}  # name -> widget mapping for current form
        self._build_ui()
        self._show_empty()

    # ── UI construction ───────────────────────────────────────────────────────

    def _build_ui(self):
        self.setMinimumWidth(260)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header
        hdr = QHBoxLayout()
        self._icon_label  = QLabel("🔧")
        self._icon_label.setStyleSheet("font-size: 22px;")
        self._type_label  = QLabel("Properties")
        self._type_label.setStyleSheet("font-size: 13px; color: #a78bfa; font-weight: 600;")
        hdr.addWidget(self._icon_label)
        hdr.addWidget(self._type_label)
        hdr.addStretch()
        layout.addLayout(hdr)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("border: none; background: #3d3d5c; max-height: 1px;")
        layout.addWidget(sep)

        # Scroll area for content
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        layout.addWidget(scroll)

        self._content = QWidget()
        scroll.setWidget(self._content)
        self._content_layout = QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 4, 0, 4)
        self._content_layout.setSpacing(8)
        self._content_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        # Node properties group (dynamically populated)
        self._node_group = QGroupBox("Node Configuration")
        self._node_form = QFormLayout(self._node_group)
        self._node_form.setSpacing(8)
        self._content_layout.addWidget(self._node_group)

        # Apply button
        self._apply_btn = QPushButton("Apply Changes")
        self._apply_btn.setObjectName("btn_attack_enable")
        self._apply_btn.clicked.connect(self._on_apply)
        self._content_layout.addWidget(self._apply_btn)

        # Status section
        self._status_group = QGroupBox("Status")
        status_layout = QVBoxLayout(self._status_group)
        self._status_label = QLabel("● Not running")
        self._status_label.setStyleSheet("color: #64748b;")
        status_layout.addWidget(self._status_label)
        self._content_layout.addWidget(self._status_group)

        # Link info section
        self._link_group = QGroupBox("Connected Links")
        link_layout = QVBoxLayout(self._link_group)
        self._links_label = QLabel("No links")
        self._links_label.setStyleSheet("color: #64748b; font-size: 12px;")
        self._links_label.setWordWrap(True)
        link_layout.addWidget(self._links_label)
        self._content_layout.addWidget(self._link_group)

        # High-risk badge (for Engineering Workstation)
        self._risk_badge = QLabel("⚠  HIGH-RISK ASSET")
        self._risk_badge.setStyleSheet(
            "background: #fbbf24; color: #7f1d1d; font-weight: 700; font-size: 11px;"
            "padding: 4px 10px; border-radius: 4px;"
        )
        self._risk_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._content_layout.addWidget(self._risk_badge)
        self._risk_badge.hide()

        # Empty placeholder
        self._empty_label = QLabel(
            "<center><br><br><br>🖱<br><br>"
            "<b style='color:#3d3d5c'>Select a node or link</b><br>"
            "<small style='color:#2d2d44'>Click any item on the canvas</small></center>"
        )
        self._empty_label.setTextFormat(Qt.TextFormat.RichText)
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._content_layout.addWidget(self._empty_label)

    # ── Private: build type-specific form ─────────────────────────────────────

    def _clear_form(self):
        """Remove all rows from the node form."""
        while self._node_form.rowCount() > 0:
            self._node_form.removeRow(0)
        self._field_widgets.clear()

    def _add_field(self, label: str, widget, key: str):
        """Add a labeled field to the form and track it."""
        self._node_form.addRow(label, widget)
        self._field_widgets[key] = widget

    def _build_common_fields(self, cfg: dict):
        """Add common fields present on all node types."""
        # Node ID / Label
        w = QLineEdit(cfg.get("label", ""))
        self._add_field("Label:", w, "label")

        # Level (read-only)
        level = cfg.get("level", -1)
        level_text = LEVEL_LABELS.get(level, "Any") if level >= 0 else "Any"
        w = QLabel(level_text)
        w.setStyleSheet("color: #a78bfa; font-weight: 500;")
        self._add_field("Level:", w, "_level_display")

    def _build_network_fields(self, cfg: dict):
        """Add IP/Port/Proto fields for network-connected nodes."""
        w = QLineEdit(cfg.get("ip", "127.0.0.1"))
        self._add_field("IP Address:", w, "ip")

        w = QSpinBox()
        w.setRange(0, 65535)
        w.setValue(int(cfg.get("port", 0)))
        self._add_field("Port:", w, "port")

        w = QComboBox()
        w.addItems(["UDP", "TCP"])
        idx = w.findText(cfg.get("proto", "UDP"))
        if idx >= 0:
            w.setCurrentIndex(idx)
        self._add_field("Transport:", w, "proto")

    def _populate_form(self, node: BaseNode, cfg: dict):
        """Build the type-specific form for the given node."""
        self._clear_form()
        nt = node.node_type

        # ── Common fields (all types) ────────────────────────────────────────
        self._build_common_fields(cfg)

        # ── Type-specific fields ─────────────────────────────────────────────
        if nt == NodeType.PMU:
            self._build_network_fields(cfg)
            w = QSpinBox()
            w.setRange(1, 120)
            w.setValue(int(cfg.get("reporting_rate", 30)))
            w.setSuffix(" fps")
            self._add_field("Reporting Rate:", w, "reporting_rate")
            w = QSpinBox()
            w.setRange(1, 65535)
            w.setValue(int(cfg.get("idcode", 1)))
            self._add_field("C37.118 ID Code:", w, "idcode")

        elif nt == NodeType.PDC:
            self._build_network_fields(cfg)
            w = QSpinBox()
            w.setRange(10, 5000)
            w.setValue(int(cfg.get("buffer_timeout", 100)))
            w.setSuffix(" ms")
            self._add_field("Buffer Timeout:", w, "buffer_timeout")
            w = QLabel(str(len(node.get_links())))
            w.setStyleSheet("color: #a78bfa;")
            self._add_field("PMU Inputs:", w, "_pmu_count_display")

        elif nt == NodeType.STATE_PDC:
            self._build_network_fields(cfg)
            # Connected PDC count (read-only)
            pdc_count = sum(1 for l in node.get_links()
                          if l.src_node.node_type == NodeType.PDC
                          or l.dst_node.node_type == NodeType.PDC)
            w = QLabel(str(pdc_count))
            w.setStyleSheet("color: #a78bfa;")
            self._add_field("Connected PDCs:", w, "_pdc_count_display")
            # Regional uplink toggle
            uplink = cfg.get("regional_uplink_connected", False)
            btn = QPushButton("🟢 Connected" if uplink else "⚫ Disconnected")
            btn.setCheckable(True)
            btn.setChecked(uplink)
            if uplink:
                btn.setStyleSheet(
                    "background: #065f46; color: #10b981; border: 1px solid #10b981;"
                    "border-radius: 4px; padding: 4px 8px; font-weight: 600;"
                )
            else:
                btn.setStyleSheet(
                    "background: #1e1e2e; color: #64748b; border: 1px solid #3d3d5c;"
                    "border-radius: 4px; padding: 4px 8px;"
                )
            btn.toggled.connect(lambda checked: self._on_uplink_toggle(checked))
            self._add_field("Regional Uplink\n(C37.118):", btn, "_regional_uplink_btn")

        elif nt == NodeType.SWITCH:
            w = QSpinBox()
            w.setRange(2, 48)
            w.setValue(int(cfg.get("port_count", 8)))
            self._add_field("Port Count:", w, "port_count")
            w = QLabel(str(len(node.get_links())))
            w.setStyleSheet("color: #a78bfa;")
            self._add_field("Connected Nodes:", w, "_conn_count_display")

        elif nt == NodeType.STATION_HMI:
            self._build_network_fields(cfg)
            w = QComboBox()
            w.addItems(["Active", "Idle", "Down"])
            idx = w.findText(cfg.get("status", "Active"))
            if idx >= 0:
                w.setCurrentIndex(idx)
            self._add_field("Status:", w, "status")

        elif nt == NodeType.ENGINEERING_WS:
            self._build_network_fields(cfg)
            # High-risk flag (read-only)
            w = QLabel("⚠ TRUE — USB/local compromise entry point")
            w.setStyleSheet("color: #fbbf24; font-weight: 600; font-size: 11px;")
            w.setWordWrap(True)
            self._add_field("High-Risk Asset:", w, "_risk_flag_display")

        elif nt == NodeType.GATEWAY_RTU:
            self._build_network_fields(cfg)
            w = QComboBox()
            w.addItems(["DNP3", "IEC104"])
            idx = w.findText(cfg.get("protocol", "DNP3"))
            if idx >= 0:
                w.setCurrentIndex(idx)
            self._add_field("Uplink Protocol:", w, "protocol")

        elif nt == NodeType.CT_VT:
            w = QLabel("CT/VT — Read-only measurement source")
            w.setStyleSheet("color: #f59e0b; font-size: 11px;")
            w.setWordWrap(True)
            self._add_field("Subtype:", w, "_subtype_display")

        elif nt == NodeType.BREAKER:
            state = cfg.get("state", "closed")
            w = QPushButton("🔴 OPEN" if state == "open" else "🟢 CLOSED")
            w.setCheckable(True)
            w.setChecked(state == "open")
            if state == "open":
                w.setStyleSheet(
                    "background: #7f1d1d; color: #ef4444; border: 1px solid #ef4444;"
                    "border-radius: 4px; padding: 4px 8px; font-weight: 700;"
                )
            else:
                w.setStyleSheet(
                    "background: #065f46; color: #10b981; border: 1px solid #10b981;"
                    "border-radius: 4px; padding: 4px 8px; font-weight: 700;"
                )
            w.toggled.connect(lambda checked: self._on_breaker_toggle(checked))
            self._add_field("Breaker State:", w, "_breaker_state_btn")

        elif nt == NodeType.PROTECTION_IED:
            self._build_network_fields(cfg)
            w = QLabel("Protection Relay — GOOSE protocol")
            w.setStyleSheet("color: #14b8a6; font-size: 11px;")
            w.setWordWrap(True)
            self._add_field("Subtype:", w, "_subtype_display")

        elif nt == NodeType.BCU:
            self._build_network_fields(cfg)
            w = QLabel("Bay Control Unit — interlocking & switching")
            w.setStyleSheet("color: #06b6d4; font-size: 11px;")
            w.setWordWrap(True)
            self._add_field("Subtype:", w, "_subtype_display")

        elif nt == NodeType.THREAT_AGENT:
            self._build_network_fields(cfg)
            # Target link info
            links = node.get_links()
            if links:
                link_info = ", ".join(
                    f"{l.src_node.label}→{l.dst_node.label} [{l.protocol}]"
                    for l in links
                )
            else:
                link_info = "Not intercepting any link"
            w = QLabel(link_info)
            w.setStyleSheet("color: #ef4444; font-size: 11px;")
            w.setWordWrap(True)
            self._add_field("Target Links:", w, "_target_display")
            # Active status
            active = cfg.get("active", False)
            w = QLabel("🔴 ACTIVE" if active else "⚫ Inactive")
            w.setStyleSheet(f"color: {'#ef4444' if active else '#64748b'}; font-weight: 600;")
            self._add_field("Attacker Status:", w, "_active_display")

        elif nt == NodeType.VIRTUAL:
            self._build_network_fields(cfg)
            w = QLineEdit(cfg.get("subtype", "generic"))
            self._add_field("Subtype:", w, "subtype")

        else:
            # Fallback for any unknown type
            self._build_network_fields(cfg)

    # ── Public API ────────────────────────────────────────────────────────────

    def show_node(self, node: BaseNode) -> None:
        """Populate panel with node properties."""
        self._current_node = node
        self._current_link = None

        cfg = node.get_config()

        # Header
        icon = NODE_ICON_TEXT.get(node.node_type, "?")
        self._icon_label.setText(icon)
        self._type_label.setText(NODE_DISPLAY_NAMES.get(node.node_type, node.node_type))

        # Color accent
        color = NODE_COLORS.get(node.node_type, "#7c3aed")
        self._type_label.setStyleSheet(f"font-size: 13px; color: {color}; font-weight: 600;")

        # Build type-specific form
        self._populate_form(node, cfg)

        # Status
        running = cfg.get("running", False)
        if running:
            self._status_label.setText("● Running")
            self._status_label.setStyleSheet("color: #10b981; font-weight: 600;")
        else:
            self._status_label.setText("● Idle")
            self._status_label.setStyleSheet("color: #64748b;")

        # Links
        links = node.get_links()
        if links:
            link_texts = []
            for l in links:
                other = l.dst_node if l.src_node is node else l.src_node
                arrow = "→" if l.src_node is node else "←"
                link_texts.append(f"{arrow} {other.label} [{l.protocol}]")
            self._links_label.setText("\n".join(link_texts))
            self._links_label.setStyleSheet("color: #a78bfa; font-size: 12px;")
        else:
            self._links_label.setText("No links")
            self._links_label.setStyleSheet("color: #64748b; font-size: 12px;")

        # High-risk badge
        if node.node_type == NodeType.ENGINEERING_WS:
            self._risk_badge.show()
        else:
            self._risk_badge.hide()

        # Visibility
        self._empty_label.hide()
        self._node_group.show()
        self._apply_btn.show()
        self._status_group.show()
        self._link_group.show()

    def show_link(self, link: LinkItem) -> None:
        """Populate panel with link properties."""
        self._current_node = None
        self._current_link = link

        self._icon_label.setText("🔗")
        status = "⚠ INTERCEPTED" if link.is_intercepted else "Clean"
        color  = "#ef4444" if link.is_intercepted else "#a78bfa"
        self._type_label.setText(f"Link — {link.protocol}")
        self._type_label.setStyleSheet(f"font-size: 13px; color: {color}; font-weight: 600;")

        # Build link-specific form
        self._clear_form()

        w = QLabel(f"{link.src_node.label} → {link.dst_node.label}")
        w.setStyleSheet("color: #e2e8f0; font-weight: 500;")
        self._add_field("Connection:", w, "_link_path")

        w = QLabel(f"{link.src_node.ip} → {link.dst_node.ip}")
        w.setStyleSheet("color: #64748b;")
        self._add_field("IP Path:", w, "_link_ips")

        w = QLabel(link.protocol)
        w.setStyleSheet(f"color: {color}; font-weight: 600;")
        self._add_field("Protocol:", w, "_link_proto")

        w = QLabel(f"● {status}")
        w.setStyleSheet(f"color: {color}; font-weight: 600;")
        self._add_field("Status:", w, "_link_status")

        self._status_label.setText(f"● {status}")
        self._status_label.setStyleSheet(f"color: {color}; font-weight: 600;")
        self._links_label.setText(f"Protocol: {link.protocol}\nIntercepted: {link.is_intercepted}")

        self._risk_badge.hide()
        self._empty_label.hide()
        self._node_group.show()
        self._apply_btn.hide()
        self._status_group.show()
        self._link_group.show()

    def clear(self) -> None:
        self._show_empty()

    def update_status(self, node: BaseNode, running: bool) -> None:
        """Update status indicator if the displayed node matches."""
        if self._current_node is node:
            self.show_node(node)

    # ── Private ───────────────────────────────────────────────────────────────

    def _show_empty(self):
        self._current_node = None
        self._current_link = None
        self._icon_label.setText("🔧")
        self._type_label.setText("Properties")
        self._type_label.setStyleSheet("font-size: 13px; color: #a78bfa; font-weight: 600;")
        self._node_group.hide()
        self._apply_btn.hide()
        self._status_group.hide()
        self._link_group.hide()
        self._risk_badge.hide()
        self._empty_label.show()

    def _on_apply(self):
        if self._current_node is None:
            return

        cfg = {}
        for key, widget in self._field_widgets.items():
            # Skip read-only display labels (prefixed with _)
            if key.startswith("_"):
                continue
            if isinstance(widget, QLineEdit):
                cfg[key] = widget.text()
            elif isinstance(widget, QSpinBox):
                cfg[key] = widget.value()
            elif isinstance(widget, QDoubleSpinBox):
                cfg[key] = widget.value()
            elif isinstance(widget, QComboBox):
                cfg[key] = widget.currentText()

        self._current_node.set_config(cfg)
        self.config_applied.emit(self._current_node, cfg)
        self.show_node(self._current_node)

    def _on_uplink_toggle(self, connected: bool):
        """Handle regional uplink toggle on State PDC."""
        if self._current_node is None:
            return
        self._current_node._config["regional_uplink_connected"] = connected
        self._current_node.update()
        self.regional_uplink_toggled.emit(self._current_node, connected)
        # Refresh the form to update button appearance
        self.show_node(self._current_node)

    def _on_breaker_toggle(self, is_open: bool):
        """Handle breaker state toggle."""
        if self._current_node is None:
            return
        self._current_node._config["state"] = "open" if is_open else "closed"
        self._current_node.update()
        self.show_node(self._current_node)
