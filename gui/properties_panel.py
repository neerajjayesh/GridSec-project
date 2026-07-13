"""
gui/properties_panel.py
=======================
Right-panel node/link configuration and properties display.

Shows the selected node's properties and allows editing:
  - Node type badge
  - IP / Port / Protocol fields (editable inline)
  - Status indicators (running, linked, etc.)
  - Linked nodes list

For a selected LinkItem:
  - Shows src → dst with protocol label
  - Protocol selector
  - Intercepted indicator
"""

from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QSpinBox, QComboBox, QPushButton,
    QFrame, QGroupBox, QScrollArea, QSizePolicy
)

from gui.node_types import (
    BaseNode, LinkItem, NodeType, NODE_DISPLAY_NAMES,
    NODE_COLORS, NODE_ICON_TEXT,
)


class PropertiesPanel(QWidget):
    """
    Properties panel — shown in the right sidebar.

    Signals:
      config_applied(node, config_dict) — user clicked Apply
    """

    config_applied = pyqtSignal(object, dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_node: Optional[BaseNode] = None
        self._current_link: Optional[LinkItem] = None
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

        # Node properties group
        self._node_group = QGroupBox("Node Configuration")
        node_form = QFormLayout(self._node_group)
        node_form.setSpacing(8)

        self._label_edit = QLineEdit()
        self._label_edit.setPlaceholderText("Node label")
        node_form.addRow("Label:", self._label_edit)

        self._ip_edit = QLineEdit()
        self._ip_edit.setPlaceholderText("127.0.0.1")
        node_form.addRow("IP Address:", self._ip_edit)

        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(4712)
        node_form.addRow("Port:", self._port_spin)

        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["UDP", "TCP"])
        node_form.addRow("Transport:", self._proto_combo)

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

        # Empty placeholder
        self._empty_label = QLabel(
            "<center><br><br><br>🖱<br><br>"
            "<b style='color:#3d3d5c'>Select a node or link</b><br>"
            "<small style='color:#2d2d44'>Click any item on the canvas</small></center>"
        )
        self._empty_label.setTextFormat(Qt.TextFormat.RichText)
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._content_layout.addWidget(self._empty_label)

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

        # Form
        self._label_edit.setText(cfg.get("label", ""))
        self._ip_edit.setText(cfg.get("ip", "127.0.0.1"))
        self._port_spin.setValue(int(cfg.get("port", 4712)))
        idx = self._proto_combo.findText(cfg.get("proto", "UDP"))
        if idx >= 0: self._proto_combo.setCurrentIndex(idx)

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

        self._label_edit.setText(f"{link.src_node.label} → {link.dst_node.label}")
        self._label_edit.setReadOnly(True)
        self._ip_edit.setText(f"src:{link.src_node.ip}  dst:{link.dst_node.ip}")
        self._ip_edit.setReadOnly(True)

        self._status_label.setText(f"● {status}")
        self._status_label.setStyleSheet(f"color: {color}; font-weight: 600;")
        self._links_label.setText(f"Protocol: {link.protocol}\nIntercepted: {link.is_intercepted}")

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
        self._empty_label.show()
        self._label_edit.setReadOnly(False)
        self._ip_edit.setReadOnly(False)

    def _on_apply(self):
        if self._current_node is None:
            return
        cfg = {
            "label": self._label_edit.text(),
            "ip":    self._ip_edit.text(),
            "port":  self._port_spin.value(),
            "proto": self._proto_combo.currentText(),
        }
        self._current_node.set_config(cfg)
        self.config_applied.emit(self._current_node, cfg)
        self.show_node(self._current_node)
