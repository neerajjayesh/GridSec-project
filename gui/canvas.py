"""
gui/canvas.py
=============
Drag-and-drop topology canvas — the heart of the GridSec Sim GUI.

Implements a Cisco Packet Tracer–style network diagram editor:
  - Dark grid background
  - Node palette on the left (drag to canvas to place)
  - Click-drag between nodes to create directed links
  - Right-click for context menu (properties / delete)
  - Double-click to open config dialog
  - Threat Agent node snaps onto a link and intercepts its traffic
  - Save/Load topology as JSON
  - Minimap (overview) in bottom-left corner of canvas

Architecture:
  QGraphicsScene + QGraphicsView
  NodeSignalBridge emits signals → MainWindow handles them
"""

import json
import math
from typing import Optional, List, Dict, Any, Tuple

from PyQt6.QtCore import (
    Qt, QPointF, QRectF, pyqtSignal, QObject, QTimer, QPoint, QLineF
)
from PyQt6.QtGui import (
    QBrush, QColor, QPen, QPainter, QFont, QPainterPath,
    QKeySequence, QAction, QPixmap, QDrag, QCursor
)
from PyQt6.QtWidgets import (
    QGraphicsScene, QGraphicsView, QGraphicsItem,
    QGraphicsLineItem, QMenu, QInputDialog, QMessageBox,
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout,
    QLabel, QLineEdit, QSpinBox, QPushButton, QComboBox,
    QWidget, QFrame
)

from gui.node_types import (
    BaseNode, LinkItem, NodeType, NODE_DISPLAY_NAMES,
    PMUNode, PDCNode, SwitchNode, ThreatAgentNode, VirtualNode,
    create_node, node_signals, PROTOCOL_COLORS,
)


# ─────────────────────────────────────────────────────────────────────────────
# Canvas signal bridge
# ─────────────────────────────────────────────────────────────────────────────

class CanvasSignals(QObject):
    """Signals emitted by the topology canvas."""
    node_selected        = pyqtSignal(object)    # BaseNode or None
    link_selected        = pyqtSignal(object)    # LinkItem or None
    topology_changed     = pyqtSignal()          # any structural change
    simulation_requested = pyqtSignal()          # "Run" toolbar button
    stop_requested       = pyqtSignal()          # "Stop" toolbar button
    node_config_changed  = pyqtSignal(object)    # node after config edit


# ─────────────────────────────────────────────────────────────────────────────
# Grid background scene
# ─────────────────────────────────────────────────────────────────────────────

class GridScene(QGraphicsScene):
    """QGraphicsScene with a dot-grid background."""

    GRID_SPACING = 32

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setBackgroundBrush(QBrush(QColor("#0f0f1e")))
        self.setSceneRect(-2000, -2000, 4000, 4000)

    def drawBackground(self, painter: QPainter, rect: QRectF) -> None:
        super().drawBackground(painter, rect)
        # Draw subtle dots
        gs   = self.GRID_SPACING
        pen  = QPen(QColor(255, 255, 255, 20), 1, Qt.PenStyle.SolidLine)
        painter.setPen(pen)

        left   = int(rect.left())   - (int(rect.left())   % gs)
        top    = int(rect.top())    - (int(rect.top())    % gs)
        right  = int(rect.right())  + gs
        bottom = int(rect.bottom()) + gs

        for x in range(left, right, gs):
            for y in range(top, bottom, gs):
                painter.drawPoint(x, y)


# ─────────────────────────────────────────────────────────────────────────────
# Node config dialog
# ─────────────────────────────────────────────────────────────────────────────

class NodeConfigDialog(QDialog):
    """Dialog for editing a node's configuration."""

    def __init__(self, node: BaseNode, parent=None):
        super().__init__(parent)
        self.node   = node
        self.result_config: Optional[dict] = None

        self.setWindowTitle(f"Configure — {NODE_DISPLAY_NAMES.get(node.node_type, node.node_type)}")
        self.setMinimumWidth(360)
        self.setModal(True)

        cfg = node.get_config()

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        # Title
        title = QLabel(f"<b>{NODE_DISPLAY_NAMES.get(node.node_type, node.node_type)}</b>")
        title.setStyleSheet("font-size: 15px; color: #a78bfa; padding: 4px 0px;")
        layout.addWidget(title)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("border-color: #3d3d5c;")
        layout.addWidget(sep)

        form = QFormLayout()
        form.setSpacing(10)

        # Label
        self._label_edit = QLineEdit(cfg.get("label", ""))
        form.addRow("Label:", self._label_edit)

        # IP
        self._ip_edit = QLineEdit(cfg.get("ip", "127.0.0.1"))
        form.addRow("IP Address:", self._ip_edit)

        # Port
        self._port_spin = QSpinBox()
        self._port_spin.setRange(1, 65535)
        self._port_spin.setValue(int(cfg.get("port", 4712)))
        form.addRow("Port:", self._port_spin)

        # Protocol
        self._proto_combo = QComboBox()
        self._proto_combo.addItems(["UDP", "TCP"])
        idx = self._proto_combo.findText(cfg.get("proto", "UDP"))
        if idx >= 0: self._proto_combo.setCurrentIndex(idx)
        form.addRow("Transport:", self._proto_combo)

        layout.addLayout(form)
        layout.addStretch()

        # Buttons
        btn_row = QHBoxLayout()
        btn_ok  = QPushButton("Apply")
        btn_ok.setObjectName("btn_attack_enable")
        btn_ok.clicked.connect(self._accept)
        btn_cancel = QPushButton("Cancel")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addStretch()
        btn_row.addWidget(btn_cancel)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _accept(self):
        self.result_config = {
            "label": self._label_edit.text(),
            "ip":    self._ip_edit.text(),
            "port":  self._port_spin.value(),
            "proto": self._proto_combo.currentText(),
        }
        self.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Drawing link (temporary line while dragging)
# ─────────────────────────────────────────────────────────────────────────────

class DrawingLine(QGraphicsLineItem):
    """Temporary dashed line shown while the user is drawing a new link."""

    def __init__(self):
        super().__init__()
        pen = QPen(QColor("#a78bfa"), 2, Qt.PenStyle.DashLine)
        pen.setDashPattern([4, 4])
        self.setPen(pen)
        self.setZValue(100)


# ─────────────────────────────────────────────────────────────────────────────
# Topology canvas view
# ─────────────────────────────────────────────────────────────────────────────

class TopologyCanvas(QGraphicsView):
    """
    Main topology canvas widget.

    Modes:
      "select"  — default; click-to-select, drag-to-move
      "connect" — click first node, drag to second node to create a link
      "delete"  — click any item to delete it
    """

    signals = CanvasSignals()

    def __init__(self, parent=None):
        scene = GridScene()
        super().__init__(scene, parent)

        self._scene    = scene
        self._mode     = "select"
        self._protocol = "C37.118"

        # Connection drawing state
        self._drawing_link = False
        self._link_start_node: Optional[BaseNode] = None
        self._drawing_line: Optional[DrawingLine] = None

        # Node counter (for auto-labeling)
        self._node_counter: Dict[str, int] = {}

        # All links (for topology save/load)
        self._links: List[LinkItem] = []
        self._nodes: List[BaseNode] = []

        # View settings
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        self.setDragMode(QGraphicsView.DragMode.NoDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setViewportUpdateMode(QGraphicsView.ViewportUpdateMode.FullViewportUpdate)
        self.setInteractive(True)

        # Enable panning with middle mouse / right-mouse drag
        self._pan_active = False
        self._pan_start  = QPoint()

        # Connect node signals
        node_signals.node_double_clicked.connect(self._on_node_double_click)
        node_signals.node_right_clicked.connect(self._on_node_right_click)
        node_signals.link_clicked.connect(self._on_link_click)
        node_signals.node_moved.connect(self._on_node_moved)

        # Welcome hint text
        self._add_hint()

    # ── Mode control ────────────────────────────────────────────────────────

    def set_mode(self, mode: str) -> None:
        """Set interaction mode: 'select', 'connect', 'delete'."""
        self._mode = mode
        if mode == "select":
            self.setDragMode(QGraphicsView.DragMode.NoDrag)
            self.setCursor(Qt.CursorShape.ArrowCursor)
        elif mode == "connect":
            self.setDragMode(QGraphicsView.DragMode.NoDrag)
            self.setCursor(Qt.CursorShape.CrossCursor)
        elif mode == "delete":
            self.setCursor(Qt.CursorShape.ForbiddenCursor)
        self._cancel_drawing()

    def set_protocol(self, protocol: str) -> None:
        self._protocol = protocol

    # ── Node placement ───────────────────────────────────────────────────────

    def add_node(self, node_type: str, scene_pos: Optional[QPointF] = None) -> BaseNode:
        """Create and place a node on the canvas."""
        # Auto-generate label
        count = self._node_counter.get(node_type, 0) + 1
        self._node_counter[node_type] = count
        short = {"PMU": "PMU", "PDC": "PDC", "SWITCH": "SW",
                 "THREAT_AGENT": "Threat", "VIRTUAL": "VNode"}
        label = f"{short.get(node_type, node_type)}-{count}"

        node = create_node(node_type, label=label)

        if scene_pos is None:
            # Place in center of view with offset
            center = self.mapToScene(self.viewport().rect().center())
            scene_pos = QPointF(center.x() + (count % 5) * 40,
                                center.y() + (count % 3) * 40)

        node.setPos(scene_pos)
        self._scene.addItem(node)
        self._nodes.append(node)
        self.signals.topology_changed.emit()
        self._remove_hint()
        return node

    def _remove_hint(self):
        for item in self._scene.items():
            if hasattr(item, "_is_hint"):
                self._scene.removeItem(item)
                break

    def _add_hint(self):
        from PyQt6.QtWidgets import QGraphicsSimpleTextItem
        hint = QGraphicsSimpleTextItem("Drag nodes from the left panel onto this canvas")
        hint._is_hint = True
        hint.setBrush(QBrush(QColor("#3d3d5c")))
        hint.setFont(QFont("Segoe UI", 16))
        hint.setPos(-250, -20)
        hint.setZValue(-2)
        self._scene.addItem(hint)

    # ── Link creation ────────────────────────────────────────────────────────

    def add_link(self, src: BaseNode, dst: BaseNode, protocol: Optional[str] = None) -> LinkItem:
        """Create a directed link between two nodes."""
        link = LinkItem(src, dst, protocol or self._protocol)
        self._scene.addItem(link)
        self._links.append(link)
        # If dst is a ThreatAgent, auto-intercept
        if dst.node_type == NodeType.THREAT_AGENT:
            pass  # threat agent is placed on a link, not as destination normally
        self.signals.topology_changed.emit()
        return link

    # ── Delete ───────────────────────────────────────────────────────────────

    def delete_selected(self) -> None:
        """Delete all selected items."""
        for item in list(self._scene.selectedItems()):
            self._delete_item(item)
        self.signals.topology_changed.emit()

    def _delete_item(self, item) -> None:
        if isinstance(item, BaseNode):
            # Remove all connected links first
            for link in list(item.get_links()):
                self._delete_link(link)
            self._scene.removeItem(item)
            if item in self._nodes:
                self._nodes.remove(item)
        elif isinstance(item, LinkItem):
            self._delete_link(item)

    def _delete_link(self, link: LinkItem) -> None:
        link.src_node.remove_link(link)
        link.dst_node.remove_link(link)
        if link in self._links:
            self._links.remove(link)
        self._scene.removeItem(link)

    def clear_canvas(self) -> None:
        """Remove all nodes and links."""
        self._scene.clear()
        self._nodes.clear()
        self._links.clear()
        self._node_counter.clear()
        self._add_hint()
        self.signals.topology_changed.emit()

    # ── Zoom ─────────────────────────────────────────────────────────────────

    def zoom_in(self)  -> None: self.scale(1.2, 1.2)
    def zoom_out(self) -> None: self.scale(1 / 1.2, 1 / 1.2)
    def zoom_fit(self) -> None: self.fitInView(self._scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)

    # ── Save / Load ──────────────────────────────────────────────────────────

    def save_topology(self) -> dict:
        """Serialize the current topology to a JSON-serializable dict."""
        nodes_data = []
        for node in self._nodes:
            cfg = node.get_config()
            cfg["_id"] = id(node)
            nodes_data.append(cfg)

        links_data = []
        for link in self._links:
            links_data.append({
                "src_id":   id(link.src_node),
                "dst_id":   id(link.dst_node),
                "protocol": link.protocol,
            })

        return {"nodes": nodes_data, "links": links_data}

    def load_topology(self, data: dict) -> None:
        """Restore a topology from a previously saved dict."""
        self.clear_canvas()

        id_map: Dict[int, BaseNode] = {}

        for nd in data.get("nodes", []):
            node_type = nd.get("node_type", NodeType.PMU)
            label     = nd.get("label", "")
            node      = self.add_node(node_type, QPointF(nd.get("x", 0), nd.get("y", 0)))
            node.set_config(nd)
            node._label_item.setPlainText(nd.get("label", label))
            id_map[nd["_id"]] = node

        for ld in data.get("links", []):
            src = id_map.get(ld["src_id"])
            dst = id_map.get(ld["dst_id"])
            if src and dst:
                self.add_link(src, dst, ld.get("protocol", "C37.118"))

    # ── Query ────────────────────────────────────────────────────────────────

    def get_pmu_nodes(self) -> List[PMUNode]:
        return [n for n in self._nodes if n.node_type == NodeType.PMU]

    def get_pdc_nodes(self) -> List[PDCNode]:
        return [n for n in self._nodes if n.node_type == NodeType.PDC]

    def get_threat_agents(self) -> List[ThreatAgentNode]:
        return [n for n in self._nodes if n.node_type == NodeType.THREAT_AGENT]

    def get_intercepted_links(self) -> List[LinkItem]:
        return [l for l in self._links if l.is_intercepted]

    def get_all_nodes(self) -> List[BaseNode]:
        return list(self._nodes)

    def get_all_links(self) -> List[LinkItem]:
        return list(self._links)

    # ── Threat agent placement on link ───────────────────────────────────────

    def _snap_threat_to_link(self, agent: ThreatAgentNode) -> Optional[LinkItem]:
        """
        If a ThreatAgent is dropped near a link, snap it to that link
        and mark the link as intercepted.
        """
        agent_pos = agent.scenePos()
        SNAP_DIST = 50.0

        for link in self._links:
            src = link._src_pt
            dst = link._dst_pt
            dist = self._point_to_segment_distance(agent_pos, src, dst)
            if dist < SNAP_DIST:
                # Snap position to midpoint of the link
                mid = QPointF((src.x() + dst.x()) / 2, (src.y() + dst.y()) / 2)
                agent.setPos(mid)
                link.add_threat_agent(agent)
                agent._config["intercepted_link"] = id(link)
                return link

        return None

    @staticmethod
    def _point_to_segment_distance(p: QPointF, a: QPointF, b: QPointF) -> float:
        """Minimum distance from point p to line segment ab."""
        ab  = QPointF(b.x() - a.x(), b.y() - a.y())
        ap  = QPointF(p.x() - a.x(), p.y() - a.y())
        ab2 = ab.x() ** 2 + ab.y() ** 2
        if ab2 < 1e-9:
            return math.hypot(ap.x(), ap.y())
        t   = max(0.0, min(1.0, (ap.x() * ab.x() + ap.y() * ab.y()) / ab2))
        proj = QPointF(a.x() + t * ab.x(), a.y() + t * ab.y())
        return math.hypot(p.x() - proj.x(), p.y() - proj.y())

    # ── Context menu ──────────────────────────────────────────────────────────

    def _show_node_context_menu(self, node: BaseNode, screen_pos: QPoint) -> None:
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu { background:#252535; border:1px solid #3d3d5c; border-radius:6px; }
            QMenu::item { padding:7px 20px; color:#e2e8f0; }
            QMenu::item:selected { background:#7c3aed; }
        """)

        act_config = menu.addAction("Configure Node")
        act_delete = menu.addAction("Delete Node")
        menu.addSeparator()

        if node.node_type == NodeType.THREAT_AGENT:
            act_activate = menu.addAction("Set as Active Attacker")
            act_activate.triggered.connect(lambda: self._activate_threat(node))

        act_config.triggered.connect(lambda: self._open_config_dialog(node))
        act_delete.triggered.connect(lambda: self._delete_item(node))
        menu.exec(screen_pos)

    def _show_link_context_menu(self, link: LinkItem, screen_pos: QPoint) -> None:
        menu = QMenu()
        menu.setStyleSheet("""
            QMenu { background:#252535; border:1px solid #3d3d5c; border-radius:6px; }
            QMenu::item { padding:7px 20px; color:#e2e8f0; }
            QMenu::item:selected { background:#7c3aed; }
        """)

        act_proto = menu.addMenu("Change Protocol")
        for proto in ["C37.118", "DNP3", "Modbus", "IEC104"]:
            a = act_proto.addAction(proto)
            a.triggered.connect(lambda checked, p=proto: self._set_link_protocol(link, p))

        act_delete = menu.addAction("Delete Link")
        act_delete.triggered.connect(lambda: self._delete_item(link))
        menu.exec(screen_pos)

    def _set_link_protocol(self, link: LinkItem, protocol: str) -> None:
        link.protocol = protocol
        link.update()
        self.signals.topology_changed.emit()

    def _activate_threat(self, node: ThreatAgentNode) -> None:
        # Deactivate all others
        for n in self.get_threat_agents():
            n._config["active"] = False
            n.update()
        node._config["active"] = True
        node.update()
        self.signals.node_config_changed.emit(node)

    # ── Config dialog ────────────────────────────────────────────────────────

    def _open_config_dialog(self, node: BaseNode) -> None:
        dlg = NodeConfigDialog(node, self)
        if dlg.exec() == QDialog.DialogCode.Accepted and dlg.result_config:
            node.set_config(dlg.result_config)
            self.signals.node_config_changed.emit(node)
            self.signals.topology_changed.emit()

    # ── Signal handlers ───────────────────────────────────────────────────────

    def _on_node_double_click(self, node: BaseNode) -> None:
        self._open_config_dialog(node)

    def _on_node_right_click(self, node: BaseNode) -> None:
        self._show_node_context_menu(node, QCursor.pos())
        self.signals.node_selected.emit(node)

    def _on_link_click(self, link: LinkItem) -> None:
        self._show_link_context_menu(link, QCursor.pos())
        self.signals.link_selected.emit(link)

    def _on_node_moved(self, node: BaseNode) -> None:
        # If it's a threat agent, check if it's near a link
        if node.node_type == NodeType.THREAT_AGENT:
            self._snap_threat_to_link(node)

    # ── Mouse events ──────────────────────────────────────────────────────────

    def mousePressEvent(self, event) -> None:
        scene_pos = self.mapToScene(event.pos())

        if event.button() == Qt.MouseButton.MiddleButton:
            # Pan start
            self._pan_active = True
            self._pan_start  = event.pos()
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            event.accept()
            return

        if event.button() == Qt.MouseButton.RightButton:
            # Let item handle it via contextMenuEvent
            super().mousePressEvent(event)
            return

        if event.button() == Qt.MouseButton.LeftButton:
            if self._mode == "delete":
                item = self._scene.itemAt(scene_pos, self.transform())
                if item and not isinstance(item, type(None)):
                    if isinstance(item, (BaseNode, LinkItem)):
                        self._delete_item(item)
                        self.signals.topology_changed.emit()
                event.accept()
                return

            if self._mode == "connect":
                item = self._scene.itemAt(scene_pos, self.transform())
                # Walk up parent chain to find BaseNode
                node = self._find_node_at(scene_pos)
                if node:
                    if not self._drawing_link:
                        # Start drawing
                        self._drawing_link     = True
                        self._link_start_node  = node
                        self._drawing_line     = DrawingLine()
                        cp = node.get_connection_point(scene_pos)
                        self._drawing_line.setLine(cp.x(), cp.y(), scene_pos.x(), scene_pos.y())
                        self._scene.addItem(self._drawing_line)
                    else:
                        # Complete the link
                        if node is not self._link_start_node:
                            self.add_link(self._link_start_node, node, self._protocol)
                        self._cancel_drawing()
                event.accept()
                return

        super().mousePressEvent(event)

    def mouseMoveEvent(self, event) -> None:
        if self._pan_active:
            delta = event.pos() - self._pan_start
            self._pan_start = event.pos()
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - delta.x())
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - delta.y())
            event.accept()
            return

        if self._drawing_link and self._drawing_line and self._link_start_node:
            scene_pos = self.mapToScene(event.pos())
            src_pt    = self._link_start_node.get_connection_point(scene_pos)
            self._drawing_line.setLine(src_pt.x(), src_pt.y(), scene_pos.x(), scene_pos.y())
            event.accept()
            return

        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.MiddleButton:
            self._pan_active = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
            event.accept()
            return
        super().mouseReleaseEvent(event)

    def _cancel_drawing(self) -> None:
        if self._drawing_line:
            self._scene.removeItem(self._drawing_line)
            self._drawing_line = None
        self._drawing_link    = False
        self._link_start_node = None

    def _find_node_at(self, scene_pos: QPointF) -> Optional[BaseNode]:
        """Find a BaseNode at the given scene position."""
        for item in self._scene.items(scene_pos):
            if isinstance(item, BaseNode):
                return item
            if hasattr(item, "parentItem") and isinstance(item.parentItem(), BaseNode):
                return item.parentItem()
        return None

    def wheelEvent(self, event) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)

    def keyPressEvent(self, event) -> None:
        if event.key() in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace):
            self.delete_selected()
        elif event.key() == Qt.Key.Key_Escape:
            self._cancel_drawing()
            self.set_mode("select")
        elif event.key() == Qt.Key.Key_F:
            self.zoom_fit()
        super().keyPressEvent(event)

    # ── Drag accept (from palette) ────────────────────────────────────────────

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasText():
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasText():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        if event.mimeData().hasText():
            node_type = event.mimeData().text()
            scene_pos = self.mapToScene(event.position().toPoint())
            self.add_node(node_type, scene_pos)
            event.acceptProposedAction()

    # ── Selection change ──────────────────────────────────────────────────────

    def _handle_selection_change(self) -> None:
        selected = self._scene.selectedItems()
        for item in selected:
            if isinstance(item, BaseNode):
                self.signals.node_selected.emit(item)
                return
            if isinstance(item, LinkItem):
                self.signals.link_selected.emit(item)
                return
        self.signals.node_selected.emit(None)

    def set_simulation_running(self, running: bool) -> None:
        """Visual feedback — mark PMU and proxy nodes as active."""
        for node in self._nodes:
            if node.node_type in (NodeType.PMU, NodeType.THREAT_AGENT):
                node._config["running"] = running
                node._config["active"]  = running
                node.update()
