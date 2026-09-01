"""
gui/canvas.py
=============
Drag-and-drop topology canvas — the heart of the GridSec Sim GUI.

Implements a Cisco Packet Tracer–style network diagram editor:
  - Dark grid background with hierarchical level lanes
  - Node palette on the left (drag to canvas to place)
  - Nodes snap to their level's horizontal lane
  - Click-drag between nodes to create directed links
  - Right-click for context menu (properties / delete)
  - Double-click to open config dialog
  - Threat Agent node snaps onto a link and intercepts its traffic
  - Save/Load topology as JSON
  - Smart link protocol defaults based on source/target level

Architecture:
  QGraphicsScene + QGraphicsView
  NodeSignalBridge emits signals → MainWindow handles them

Level lanes (bottom to top):
  L0 — Process  (y: 400..600)
  L1 — Bay      (y: 200..400)
  L2 — Station  (y: 0..200)
  L3 — State    (y: -200..0)
"""

import json
import math
import uuid
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
    BaseNode, LinkItem, NodeType, NODE_DISPLAY_NAMES, NODE_LEVEL,
    NODE_SHORT_NAMES, LEVEL_LABELS,
    PMUNode, PDCNode, SwitchNode, ThreatAgentNode, VirtualNode,
    CTVTNode, BreakerNode, ProtectionIEDNode, BCUNode,
    StationHMINode, EngineeringWSNode, GatewayRTUNode, StatePDCNode,
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
# Level lane layout constants
# ─────────────────────────────────────────────────────────────────────────────

LANE_HEIGHT = 200   # px per level lane
# Lane Y ranges (top of lane → bottom of lane), level 3 at top, level 0 at bottom
# L3: -200..0,  L2: 0..200,  L1: 200..400,  L0: 400..600
LANE_Y_TOP = {
    3: -200,
    2:    0,
    1:  200,
    0:  400,
}
LANE_Y_BOTTOM = {level: top + LANE_HEIGHT for level, top in LANE_Y_TOP.items()}

# Center Y for each lane (where nodes snap to by default)
LANE_Y_CENTER = {level: top + LANE_HEIGHT // 2 for level, top in LANE_Y_TOP.items()}

# Canvas left edge for lane labels
LANE_LABEL_X = -450


# ─────────────────────────────────────────────────────────────────────────────
# Grid background scene with level lanes
# ─────────────────────────────────────────────────────────────────────────────

class GridScene(QGraphicsScene):
    """QGraphicsScene with a dot-grid background and level lane dividers."""

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

        # ── Draw level lane dividers and labels ──────────────────────────────
        lane_pen = QPen(QColor(255, 255, 255, 25), 1, Qt.PenStyle.DashLine)
        lane_pen.setDashPattern([8, 8])
        label_font = QFont("Segoe UI", 10, QFont.Weight.DemiBold)

        # Visible rect boundaries
        vis_left  = int(rect.left())
        vis_right = int(rect.right())

        for level in [0, 1, 2, 3]:
            lane_top = LANE_Y_TOP[level]

            # Horizontal divider line at the top of each lane
            painter.setPen(lane_pen)
            painter.drawLine(vis_left, lane_top, vis_right, lane_top)

            # Lane label on the left
            painter.setFont(label_font)
            painter.setPen(QColor(167, 139, 250, 60))  # faint purple
            label_text = LEVEL_LABELS.get(level, f"L{level}")
            painter.drawText(
                int(max(vis_left + 10, LANE_LABEL_X)),
                lane_top + 22,
                label_text,
            )

        # Bottom boundary of Level 0
        painter.setPen(lane_pen)
        painter.drawLine(vis_left, LANE_Y_BOTTOM[0], vis_right, LANE_Y_BOTTOM[0])


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
        self._port_spin.setRange(0, 65535)
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
# Smart protocol defaults based on source → target level
# ─────────────────────────────────────────────────────────────────────────────

def _default_link_protocol(src_node: BaseNode, dst_node: BaseNode, current: str) -> str:
    """Choose a sensible default protocol based on node types/levels."""
    src_level = NODE_LEVEL.get(src_node.node_type, -1)
    dst_level = NODE_LEVEL.get(dst_node.node_type, -1)
    src_type  = src_node.node_type
    dst_type  = dst_node.node_type

    # Ensure src_level <= dst_level (lower→higher) for protocol lookup
    if src_level > dst_level:
        src_level, dst_level = dst_level, src_level
        src_type, dst_type   = dst_type, src_type

    # L0 → L1: sensor wiring or GOOSE
    if src_level == 0 and dst_level == 1:
        return "GOOSE"

    # L1 → L2: PMU→PDC uses C37.118, IED/BCU uses GOOSE
    if src_level == 1 and dst_level == 2:
        if src_type == NodeType.PMU or dst_type == NodeType.PMU:
            return "C37.118"
        return "GOOSE"

    # L2 → L3: PDC→StatePDC uses C37.118, RTU→StatePDC uses DNP3
    if src_level == 2 and dst_level == 3:
        if src_type == NodeType.GATEWAY_RTU or dst_type == NodeType.GATEWAY_RTU:
            return "DNP3"
        return "C37.118"

    # Same level or agnostic — keep current protocol
    return current


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

        # Enable panning with middle mouse or Space + left-click drag
        self._pan_active = False
        self._pan_start  = QPoint()
        self._space_held = False   # True while spacebar is held down

        # Connect node signals
        node_signals.node_double_clicked.connect(self._on_node_double_click)
        node_signals.node_right_clicked.connect(self._on_node_right_click)
        node_signals.link_clicked.connect(self._on_link_click)
        node_signals.node_moved.connect(self._on_node_moved)

        # ── FIX: Connect scene selection changed to handle Properties panel ──
        self._scene.selectionChanged.connect(self._handle_selection_change)

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
        """Create and place a node on the canvas, snapping to its level lane."""
        # Auto-generate label
        count = self._node_counter.get(node_type, 0) + 1
        self._node_counter[node_type] = count
        label = f"{NODE_SHORT_NAMES.get(node_type, node_type)}-{count}"

        node = create_node(node_type, label=label)
        # Persist a stable identifier.  Python's id() is only valid for the
        # current process and made topology files needlessly brittle.
        node._topology_id = str(uuid.uuid4())

        if scene_pos is None:
            # Place in center of view with offset
            center = self.mapToScene(self.viewport().rect().center())
            scene_pos = QPointF(center.x() + (count % 5) * 80,
                                center.y() + (count % 3) * 40)

        # Snap Y to the correct level lane
        level = NODE_LEVEL.get(node_type, -1)
        if level >= 0 and level in LANE_Y_CENTER:
            # Snap to lane center Y, keep X as-is
            snapped_y = LANE_Y_CENTER[level]
            # Allow some spread within the lane
            offset_y = ((count - 1) % 3 - 1) * 50
            scene_pos = QPointF(scene_pos.x(), snapped_y + offset_y)

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
        hint.setPos(-250, 180)
        hint.setZValue(-2)
        self._scene.addItem(hint)

    # ── Link creation ────────────────────────────────────────────────────────

    def add_link(self, src: BaseNode, dst: BaseNode, protocol: Optional[str] = None) -> LinkItem:
        """Create a directed link between two nodes with smart protocol defaults."""
        # Determine protocol: explicit > smart default > canvas default
        if protocol is None:
            protocol = _default_link_protocol(src, dst, self._protocol)

        link = LinkItem(src, dst, protocol)
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
            # An attacker is owned by the canvas but also registered with the
            # intercepted link.  Clear that registration before removing the
            # node so a deleted attacker cannot leave a link marked red.
            if item.node_type == NodeType.THREAT_AGENT:
                for link in self._links:
                    link.remove_threat_agent(item)
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
        """Serialize the current topology using the portable v2 schema."""
        nodes_data = []
        for node in self._nodes:
            cfg = node.get_config()
            cfg["id"] = getattr(node, "_topology_id", str(uuid.uuid4()))
            nodes_data.append(cfg)

        links_data = []
        for link in self._links:
            links_data.append({
                "src_id":   getattr(link.src_node, "_topology_id", str(id(link.src_node))),
                "dst_id":   getattr(link.dst_node, "_topology_id", str(id(link.dst_node))),
                "protocol": link.protocol,
                # Persist the visual and functional MitM relationship.  The
                # old format only stored the endpoints, so loaded topologies
                # silently lost their intercepted-link state.
                "threat_agent_ids": [
                    getattr(agent, "_topology_id", str(id(agent)))
                    for agent in link._threat_agents
                ],
            })

        return {"format": "GridSecSim", "version": 2, "nodes": nodes_data, "links": links_data}

    def load_topology(self, data: dict) -> None:
        """Restore a topology from a previously saved dict."""
        self.clear_canvas()

        id_map: Dict[Any, BaseNode] = {}

        for nd in data.get("nodes", []):
            node_type = nd.get("node_type", NodeType.PMU)
            label     = nd.get("label", "")
            node      = self.add_node(node_type, QPointF(nd.get("x", 0), nd.get("y", 0)))
            node.set_config(nd)
            node._label_item.setPlainText(nd.get("label", label))
            topology_id = nd.get("id", nd.get("_id", str(uuid.uuid4())))
            node._topology_id = str(topology_id)
            # Accept the legacy runtime-ID format as well as v2 IDs.
            id_map[topology_id] = node
            id_map[str(topology_id)] = node

        loaded_links = []
        for ld in data.get("links", []):
            src_key, dst_key = ld.get("src_id"), ld.get("dst_id")
            src = id_map.get(src_key) or id_map.get(str(src_key))
            dst = id_map.get(dst_key) or id_map.get(str(dst_key))
            if src and dst:
                link = self.add_link(src, dst, ld.get("protocol", "C37.118"))
                loaded_links.append((link, ld))

        # Restore MitM attachments after every link exists.  This remains
        # backwards compatible with legacy files: no attachment list simply
        # means the topology loads as it did before.
        for link, ld in loaded_links:
            for agent_id in ld.get("threat_agent_ids", []):
                agent = id_map.get(agent_id) or id_map.get(str(agent_id))
                if isinstance(agent, ThreatAgentNode):
                    link.add_threat_agent(agent)
                    agent._config["intercepted_link"] = id(link)

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

    def get_state_pdc_nodes(self) -> List[StatePDCNode]:
        return [n for n in self._nodes if n.node_type == NodeType.STATE_PDC]

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

        # Breaker toggle
        if node.node_type == NodeType.BREAKER:
            state = node._config.get("state", "closed")
            toggle_text = "Open Breaker" if state == "closed" else "Close Breaker"
            act_toggle = menu.addAction(toggle_text)
            act_toggle.triggered.connect(lambda: self._toggle_breaker(node))

        # State PDC regional uplink
        if node.node_type == NodeType.STATE_PDC:
            uplink = node._config.get("regional_uplink_connected", False)
            uplink_text = "Disconnect Regional Uplink" if uplink else "Connect Regional Uplink"
            act_uplink = menu.addAction(uplink_text)
            act_uplink.triggered.connect(lambda: self._toggle_regional_uplink(node))

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
        for proto in ["C37.118", "DNP3", "Modbus", "IEC104", "GOOSE"]:
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

    def _toggle_breaker(self, node: BaseNode) -> None:
        """Toggle breaker state between open and closed."""
        current = node._config.get("state", "closed")
        node._config["state"] = "open" if current == "closed" else "closed"
        node.update()
        self.signals.node_config_changed.emit(node)

    def _toggle_regional_uplink(self, node: BaseNode) -> None:
        """Toggle regional uplink connection on State PDC."""
        current = node._config.get("regional_uplink_connected", False)
        node._config["regional_uplink_connected"] = not current
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

        # ── Space + left-click OR middle-click = PAN ─────────────────────
        if event.button() == Qt.MouseButton.MiddleButton or (
            event.button() == Qt.MouseButton.LeftButton and self._space_held
        ):
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
                            self.add_link(self._link_start_node, node)
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
        if event.button() == Qt.MouseButton.MiddleButton or (
            event.button() == Qt.MouseButton.LeftButton and self._pan_active
        ):
            self._pan_active = False
            # Restore cursor: open hand if space still held, else arrow
            if self._space_held:
                self.setCursor(Qt.CursorShape.OpenHandCursor)
            else:
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
        if event.key() == Qt.Key.Key_Space and not event.isAutoRepeat():
            # Enter hand/pan mode while space is held
            self._space_held = True
            self.setCursor(Qt.CursorShape.OpenHandCursor)
            event.accept()
            return
        if event.key() in (Qt.Key.Key_Delete, Qt.Key.Key_Backspace):
            self.delete_selected()
        elif event.key() == Qt.Key.Key_Escape:
            self._cancel_drawing()
            self.set_mode("select")
        elif event.key() == Qt.Key.Key_F:
            self.zoom_fit()
        super().keyPressEvent(event)

    def keyReleaseEvent(self, event) -> None:
        if event.key() == Qt.Key.Key_Space and not event.isAutoRepeat():
            # Exit hand/pan mode
            self._space_held = False
            self._pan_active = False
            self.setCursor(Qt.CursorShape.ArrowCursor)
            event.accept()
            return
        super().keyReleaseEvent(event)

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

    # ── Selection change (FIX: this was never connected before) ──────────────

    def _handle_selection_change(self) -> None:
        """Called when scene selection changes — updates Properties panel."""
        selected = self._scene.selectedItems()
        for item in selected:
            if isinstance(item, BaseNode):
                self.signals.node_selected.emit(item)
                return
            if isinstance(item, LinkItem):
                self.signals.link_selected.emit(item)
                return
        # Nothing selected — clear properties
        self.signals.node_selected.emit(None)

    def set_simulation_running(self, running: bool) -> None:
        """Visual feedback — mark PMU and proxy nodes as active."""
        for node in self._nodes:
            if node.node_type in (NodeType.PMU, NodeType.THREAT_AGENT):
                node._config["running"] = running
                node._config["active"]  = running
                node.update()
