"""
gui/node_types.py
=================
QGraphicsItem subclasses for all topology node types.

Node types:
  - PMUNode      — green circle   (Phasor Measurement Unit)
  - PDCNode      — blue rectangle (data concentrator / openPDC)
  - SwitchNode   — gray diamond   (network switch)
  - ThreatAgentNode — red triangle with ⚠ symbol (MitM attacker)
  - VirtualNode  — purple circle  (generic virtual device)

Also:
  - LinkItem     — directed line between two nodes with protocol label
  - NodeLabel    — text label below a node

All items emit signals via NodeSignalBridge (a QObject relay) for
thread-safe communication with the main window.
"""

import math
from typing import Optional, Dict, Any, List, TYPE_CHECKING

from PyQt6.QtCore import (
    Qt, QPointF, QRectF, pyqtSignal, QObject
)
from PyQt6.QtGui import (
    QBrush, QColor, QPen, QPainter, QPainterPath,
    QFont, QFontMetrics, QPolygonF, QLinearGradient
)
from PyQt6.QtWidgets import (
    QGraphicsItem, QGraphicsObject, QGraphicsTextItem,
    QStyleOptionGraphicsItem, QWidget, QGraphicsLineItem
)

if TYPE_CHECKING:
    from gui.canvas import TopologyCanvas


# ─────────────────────────────────────────────────────────────────────────────
# Signal bridge (QObject needed for signals in QGraphicsItem)
# ─────────────────────────────────────────────────────────────────────────────

class NodeSignalBridge(QObject):
    """Relay object that emits signals on behalf of QGraphicsItem nodes."""
    node_selected    = pyqtSignal(object)   # emits the node item
    node_moved       = pyqtSignal(object)   # emits the node item
    node_double_clicked = pyqtSignal(object)
    node_right_clicked  = pyqtSignal(object)
    link_clicked        = pyqtSignal(object)


# Shared global signal bridge — imported by canvas.py
node_signals = NodeSignalBridge()


# ─────────────────────────────────────────────────────────────────────────────
# Node type constants
# ─────────────────────────────────────────────────────────────────────────────

class NodeType:
    PMU          = "PMU"
    PDC          = "PDC"
    SWITCH       = "SWITCH"
    THREAT_AGENT = "THREAT_AGENT"
    VIRTUAL      = "VIRTUAL"


NODE_DISPLAY_NAMES = {
    NodeType.PMU:          "PMU",
    NodeType.PDC:          "PDC / openPDC",
    NodeType.SWITCH:       "Switch",
    NodeType.THREAT_AGENT: "Threat Agent",
    NodeType.VIRTUAL:      "Virtual Node",
}

NODE_DESCRIPTIONS = {
    NodeType.PMU:          "Phasor Measurement Unit — generates C37.118 synchrophasor data",
    NodeType.PDC:          "Phasor Data Concentrator — receives and aggregates PMU data",
    NodeType.SWITCH:       "Network switch — routes traffic between nodes",
    NodeType.THREAT_AGENT: "MitM attacker — intercepts and modifies traffic on a link",
    NodeType.VIRTUAL:      "Generic virtual device",
}

NODE_COLORS = {
    NodeType.PMU:          "#10b981",   # green
    NodeType.PDC:          "#3b82f6",   # blue
    NodeType.SWITCH:       "#64748b",   # gray
    NodeType.THREAT_AGENT: "#ef4444",   # red
    NodeType.VIRTUAL:      "#8b5cf6",   # purple
}

NODE_ICON_TEXT = {
    NodeType.PMU:          "PMU",
    NodeType.PDC:          "PDC",
    NodeType.SWITCH:       "SW",
    NodeType.THREAT_AGENT: "!!",
    NodeType.VIRTUAL:      "VN",
}


# ─────────────────────────────────────────────────────────────────────────────
# Base node class
# ─────────────────────────────────────────────────────────────────────────────

class BaseNode(QGraphicsItem):
    """
    Abstract base for all topology nodes.

    Provides:
    - Selection highlight (glow effect via extra pen)
    - Drag-and-drop movement
    - Right-click context menu emission
    - Double-click config emission
    - Config dict serialization / deserialization
    """

    NODE_SIZE = 56      # bounding box half-width/height (shape fills this)

    def __init__(self, node_type: str, label: str = ""):
        super().__init__()

        self.node_type = node_type
        self._label    = label or NODE_DISPLAY_NAMES.get(node_type, node_type)
        self._config: Dict[str, Any] = {
            "node_type": node_type,
            "label":     self._label,
            "ip":        "127.0.0.1",
            "port":      4712,
            "proto":     "UDP",
        }

        # Visual
        self._color       = QColor(NODE_COLORS.get(node_type, "#7c3aed"))
        self._icon_text   = NODE_ICON_TEXT.get(node_type, "?")
        self._selected_glow = False

        # Ports (connection points — list of QPointF relative to node center)
        self._ports: List[QPointF] = []
        self._connected_links: List["LinkItem"] = []

        # Qt flags
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsFocusable)
        self.setAcceptHoverEvents(True)
        self.setCacheMode(QGraphicsItem.CacheMode.DeviceCoordinateCache)

        # Text label item (child)
        self._label_item = QGraphicsTextItem(self._label, self)
        font = QFont("Segoe UI", 9, QFont.Weight.Medium)
        self._label_item.setFont(font)
        self._label_item.setDefaultTextColor(QColor("#e2e8f0"))
        self._label_item.setPos(-self._label_item.boundingRect().width() / 2,
                                 self.NODE_SIZE / 2 + 4)

    # ── QGraphicsItem required methods ─────────────────────────────────────

    def boundingRect(self) -> QRectF:
        s = self.NODE_SIZE
        return QRectF(-s, -s, s * 2, s * 2)

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        s = self.NODE_SIZE
        path.addEllipse(QRectF(-s * 0.8, -s * 0.8, s * 1.6, s * 1.6))
        return path

    def paint(self, painter: QPainter, option: QStyleOptionGraphicsItem, widget: QWidget) -> None:
        raise NotImplementedError("Subclasses must implement paint()")

    # ── Helpers ────────────────────────────────────────────────────────────

    def _draw_selection_glow(self, painter: QPainter) -> None:
        if self.isSelected():
            pen = QPen(QColor("#7c3aed"), 3, Qt.PenStyle.SolidLine)
            pen.setCosmetic(False)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            r = self.NODE_SIZE * 0.88
            painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

    def _draw_icon(self, painter: QPainter) -> None:
        # Use DejaVu Sans Bold — always available on Ubuntu/WSL2
        font = QFont("DejaVu Sans", 11, QFont.Weight.Bold)
        painter.setFont(font)
        painter.setPen(QColor("#ffffff"))
        fm  = QFontMetrics(font)
        br  = fm.boundingRect(self._icon_text)
        painter.drawText(
            int(-br.width() / 2),
            int(br.height() / 3),
            self._icon_text,
        )

    def _draw_label(self, painter: QPainter) -> None:
        pass  # handled by QGraphicsTextItem child

    # ── Config ─────────────────────────────────────────────────────────────

    def get_config(self) -> dict:
        cfg = dict(self._config)
        cfg["x"] = self.pos().x()
        cfg["y"] = self.pos().y()
        return cfg

    def set_config(self, cfg: dict) -> None:
        self._config.update(cfg)
        label = cfg.get("label", self._label)
        self._label = label
        self._label_item.setPlainText(label)
        # Re-centre label
        self._label_item.setPos(
            -self._label_item.boundingRect().width() / 2,
             self.NODE_SIZE / 2 + 4,
        )
        self.update()

    @property
    def ip(self)    -> str:  return self._config.get("ip", "127.0.0.1")
    @property
    def port(self)  -> int:  return int(self._config.get("port", 4712))
    @property
    def proto(self) -> str:  return self._config.get("proto", "UDP")
    @property
    def label(self) -> str:  return self._label

    # ── Links ──────────────────────────────────────────────────────────────

    def add_link(self, link: "LinkItem") -> None:
        if link not in self._connected_links:
            self._connected_links.append(link)

    def remove_link(self, link: "LinkItem") -> None:
        if link in self._connected_links:
            self._connected_links.remove(link)

    def get_links(self) -> List["LinkItem"]:
        return list(self._connected_links)

    # ── Connection point ───────────────────────────────────────────────────

    def get_connection_point(self, toward: QPointF) -> QPointF:
        """Return the point on the node perimeter closest to `toward`."""
        center = self.scenePos()
        dx     = toward.x() - center.x()
        dy     = toward.y() - center.y()
        dist   = math.hypot(dx, dy) or 1.0
        r      = self.NODE_SIZE * 0.72
        return QPointF(center.x() + dx / dist * r, center.y() + dy / dist * r)

    # ── Qt events ──────────────────────────────────────────────────────────

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged:
            # Update all connected links
            for link in self._connected_links:
                link.update_geometry()
            node_signals.node_moved.emit(self)
        return super().itemChange(change, value)

    def mouseDoubleClickEvent(self, event) -> None:
        node_signals.node_double_clicked.emit(self)

    def contextMenuEvent(self, event) -> None:
        self.setSelected(True)
        node_signals.node_right_clicked.emit(self)
        event.accept()

    def hoverEnterEvent(self, event) -> None:
        self.setToolTip(
            f"<b>{self._label}</b><br>"
            f"{NODE_DESCRIPTIONS.get(self.node_type, '')}<br>"
            f"<small>IP: {self.ip}  Port: {self.port}  {self.proto}</small>"
        )
        self.update()

    def hoverLeaveEvent(self, event) -> None:
        self.update()


# ─────────────────────────────────────────────────────────────────────────────
# Concrete node types
# ─────────────────────────────────────────────────────────────────────────────

class PMUNode(BaseNode):
    """Green circle — Phasor Measurement Unit."""

    def __init__(self, label: str = "PMU-1"):
        super().__init__(NodeType.PMU, label)
        self._config["port"] = 4712

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.NODE_SIZE * 0.75

        # Outer glow when running
        if self._config.get("running"):
            glow_pen = QPen(QColor("#10b981"), 6, Qt.PenStyle.SolidLine)
            glow_pen.setCosmetic(False)
            painter.setPen(glow_pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawEllipse(QRectF(-r - 4, -r - 4, (r + 4) * 2, (r + 4) * 2))

        # Gradient fill
        grad = QLinearGradient(QPointF(-r, -r), QPointF(r, r))
        grad.setColorAt(0, QColor("#1de9b6"))
        grad.setColorAt(1, QColor("#10b981"))
        painter.setPen(QPen(QColor("#059669"), 2))
        painter.setBrush(QBrush(grad))
        painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

        self._draw_icon(painter)
        self._draw_selection_glow(painter)


class PDCNode(BaseNode):
    """Blue rectangle — PDC / openPDC."""

    def __init__(self, label: str = "PDC-1"):
        super().__init__(NodeType.PDC, label)
        self._config["port"] = 4713

    def boundingRect(self) -> QRectF:
        s = self.NODE_SIZE
        return QRectF(-s, -s * 0.75, s * 2, s * 1.8)

    def shape(self) -> QPainterPath:
        path = QPainterPath()
        path.addRoundedRect(QRectF(-self.NODE_SIZE * 0.85, -self.NODE_SIZE * 0.65,
                                    self.NODE_SIZE * 1.7, self.NODE_SIZE * 1.3), 8, 8)
        return path

    def get_connection_point(self, toward: QPointF) -> QPointF:
        center = self.scenePos()
        dx     = toward.x() - center.x()
        dy     = toward.y() - center.y()
        dist   = math.hypot(dx, dy) or 1.0
        rx     = self.NODE_SIZE * 0.85
        ry     = self.NODE_SIZE * 0.65
        # Clip to rectangle edge
        scale  = min(abs(rx / (dx or 1e-9)), abs(ry / (dy or 1e-9)))
        return QPointF(center.x() + dx * scale, center.y() + dy * scale)

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rx, ry = self.NODE_SIZE * 0.85, self.NODE_SIZE * 0.65

        grad = QLinearGradient(QPointF(-rx, -ry), QPointF(rx, ry))
        grad.setColorAt(0, QColor("#60a5fa"))
        grad.setColorAt(1, QColor("#2563eb"))
        painter.setPen(QPen(QColor("#1d4ed8"), 2))
        painter.setBrush(QBrush(grad))
        painter.drawRoundedRect(QRectF(-rx, -ry, rx * 2, ry * 2), 8, 8)

        self._draw_icon(painter)
        self._draw_selection_glow(painter)


class SwitchNode(BaseNode):
    """Gray diamond — network switch."""

    def __init__(self, label: str = "SW-1"):
        super().__init__(NodeType.SWITCH, label)
        self._icon_text = "SW"

    def shape(self) -> QPainterPath:
        s = self.NODE_SIZE * 0.78
        poly = QPolygonF([
            QPointF(0, -s),
            QPointF(s, 0),
            QPointF(0, s),
            QPointF(-s, 0),
        ])
        path = QPainterPath()
        path.addPolygon(poly)
        path.closeSubpath()
        return path

    def get_connection_point(self, toward: QPointF) -> QPointF:
        center = self.scenePos()
        dx = toward.x() - center.x()
        dy = toward.y() - center.y()
        dist = math.hypot(dx, dy) or 1.0
        r = self.NODE_SIZE * 0.7
        return QPointF(center.x() + dx / dist * r, center.y() + dy / dist * r)

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = self.NODE_SIZE * 0.78

        poly = QPolygonF([
            QPointF(0, -s),
            QPointF(s, 0),
            QPointF(0, s),
            QPointF(-s, 0),
        ])

        grad = QLinearGradient(QPointF(-s, -s), QPointF(s, s))
        grad.setColorAt(0, QColor("#94a3b8"))
        grad.setColorAt(1, QColor("#475569"))
        painter.setPen(QPen(QColor("#334155"), 2))
        painter.setBrush(QBrush(grad))
        painter.drawPolygon(poly)

        self._draw_icon(painter)
        self._draw_selection_glow(painter)


class ThreatAgentNode(BaseNode):
    """Red triangle with skull — MitM attacker."""

    def __init__(self, label: str = "Threat-1"):
        super().__init__(NodeType.THREAT_AGENT, label)
        self._icon_text = "!!"
        self._pulse_phase = 0.0

    def shape(self) -> QPainterPath:
        s = self.NODE_SIZE * 0.8
        poly = QPolygonF([
            QPointF(0, -s),
            QPointF(s * 0.866, s * 0.5),
            QPointF(-s * 0.866, s * 0.5),
        ])
        path = QPainterPath()
        path.addPolygon(poly)
        path.closeSubpath()
        return path

    def get_connection_point(self, toward: QPointF) -> QPointF:
        center = self.scenePos()
        dx = toward.x() - center.x()
        dy = toward.y() - center.y()
        dist = math.hypot(dx, dy) or 1.0
        r = self.NODE_SIZE * 0.7
        return QPointF(center.x() + dx / dist * r, center.y() + dy / dist * r)

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = self.NODE_SIZE * 0.8

        poly = QPolygonF([
            QPointF(0, -s),
            QPointF(s * 0.866, s * 0.5),
            QPointF(-s * 0.866, s * 0.5),
        ])

        # Pulsing red glow when selected or active
        active = self._config.get("active", False)
        if active or self.isSelected():
            glow = QPen(QColor(239, 68, 68, 120), 8)
            painter.setPen(glow)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPolygon(poly)

        grad = QLinearGradient(QPointF(0, -s), QPointF(0, s))
        grad.setColorAt(0, QColor("#f87171"))
        grad.setColorAt(1, QColor("#991b1b"))
        painter.setPen(QPen(QColor("#7f1d1d"), 2))
        painter.setBrush(QBrush(grad))
        painter.drawPolygon(poly)

        self._draw_icon(painter)
        self._draw_selection_glow(painter)


class VirtualNode(BaseNode):
    """Purple circle — generic virtual device."""

    def __init__(self, label: str = "VNode-1"):
        super().__init__(NodeType.VIRTUAL, label)
        self._icon_text = "VN"

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self.NODE_SIZE * 0.75

        grad = QLinearGradient(QPointF(-r, -r), QPointF(r, r))
        grad.setColorAt(0, QColor("#c4b5fd"))
        grad.setColorAt(1, QColor("#7c3aed"))
        painter.setPen(QPen(QColor("#5b21b6"), 2))
        painter.setBrush(QBrush(grad))
        painter.drawEllipse(QRectF(-r, -r, r * 2, r * 2))

        self._draw_icon(painter)
        self._draw_selection_glow(painter)


# ─────────────────────────────────────────────────────────────────────────────
# Link item
# ─────────────────────────────────────────────────────────────────────────────

PROTOCOL_COLORS = {
    "C37.118": "#a78bfa",
    "DNP3":    "#fbbf24",
    "Modbus":  "#34d399",
    "IEC104":  "#60a5fa",
    "GOOSE":   "#f97316",   # orange — IEC 61850 GOOSE
    "Unknown": "#64748b",
}


class LinkItem(QGraphicsItem):
    """
    Directed connection line between two nodes.

    Draws:
    - Solid line with arrowhead (direction: src → dst)
    - Protocol label in the middle
    - Highlight when selected

    When a ThreatAgentNode is placed on a link, that link becomes "intercepted"
    and is drawn in red with a dashed style.
    """

    def __init__(
        self,
        src_node: BaseNode,
        dst_node: BaseNode,
        protocol: str = "C37.118",
    ):
        super().__init__()
        self.src_node = src_node
        self.dst_node = dst_node
        self.protocol = protocol
        self._threat_agents: List[ThreatAgentNode] = []
        self._intercepted = False

        # Register with nodes
        src_node.add_link(self)
        dst_node.add_link(self)

        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setZValue(-1)   # draw below nodes
        self.setAcceptHoverEvents(True)

        # Geometry (updated by update_geometry)
        self._src_pt = QPointF()
        self._dst_pt = QPointF()
        self.update_geometry()

    def update_geometry(self) -> None:
        """Recalculate endpoint positions from node positions."""
        self.prepareGeometryChange()
        src_center = self.src_node.scenePos()
        dst_center = self.dst_node.scenePos()
        self._src_pt = self.src_node.get_connection_point(dst_center)
        self._dst_pt = self.dst_node.get_connection_point(src_center)

    def boundingRect(self) -> QRectF:
        # Expand by 20px to include label + arrow
        x_min = min(self._src_pt.x(), self._dst_pt.x()) - 20
        y_min = min(self._src_pt.y(), self._dst_pt.y()) - 20
        x_max = max(self._src_pt.x(), self._dst_pt.x()) + 20
        y_max = max(self._src_pt.y(), self._dst_pt.y()) + 20
        return QRectF(QPointF(x_min, y_min), QPointF(x_max, y_max))

    def paint(self, painter, option, widget):
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        src = self._src_pt
        dst = self._dst_pt

        # Colors
        if self._intercepted:
            line_color = QColor("#ef4444")
            style      = Qt.PenStyle.DashLine
        else:
            line_color = QColor(PROTOCOL_COLORS.get(self.protocol, "#64748b"))
            style      = Qt.PenStyle.SolidLine

        width = 3 if self.isSelected() else 2
        pen   = QPen(line_color, width, style)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        painter.setPen(pen)
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawLine(src, dst)

        # Arrowhead at dst
        self._draw_arrowhead(painter, src, dst, line_color)

        # Protocol label in center
        mid = QPointF((src.x() + dst.x()) / 2, (src.y() + dst.y()) / 2)
        self._draw_label(painter, mid)

    def _draw_arrowhead(self, painter, src, dst, color):
        dx  = dst.x() - src.x()
        dy  = dst.y() - src.y()
        dist = math.hypot(dx, dy)
        if dist < 1:
            return
        ux, uy = dx / dist, dy / dist
        size = 10
        perp_x, perp_y = -uy * size * 0.4, ux * size * 0.4
        tip   = dst
        base1 = QPointF(dst.x() - ux * size + perp_x, dst.y() - uy * size + perp_y)
        base2 = QPointF(dst.x() - ux * size - perp_x, dst.y() - uy * size - perp_y)
        poly  = QPolygonF([tip, base1, base2])
        painter.setBrush(QBrush(color))
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawPolygon(poly)

    def _draw_label(self, painter, center):
        font = QFont("Segoe UI", 9, QFont.Weight.Medium)
        painter.setFont(font)
        fm   = QFontMetrics(font)
        text = self.protocol
        if self._threat_agents:
            text = f"[!] {text}"
        rect = fm.boundingRect(text)

        # Background pill
        bg_rect = QRectF(
            center.x() - rect.width() / 2 - 5,
            center.y() - rect.height() / 2 - 2,
            rect.width() + 10,
            rect.height() + 4,
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(30, 30, 46, 200)))
        painter.drawRoundedRect(bg_rect, 4, 4)

        text_color = QColor("#ef4444") if self._threat_agents else QColor(PROTOCOL_COLORS.get(self.protocol, "#e2e8f0"))
        painter.setPen(text_color)
        painter.drawText(
            int(center.x() - rect.width() / 2),
            int(center.y() + rect.height() / 4),
            text
        )

    def add_threat_agent(self, agent: ThreatAgentNode) -> None:
        if agent not in self._threat_agents:
            self._threat_agents.append(agent)
            self._intercepted = True
            self.update()

    def remove_threat_agent(self, agent: ThreatAgentNode) -> None:
        if agent in self._threat_agents:
            self._threat_agents.remove(agent)
            self._intercepted = bool(self._threat_agents)
            self.update()

    @property
    def is_intercepted(self) -> bool:
        return self._intercepted

    def to_dict(self) -> dict:
        return {
            "src_id":   id(self.src_node),
            "dst_id":   id(self.dst_node),
            "protocol": self.protocol,
            "intercepted": self._intercepted,
        }

    def mouseDoubleClickEvent(self, event):
        node_signals.link_clicked.emit(self)

    def contextMenuEvent(self, event):
        self.setSelected(True)
        node_signals.link_clicked.emit(self)
        event.accept()


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

NODE_CLASSES = {
    NodeType.PMU:          PMUNode,
    NodeType.PDC:          PDCNode,
    NodeType.SWITCH:       SwitchNode,
    NodeType.THREAT_AGENT: ThreatAgentNode,
    NodeType.VIRTUAL:      VirtualNode,
}

def create_node(node_type: str, label: str = "", config: Optional[dict] = None) -> BaseNode:
    """Create a node of the given type, optionally restoring config."""
    cls  = NODE_CLASSES.get(node_type, VirtualNode)
    node = cls(label=label or "")
    if config:
        node.set_config(config)
    return node
