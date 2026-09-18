"""
gui/integration_panel.py
========================
GridSec Sim — External Tool Integrations Panel

Provides a tabbed UI for configuring and monitoring all integrations:
  Tab 1: Capture   — pcap file + Wireshark FIFO, Zeek, Security Onion
  Tab 2: Syslog    — CEF syslog for Dragos, Claroty, Splunk, QRadar
  Tab 3: REST API  — expose REST endpoints for any tool to consume
  Tab 4: Export    — STIX 2.1, CSV, JSON, pcap download
  Tab 5: Guides    — step-by-step connection guides for each tool
"""

import os
import shutil
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Optional

from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QUrl
from PyQt6.QtGui import QFont, QColor, QDesktopServices
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox,
    QComboBox, QTextEdit, QFrame, QTabWidget, QStackedWidget,
    QFileDialog, QGroupBox, QScrollArea, QSizePolicy,
    QMessageBox, QApplication,
)


# ── Shared styles ──────────────────────────────────────────────────────────────

_BTN_PRIMARY = """
    QPushButton {
        background: #7c3aed; color: #fff; border: none;
        border-radius: 5px; padding: 6px 14px; font-weight: 600;
        font-size: 12px;
    }
    QPushButton:hover   { background: #6d28d9; }
    QPushButton:pressed { background: #5b21b6; }
    QPushButton:disabled{ background: #3d3d5c; color: #64748b; }
"""
_BTN_SUCCESS = """
    QPushButton {
        background: #059669; color: #fff; border: none;
        border-radius: 5px; padding: 6px 14px; font-weight: 600; font-size: 12px;
    }
    QPushButton:hover { background: #047857; }
    QPushButton:disabled { background: #3d3d5c; color: #64748b; }
"""
_BTN_DANGER = """
    QPushButton {
        background: #dc2626; color: #fff; border: none;
        border-radius: 5px; padding: 6px 14px; font-weight: 600; font-size: 12px;
    }
    QPushButton:hover { background: #b91c1c; }
    QPushButton:disabled { background: #3d3d5c; color: #64748b; }
"""
_BTN_NEUTRAL = """
    QPushButton {
        background: #334155; color: #94a3b8; border: 1px solid #3d3d5c;
        border-radius: 5px; padding: 6px 12px; font-size: 11px;
    }
    QPushButton:hover { background: #3d4f65; color: #e2e8f0; }
"""
_INPUT = """
    QLineEdit, QSpinBox, QComboBox {
        background: #1a1a2e; border: 1px solid #3d3d5c; border-radius: 4px;
        color: #e2e8f0; padding: 4px 8px; font-size: 12px;
    }
    QLineEdit:focus, QSpinBox:focus { border-color: #7c3aed; }
"""
_LABEL_H = "color: #a78bfa; font-weight: 700; font-size: 11px;"
_LABEL   = "color: #94a3b8; font-size: 12px;"
_STATUS_ON  = "color: #34d399; font-size: 12px; font-weight: 600;"
_STATUS_OFF = "color: #64748b; font-size: 12px;"
_STATUS_ERR = "color: #ef4444; font-size: 12px;"


def _sep() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setStyleSheet("border: none; background: #2d2d44; max-height: 1px;")
    return f


def _section(title: str) -> QLabel:
    l = QLabel(title)
    l.setStyleSheet(_LABEL_H)
    return l


def _lbl(text: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(_LABEL)
    return l


def _copy_btn(text_widget) -> QPushButton:
    b = QPushButton("Copy")
    b.setStyleSheet(_BTN_NEUTRAL)
    b.setFixedWidth(55)
    b.clicked.connect(lambda: QApplication.clipboard().setText(text_widget.text()))
    return b


# ── Signal relay ───────────────────────────────────────────────────────────────

class IntegrationSignals(QObject):
    status_updated = pyqtSignal()


# ── Capture tab ───────────────────────────────────────────────────────────────

class CaptureTab(QWidget):
    """pcap capture + Wireshark / Zeek / Security Onion integration."""

    def __init__(self, manager_ref, parent=None):
        super().__init__(parent)
        self._mgr = manager_ref
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        layout.addWidget(_section("pcap Capture"))
        layout.addWidget(_sep())

        # File path
        path_row = QHBoxLayout()
        path_row.addWidget(_lbl("Output file:"))
        self._path_edit = QLineEdit(self._default_capture_path())
        self._path_edit.setStyleSheet(_INPUT)
        path_row.addWidget(self._path_edit, 1)
        browse = QPushButton("Browse")
        browse.setStyleSheet(_BTN_NEUTRAL)
        browse.clicked.connect(self._browse)
        path_row.addWidget(browse)
        layout.addLayout(path_row)

        # FIFO option
        self._fifo_cb = QCheckBox("Use named FIFO pipe (Wireshark connects live)")
        self._fifo_cb.setStyleSheet("color: #94a3b8;")
        self._fifo_cb.toggled.connect(self._on_fifo_toggled)
        if os.name == "nt":
            self._fifo_cb.setToolTip("Live FIFO capture requires GridSec Sim to run inside Linux/WSL.")
            self._fifo_cb.setEnabled(False)
        layout.addWidget(self._fifo_cb)

        # Wireshark command
        self._ws_cmd = QLineEdit()
        self._ws_cmd.setReadOnly(True)
        self._ws_cmd.setStyleSheet(_INPUT + "color: #34d399;")
        self._ws_cmd.setText(self._wireshark_command(self._path_edit.text()))
        ws_row = QHBoxLayout()
        ws_row.addWidget(_lbl("Wireshark cmd:"))
        ws_row.addWidget(self._ws_cmd, 1)
        ws_row.addWidget(_copy_btn(self._ws_cmd))
        layout.addLayout(ws_row)

        # Zeek command
        self._zeek_cmd = QLineEdit("zeek -r /tmp/gridsec_capture.pcap local")
        self._zeek_cmd.setReadOnly(True)
        self._zeek_cmd.setStyleSheet(_INPUT + "color: #34d399;")
        z_row = QHBoxLayout()
        z_row.addWidget(_lbl("Zeek cmd:"))
        z_row.addWidget(self._zeek_cmd, 1)
        z_row.addWidget(_copy_btn(self._zeek_cmd))
        layout.addLayout(z_row)

        layout.addWidget(_sep())

        # Control buttons
        btn_row = QHBoxLayout()
        self._start_btn = QPushButton("Start Capture")
        self._start_btn.setStyleSheet(_BTN_SUCCESS)
        self._start_btn.clicked.connect(self._start_capture)
        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet(_BTN_DANGER)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_capture)
        self._ws_btn = QPushButton("Open Wireshark")
        self._ws_btn.setStyleSheet(_BTN_PRIMARY)
        self._ws_btn.clicked.connect(self._open_wireshark)
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        btn_row.addWidget(self._ws_btn)
        layout.addLayout(btn_row)

        # Status
        self._status_lbl = QLabel("● Not capturing")
        self._status_lbl.setStyleSheet(_STATUS_OFF)
        self._pkt_lbl = QLabel("Packets: 0")
        self._pkt_lbl.setStyleSheet(_LABEL)
        status_row = QHBoxLayout()
        status_row.addWidget(self._status_lbl)
        status_row.addStretch()
        status_row.addWidget(self._pkt_lbl)
        layout.addLayout(status_row)

        layout.addWidget(_sep())
        layout.addWidget(_section("Compatible Tools"))

        compat = QLabel(
            "Wireshark   Zeek / Bro   Security Onion\n"
            "Arkime (Moloch)   NetworkMiner   tcpdump   tshark"
        )
        compat.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(compat)

        layout.addStretch()

    def _on_fifo_toggled(self, checked: bool):
        if checked:
            path = "/tmp/gridsec_live.pcap"
            self._path_edit.setText(path)
            self._ws_cmd.setText(f"wireshark -k -i {path}")
            self._zeek_cmd.setText(f"# Zeek does not support FIFO; use file mode")
        else:
            path = "/tmp/gridsec_capture.pcap"
            self._path_edit.setText(path)
            self._ws_cmd.setText(f"wireshark {path}")
            self._zeek_cmd.setText(f"zeek -r {path} local")

    @staticmethod
    def _default_capture_path() -> str:
        if os.name == "nt":
            return str(Path.home() / "Documents" / "GridSecSim" / "gridsec_capture.pcap")
        return "/tmp/gridsec_capture.pcap"

    @staticmethod
    def _windows_to_wsl_path(path: str) -> str:
        """Convert C:\\... into /mnt/c/... for a WSL-launched Wireshark."""
        drive, tail = os.path.splitdrive(os.path.abspath(path))
        if drive:
            return f"/mnt/{drive[0].lower()}{tail.replace(os.sep, '/')}"
        return path

    def _wireshark_command(self, path: str) -> str:
        if os.name == "nt" and not (shutil.which("wireshark") or shutil.which("wireshark.exe")):
            return f"wsl wireshark {self._windows_to_wsl_path(path)}"
        return f"wireshark {path}"

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save pcap As", self._path_edit.text(),
            "pcap files (*.pcap);;All (*)"
        )
        if path:
            self._path_edit.setText(path)
            self._ws_cmd.setText(self._wireshark_command(path))

    def _start_capture(self):
        path     = self._path_edit.text().strip()
        use_fifo = self._fifo_cb.isChecked()
        if not use_fifo and os.path.isfile(path):
            answer = QMessageBox.question(
                self, "Replace Capture?", "This file already exists. Replace its contents?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        self._mgr.configure_pcap(path=path, use_fifo=use_fifo)
        result = self._mgr.start_pcap_only()
        if "error" in result.get("pcap", "").lower():
            self._status_lbl.setText(f"● Error: {result['pcap']}")
            self._status_lbl.setStyleSheet(_STATUS_ERR)
        else:
            self._status_lbl.setText("● Capturing...")
            self._status_lbl.setStyleSheet(_STATUS_ON)
            self._start_btn.setEnabled(False)
            self._stop_btn.setEnabled(True)
            self._path_edit.setEnabled(False)
            self._fifo_cb.setEnabled(False)

    def _stop_capture(self):
        self._mgr.stop_pcap_only()
        self._status_lbl.setText("● Stopped")
        self._status_lbl.setStyleSheet(_STATUS_OFF)
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._path_edit.setEnabled(True)
        self._fifo_cb.setEnabled(os.name != "nt")

    def _open_wireshark(self):
        path = self._mgr.pcap_path or self._path_edit.text().strip()
        use_fifo = self._fifo_cb.isChecked()
        if not os.path.exists(path):
            QMessageBox.information(self, "No Capture Yet", "Start Capture first, then run the simulation.")
            return
        try:
            native_wireshark = shutil.which("wireshark") or shutil.which("wireshark.exe")
            if native_wireshark:
                cmd = [native_wireshark, "-k", "-i", path] if use_fifo else [native_wireshark, path]
                subprocess.Popen(cmd)
            elif os.name == "nt" and shutil.which("wsl.exe"):
                wsl_path = self._windows_to_wsl_path(path)
                linux_cmd = f"exec wireshark {'-k -i ' if use_fifo else ''}{shlex.quote(wsl_path)}"
                subprocess.Popen(["wsl.exe", "-e", "bash", "-lc", linux_cmd])
            else:
                raise FileNotFoundError("Wireshark executable was not found")
            self._status_lbl.setText("● Wireshark launch requested")
            self._status_lbl.setStyleSheet(_STATUS_ON)
        except OSError:
            QMessageBox.warning(self, "Wireshark",
                "Wireshark not found.\n"
                "Install with: sudo apt install wireshark (WSL/Linux)\n"
                "or install the Windows Wireshark desktop application.\n\n"
                f"Or copy command:\n{self._ws_cmd.text()}")

    def update_stats(self):
        if self._mgr and self._mgr._pcap and self._mgr._pcap.error:
            self._status_lbl.setText(f"● Capture error: {self._mgr._pcap.error}")
            self._status_lbl.setStyleSheet(_STATUS_ERR)
        if self._mgr and self._mgr.pcap_packet_count > 0:
            self._pkt_lbl.setText(f"Packets: {self._mgr.pcap_packet_count:,}")


# ── Syslog tab ────────────────────────────────────────────────────────────────

class SyslogTab(QWidget):
    """Syslog / CEF export for Dragos, Claroty, Splunk, QRadar."""

    def __init__(self, manager_ref, parent=None):
        super().__init__(parent)
        self._mgr = manager_ref
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        layout.addWidget(_section("Syslog / CEF Configuration"))
        layout.addWidget(_sep())

        grid = QGridLayout()
        grid.setSpacing(8)

        grid.addWidget(_lbl("Host:"), 0, 0)
        self._host = QLineEdit("127.0.0.1")
        self._host.setStyleSheet(_INPUT)
        grid.addWidget(self._host, 0, 1)

        grid.addWidget(_lbl("Port:"), 1, 0)
        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(514)
        self._port.setStyleSheet(_INPUT)
        grid.addWidget(self._port, 1, 1)

        grid.addWidget(_lbl("Protocol:"), 2, 0)
        self._proto = QComboBox()
        self._proto.addItems(["UDP", "TCP"])
        self._proto.setStyleSheet(_INPUT)
        grid.addWidget(self._proto, 2, 1)

        layout.addLayout(grid)

        # Preset buttons
        layout.addWidget(_section("Quick Connect"))
        preset_row = QHBoxLayout()
        for tool, host in [("Dragos", ""), ("Claroty", ""),
                           ("Splunk", ""), ("Local", "127.0.0.1")]:
            b = QPushButton(tool)
            b.setStyleSheet(_BTN_NEUTRAL)
            h = host
            b.clicked.connect(lambda _, h=h: (
                self._host.setText(h or "YOUR_TOOL_IP"),
            ))
            preset_row.addWidget(b)
        layout.addLayout(preset_row)

        layout.addWidget(_sep())

        # Control
        btn_row = QHBoxLayout()
        self._test_btn   = QPushButton("Test Connection")
        self._test_btn.setStyleSheet(_BTN_NEUTRAL)
        self._test_btn.clicked.connect(self._test)
        self._enable_btn = QPushButton("Enable")
        self._enable_btn.setStyleSheet(_BTN_SUCCESS)
        self._enable_btn.clicked.connect(self._enable)
        self._disable_btn = QPushButton("Disable")
        self._disable_btn.setStyleSheet(_BTN_DANGER)
        self._disable_btn.setEnabled(False)
        self._disable_btn.clicked.connect(self._disable)
        btn_row.addWidget(self._test_btn)
        btn_row.addWidget(self._enable_btn)
        btn_row.addWidget(self._disable_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

        self._status_lbl = QLabel("● Not connected")
        self._status_lbl.setStyleSheet(_STATUS_OFF)
        self._sent_lbl   = QLabel("Sent: 0")
        self._sent_lbl.setStyleSheet(_LABEL)
        status_row = QHBoxLayout()
        status_row.addWidget(self._status_lbl)
        status_row.addStretch()
        status_row.addWidget(self._sent_lbl)
        layout.addLayout(status_row)

        layout.addWidget(_sep())
        layout.addWidget(_section("CEF Format Preview"))
        self._cef_preview = QTextEdit()
        self._cef_preview.setReadOnly(True)
        self._cef_preview.setMaximumHeight(90)
        self._cef_preview.setStyleSheet(
            "background:#0d0d1a; color:#34d399; font-family:monospace; font-size:10px;"
        )
        self._cef_preview.setPlainText(
            "CEF:0|GridSecSim|GridSec Sim|1.0|NOISE|ICS Attack - NOISE on C37.118|7|"
            "rt=1719399600000 src=10.0.0.1 dst=10.0.0.2 proto=C37.118 cat=NOISE outcome=attacked"
        )
        layout.addWidget(self._cef_preview)

        layout.addWidget(_sep())
        compat = QLabel("Dragos Platform   Claroty CTD   Splunk ES   IBM QRadar\n"
                        "ArcSight   Microsoft Sentinel   Nozomi   Any syslog receiver")
        compat.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(compat)
        layout.addStretch()

    def _test(self):
        host = self._host.text().strip()
        port = self._port.value()
        proto = self._proto.currentText()
        self._mgr.configure_syslog(host=host, port=port, protocol=proto)
        ok, msg = self._mgr.test_syslog()
        if ok:
            self._status_lbl.setText(f"● {msg}")
            self._status_lbl.setStyleSheet(_STATUS_ON)
        else:
            self._status_lbl.setText(f"● {msg}")
            self._status_lbl.setStyleSheet(_STATUS_ERR)

    def _enable(self):
        host  = self._host.text().strip()
        port  = self._port.value()
        proto = self._proto.currentText()
        self._mgr.configure_syslog(host=host, port=port, protocol=proto)
        result = self._mgr.start_syslog_only()["syslog"]
        if "error" in result.lower():
            self._status_lbl.setText(f"● {result}")
            self._status_lbl.setStyleSheet(_STATUS_ERR)
        else:
            self._status_lbl.setText(f"● Sending to {host}:{port}")
            self._status_lbl.setStyleSheet(_STATUS_ON)
            self._enable_btn.setEnabled(False)
            self._disable_btn.setEnabled(True)

    def _disable(self):
        self._mgr.stop_syslog_only()
        self._status_lbl.setText("● Disabled")
        self._status_lbl.setStyleSheet(_STATUS_OFF)
        self._enable_btn.setEnabled(True)
        self._disable_btn.setEnabled(False)

    def update_stats(self):
        self._sent_lbl.setText(f"Sent: {self._mgr.syslog_count:,}")


# ── REST API tab ──────────────────────────────────────────────────────────────

class RestAPITab(QWidget):
    """REST API server for Dragos, Claroty, custom tool integration."""

    def __init__(self, manager_ref, parent=None):
        super().__init__(parent)
        self._mgr = manager_ref
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        layout.addWidget(_section("REST API Server"))
        layout.addWidget(_sep())

        grid = QGridLayout()
        grid.setSpacing(8)
        grid.addWidget(_lbl("Listen IP:"), 0, 0)
        self._host = QLineEdit("127.0.0.1")
        self._host.setStyleSheet(_INPUT)
        grid.addWidget(self._host, 0, 1)
        grid.addWidget(_lbl("Port:"), 1, 0)
        self._port = QSpinBox()
        self._port.setRange(1024, 65535)
        self._port.setValue(8080)
        self._port.setStyleSheet(_INPUT)
        grid.addWidget(self._port, 1, 1)
        layout.addLayout(grid)

        # Auth
        self._auth_cb = QCheckBox("Enable API key authentication")
        self._auth_cb.setChecked(True)
        self._auth_cb.setStyleSheet("color: #94a3b8;")
        layout.addWidget(self._auth_cb)

        # API key display
        key_row = QHBoxLayout()
        key_row.addWidget(_lbl("API Key:"))
        self._key_edit = QLineEdit("(not started)")
        self._key_edit.setReadOnly(True)
        self._key_edit.setStyleSheet(_INPUT + "color: #fbbf24;")
        key_row.addWidget(self._key_edit, 1)
        key_row.addWidget(_copy_btn(self._key_edit))
        layout.addLayout(key_row)

        layout.addWidget(_sep())

        # Control
        btn_row = QHBoxLayout()
        self._start_btn = QPushButton("Start API Server")
        self._start_btn.setStyleSheet(_BTN_SUCCESS)
        self._start_btn.clicked.connect(self._start)
        self._stop_btn = QPushButton("Stop")
        self._stop_btn.setStyleSheet(_BTN_DANGER)
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop)
        self._browser_btn = QPushButton("Open Docs in Browser")
        self._browser_btn.setStyleSheet(_BTN_NEUTRAL)
        self._browser_btn.setEnabled(False)
        self._browser_btn.clicked.connect(self._open_browser)
        btn_row.addWidget(self._start_btn)
        btn_row.addWidget(self._stop_btn)
        btn_row.addStretch()
        btn_row.addWidget(self._browser_btn)
        layout.addLayout(btn_row)

        self._status_lbl = QLabel("● Not running")
        self._status_lbl.setStyleSheet(_STATUS_OFF)
        layout.addWidget(self._status_lbl)

        layout.addWidget(_sep())
        layout.addWidget(_section("Key Endpoints"))

        self._url_base = QLineEdit("http://127.0.0.1:8080")
        self._url_base.setReadOnly(True)
        self._url_base.setStyleSheet(_INPUT + "color: #a78bfa;")

        endpoints_text = QTextEdit()
        endpoints_text.setReadOnly(True)
        endpoints_text.setMaximumHeight(140)
        endpoints_text.setStyleSheet(
            "background:#0d0d1a; color:#94a3b8; font-family:monospace; font-size:10px; border:none;"
        )
        endpoints_text.setPlainText(
            "GET  /api/v1/status             Public health check\n"
            "GET  /api/v1/incidents          Full incident log (JSON)\n"
            "GET  /api/v1/attacks/current    Active attack details\n"
            "GET  /api/v1/topology           Network topology\n"
            "GET  /api/v1/export/stix        STIX 2.1 bundle\n"
            "GET  /api/v1/export/csv         CSV incident log\n"
            "GET  /api/v1/export/pcap        Download pcap capture\n"
            "GET  /api/v1/events             Live SSE stream\n"
            "POST /api/v1/attack/enable      Enable attack remotely\n"
            "POST /api/v1/attack/disable     Disable all attacks"
        )
        layout.addWidget(endpoints_text)

        layout.addWidget(_sep())
        compat = QLabel("Dragos Platform   Claroty CTD   Nozomi   SOAR/SIEM\n"
                        "Custom scripts (curl, Python requests, Postman)")
        compat.setStyleSheet("color: #64748b; font-size: 11px;")
        layout.addWidget(compat)
        layout.addStretch()

    def _start(self):
        host = self._host.text().strip()
        port = self._port.value()
        self._mgr.configure_rest_api(host=host, port=port)
        result = self._mgr.start_rest_only()["rest_api"]
        if "error" in result.lower() or "failed" in result.lower():
            self._status_lbl.setText(f"● {result}")
            self._status_lbl.setStyleSheet(_STATUS_ERR)
        else:
            url = f"http://{host if host != '0.0.0.0' else '127.0.0.1'}:{self._mgr.api_port}"
            self._status_lbl.setText(f"● Serving at {url}/api/v1/")
            self._status_lbl.setStyleSheet(_STATUS_ON)
            self._key_edit.setText(self._mgr.api_key)
            self._url_base.setText(url)
            self._start_btn.setEnabled(False)
            self._stop_btn.setEnabled(True)
            self._browser_btn.setEnabled(True)
            if not self._auth_cb.isChecked():
                self._mgr.disable_rest_auth()

    def _stop(self):
        self._mgr.stop_rest_only()
        self._status_lbl.setText("● Stopped")
        self._status_lbl.setStyleSheet(_STATUS_OFF)
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._browser_btn.setEnabled(False)

    def _open_browser(self):
        url = self._url_base.text()
        try:
            if not QDesktopServices.openUrl(QUrl(url)):
                raise OSError("No browser is available")
        except Exception:
            QApplication.clipboard().setText(url)
            QMessageBox.information(self, "Open Browser",
                f"URL copied to clipboard:\n{url}\n\nOpen it in your browser.")


# ── Export tab ────────────────────────────────────────────────────────────────

class ExportTab(QWidget):
    """Export incidents as STIX 2.1, CSV, JSON, and pcap."""

    def __init__(self, manager_ref, parent=None):
        super().__init__(parent)
        self._mgr = manager_ref
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        layout.addWidget(_section("Export Formats"))
        layout.addWidget(_sep())

        # Stats
        self._stats_lbl = QLabel("No incidents recorded yet")
        self._stats_lbl.setStyleSheet(_LABEL)
        layout.addWidget(self._stats_lbl)

        layout.addWidget(_sep())

        # STIX 2.1
        stix_box = QGroupBox("STIX 2.1 — Threat Intelligence")
        stix_box.setStyleSheet(
            "QGroupBox { color: #a78bfa; font-weight: 700; border: 1px solid #3d3d5c; "
            "border-radius: 6px; margin-top: 8px; padding-top: 8px; }"
        )
        stix_layout = QVBoxLayout(stix_box)
        stix_desc = QLabel(
            "Exports attack-patterns, indicators, and observed-data as a\n"
            "STIX 2.1 bundle mapped to MITRE ATT&CK for ICS techniques.\n"
            "Import into: OpenCTI, MISP, Threat Intelligence Platforms."
        )
        stix_desc.setStyleSheet("color: #64748b; font-size: 11px;")
        stix_layout.addWidget(stix_desc)
        stix_btn = QPushButton("Export STIX 2.1 Bundle")
        stix_btn.setStyleSheet(_BTN_PRIMARY)
        stix_btn.clicked.connect(self._export_stix)
        stix_layout.addWidget(stix_btn)
        layout.addWidget(stix_box)

        # CSV
        csv_btn = QPushButton("Export Incident Log — CSV")
        csv_btn.setStyleSheet(_BTN_NEUTRAL)
        csv_btn.setToolTip("Import into Excel, Splunk, or any SIEM")
        csv_btn.clicked.connect(self._export_csv)
        layout.addWidget(csv_btn)

        # JSON
        json_btn = QPushButton("Export Incident Log — JSON")
        json_btn.setStyleSheet(_BTN_NEUTRAL)
        json_btn.setToolTip("Raw JSON for custom integrations")
        json_btn.clicked.connect(self._export_json)
        layout.addWidget(json_btn)

        # pcap
        pcap_btn = QPushButton("Export pcap Capture File")
        pcap_btn.setStyleSheet(_BTN_NEUTRAL)
        pcap_btn.setToolTip("Open in Wireshark, Zeek, Arkime, Security Onion")
        pcap_btn.clicked.connect(self._export_pcap)
        layout.addWidget(pcap_btn)

        layout.addWidget(_sep())
        layout.addWidget(_section("Import into Other Tools"))

        guide_text = QTextEdit()
        guide_text.setReadOnly(True)
        guide_text.setStyleSheet(
            "background:#0d0d1a; color:#94a3b8; font-family:monospace; "
            "font-size:10px; border:none;"
        )
        guide_text.setPlainText(
            "# Zeek (analyze pcap offline):\n"
            "zeek -r gridsec_capture.pcap local\n\n"
            "# tshark (CLI Wireshark):\n"
            "tshark -r gridsec_capture.pcap -Y dnp3\n"
            "tshark -r gridsec_capture.pcap -Y modbus\n"
            "tshark -r gridsec_capture.pcap -Y goose\n\n"
            "# Security Onion (import pcap):\n"
            "so-import-pcap gridsec_capture.pcap\n\n"
            "# Arkime (upload pcap):\n"
            "arkime-capture -r gridsec_capture.pcap\n\n"
            "# MISP (import STIX 2.1):\n"
            "misp-import --stix gridsec_stix2.json"
        )
        layout.addWidget(guide_text)
        layout.addStretch()

    def update_stats(self):
        n = self._mgr.incident_count
        pcap_n = self._mgr.pcap_packet_count
        self._stats_lbl.setText(
            f"Incidents: {n:,}    pcap packets: {pcap_n:,}"
        )

    def _export_stix(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save STIX 2.1", "gridsec_stix2.json", "JSON (*.json)"
        )
        if path:
            try:
                self._mgr.export_stix(path)
                QMessageBox.information(self, "Exported",
                    f"STIX 2.1 bundle saved to:\n{path}\n\n"
                    "Import into: OpenCTI, MISP, Anomali ThreatStream")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save CSV", "gridsec_incidents.csv", "CSV (*.csv)"
        )
        if path:
            try:
                self._mgr.export_csv(path)
                QMessageBox.information(self, "Exported", f"CSV saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON", "gridsec_incidents.json", "JSON (*.json)"
        )
        if path:
            try:
                self._mgr.export_json(path)
                QMessageBox.information(self, "Exported", f"JSON saved to:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))

    def _export_pcap(self):
        src = self._mgr.pcap_path
        if not src or not os.path.isfile(src):
            QMessageBox.warning(self, "No pcap",
                "No pcap file found. Enable pcap capture first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save pcap", "gridsec_capture.pcap", "pcap (*.pcap)"
        )
        if path:
            import shutil
            try:
                shutil.copy2(src, path)
                QMessageBox.information(self, "Exported",
                    f"pcap saved to:\n{path}\n\n"
                    "Open with: wireshark, zeek, tshark, arkime")
            except Exception as e:
                QMessageBox.critical(self, "Error", str(e))


# ── Guides tab ────────────────────────────────────────────────────────────────

class GuidesTab(QWidget):
    """Step-by-step connection guides for each external tool."""

    GUIDES = {
        "Wireshark": """
Wireshark — Live Capture + Protocol Dissection
===============================================

Option A: Live FIFO (real-time):
  1. In Integrations > Capture tab:
     - Check "Use named FIFO pipe"
     - Click "Start Capture"
  2. In Integrations > Capture tab:
     - Click "Open Wireshark"
     OR run in terminal:
     wireshark -k -i /tmp/gridsec_live.pcap
  3. Wireshark will show live packets as the sim runs

Option B: Post-capture file:
  1. In Integrations > Capture tab:
     - Set file path and start capture
     - Run simulation, then stop
  2. Click "Open Wireshark" to open the file

Useful Wireshark Filters:
  dnp3             — DNP3 packets (UDP/20000)
  modbus           — Modbus/TCP packets (TCP/502)
  goose            — GOOSE packets (EtherType 0x88B8)
  udp.port == 4712 — C37.118 synchrophasor
  tcp.port == 502  — Modbus
  udp.port == 20000 — DNP3

Color rules (Wireshark > View > Coloring Rules):
  Add rule: goose    → red background
  Add rule: dnp3     → yellow background
  Add rule: modbus   → green background
""",
        "Dragos": """
Dragos Platform Integration
===========================

Method 1: Syslog / CEF (Recommended)
  1. In Dragos: Settings > Integrations > Syslog
     - Enable syslog ingestion
     - Note the syslog host IP and port

  2. In GridSec Sim > Integrations > Syslog tab:
     - Host: <Dragos sensor IP>
     - Port: 514 (or configured port)
     - Protocol: UDP
     - Click "Enable"

  3. Run an attack in GridSec Sim
     - Dragos will ingest CEF alerts
     - Check Dragos Threat Activity for ICS alerts

Method 2: REST API polling
  1. In GridSec Sim > Integrations > REST API tab:
     - Start the API server on port 8080
     - Note the API key

  2. In Dragos or your automation:
     curl -H "Authorization: Bearer <KEY>" \\
       http://<GridSecSim_IP>:8080/api/v1/incidents

  3. Import pcap into Dragos:
     - Export pcap from GridSec Sim
     - Upload to Dragos for protocol analysis

Method 3: pcap network tap
  Use the FIFO pipe to stream traffic to a monitoring port
  that Dragos's passive sensor is monitoring.
""",
        "Claroty": """
Claroty CTD Integration
========================

Method 1: Syslog / CEF
  1. In Claroty: Administration > Integrations > Syslog
     - Enable CEF syslog ingestion
     - Set up a syslog listener

  2. In GridSec Sim > Integrations > Syslog tab:
     - Host: <Claroty server IP>
     - Port: 514
     - Click "Enable"
  
  3. Incidents appear in Claroty as network security alerts
     with CEF fields: src, dst, proto, attack type, severity

Method 2: pcap analysis
  1. Export pcap from GridSec Sim
  2. In Claroty: go to Network > Import Capture
  3. Upload the pcap file
  4. Claroty will analyze DNP3, Modbus, and GOOSE traffic
     and may flag anomalous protocol behavior

Method 3: REST API
  Use curl or a script to pull incidents and push them
  into Claroty's custom alert API if available.
""",
        "Splunk": """
Splunk Integration
==================

Method 1: Syslog / CEF (Universal Forwarder)
  1. Install Splunk Add-on for CEF on your Splunk instance
  2. Configure a UDP/TCP syslog input (port 514 or custom)
  3. In GridSec Sim > Integrations > Syslog:
     - Host: <Splunk server IP>
     - Port: <syslog input port>
     - Click "Enable"
  4. CEF events appear in Splunk search:
     index=* sourcetype="syslog" GridSecSim

Method 2: REST API + Script
  Create a Splunk scripted input or Modular Input:
  
  import requests
  resp = requests.get(
    "http://127.0.0.1:8080/api/v1/incidents",
    headers={"Authorization": "Bearer <KEY>"}
  )
  # Send to Splunk HEC:
  requests.post(
    "http://splunk:8088/services/collector",
    headers={"Authorization": "Splunk HEC_TOKEN"},
    json={"event": resp.json()}
  )

Method 3: Import CSV
  Export CSV from GridSec Sim > Integrations > Export
  Upload to Splunk: Settings > Add Data > Upload
""",
        "Zeek / Bro": """
Zeek (Bro) Integration
======================

Zeek is a passive network analyzer perfect for ICS protocol analysis.

Step 1: Export pcap from GridSec Sim
  - Integrations > Capture > Start Capture
  - Run your attack simulation
  - Stop capture
  - Integrations > Export > Export pcap

Step 2: Analyze with Zeek
  # Basic analysis (generates conn.log, dns.log, etc.)
  zeek -r gridsec_capture.pcap local

  # With Zeek ICS package (dnp3, modbus, enip):
  sudo zkg install zeek/zeek-dnp3
  zeek -r gridsec_capture.pcap Site::local_nets=10.0.0.0/24

  # Filter specific protocols:
  tshark -r gridsec_capture.pcap -Y dnp3 -T json > dnp3_events.json

Step 3: Useful Zeek logs
  conn.log     — all connections (check for anomalies)
  dnp3.log     — DNP3 function codes and values
  modbus.log   — Modbus register reads/writes
  weird.log    — protocol anomalies detected by Zeek

Step 4: Security Onion
  # Import pcap into Security Onion:
  so-import-pcap gridsec_capture.pcap
  # Then view in Kibana/Grafana dashboards
""",
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        # Tool selector
        sel_row = QHBoxLayout()
        sel_row.addWidget(_lbl("Tool:"))
        self._selector = QComboBox()
        self._selector.setStyleSheet(_INPUT)
        for name in self.GUIDES:
            self._selector.addItem(name)
        self._selector.currentTextChanged.connect(self._show_guide)
        sel_row.addWidget(self._selector)
        sel_row.addStretch()
        layout.addLayout(sel_row)

        self._text = QTextEdit()
        self._text.setReadOnly(True)
        self._text.setStyleSheet(
            "background:#0d0d1a; color:#e2e8f0; font-family:monospace; "
            "font-size:11px; border:none; line-height: 1.5;"
        )
        layout.addWidget(self._text)

        self._show_guide(self._selector.currentText())

    def _show_guide(self, name: str):
        self._text.setPlainText(self.GUIDES.get(name, "").strip())


# ── Main Integration Panel ────────────────────────────────────────────────────

class IntegrationPanel(QWidget):
    """
    Main Integrations panel — added as a tab in the right panel.

    Holds a reference to the IntegrationManager and keeps UI in sync.
    """

    def __init__(self, manager_ref, parent=None):
        super().__init__(parent)
        self._mgr = manager_ref
        self._setup_ui()

        # Refresh timer
        self._timer = QTimer(self)
        self._timer.setInterval(2000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header
        header = QFrame()
        header.setFixedHeight(32)
        header.setStyleSheet("background: #1a1a2e; border-bottom: 1px solid #2d2d44;")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(10, 0, 10, 0)
        title = QLabel("External Integrations")
        title.setStyleSheet("color: #a78bfa; font-weight: 600; font-size: 12px;")
        h_layout.addWidget(title)
        h_layout.addStretch()
        layout.addWidget(header)

        # A single selector avoids clipped nested tab bars on smaller screens.
        selector = QComboBox()
        selector.setAccessibleName("Integration section")
        tabs = QStackedWidget()
        layout.addWidget(selector)
        selector.currentIndexChanged.connect(tabs.setCurrentIndex)

        self._capture_tab = CaptureTab(self._mgr)
        self._syslog_tab  = SyslogTab(self._mgr)
        self._rest_tab    = RestAPITab(self._mgr)
        self._export_tab  = ExportTab(self._mgr)
        self._guides_tab  = GuidesTab()

        for name, page in (
            ("Capture — Wireshark / PCAP", self._capture_tab),
            ("Syslog / CEF", self._syslog_tab),
            ("REST API", self._rest_tab),
            ("Export incident reports", self._export_tab),
            ("Connection guides", self._guides_tab),
        ):
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setFrameShape(QFrame.Shape.NoFrame)
            scroll.setWidget(page)
            tabs.addWidget(scroll)
            selector.addItem(name)

        layout.addWidget(tabs)

    def _refresh(self):
        """Periodically update stats labels."""
        self._capture_tab.update_stats()
        self._syslog_tab.update_stats()
        self._export_tab.update_stats()
