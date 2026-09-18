"""
core/integration_manager.py
============================
GridSec Sim — Central Integration Manager

Coordinates all external tool integrations:
  - pcap capture  → Wireshark, Zeek, Security Onion, Arkime
  - Syslog / CEF  → Dragos, Claroty, Splunk, QRadar, ArcSight, Sentinel
  - REST API      → Dragos, Claroty, custom tools, SOAR
  - STIX 2.1      → Threat intelligence platforms
  - CSV/JSON      → Any SIEM or analysis tool

Usage:
    mgr = IntegrationManager()
    mgr.start()
    mgr.record_packet(record, raw_bytes, protocol="C37.118")
    mgr.stop()
"""

import csv
import io
import json
import logging
import os
import socket
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from core.pcap_writer import PcapWriter
from core.rest_api import GridSecRESTServer

logger = logging.getLogger(__name__)


# ── Incident record ────────────────────────────────────────────────────────────

@dataclass
class Incident:
    """A security incident detected during simulation."""
    id:           str   = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:    float = field(default_factory=time.time)
    protocol:     str   = "C37.118"
    src_ip:       str   = "10.0.0.1"
    dst_ip:       str   = "10.0.0.2"
    attack_type:  str   = "CLEAN"
    status:       str   = "clean"      # clean | attacked | dropped | invalid
    severity:     str   = "INFO"       # INFO | LOW | MEDIUM | HIGH | CRITICAL
    description:  str   = ""
    original_val: dict  = field(default_factory=dict)
    modified_val: dict  = field(default_factory=dict)

    def as_cef(self) -> str:
        """
        Format as ArcSight CEF (Common Event Format).
        Compatible with Dragos, Claroty, Splunk, QRadar, ArcSight, Sentinel.

        Format: CEF:Version|Device Vendor|Device Product|Device Version|
                SignatureID|Name|Severity|Extension
        """
        severity_map = {"INFO": 0, "LOW": 3, "MEDIUM": 5,
                        "HIGH": 7, "CRITICAL": 10}
        sev_num = severity_map.get(self.severity, 5)

        # CEF extension fields
        ts_ms  = int(self.timestamp * 1000)
        ext    = (
            f"rt={ts_ms} "
            f"src={self.src_ip} "
            f"dst={self.dst_ip} "
            f"proto={self.protocol} "
            f"cat={self.attack_type} "
            f"outcome={self.status}"
        )
        if self.modified_val:
            ext += f" msg={json.dumps(self.modified_val)}"

        return (
            f"CEF:0|GridSecSim|GridSec Sim|1.0|"
            f"{self.attack_type}|"
            f"ICS Attack - {self.attack_type} on {self.protocol}|"
            f"{sev_num}|"
            f"{ext}"
        )

    def as_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_iso"] = datetime.fromtimestamp(
            self.timestamp, tz=timezone.utc
        ).isoformat()
        return d


# ── Syslog/CEF sender ─────────────────────────────────────────────────────────

class SyslogCEFSender:
    """
    Sends CEF-formatted syslog messages to a remote syslog server.

    Compatible with:
      Dragos   — enable syslog ingestion in your Dragos sensor
      Claroty  — configure syslog in Claroty CTD
      Splunk   — use Splunk Add-on for Security (CEF parsing)
      QRadar   — auto-parsed as CEF events
      ArcSight — native CEF
      Sentinel — Azure Monitor CEF connector
    """

    # RFC 5424 facilities
    FACILITY_LOCAL0 = 16
    FACILITY_LOCAL7 = 23
    SEVERITY_INFO    = 6
    SEVERITY_WARNING = 4
    SEVERITY_ALERT   = 1

    def __init__(
        self,
        host:     str  = "127.0.0.1",
        port:     int  = 514,
        protocol: str  = "UDP",     # UDP or TCP
        facility: int  = FACILITY_LOCAL7,
    ):
        self._host     = host
        self._port     = port
        self._protocol = protocol.upper()
        self._facility = facility
        self._sock:    Optional[socket.socket] = None
        self._lock     = threading.Lock()
        self.messages_sent  = 0
        self.last_error     = ""
        self._connected     = False

    def connect(self) -> bool:
        """Establish socket connection."""
        self.disconnect()
        try:
            with self._lock:
                if self._protocol == "UDP":
                    self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    self._connected = True
                else:   # TCP
                    self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self._sock.settimeout(5.0)
                    self._sock.connect((self._host, self._port))
                    self._connected = True
            logger.info(f"Syslog: connected {self._protocol} → {self._host}:{self._port}")
            return True
        except Exception as e:
            self.last_error = str(e)
            self.disconnect()
            self._connected = False
            logger.warning(f"Syslog: connect failed: {e}")
            return False

    def disconnect(self) -> None:
        with self._lock:
            if self._sock:
                try:
                    self._sock.close()
                except Exception:
                    pass
                self._sock = None
            self._connected = False

    def send_cef(self, incident: Incident) -> bool:
        """Send a CEF-formatted syslog message."""
        if not self._connected or self._sock is None:
            return False

        severity = {"INFO": self.SEVERITY_INFO, "LOW": self.SEVERITY_INFO,
                    "MEDIUM": self.SEVERITY_WARNING,
                    "HIGH": self.SEVERITY_ALERT,
                    "CRITICAL": self.SEVERITY_ALERT}.get(incident.severity,
                                                         self.SEVERITY_INFO)

        priority  = (self._facility * 8) + severity
        timestamp = datetime.fromtimestamp(
            incident.timestamp, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        hostname  = socket.gethostname()

        cef_msg   = incident.as_cef()
        # RFC 5424 syslog message
        syslog_msg = (
            f"<{priority}>1 {timestamp} {hostname} "
            f"GridSecSim - - - {cef_msg}\n"
        ).encode("utf-8")

        try:
            with self._lock:
                if self._protocol == "UDP":
                    self._sock.sendto(syslog_msg, (self._host, self._port))
                else:
                    self._sock.sendall(syslog_msg)
            self.messages_sent += 1
            return True
        except Exception as e:
            self.last_error = str(e)
            self._connected = False
            return False

    def test_connection(self) -> tuple:
        """Send a test message. Returns (success: bool, msg: str)."""
        if not self.connect():
            return False, f"Connection failed: {self.last_error}"
        test_inc = Incident(
            protocol    = "SYSTEM",
            attack_type = "TEST",
            status      = "clean",
            severity    = "INFO",
            description = "GridSec Sim syslog connection test",
        )
        ok = self.send_cef(test_inc)
        if ok:
            return True, f"Test CEF message sent to {self._host}:{self._port}"
        return False, f"Send failed: {self.last_error}"

    @property
    def is_connected(self) -> bool:
        return self._connected


# ── STIX 2.1 exporter ────────────────────────────────────────────────────────

# MITRE ATT&CK for ICS technique mappings
ATTACK_TO_MITRE = {
    "NOISE":              ("T0815", "Denial of Control", "Modify Operational Technology"),
    "RAMP":               ("T0831", "Manipulation of Control", "Ramp Attack on Sensor"),
    "PULSE":              ("T0801", "Monitor Process State", "Pulse Injection"),
    "REPLAY":             ("T0830", "Man in the Middle", "Replay Attack"),
    "DELAY":              ("T0830", "Man in the Middle", "Delay Attack"),
    "DROP":               ("T0800", "Activate Firmware Update Mode", "Packet Drop"),
    "FREQUENCY_OVERRIDE": ("T0836", "Modify Parameter", "Frequency Override"),
    "MAGNITUDE_OVERRIDE": ("T0836", "Modify Parameter", "Magnitude Override"),
    "ANGLE_OVERRIDE":     ("T0836", "Modify Parameter", "Angle Override"),
    "SCALE":              ("T0836", "Modify Parameter", "Scale Attack"),
}


def generate_stix_bundle(
    incidents:    List[Incident],
    session_id:   str = "",
    tool_name:    str = "GridSec Sim",
) -> dict:
    """
    Generate a STIX 2.1 bundle from recorded incidents.

    Objects included:
      - identity        (tool)
      - attack-pattern  (per unique attack type, mapped to MITRE ATT&CK ICS)
      - indicator       (network traffic indicators)
      - observed-data   (actual measurements)
      - campaign        (simulation session)
      - course-of-action (mitigations)
      - relationship    (links all objects)
    """
    now_iso = datetime.now(tz=timezone.utc).isoformat()
    bundle_id = f"bundle--{uuid.uuid4()}"

    if not session_id:
        session_id = str(uuid.uuid4())

    objects = []

    # ── Identity: GridSec Sim tool ──────────────────────────────────────────
    tool_identity_id = f"identity--{uuid.uuid4()}"
    objects.append({
        "type":              "identity",
        "spec_version":      "2.1",
        "id":                tool_identity_id,
        "created":           now_iso,
        "modified":          now_iso,
        "name":              tool_name,
        "identity_class":    "system",
        "description":       "Smart Grid Cybersecurity Simulation Tool. "
                             "Simulates ICS/SCADA protocol attacks for "
                             "research and training.",
        "sectors":           ["energy"],
    })

    # ── Campaign: simulation session ────────────────────────────────────────
    campaign_id = f"campaign--{session_id}"
    attack_types = list({i.attack_type for i in incidents if i.status == "attacked"})
    objects.append({
        "type":            "campaign",
        "spec_version":    "2.1",
        "id":              campaign_id,
        "created":         now_iso,
        "modified":        now_iso,
        "name":            f"GridSec Sim Session — {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "description":     f"Simulated ICS attacks on protocols: "
                           f"{', '.join({i.protocol for i in incidents})}. "
                           f"Attack types used: {', '.join(attack_types) or 'None'}.",
        "objective":       "Cybersecurity training and IDS evaluation",
    })

    # ── Attack patterns + indicators + courses of action ───────────────────
    ap_ids: Dict[str, str] = {}
    coa_ids: Dict[str, str] = {}

    for at in set(i.attack_type for i in incidents if i.status in ("attacked", "dropped")):
        mitre = ATTACK_TO_MITRE.get(at, ("T0000", "Unknown", at))
        ap_id = f"attack-pattern--{uuid.uuid4()}"
        ap_ids[at] = ap_id

        objects.append({
            "type":         "attack-pattern",
            "spec_version": "2.1",
            "id":           ap_id,
            "created":      now_iso,
            "modified":     now_iso,
            "name":         mitre[2],
            "description":  f"ICS attack type '{at}' simulated on "
                            f"industrial control system protocols.",
            "kill_chain_phases": [{
                "kill_chain_name": "mitre-ics-attack",
                "phase_name":      "impact",
            }],
            "external_references": [{
                "source_name":   "mitre-ics-attack",
                "external_id":   mitre[0],
                "url":           f"https://attack.mitre.org/techniques/{mitre[0]}/",
            }],
        })

        # Indicator: network-level indicator for this attack
        ind_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type":          "indicator",
            "spec_version":  "2.1",
            "id":            ind_id,
            "created":       now_iso,
            "modified":      now_iso,
            "name":          f"Network indicator for {at} attack",
            "description":   f"Anomalous ICS protocol traffic consistent with {at} attack. "
                             f"Technique: {mitre[0]} — {mitre[1]}.",
            "indicator_types": ["malicious-activity", "anomalous-activity"],
            "pattern":       f"[network-traffic:dst_port = 4712 OR "
                             f"network-traffic:dst_port = 20000 OR "
                             f"network-traffic:dst_port = 502]",
            "pattern_type":  "stix",
            "valid_from":    now_iso,
            "labels":        ["ics", "scada", at.lower()],
        })

        # Course of action: mitigation
        coa_id = f"course-of-action--{uuid.uuid4()}"
        coa_ids[at] = coa_id
        mitigations = {
            "NOISE":    "Implement anomaly detection on voltage/frequency measurements. "
                        "Use IEC 62351 authentication for C37.118.",
            "REPLAY":   "Use sequence numbers and timestamps. "
                        "Enable IEC 62351-3 TLS on synchrophasor links.",
            "DELAY":    "Monitor latency thresholds. Alert on PDC data gaps > 200ms.",
            "DROP":     "Implement redundant communication paths. "
                        "Use DNP3 unsolicited response confirm/retry.",
            "RAMP":     "Implement rate-of-change detection on analog inputs.",
            "PULSE":    "Whitelist expected value ranges on all measurement channels.",
            "FREQUENCY_OVERRIDE": "Implement frequency deviation alarms. "
                                  "Validate against GPS-synchronized reference.",
            "MAGNITUDE_OVERRIDE": "Implement magnitude plausibility checks.",
            "ANGLE_OVERRIDE":     "Implement phase angle consistency validation.",
            "SCALE":   "Monitor scaling factor anomalies in SCADA historian.",
        }
        objects.append({
            "type":         "course-of-action",
            "spec_version": "2.1",
            "id":           coa_id,
            "created":      now_iso,
            "modified":     now_iso,
            "name":         f"Mitigation: {at}",
            "description":  mitigations.get(at, f"Implement monitoring for {at} attacks."),
        })

        # Relationships
        objects.append({
            "type":             "relationship",
            "spec_version":     "2.1",
            "id":               f"relationship--{uuid.uuid4()}",
            "created":          now_iso,
            "modified":         now_iso,
            "relationship_type":"mitigates",
            "source_ref":       coa_id,
            "target_ref":       ap_id,
        })
        objects.append({
            "type":             "relationship",
            "spec_version":     "2.1",
            "id":               f"relationship--{uuid.uuid4()}",
            "created":          now_iso,
            "modified":         now_iso,
            "relationship_type":"indicates",
            "source_ref":       ind_id,
            "target_ref":       ap_id,
        })
        objects.append({
            "type":             "relationship",
            "spec_version":     "2.1",
            "id":               f"relationship--{uuid.uuid4()}",
            "created":          now_iso,
            "modified":         now_iso,
            "relationship_type":"uses",
            "source_ref":       campaign_id,
            "target_ref":       ap_id,
        })

    # ── Observed data: sampled incidents ─────────────────────────────────────
    attacked = [i for i in incidents if i.status == "attacked"][-20:]
    for inc in attacked:
        objects.append({
            "type":            "observed-data",
            "spec_version":    "2.1",
            "id":              f"observed-data--{uuid.uuid4()}",
            "created":         now_iso,
            "modified":        now_iso,
            "first_observed":  datetime.fromtimestamp(inc.timestamp,
                                tz=timezone.utc).isoformat(),
            "last_observed":   datetime.fromtimestamp(inc.timestamp,
                                tz=timezone.utc).isoformat(),
            "number_observed": 1,
            "objects": {
                "0": {
                    "type":     "network-traffic",
                    "src_ref":  "1",
                    "dst_ref":  "2",
                    "protocols": [inc.protocol.lower()],
                    "extensions": {
                        "x-ics-attack": {
                            "attack_type":   inc.attack_type,
                            "original_data": inc.original_val,
                            "modified_data": inc.modified_val,
                            "severity":      inc.severity,
                        }
                    }
                },
                "1": {"type": "ipv4-addr", "value": inc.src_ip},
                "2": {"type": "ipv4-addr", "value": inc.dst_ip},
            }
        })

    return {
        "type":         "bundle",
        "id":           bundle_id,
        "spec_version": "2.1",
        "objects":      objects,
    }


# ── CSV exporter ──────────────────────────────────────────────────────────────

def incidents_to_csv(incidents: List[Incident]) -> str:
    """Convert incident list to CSV string."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=[
        "id", "timestamp_iso", "protocol", "src_ip", "dst_ip",
        "attack_type", "status", "severity", "description",
    ])
    writer.writeheader()
    for inc in incidents:
        d = inc.as_dict()
        writer.writerow({k: d.get(k, "") for k in writer.fieldnames})
    return output.getvalue()


# ── Integration Manager ───────────────────────────────────────────────────────

class IntegrationManager:
    """
    Central hub for all GridSec Sim external integrations.

    Start all integrations once, then call record_packet() for every
    packet processed by the PDC proxy.

    Example:
        mgr = IntegrationManager()
        mgr.configure_pcap(path="/tmp/gridsec.pcap")
        mgr.configure_syslog(host="192.168.1.10", port=514)
        mgr.configure_rest_api(host="0.0.0.0", port=8080)
        mgr.start()

        # Called from PDCProxy callback:
        mgr.record_packet(record, raw_c37118_bytes, protocol="C37.118")

        mgr.stop()
    """

    MAX_INCIDENTS = 10_000
    MAX_PACKETS   = 1_000

    def __init__(self):
        self._lock      = threading.Lock()
        self._incidents: deque = deque(maxlen=self.MAX_INCIDENTS)
        self._packets:   deque = deque(maxlen=self.MAX_PACKETS)
        self._session_id = str(uuid.uuid4())
        self._start_time  = time.time()

        # Component handles
        self._pcap:   Optional[PcapWriter]       = None
        self._syslog: Optional[SyslogCEFSender]  = None
        self._rest:   Optional[GridSecRESTServer] = None

        # Config (set before start())
        self._last_pcap_path = ""
        self._last_pcap_count = 0
        self._pcap_cfg:   dict = {}
        self._syslog_cfg: dict = {}
        self._rest_cfg:   dict = {}

        # Simulation state (updated by main window)
        self.sim_running   = False
        self.topology_data: dict = {}
        self.attack_data:   dict = {}

        # Callbacks (optional)
        self.on_incident: Optional[Callable[[Incident], None]] = None

    # ── Configuration ─────────────────────────────────────────────────────────

    def configure_pcap(self, path: str = "/tmp/gridsec_capture.pcap",
                       use_fifo: bool = False) -> None:
        self._pcap_cfg = {"path": path, "use_fifo": use_fifo}

    def configure_syslog(self, host: str = "127.0.0.1", port: int = 514,
                         protocol: str = "UDP") -> None:
        self._syslog_cfg = {"host": host, "port": port, "protocol": protocol}

    def configure_rest_api(self, host: str = "127.0.0.1", port: int = 8080) -> None:
        self._rest_cfg = {"host": host, "port": port}

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def start(self) -> dict:
        results = {}
        if self._pcap_cfg:
            results.update(self.start_pcap_only())
        if self._syslog_cfg:
            results.update(self.start_syslog_only())
        if self._rest_cfg:
            results.update(self.start_rest_only())
        return results

    def start_pcap_only(self) -> dict:
        if self._pcap:
            return {"pcap": "already started"}
        try:
            writer = PcapWriter(**self._pcap_cfg)
            if writer.error:
                writer.close()
                raise OSError(writer.error)
            self._pcap = writer
            self._last_pcap_path = writer.path
            self._last_pcap_count = 0
            return {"pcap": "started"}
        except Exception as exc:
            return {"pcap": f"error: {exc}"}

    def stop_pcap_only(self) -> None:
        writer, self._pcap = self._pcap, None
        if writer:
            writer.close()
            self._last_pcap_count = writer.packet_count

    def start_syslog_only(self) -> dict:
        if self._syslog and self._syslog.is_connected:
            return {"syslog": "connected"}
        self.stop_syslog_only()
        sender = SyslogCEFSender(**self._syslog_cfg)
        if not sender.connect():
            sender.disconnect()
            return {"syslog": f"error: {sender.last_error}"}
        self._syslog = sender
        return {"syslog": "connected"}

    def stop_syslog_only(self) -> None:
        sender, self._syslog = self._syslog, None
        if sender:
            sender.disconnect()

    def test_syslog(self) -> tuple:
        sender = SyslogCEFSender(**self._syslog_cfg)
        try:
            return sender.test_connection()
        finally:
            sender.disconnect()

    def start_rest_only(self) -> dict:
        if self._rest:
            return {"rest_api": f"listening on port {self._rest.port}"}
        server = GridSecRESTServer(**self._rest_cfg)
        self._rest = server
        self._wire_rest_callbacks()
        if not server.start():
            self._rest = None
            return {"rest_api": f"error: {server.last_error}"}
        return {"rest_api": f"listening on port {server.port}"}

    def stop_rest_only(self) -> None:
        server, self._rest = self._rest, None
        if server:
            server.stop()

    def disable_rest_auth(self) -> None:
        if self._rest:
            self._rest.disable_auth()

    def stop(self) -> None:
        """Stop integrations without discarding the last capture file."""
        self.stop_pcap_only()
        self.stop_syslog_only()
        self.stop_rest_only()
        self.sim_running = False

    # ── Packet ingestion ──────────────────────────────────────────────────────

    def record_packet(
        self,
        record,                         # PacketRecord from pdc_proxy
        raw_bytes:      bytes = b"",
        protocol:       str   = "C37.118",
        src_ip:         str   = "10.0.0.1",
        dst_ip:         str   = "10.0.0.2",
        src_port:       int   = 49000,
        dst_port:       int   = 4712,
        transport:      str   = "UDP",  # UDP or TCP
    ) -> None:
        """
        Process one packet from the PDC proxy.
        Feeds pcap writer, syslog, REST API, and incident log.
        """
        try:
            ts = getattr(record, "timestamp", time.time())
            raw_bytes = raw_bytes or getattr(record, "raw_bytes", b"")

            # Build incident
            status    = getattr(record, "status", "clean")
            atk_type  = getattr(record, "attack_type", "") or "NONE"
            original  = getattr(record, "original", {}) or {}
            modified  = getattr(record, "modified", {}) or {}

            severity = {
                "clean":   "INFO",
                "attacked":"HIGH",
                "dropped": "MEDIUM",
                "invalid": "LOW",
                "forward_error": "HIGH",
            }.get(status, "INFO")

            incident = Incident(
                timestamp   = ts,
                protocol    = protocol,
                src_ip      = src_ip,
                dst_ip      = dst_ip,
                attack_type = atk_type,
                status      = status,
                severity    = severity,
                description = getattr(record, "description", "") or f"{protocol} {status} packet ({atk_type})",
                original_val= _serialize_frame(original),
                modified_val= _serialize_frame(modified) if modified else {},
            )

            with self._lock:
                self._incidents.append(incident)
                self._packets.append({
                    "timestamp": ts,
                    "protocol":  protocol,
                    "status":    status,
                    "attack":    atk_type,
                    "src":       f"{src_ip}:{src_port}",
                    "dst":       f"{dst_ip}:{dst_port}",
                    "len":       len(raw_bytes),
                    "forwarded": getattr(record, "forwarded", None),
                    "latency_ms": getattr(record, "latency_ms", 0),
                })

            # Write to pcap
            if self._pcap and raw_bytes:
                self._write_to_pcap(raw_bytes, protocol, src_ip, dst_ip,
                                    src_port, dst_port, transport, ts)

            # Syslog only for attacks/drops
            if self._syslog and status in ("attacked", "dropped", "invalid", "forward_error"):
                self._syslog.send_cef(incident)

            # REST SSE broadcast
            if self._rest and status in ("attacked", "dropped"):
                self._rest.broadcast_event("incident", incident.as_dict())

            # External callback
            if self.on_incident:
                self.on_incident(incident)

        except Exception as exc:
            logger.exception("IntegrationManager.record_packet failed")

    def _write_to_pcap(self, raw: bytes, protocol: str,
                       src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int,
                       transport: str, ts: float) -> None:
        """Route raw bytes to the correct pcap write method."""
        try:
            p = protocol.upper()
            if p == "GOOSE":
                self._pcap.write_goose(raw, ts)
            elif transport.upper() == "TCP":
                self._pcap.write_tcp(src_ip, dst_ip, src_port, dst_port, raw, ts)
            else:
                self._pcap.write_udp(src_ip, dst_ip, src_port, dst_port, raw, ts)
        except Exception:
            logger.exception("Failed to capture packet")

    # ── REST API callbacks ────────────────────────────────────────────────────

    def _wire_rest_callbacks(self) -> None:
        if not self._rest:
            return
        self._rest.set_status_callback(self._api_status)
        self._rest.set_topology_callback(lambda: self.topology_data)
        self._rest.set_attacks_callback(lambda: self.attack_data)
        self._rest.set_incidents_callback(self._api_incidents)
        self._rest.set_packets_callback(self._api_packets)
        self._rest.set_stix_callback(self._api_stix)
        self._rest.set_csv_callback(self._api_csv)
        self._rest.set_pcap_path_callback(
            lambda: self.pcap_path
        )
        self._rest.set_enable_attack_callback(self._api_enable_attack)
        self._rest.set_disable_attack_callback(self._api_disable_attack)

    def _api_status(self) -> dict:
        with self._lock:
            incidents = list(self._incidents)
        attacked = sum(1 for i in incidents if i.status == "attacked")
        return {
            "sim_running":    self.sim_running,
            "session_id":     self._session_id,
            "uptime_s":       int(time.time() - self._start_time),
            "total_incidents": len(incidents),
            "attacked":       attacked,
            "integrations": {
                "pcap":    self._pcap is not None and self._pcap.is_active,
                "syslog":  self._syslog is not None and self._syslog.is_connected,
                "rest_api": self._rest is not None,
            }
        }

    def _api_incidents(self) -> List[dict]:
        with self._lock:
            return [i.as_dict() for i in self._incidents]

    def _api_packets(self) -> List[dict]:
        with self._lock:
            return list(self._packets)

    def _api_stix(self) -> dict:
        with self._lock:
            incidents = list(self._incidents)
        return generate_stix_bundle(incidents, self._session_id)

    def _api_csv(self) -> str:
        with self._lock:
            incidents = list(self._incidents)
        return incidents_to_csv(incidents)

    def _api_enable_attack(self, attack_type: str, params: dict) -> bool:
        # This is called via REST API; the actual engine manipulation
        # happens via the attack_enable_hook if set
        if self._attack_enable_hook:
            return self._attack_enable_hook(attack_type, params)
        return False

    def _api_disable_attack(self) -> bool:
        if self._attack_disable_hook:
            return bool(self._attack_disable_hook())
        return False

    # ── Attack hooks (set by MainWindow) ─────────────────────────────────────

    _attack_enable_hook:  Optional[Callable] = None
    _attack_disable_hook: Optional[Callable] = None

    def set_attack_hooks(self, enable_fn: Callable, disable_fn: Callable) -> None:
        self._attack_enable_hook  = enable_fn
        self._attack_disable_hook = disable_fn

    # ── Query methods ─────────────────────────────────────────────────────────

    @property
    def incident_count(self) -> int:
        with self._lock:
            return len(self._incidents)

    @property
    def api_key(self) -> str:
        return self._rest.api_key if self._rest else ""

    @property
    def api_port(self) -> int:
        return self._rest.port if self._rest else 0

    @property
    def pcap_path(self) -> str:
        return self._pcap.path if self._pcap else self._last_pcap_path

    @property
    def pcap_packet_count(self) -> int:
        return self._pcap.packet_count if self._pcap else self._last_pcap_count

    @property
    def syslog_count(self) -> int:
        return self._syslog.messages_sent if self._syslog else 0

    def export_stix(self, path: str) -> None:
        """Save STIX 2.1 bundle to file."""
        bundle = self._api_stix()
        with open(path, "w", encoding="utf-8", newline="") as f:
            json.dump(bundle, f, indent=2)
        logger.info(f"STIX exported to {path}")

    def export_csv(self, path: str) -> None:
        """Save incident CSV to file."""
        csv_data = self._api_csv()
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write(csv_data)
        logger.info(f"CSV exported to {path}")

    def export_json(self, path: str) -> None:
        """Save full incident JSON to file."""
        incidents = self._api_incidents()
        with open(path, "w", encoding="utf-8", newline="") as f:
            json.dump({
                "session_id":  self._session_id,
                "exported_at": datetime.now(tz=timezone.utc).isoformat(),
                "incidents":   incidents,
            }, f, indent=2)
        logger.info(f"JSON exported to {path}")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _serialize_frame(frame_dict: dict) -> dict:
    """Make frame dict JSON-serializable."""
    out = {}
    for k, v in frame_dict.items():
        if isinstance(v, (int, float, str, bool, type(None))):
            out[k] = v
        elif isinstance(v, bytes):
            out[k] = v.hex()
        elif isinstance(v, list):
            try:
                out[k] = [list(item) if hasattr(item, '__iter__') else item
                          for item in v]
            except Exception:
                out[k] = str(v)
        else:
            out[k] = str(v)
    return out
