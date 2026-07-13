"""
core/pdc_proxy.py
=================
MitM (Man-in-the-Middle) proxy for IEEE C37.118 synchrophasor traffic.

Pipeline:
  PMU → [UDP/TCP listen] → parse → traffic_filter → attack_engine
      → [re-encode] → [UDP/TCP forward] → openPDC

Features:
  - Supports both UDP and TCP (C37.118 can use either)
  - Binds a local listen port for incoming PMU data
  - Forwards each (possibly modified) frame to the configured PDC target
  - Emits callbacks for GUI: on_packet(original_dict, modified_dict, status)
  - Thread-safe — all I/O in its own daemon thread
  - Handles: port-in-use, target unreachable, invalid frame format

Status strings (for packet log colors):
  "clean"    — passed through unmodified
  "attacked" — modified by attack engine
  "dropped"  — discarded (not forwarded)
  "invalid"  — parse error (not forwarded)
"""

import logging
import select
import socket
import threading
import time
from typing import Callable, Optional, Tuple

from core.attack_engine import AttackEngine
from core.packet_parser import parse_frame, rebuild_frame, frame_summary
from core.traffic_filter import TrafficFilter
from protocols.c37118 import C37118Codec

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# PacketRecord — emitted for each processed packet
# ─────────────────────────────────────────────────────────────────────────────

class PacketRecord:
    """Represents one packet as it flows through the proxy pipeline."""
    __slots__ = (
        "timestamp", "original", "modified", "status",
        "attack_type", "description", "src_addr"
    )

    def __init__(
        self,
        timestamp:   float,
        original:    dict,
        modified:    dict,
        status:      str,
        attack_type: str = "",
        description: str = "",
        src_addr:    tuple = ("", 0),
    ):
        self.timestamp   = timestamp
        self.original    = original
        self.modified    = modified
        self.status      = status       # "clean" | "attacked" | "dropped" | "invalid"
        self.attack_type = attack_type
        self.description = description
        self.src_addr    = src_addr

    def log_line(self) -> str:
        ts  = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        ms  = int((self.timestamp % 1) * 1000)
        org = frame_summary(self.original)
        if self.status == "attacked":
            mod = frame_summary(self.modified)
            return f"[{ts}.{ms:03d}] {self.status.upper():<8} {org}  →  {mod}  [{self.attack_type}]"
        return f"[{ts}.{ms:03d}] {self.status.upper():<8} {org}"


# ─────────────────────────────────────────────────────────────────────────────
# PDCProxy
# ─────────────────────────────────────────────────────────────────────────────

class PDCProxy(threading.Thread):
    """
    MitM proxy that sits between the PMU simulator and openPDC.

    Parameters
    ----------
    listen_host  : address to bind for incoming PMU data (default "0.0.0.0")
    listen_port  : UDP/TCP port to bind (default 4712)
    target_host  : openPDC IP (default "127.0.0.1")
    target_port  : openPDC port (default 4713)
    proto        : "UDP" or "TCP"
    codec        : C37118Codec instance (must match PMU's settings)
    attack_engine: AttackEngine instance shared with GUI
    traffic_filter: TrafficFilter instance shared with GUI
    on_packet    : callback(PacketRecord) called for each processed packet
    """

    def __init__(
        self,
        listen_host:    str = "0.0.0.0",
        listen_port:    int = 4712,
        target_host:    str = "127.0.0.1",
        target_port:    int = 4713,
        proto:          str = "UDP",
        codec:          Optional[C37118Codec] = None,
        attack_engine:  Optional[AttackEngine] = None,
        traffic_filter: Optional[TrafficFilter] = None,
        on_packet:      Optional[Callable[[PacketRecord], None]] = None,
    ):
        super().__init__(daemon=True, name="PDCProxy")

        self.listen_host    = listen_host
        self.listen_port    = listen_port
        self.target_host    = target_host
        self.target_port    = target_port
        self.proto          = proto.upper()

        self.codec          = codec or C37118Codec(
            idcode=1, num_phasors=3, num_analog=1, num_digital=1
        )
        self.attack_engine  = attack_engine or AttackEngine()
        self.traffic_filter = traffic_filter or TrafficFilter()
        self.on_packet      = on_packet

        self._stop_event    = threading.Event()
        self._running       = False

        # Packet stats
        self.stats = {
            "total":    0,
            "clean":    0,
            "attacked": 0,
            "dropped":  0,
            "invalid":  0,
            "errors":   0,
        }

        # Sockets (created in run())
        self._listen_sock: Optional[socket.socket] = None
        self._send_sock:   Optional[socket.socket] = None

    # ── Public API ─────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            logger.warning("PDCProxy: already running")
            return
        self._stop_event.clear()
        self._running = True
        super().start()
        logger.info(
            f"PDCProxy: started  listen={self.listen_host}:{self.listen_port} "
            f"target={self.target_host}:{self.target_port}  proto={self.proto}"
        )

    def stop(self) -> None:
        self._stop_event.set()
        self._running = False
        # Unblock the socket.select() call
        if self._listen_sock:
            try:
                self._listen_sock.close()
            except Exception:
                pass
        logger.info("PDCProxy: stop requested")

    def set_target(self, host: str, port: int) -> None:
        """Change the target (openPDC) address — takes effect on next packet."""
        self.target_host = host
        self.target_port = port
        logger.info(f"PDCProxy: target changed to {host}:{port}")

    @property
    def is_running(self) -> bool:
        return self._running and self.is_alive()

    # ── Thread entry point ──────────────────────────────────────────────────

    def run(self) -> None:
        if self.proto == "UDP":
            self._run_udp()
        elif self.proto == "TCP":
            self._run_tcp()
        else:
            logger.error(f"PDCProxy: unknown protocol {self.proto}")
            self._running = False

    # ── UDP mode ─────────────────────────────────────────────────────────────

    def _run_udp(self) -> None:
        # Listen socket
        try:
            self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listen_sock.bind((self.listen_host, self.listen_port))
            self._listen_sock.setblocking(False)
            logger.info(f"PDCProxy (UDP): listening on {self.listen_host}:{self.listen_port}")
        except OSError as exc:
            logger.error(f"PDCProxy (UDP): cannot bind port {self.listen_port}: {exc}")
            self._running = False
            return

        # Send socket
        self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            while not self._stop_event.is_set():
                # Non-blocking recv with select
                try:
                    ready, _, _ = select.select([self._listen_sock], [], [], 0.1)
                except (ValueError, OSError):
                    break

                if not ready:
                    continue

                try:
                    raw_data, src_addr = self._listen_sock.recvfrom(65536)
                except OSError:
                    break

                packet_info = {
                    "src_ip":   src_addr[0],
                    "dst_ip":   self.target_host,
                    "src_port": src_addr[1],
                    "dst_port": self.target_port,
                    "proto":    "UDP",
                }
                self._process_packet(raw_data, src_addr, packet_info)

        finally:
            if self._listen_sock:
                try: self._listen_sock.close()
                except Exception: pass
            if self._send_sock:
                try: self._send_sock.close()
                except Exception: pass
            self._running = False
            logger.info(f"PDCProxy (UDP): stopped. Stats: {self.stats}")

    # ── TCP mode ─────────────────────────────────────────────────────────────

    def _run_tcp(self) -> None:
        try:
            self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listen_sock.bind((self.listen_host, self.listen_port))
            self._listen_sock.listen(5)
            self._listen_sock.setblocking(False)
            logger.info(f"PDCProxy (TCP): listening on {self.listen_host}:{self.listen_port}")
        except OSError as exc:
            logger.error(f"PDCProxy (TCP): cannot bind port {self.listen_port}: {exc}")
            self._running = False
            return

        try:
            while not self._stop_event.is_set():
                try:
                    ready, _, _ = select.select([self._listen_sock], [], [], 0.1)
                except (ValueError, OSError):
                    break

                if not ready:
                    continue

                try:
                    conn, src_addr = self._listen_sock.accept()
                except OSError:
                    break

                # Handle each connection in its own thread
                t = threading.Thread(
                    target=self._handle_tcp_connection,
                    args=(conn, src_addr),
                    daemon=True,
                    name=f"PDCProxy-TCP-{src_addr[0]}:{src_addr[1]}",
                )
                t.start()

        finally:
            if self._listen_sock:
                try: self._listen_sock.close()
                except Exception: pass
            self._running = False
            logger.info(f"PDCProxy (TCP): stopped. Stats: {self.stats}")

    def _handle_tcp_connection(self, conn: socket.socket, src_addr: tuple) -> None:
        """Handle one TCP client connection (one PMU connection)."""
        logger.info(f"PDCProxy (TCP): connection from {src_addr}")
        buf  = b""
        conn.settimeout(5.0)

        # Connect to target PDC via TCP
        try:
            fwd_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            fwd_sock.settimeout(3.0)
            fwd_sock.connect((self.target_host, self.target_port))
        except OSError as exc:
            logger.warning(f"PDCProxy (TCP): cannot connect to target {self.target_host}:{self.target_port}: {exc}")
            fwd_sock = None

        try:
            while not self._stop_event.is_set():
                try:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                except (socket.timeout, OSError):
                    break

                # Parse all complete frames from buffer
                while len(buf) >= 6:
                    # Read FRAMESIZE from bytes [2-3]
                    if len(buf) < 4:
                        break
                    import struct
                    frame_size = struct.unpack_from(">H", buf, 2)[0]
                    if frame_size < 14 or frame_size > 65535:
                        buf = buf[1:]   # skip one byte and resync
                        continue
                    if len(buf) < frame_size:
                        break           # wait for more data

                    raw_data = buf[:frame_size]
                    buf      = buf[frame_size:]

                    packet_info = {
                        "src_ip":   src_addr[0],
                        "dst_ip":   self.target_host,
                        "src_port": src_addr[1],
                        "dst_port": self.target_port,
                        "proto":    "TCP",
                    }
                    out_bytes, record = self._process_packet_bytes(raw_data, src_addr, packet_info)

                    # Forward to PDC via TCP
                    if out_bytes and fwd_sock:
                        try:
                            fwd_sock.sendall(out_bytes)
                        except OSError as exc:
                            logger.warning(f"PDCProxy (TCP): forward error: {exc}")

        finally:
            conn.close()
            if fwd_sock:
                try: fwd_sock.close()
                except Exception: pass

    # ── Core pipeline ─────────────────────────────────────────────────────────

    def _process_packet(
        self,
        raw_data:    bytes,
        src_addr:    tuple,
        packet_info: dict,
    ) -> None:
        """
        Process one incoming raw packet through the full pipeline:
        parse → filter → attack → re-encode → forward (UDP).
        """
        out_bytes, record = self._process_packet_bytes(raw_data, src_addr, packet_info)

        # Forward via UDP
        if out_bytes:
            try:
                self._send_sock.sendto(out_bytes, (self.target_host, self.target_port))
            except OSError as exc:
                self.stats["errors"] += 1
                if self.stats["errors"] % 50 == 1:
                    logger.warning(f"PDCProxy: forward error: {exc}")

    def _process_packet_bytes(
        self,
        raw_data:    bytes,
        src_addr:    tuple,
        packet_info: dict,
    ) -> Tuple[Optional[bytes], PacketRecord]:
        """
        Full pipeline: parse → filter → attack → rebuild.
        Returns (output_bytes_or_None, PacketRecord).
        output_bytes is None if the packet was dropped or invalid.
        """
        self.stats["total"] += 1
        ts = time.time()

        # ── 1. Parse ──────────────────────────────────────────────────────────
        original_dict = parse_frame(raw_data)
        if original_dict is None or original_dict.get("frame_type") in ("data_invalid", "cmd_invalid", "cfg_invalid", "unknown"):
            self.stats["invalid"] += 1
            record = PacketRecord(
                timestamp=ts, original=original_dict or {},
                modified={}, status="invalid", src_addr=src_addr,
                description="parse error"
            )
            if self.on_packet:
                try: self.on_packet(record)
                except Exception: pass
            return None, record

        # ── 2. Non-data frames: always pass through (CFG-2, commands) ─────────
        if original_dict.get("frame_type") != "data":
            self.stats["clean"] += 1
            record = PacketRecord(
                timestamp=ts, original=original_dict,
                modified=original_dict, status="clean", src_addr=src_addr,
            )
            if self.on_packet:
                try: self.on_packet(record)
                except Exception: pass
            return raw_data, record

        # ── 3. Traffic filter ─────────────────────────────────────────────────
        if not self.traffic_filter.matches(packet_info):
            self.stats["clean"] += 1
            record = PacketRecord(
                timestamp=ts, original=original_dict,
                modified=original_dict, status="clean", src_addr=src_addr,
                description="filter: no match"
            )
            if self.on_packet:
                try: self.on_packet(record)
                except Exception: pass
            return raw_data, record

        # ── 4. Attack engine ──────────────────────────────────────────────────
        modified_dict, was_modified, was_dropped = self.attack_engine.apply(original_dict)

        if was_dropped:
            self.stats["dropped"] += 1
            record = PacketRecord(
                timestamp=ts, original=original_dict, modified=modified_dict,
                status="dropped",
                attack_type=self.attack_engine.active_type.value,
                src_addr=src_addr,
            )
            if self.on_packet:
                try: self.on_packet(record)
                except Exception: pass
            return None, record

        # ── 5. Rebuild (re-encode) ─────────────────────────────────────────────
        if was_modified:
            out_bytes = rebuild_frame(modified_dict)
            self.stats["attacked"] += 1
            status = "attacked"
        else:
            out_bytes = raw_data   # unmodified — forward original bytes (preserves CRC)
            self.stats["clean"] += 1
            status = "clean"

        attack_type_str = self.attack_engine.active_type.value if was_modified else ""
        record = PacketRecord(
            timestamp=ts, original=original_dict, modified=modified_dict,
            status=status, attack_type=attack_type_str,
            src_addr=src_addr,
        )
        if self.on_packet:
            try: self.on_packet(record)
            except Exception: pass

        return out_bytes, record


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import math
    from core.attack_engine import AttackEngine, AttackType
    from core.traffic_filter import TrafficFilter
    from core.pmu_simulator import PMUSimulator

    print("PDCProxy self-test — PMU → proxy → PDC listener")

    PMU_PORT   = 19880
    PROXY_PORT = 19881
    PDC_PORT   = 19882

    records = []
    def on_pkt(r):
        records.append(r)
        if len(records) % 10 == 1:
            print(f"  [{r.status.upper():<8}] {r.log_line()}")

    # Build components
    engine = AttackEngine()
    engine.set_attack(AttackType.NOISE, {"noise_std": 5.0})

    filt = TrafficFilter()
    # No rules = attack everything

    proxy = PDCProxy(
        listen_host="127.0.0.1", listen_port=PROXY_PORT,
        target_host="127.0.0.1", target_port=PDC_PORT,
        proto="UDP",
        attack_engine=engine,
        traffic_filter=filt,
        on_packet=on_pkt,
    )
    proxy.start()
    time.sleep(0.2)

    # PDC listener
    pdc_received = []
    pdc_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    pdc_sock.bind(("127.0.0.1", PDC_PORT))
    pdc_sock.settimeout(0.1)

    def pdc_listener():
        while True:
            try:
                data, _ = pdc_sock.recvfrom(4096)
                pdc_received.append(data)
            except socket.timeout:
                pass
            except OSError:
                break

    pdc_t = threading.Thread(target=pdc_listener, daemon=True)
    pdc_t.start()

    # PMU
    pmu = PMUSimulator(
        dst_host="127.0.0.1", dst_port=PROXY_PORT,
        fps=30, nom_freq=50.0, nom_voltage=120.0
    )
    pmu.start()

    time.sleep(3.0)

    pmu.stop()
    proxy.stop()
    time.sleep(0.2)
    pdc_sock.close()

    print(f"\n{'='*50}")
    print(f"PMU sent:     {pmu.packets_sent} packets")
    print(f"Proxy stats:  {proxy.stats}")
    print(f"PDC received: {len(pdc_received)} packets")
    print(f"Records:      {len(records)}")

    assert pmu.packets_sent > 50, "PMU sent too few packets"
    assert proxy.stats["attacked"] > 10, "Expected attacked packets"
    assert len(pdc_received) > 10, "PDC received too few packets"

    print("\nPDCProxy ALL TESTS PASSED ✔")
