"""Threaded C37.118 UDP/TCP interception with explicit forwarding outcomes."""
import logging
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

from core.attack_engine import AttackEngine
from core.packet_parser import parse_frame, rebuild_frame, frame_summary
from core.traffic_filter import TrafficFilter
from protocols.c37118 import C37118Codec

logger = logging.getLogger(__name__)


@dataclass
class PacketRecord:
    timestamp: float
    original: dict
    modified: dict
    status: str
    attack_type: str = ""
    description: str = ""
    src_addr: tuple = ("", 0)
    raw_bytes: bytes = b""
    original_bytes: bytes = b""
    dst_addr: tuple = ("", 0)
    transport: str = "UDP"
    forwarded: bool = False
    latency_ms: float = 0.0

    def log_line(self) -> str:
        ts = time.strftime("%H:%M:%S", time.localtime(self.timestamp))
        return f"[{ts}] {self.status.upper():<8} {frame_summary(self.original)} {self.description}"


class PDCProxy(threading.Thread):
    """A local interception endpoint; callbacks run after the send attempt."""

    def __init__(self, listen_host="0.0.0.0", listen_port=4712,
                 target_host="127.0.0.1", target_port=4713, proto="UDP",
                 codec=None, attack_engine=None, traffic_filter=None,
                 on_packet=None):
        super().__init__(daemon=True, name="PDCProxy")
        self.listen_host, self.listen_port = listen_host, listen_port
        self.target_host, self.target_port = target_host, target_port
        self.proto = proto.upper()
        if self.proto not in ("UDP", "TCP"):
            raise ValueError("Transport must be UDP or TCP")
        self.codec = codec or C37118Codec(num_digital=1)
        self.attack_engine = attack_engine or AttackEngine()
        self.traffic_filter = traffic_filter or TrafficFilter()
        self.on_packet = on_packet
        self.attack_enabled = True
        self._stop_event = threading.Event()
        self.ready = threading.Event()
        self.last_error = ""
        self._running = False
        self._listen_sock = self._send_sock = None
        self._clients = set()
        self._workers = set()
        self._clients_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self.stats = dict.fromkeys(("total", "clean", "attacked", "dropped", "invalid", "errors"), 0)

    def start(self):
        if self._running:
            return
        self._running = True
        super().start()

    def stop(self):
        self._stop_event.set()
        self.attack_engine.cancel_event.set()
        self._running = False
        with self._clients_lock:
            sockets = list(self._clients)
        if self._listen_sock:
            sockets.append(self._listen_sock)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()

    def set_target(self, host, port):
        self.target_host, self.target_port = host, port

    @property
    def is_running(self):
        return self._running and self.is_alive()

    def _count(self, key):
        with self._stats_lock:
            self.stats[key] += 1

    def run(self):
        try:
            kind = socket.SOCK_DGRAM if self.proto == "UDP" else socket.SOCK_STREAM
            self._listen_sock = socket.socket(socket.AF_INET, kind)
            if self.proto == "TCP":
                self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listen_sock.bind((self.listen_host, self.listen_port))
            self.listen_port = self._listen_sock.getsockname()[1]
            if self.proto == "TCP":
                self._listen_sock.listen(16)
            else:
                self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._listen_sock.setblocking(False)
            self.ready.set()
            while not self._stop_event.is_set():
                readable, _, _ = select.select([self._listen_sock], [], [], 0.1)
                if not readable:
                    continue
                if self.proto == "UDP":
                    raw, src = self._listen_sock.recvfrom(65535)
                    self._process_packet(raw, src, self._packet_info(src))
                else:
                    conn, src = self._listen_sock.accept()
                    with self._clients_lock:
                        if len(self._workers) >= 16:
                            conn.close()
                            continue
                        self._clients.add(conn)
                        worker = threading.Thread(target=self._handle_tcp_connection,
                                                  args=(conn, src), daemon=True)
                        self._workers.add(worker)
                    worker.start()
        except (OSError, ValueError) as exc:
            if not self._stop_event.is_set():
                self.last_error = str(exc)
                logger.error("Proxy failed: %s", exc)
        finally:
            self.ready.set()
            self._running = False
            for sock in (self._listen_sock, self._send_sock):
                if sock:
                    sock.close()
            with self._clients_lock:
                workers = list(self._workers)
            for worker in workers:
                worker.join(timeout=1)

    def _packet_info(self, src):
        return {"src_ip": src[0], "src_port": src[1], "dst_ip": self.target_host,
                "dst_port": self.target_port, "proto": self.proto}

    def _handle_tcp_connection(self, conn, src):
        fwd = None
        try:
            conn.settimeout(0.2)
            fwd = socket.create_connection((self.target_host, self.target_port), timeout=1)
            with self._clients_lock:
                self._clients.add(fwd)
            buf = b""
            while not self._stop_event.is_set():
                try:
                    chunk = conn.recv(8192)
                except socket.timeout:
                    continue
                if not chunk:
                    break
                buf += chunk
                while len(buf) >= 4:
                    frame_size = struct.unpack_from(">H", buf, 2)[0]
                    if buf[0] != 0xAA or not 16 <= frame_size <= 65535:
                        buf = buf[1:]
                        continue
                    if len(buf) < frame_size:
                        break
                    raw, buf = buf[:frame_size], buf[frame_size:]
                    out, record = self._process_packet_bytes(raw, src, self._packet_info(src))
                    self._forward(out, record, fwd.sendall)
        except OSError as exc:
            if not self._stop_event.is_set():
                self.last_error = str(exc)
                self._count("errors")
                logger.warning("TCP connection failed: %s", exc)
        finally:
            with self._clients_lock:
                self._clients.discard(conn)
                self._clients.discard(fwd)
                self._workers.discard(threading.current_thread())
            conn.close()
            if fwd:
                fwd.close()

    def _process_packet(self, raw_data, src_addr, packet_info):
        out, record = self._process_packet_bytes(raw_data, src_addr, packet_info)
        self._forward(out, record,
                      lambda data: self._send_sock.sendto(data, record.dst_addr))

    def _forward(self, out, record, send):
        if self._stop_event.is_set():
            return
        if out is not None:
            try:
                send(out)
                record.forwarded = True  # UDP means sent, not an acknowledgement.
            except OSError as exc:
                self._count("errors")
                record.status = "forward_error"
                record.description = f"Forward failed: {exc}"
        if self.on_packet:
            try:
                self.on_packet(record)
            except Exception:
                logger.exception("Packet callback failed")

    def _process_packet_bytes(self, raw_data, src_addr, packet_info):
        started = time.monotonic()
        self._count("total")
        record = PacketRecord(time.time(), {}, {}, "invalid", src_addr=src_addr,
                              original_bytes=raw_data, raw_bytes=raw_data,
                              dst_addr=(self.target_host, self.target_port),
                              transport=self.proto)
        out = None
        try:
            original = parse_frame(raw_data, self.codec)
            record.original = original or {}
            kind = record.original.get("frame_type", "unknown")
            if kind in ("unknown", "data_invalid", "cfg_invalid", "cmd_invalid"):
                raise ValueError("Invalid frame length, format or CRC")
            record.modified = record.original
            record.status = "clean"
            out = raw_data
            if kind == "data" and self.attack_enabled and self.traffic_filter.matches(packet_info):
                result = self.attack_engine.apply_result(record.original)
                record.modified = result.frame_dict
                record.description = result.description
                if result.was_dropped:
                    out, record.status = None, "dropped"
                elif result.was_modified:
                    out = rebuild_frame(result.frame_dict, self.codec)
                    record.status = "attacked"
                elif getattr(result, "was_delayed", False):
                    record.status = "attacked"
                if record.status != "clean":
                    record.attack_type = result.attack_type.value
            record.raw_bytes = out if out is not None else raw_data
        except (ValueError, TypeError, KeyError, OverflowError, struct.error) as exc:
            out = None
            record.status = "invalid"
            record.modified = {}
            record.description = str(exc)
        self._count(record.status)
        record.latency_ms = (time.monotonic() - started) * 1000
        return out, record


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
