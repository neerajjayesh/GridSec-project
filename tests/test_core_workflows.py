"""Real loopback I/O and malformed-input regressions; no external services required."""
import http.client
import json
import queue
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path

from core.attack_engine import AttackEngine, AttackType
from core.integration_manager import IntegrationManager, Incident
from core.packet_parser import parse_frame, rebuild_frame
from core.pcap_writer import PcapWriter, build_tcp_packet, _ip_checksum
from core.pdc_proxy import PDCProxy
from core.pmu_simulator import PMUSimulator
from core.rest_api import GridSecRESTServer
from protocols.c37118 import C37118Codec, crc_bytes


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.codec = C37118Codec(idcode=17, num_digital=1)
        self.raw = self.codec.encode_data_frame(
            [(120, 0), (121, -2), (119, 2)], 50, 0.1, [45], [0xA501],
            soc=1700000000, fracsec=500000, stat=0x100)

    def test_roundtrip_preserves_channels_identity_time(self):
        parsed = parse_frame(self.raw, self.codec)
        parsed["freq"] = 60
        # Rebuilding with another station ID must still preserve the source.
        out = rebuild_frame(parsed, C37118Codec(idcode=99, num_digital=1))
        decoded = parse_frame(out, self.codec)
        for key in ("digital", "idcode", "soc", "fracsec", "stat", "analog"):
            self.assertEqual(decoded[key], parsed[key])
        self.assertEqual(decoded["freq"], 60)
        self.assertEqual(len(out), len(self.raw))

    def test_bad_sizes_crc_and_truncated_config_are_rejected(self):
        self.assertIsNone(self.codec.decode_data_frame(self.raw[:-2]))
        self.assertIsNone(C37118Codec(num_digital=0).decode_data_frame(self.raw))
        for length in range(len(self.raw)):
            packet = self.raw[:length]
            result = parse_frame(packet, self.codec)
            self.assertTrue(result is None or result["frame_type"].endswith("invalid"))
        cfg = self.codec.encode_config_frame()
        for length in range(16, len(cfg), 11):
            body = cfg[:2] + struct.pack(">H", length + 2) + cfg[4:length]
            self.assertIsNone(self.codec.decode_config_frame(body + crc_bytes(body)))

    def test_rebuild_failure_is_not_silently_reported_as_success(self):
        frame = parse_frame(self.raw, self.codec)
        frame["freq"] = "bad"
        with self.assertRaises(ValueError):
            rebuild_frame(frame, self.codec)

    def test_schedule_counts_skipped_frames_and_none_is_safe(self):
        engine = AttackEngine()
        engine.enable()
        frame = parse_frame(self.raw, self.codec)
        self.assertFalse(engine.apply(frame)[1])
        engine.reset_stats()
        engine.set_attack(AttackType.SCALE, {"scale_factor": 2})
        engine.set_schedule(2, 2)
        self.assertEqual([engine.apply(frame)[1] for _ in range(5)],
                         [False, False, True, True, False])

    def test_invalid_attack_update_is_atomic(self):
        engine = AttackEngine()
        engine.set_attack(AttackType.NOISE, {"noise_std": 3})
        before = engine.snapshot()
        for params in ({"scale_factor": float("nan")}, {"scale_factor": "oops"},
                       {"bogus": 1}, {"scale_factor": float("inf")}):
            with self.assertRaises(ValueError):
                engine.set_attack(AttackType.SCALE, params)
            self.assertEqual(before, engine.snapshot())

    def test_delay_is_reported_and_stop_is_interruptible(self):
        engine = AttackEngine()
        engine.set_attack(AttackType.DELAY, {"delay_ms": 5000})
        proxy = PDCProxy(codec=self.codec, attack_engine=engine)
        result = []
        worker = threading.Thread(target=lambda: result.append(
            proxy._process_packet_bytes(self.raw, ("127.0.0.1", 1234), {})))
        worker.start()
        time.sleep(0.04)
        proxy.stop()
        worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result[0][1].status, "attacked")
        self.assertEqual(result[0][0], self.raw)

    def test_real_udp_forward_drop_capture_and_port_conflict(self):
        received = queue.Queue()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(1)
            engine = AttackEngine()
            engine.set_attack(AttackType.FREQUENCY_OVERRIDE, {"target_freq": 60})
            proxy = PDCProxy(listen_host="127.0.0.1", listen_port=0,
                             target_port=sink.getsockname()[1], codec=self.codec,
                             attack_engine=engine, on_packet=received.put)
            proxy.start()
            self.addCleanup(lambda: (proxy.stop(), proxy.join(2)))
            self.assertTrue(proxy.ready.wait(1))
            self.assertEqual(proxy.last_error, "")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
                sender.sendto(self.raw, ("127.0.0.1", proxy.listen_port))
                wire = sink.recv(65535)
                record = received.get(timeout=1)
                self.assertTrue(record.forwarded)
                self.assertEqual(record.raw_bytes, wire)
                self.assertEqual(parse_frame(wire, self.codec)["digital"], [0xA501])
                self.assertEqual(parse_frame(wire, self.codec)["freq"], 60)
                conflict = PDCProxy(listen_host="127.0.0.1", listen_port=proxy.listen_port)
                conflict.start()
                conflict.ready.wait(1)
                conflict.join(1)
                self.assertTrue(conflict.last_error)
                engine.set_attack(AttackType.DROP, {"drop_percent": 100})
                sender.sendto(self.raw, ("127.0.0.1", proxy.listen_port))
                dropped = received.get(timeout=1)
                self.assertEqual(dropped.status, "dropped")
                self.assertFalse(dropped.forwarded)
            with tempfile.TemporaryDirectory() as folder:
                path = str(Path(folder) / "capture.pcap")
                manager = IntegrationManager()
                manager.configure_pcap(path)
                self.assertEqual(manager.start_pcap_only()["pcap"], "started")
                manager.record_packet(record, record.raw_bytes, src_ip=record.src_addr[0],
                                      src_port=record.src_addr[1], dst_ip=record.dst_addr[0],
                                      dst_port=record.dst_addr[1])
                manager.stop()
                data = Path(path).read_bytes()
                self.assertTrue(data.endswith(wire))
                self.assertEqual(manager.pcap_packet_count, 1)
                self.assertEqual(manager.pcap_path, path)

    def test_tcp_fragmented_and_coalesced_frames(self):
        records = queue.Queue()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            listener.settimeout(2)
            proxy = PDCProxy(listen_host="127.0.0.1", listen_port=0, proto="TCP",
                             target_port=listener.getsockname()[1], codec=self.codec,
                             on_packet=records.put)
            proxy.start()
            self.addCleanup(lambda: (proxy.stop(), proxy.join(2)))
            self.assertTrue(proxy.ready.wait(1))
            with socket.create_connection(("127.0.0.1", proxy.listen_port), timeout=2) as client:
                conn, _ = listener.accept()
                with conn:
                    conn.settimeout(2)
                    client.sendall(self.raw[:3])
                    client.sendall(self.raw[3:] + self.raw)
                    data = b""
                    while len(data) < len(self.raw) * 2:
                        data += conn.recv(65535)
                    self.assertEqual(data, self.raw * 2)
                    self.assertTrue(records.get(timeout=1).forwarded)
                    self.assertTrue(records.get(timeout=1).forwarded)

    def test_pmu_honors_identity_rate_and_shuts_down(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(2)
            pmu = PMUSimulator(dst_port=sink.getsockname()[1], idcode=31, fps=10)
            pmu.start()
            try:
                self.assertTrue(pmu.ready.wait(1))
                cfg = self.codec.decode_config_frame(sink.recv(65535))
                self.assertEqual(cfg["data_rate"], 10)
                frame = parse_frame(sink.recv(65535), self.codec)
                self.assertEqual(frame["idcode"], 31)
                self.assertEqual(frame["digital"], [1])
            finally:
                pmu.stop()
                pmu.join(1)
            self.assertFalse(pmu.is_alive())

    def test_late_capture_gets_configuration_metadata(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(1)
            pmu = PMUSimulator(dst_port=sink.getsockname()[1], fps=30)
            pmu.config_interval = 0.05
            pmu.start()
            try:
                cfg_count = 0
                for _ in range(8):
                    packet = sink.recv(65535)
                    if self.codec.detect_frame_type(packet) == "cfg2":
                        cfg_count += 1
                self.assertGreaterEqual(cfg_count, 2)
            finally:
                pmu.stop()
                pmu.join(1)


class IntegrationTests(unittest.TestCase):
    def test_modbus_fragmentation_write_and_illegal_address(self):
        from core.modbus_simulator import ModbusServer
        from protocols.modbus import build_write_single_register_request, decode_frame
        server = ModbusServer(port=0)
        server.start()
        try:
            self.assertTrue(server.ready.wait(1))
            self.assertEqual(server.last_error, "")
            with socket.create_connection(("127.0.0.1", server._port), timeout=2) as client:
                request = build_write_single_register_request(2, 123, transaction_id=8)
                client.sendall(request[:2])
                client.sendall(request[2:] + build_write_single_register_request(100, 42, transaction_id=9))
                data = b""
                while len(data) < 21:
                    chunk = client.recv(4096)
                    self.assertTrue(chunk)
                    data += chunk
                self.assertEqual(data[:12], request)
                self.assertEqual(server._holding_regs[2], 123)
                self.assertTrue(decode_frame(data[12:]).is_exception)
        finally:
            server.stop()
        self.assertFalse(server._thread.is_alive())

    def test_dnp3_header_checksum_and_truncation(self):
        from protocols.dnp3 import DNP3DataLink, crc16_dnp
        self.assertEqual(crc16_dnp(b"123456789"), 0xEA82)
        raw = DNP3DataLink(control=0xC4, dst_addr=1, src_addr=1024).encode_frame(bytes(range(40)))
        self.assertEqual(struct.unpack_from("<H", raw, 8)[0], crc16_dnp(raw[:8]))
        self.assertIsNotNone(DNP3DataLink.decode_frame(raw))
        for n in range(len(raw)):
            self.assertIsNone(DNP3DataLink.decode_frame(raw[:n]))
        self.assertIsNone(DNP3DataLink.decode_frame(raw + b"extra"))

    def test_auxiliary_adapters_start_and_stop_on_loopback(self):
        from core.dnp3_simulator import DNP3Simulator
        from core.modbus_simulator import ModbusSimulator
        dnp = DNP3Simulator(bind_port=0, target_port=20001, fps=0.1)
        modbus = ModbusSimulator(port=0, poll_rate_hz=10)
        try:
            dnp.start()
            modbus.start()
            time.sleep(0.2)
            self.assertGreater(modbus.master.polls_sent, 0)
            self.assertGreater(dnp.frames_sent, 0)
        finally:
            dnp.stop()
            modbus.stop()
        self.assertFalse(dnp._sender_thread.is_alive())
        self.assertFalse(modbus.server._thread.is_alive())

    def test_iec104_rejects_bad_lengths(self):
        from protocols.iec104 import IEC104Frame, encode_startdt_act
        raw = encode_startdt_act()
        self.assertIsNotNone(IEC104Frame.decode(raw))
        self.assertIsNone(IEC104Frame.decode(raw + b"extra"))
        self.assertIsNone(IEC104Frame.decode(raw[:1] + b"\xff" + raw[2:]))

    def test_tcp_checksum(self):
        packet = build_tcp_packet("127.0.0.1", "127.0.0.2", 50000, 502, b"payload")
        tcp = packet[34:]
        pseudo = struct.pack(">4s4sBBH", socket.inet_aton("127.0.0.1"),
                             socket.inet_aton("127.0.0.2"), 0, 6, len(tcp))
        self.assertEqual(_ip_checksum(pseudo + tcp), 0)

    def test_empty_capture_header_and_open_error(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "empty.pcap"
            writer = PcapWriter(str(path))
            self.assertEqual(path.stat().st_size, 24)
            writer.close()
            manager = IntegrationManager()
            manager.configure_pcap(folder)
            self.assertIn("error", manager.start_pcap_only()["pcap"])

    @unittest.skipUnless(hasattr(__import__("os"), "mkfifo"), "Linux FIFO")
    def test_fifo_never_replaces_existing_file_and_stops_without_reader(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "important.txt"
            path.write_text("keep")
            writer = PcapWriter(str(path), use_fifo=True)
            self.assertTrue(writer.error)
            writer.close()
            self.assertEqual(path.read_text(), "keep")
            fifo = PcapWriter(str(Path(folder) / "live"), use_fifo=True)
            fifo.close()
            self.assertFalse(fifo._fifo_thread.is_alive())

    def test_syslog_buttons_backend_and_test_socket_cleanup(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink:
            sink.bind(("127.0.0.1", 0))
            sink.settimeout(1)
            manager = IntegrationManager()
            manager.configure_syslog(port=sink.getsockname()[1])
            self.assertTrue(manager.test_syslog()[0])
            self.assertIn(b"CEF:0", sink.recv(65535))
            self.assertEqual(manager.start_syslog_only()["syslog"], "connected")
            manager.stop_syslog_only()
            self.assertIsNone(manager._syslog)


class RestTests(unittest.TestCase):
    def setUp(self):
        self.server = GridSecRESTServer(port=0)
        self.server.set_incidents_callback(lambda: [
            {"protocol": "DNP3", "status": "attacked"},
            {"protocol": "C37.118", "status": "clean"}])
        self.assertTrue(self.server.start())
        self.addCleanup(self.server.stop)

    def request(self, path, body=None, method="GET", key=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=2)
        try:
            headers = {"Authorization": "Bearer " + (key or self.server.api_key)}
            conn.request(method, path, body=body, headers=headers)
            response = conn.getresponse()
            return response.status, response.read()
        finally:
            conn.close()

    def test_docs_filter_auth_validation(self):
        status, page = self.request("/")
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.api_key.encode(), page)
        status, payload = self.request("/api/v1/incidents?proto=dnp3")
        self.assertEqual(json.loads(payload)["count"], 1)
        self.assertEqual(self.request("/api/v1/incidents", key="wrong")[0], 401)
        for limit in ("0", "-1", "hello", "10001"):
            self.assertEqual(self.request("/api/v1/incidents?limit=" + limit)[0], 400)
        for body in ("[1]", "null", "{", '{"type":"NOISE","params":[]}'):
            self.assertEqual(self.request("/api/v1/attack/enable", body, "POST")[0], 400)
        self.assertEqual(self.request("/api/v1/attack/disable", "{}", "POST")[0], 503)

    def test_sse_does_not_block_requests_or_stop(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=2)
        conn.request("GET", "/api/v1/events", headers={
            "Authorization": "Bearer " + self.server.api_key})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertIn(b"GridSec", response.fp.readline())
        self.assertEqual(self.request("/api/v1/status")[0], 200)
        start = time.monotonic()
        self.server.stop()
        self.assertLess(time.monotonic() - start, 1)
        response.close()
        conn.close()
        self.assertTrue(self.server.start())
        self.assertEqual(self.request("/api/v1/status")[0], 200)

    def test_servers_have_independent_auth_and_callbacks(self):
        other = GridSecRESTServer(port=0)
        other.set_api_key("another-key")
        other.disable_auth()
        self.assertTrue(other.start())
        try:
            self.assertNotEqual(self.server.api_key, other.api_key)
            self.assertEqual(self.request("/api/v1/topology", key="another-key")[0], 401)
        finally:
            other.stop()


if __name__ == "__main__":
    unittest.main()
