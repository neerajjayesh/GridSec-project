"""
core/modbus_simulator.py
=========================
Modbus TCP Server + Periodic Master Simulator

Runs a real Modbus TCP server on port 502 (or configurable).
Also runs a Modbus master thread that periodically polls the server,
generating bidirectional request/response traffic visible in Wireshark.

Wireshark filter: modbus
Port:             TCP 502
"""

import logging
import select
import socket
import struct
import threading
import time
from typing import Callable, Dict, List, Optional

from protocols.modbus import (
    MODBUS_PORT,
    FC_READ_INPUT_REGS,
    FC_READ_HOLDING_REGS,
    FC_WRITE_SINGLE_REG,
    EX_ILLEGAL_DATA_ADDRESS,
    EX_ILLEGAL_DATA_VALUE,
    EX_ILLEGAL_FUNCTION,
    build_read_registers_response,
    build_exception_response,
    build_read_input_registers_request,
    build_power_system_registers,
    decode_frame,
    float_to_reg,
    reg_to_float,
)

logger = logging.getLogger(__name__)


class ModbusServer:
    """
    Modbus TCP server (slave/outstation) on TCP port 502.

    Holds an internal register map that reflects live power system values.
    Responds to Read Input Registers, Read Holding Registers, and
    Write Single Register commands.
    """

    MAX_INPUT_REGS   = 32
    MAX_HOLDING_REGS = 16

    def __init__(
        self,
        host:     str = "127.0.0.1",
        port:     int = MODBUS_PORT,
        unit_id:  int = 1,
        callback: Optional[Callable[[dict], None]] = None,
    ):
        self._host     = host
        self._port     = port
        self._unit_id  = unit_id
        self._callback = callback

        # Input registers (read-only from master perspective)
        self._input_regs: List[int] = [0] * self.MAX_INPUT_REGS
        # Holding registers (read/write)
        self._holding_regs: List[int] = [0] * self.MAX_HOLDING_REGS
        self._holding_regs[0] = float_to_reg(220.0, 10.0)   # voltage setpoint
        self._holding_regs[1] = float_to_reg(50.0, 100.0)   # frequency setpoint

        self._lock   = threading.Lock()
        self._running = False
        self.ready = threading.Event()
        self.last_error = ""
        self._clients = set()
        self._client_lock = threading.Lock()
        self._server_sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread]   = None

        self.connections_served = 0
        self.requests_handled   = 0

    def update_input_registers(
        self,
        va:            float,
        vb:            float,
        vc:            float,
        freq:          float,
        active_power:  float = 450.0,
        reactive_power: float = 80.0,
        ia: float = 10.0,
        ib: float = 10.0,
        ic: float = 10.0,
        power_factor: float = 0.95,
    ) -> None:
        """Update the input register map with current measurements."""
        regs = build_power_system_registers(
            va, vb, vc, freq,
            active_power, reactive_power,
            ia, ib, ic, power_factor,
        )
        with self._lock:
            for i, v in enumerate(regs):
                if i < self.MAX_INPUT_REGS:
                    self._input_regs[i] = v

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self.ready.clear()
        self.last_error = ""
        self._thread  = threading.Thread(target=self._run, daemon=True,
                                          name="Modbus-Server")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        with self._client_lock:
            clients = list(self._clients)
        for client in clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            client.close()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
            self._server_sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        logger.info("Modbus server stopped")

    def _run(self) -> None:
        try:
            self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_sock.bind((self._host, self._port))
            self._port = self._server_sock.getsockname()[1]
            self._server_sock.listen(8)
            self._server_sock.settimeout(1.0)
            logger.info(f"Modbus TCP server listening on {self._host}:{self._port}")

        except OSError as e:
            self._server_sock.close()
            if not isinstance(e, PermissionError):
                self.last_error = str(e)
                self._running = False
                self.ready.set()
                return
            # Try a high port fallback
            try:
                self._port       = self._port + 10000   # e.g., 10502
                self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._server_sock.bind((self._host, self._port))
                self._server_sock.listen(8)
                self._server_sock.settimeout(1.0)
                logger.info(f"Modbus server fallback: listening on port {self._port}")
            except Exception as e2:
                logger.error(f"Modbus server could not start: {e2}")
                self.last_error = str(e2)
                self._running = False
                self._server_sock.close()
                self.ready.set()
                return
        self.ready.set()
        while self._running:
            try:
                client_sock, addr = self._server_sock.accept()
                with self._client_lock:
                    if len(self._clients) >= 16:
                        client_sock.close()
                        continue
                    self._clients.add(client_sock)
                self.connections_served += 1
                ct = threading.Thread(
                    target=self._handle_client,
                    args=(client_sock, addr),
                    daemon=True,
                    name=f"Modbus-Client-{addr[1]}",
                )
                ct.start()
            except socket.timeout:
                continue
            except Exception as exc:
                if self._running:
                    logger.debug(f"Modbus accept error: {exc}")

    def _handle_client(self, sock: socket.socket, addr) -> None:
        """Handle one Modbus TCP client connection."""
        logger.debug(f"Modbus: client connected from {addr}")
        sock.settimeout(0.2)
        buffer = b""
        idle_since = time.monotonic()
        try:
            while self._running:
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    if time.monotonic() - idle_since > 30:
                        break
                    continue
                if not data:
                    break

                idle_since = time.monotonic()
                buffer += data
                while len(buffer) >= 6:
                    pid, length = struct.unpack_from(">HH", buffer, 2)
                    if pid or not 2 <= length <= 254:
                        return
                    if len(buffer) < 6 + length:
                        break
                    raw, buffer = buffer[:6 + length], buffer[6 + length:]
                    frame = decode_frame(raw, is_request=True)
                    if frame is None:
                        return
                    self.requests_handled += 1
                    response = self._process_request(frame, raw)
                    if response:
                        sock.sendall(response)
                    if self._callback:
                        self._callback({"proto": "Modbus", "fc": frame.fc,
                                        "is_req": True, "reg_start": frame.register_start,
                                        "reg_count": frame.register_count})

        except Exception as exc:
            logger.debug(f"Modbus client handler error: {exc}")
        finally:
            with self._client_lock:
                self._clients.discard(sock)
            try:
                sock.close()
            except Exception:
                pass

    def _process_request(self, frame, raw: bytes) -> Optional[bytes]:
        """Process a decoded Modbus request and return a response."""
        tid = frame.transaction_id
        uid = frame.unit_id
        if frame.is_exception:
            return None
        if frame.fc in (FC_READ_INPUT_REGS, FC_READ_HOLDING_REGS) and not 1 <= frame.register_count <= 125:
            return build_exception_response(frame.fc, EX_ILLEGAL_DATA_VALUE, tid, uid)

        if frame.fc == FC_READ_INPUT_REGS and frame.is_request:
            start = frame.register_start
            count = frame.register_count
            with self._lock:
                if start + count > self.MAX_INPUT_REGS:
                    return build_exception_response(FC_READ_INPUT_REGS,
                                                    EX_ILLEGAL_DATA_ADDRESS, tid, uid)
                values = self._input_regs[start:start + count]
            return build_read_registers_response(values, tid, uid, FC_READ_INPUT_REGS)

        elif frame.fc == FC_READ_HOLDING_REGS and frame.is_request:
            start = frame.register_start
            count = frame.register_count
            with self._lock:
                if start + count > self.MAX_HOLDING_REGS:
                    return build_exception_response(FC_READ_HOLDING_REGS,
                                                    EX_ILLEGAL_DATA_ADDRESS, tid, uid)
                values = self._holding_regs[start:start + count]
            return build_read_registers_response(values, tid, uid, FC_READ_HOLDING_REGS)

        elif frame.fc == FC_WRITE_SINGLE_REG and frame.is_request:
            reg  = frame.register_start
            val  = frame.register_values[0] if frame.register_values else 0
            with self._lock:
                if reg < self.MAX_HOLDING_REGS:
                    self._holding_regs[reg] = val
                else:
                    return build_exception_response(frame.fc, EX_ILLEGAL_DATA_ADDRESS, tid, uid)
            from protocols.modbus import build_write_register_response
            return build_write_register_response(reg, val, tid, uid)

        return build_exception_response(frame.fc, EX_ILLEGAL_FUNCTION, tid, uid)


class ModbusMaster:
    """
    Modbus TCP master (client) that polls the local server periodically.

    This generates the request/response traffic that Wireshark captures
    and labels as "Modbus/TCP".
    """

    def __init__(
        self,
        server_ip:   str   = "127.0.0.1",
        server_port: int   = MODBUS_PORT,
        unit_id:     int   = 1,
        poll_rate_hz: float = 1.0,
    ):
        self._server_ip   = server_ip
        self._server_port = server_port
        self._unit_id     = unit_id
        self._interval    = 1.0 / max(0.1, poll_rate_hz)

        self._running   = False
        self._thread:   Optional[threading.Thread] = None
        self._tid       = 0
        self._stop_event = threading.Event()

        self.polls_sent = 0

    def start(self, fallback_port: int = MODBUS_PORT) -> None:
        """Start polling. fallback_port is used if the server moved to a high port."""
        self._server_port = fallback_port
        if self._running:
            return
        self._running = True
        self._stop_event.clear()
        self._thread  = threading.Thread(target=self._run, daemon=True,
                                          name="Modbus-Master")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

    def _run(self) -> None:
        logger.info(f"Modbus master polling {self._server_ip}:{self._server_port}")

        while self._running:
            try:
                self._poll()
            except Exception as exc:
                logger.debug(f"Modbus master poll error: {exc}")
            self._stop_event.wait(self._interval)

    def _poll(self) -> None:
        """Connect, send Read Input Registers request, receive response, disconnect."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((self._server_ip, self._server_port))

            self._tid = (self._tid + 1) & 0xFFFF
            req = build_read_input_registers_request(
                start_reg      = 0,
                count          = 10,
                transaction_id = self._tid,
                unit_id        = self._unit_id,
            )
            sock.sendall(req)
            _ = sock.recv(1024)   # receive response
            self.polls_sent += 1
            sock.close()
        except Exception:
            pass  # server not ready yet
        finally:
            if sock:
                sock.close()


class ModbusSimulator:
    """
    Combined Modbus TCP simulator: server + master poller.

    Start this to generate visible Modbus/TCP traffic in Wireshark.
    """

    def __init__(
        self,
        host:         str   = "127.0.0.1",
        port:         int   = MODBUS_PORT,
        poll_rate_hz: float = 1.0,
        callback:     Optional[Callable[[dict], None]] = None,
    ):
        self._host = host
        self._port = port

        self.server = ModbusServer(host, port, callback=callback)
        self.master = ModbusMaster(host, port, poll_rate_hz=poll_rate_hz)

    def update_values(
        self,
        va:            float,
        vb:            float,
        vc:            float,
        freq:          float,
        active_power:  float = 450.0,
        reactive_power: float = 80.0,
    ) -> None:
        """Push new measurement values to the server's register map."""
        self.server.update_input_registers(
            va, vb, vc, freq, active_power, reactive_power
        )

    def start(self) -> None:
        self.server.start()
        if not self.server.ready.wait(2) or self.server.last_error:
            self.server.stop()
            raise OSError(self.server.last_error or "Modbus server startup timed out")
        self.master.start(fallback_port=self.server._port)
        logger.info(f"Modbus simulator started (server={self._host}:{self.server._port})")

    def stop(self) -> None:
        self.master.stop()
        self.server.stop()
        logger.info("Modbus simulator stopped")

    @property
    def active_port(self) -> int:
        return self.server._port
