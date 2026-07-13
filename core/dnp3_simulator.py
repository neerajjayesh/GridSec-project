"""
core/dnp3_simulator.py
=======================
DNP3 Outstation Simulator Thread

Sends real DNP3 Unsolicited Response frames over UDP port 20000.
Wireshark on the "any" interface will see and fully dissect these.

Architecture:
  - DNP3Simulator acts as an "outstation" (slave device)
  - Sends periodic Unsolicited Responses with analog + binary data
  - Also listens for incoming requests and responds to them (optional)
  - DNP3 master polls: sends a Read Request, outstation responds

Wireshark filter: dnp3
Port:             UDP 20000 (also TCP 20000)
"""

import logging
import socket
import struct
import threading
import time
from typing import Callable, List, Optional

from protocols.dnp3 import (
    build_unsolicited_response,
    build_read_request,
    DNP3DataLink,
    DNP3_PORT,
    FC_UNSOLICITED_RESP,
    FC_READ,
    FC_RESPONSE,
    FC_CONFIRM,
    IIN_DEVICE_RESTART,
    encode_app_layer,
    encode_transport,
    encode_analog_inputs_float,
    encode_binary_inputs,
)

logger = logging.getLogger(__name__)


class DNP3Simulator:
    """
    DNP3 outstation simulator.

    Sends DNP3 Unsolicited Response frames (UDP, port 20000) containing:
      Analog Inputs (Group 30 Var 5, float32):
        Index 0 = Va magnitude
        Index 1 = Vb magnitude
        Index 2 = Vc magnitude
        Index 3 = Frequency (Hz)
        Index 4 = Active Power (kW)
        Index 5 = Reactive Power (kVar)
      Binary Inputs (Group 1 Var 2):
        Index 6 = Trip status
        Index 7 = CB closed status

    Also optionally runs a listener that responds to incoming Read Requests.
    """

    OUTSTATION_ADDR = 1    # DNP3 outstation address
    MASTER_ADDR     = 3    # DNP3 master address

    def __init__(
        self,
        target_ip:   str   = "127.0.0.1",
        target_port: int   = DNP3_PORT,
        bind_port:   int   = DNP3_PORT,
        fps:         float = 1.0,
        callback:    Optional[Callable[[dict], None]] = None,
    ):
        self._target_ip   = target_ip
        self._target_port = target_port
        self._bind_port   = bind_port
        self._fps         = fps
        self._callback    = callback

        # Current measurement values
        self._va   = 120.0
        self._vb   = 119.5
        self._vc   = 120.5
        self._freq = 50.0
        self._active_power   = 450.0
        self._reactive_power =  80.0
        self._trip      = False
        self._cb_closed = True
        self._lock      = threading.Lock()

        # Thread control
        self._running        = False
        self._sender_thread: Optional[threading.Thread] = None
        self._listen_thread: Optional[threading.Thread] = None
        self._sock:          Optional[socket.socket]    = None

        # Sequence counters
        self._app_seq       = 0
        self._transport_seq = 0
        self._iin           = IIN_DEVICE_RESTART

        # Stats
        self.frames_sent     = 0
        self.frames_received = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def update_values(
        self,
        va:            float,
        vb:            float,
        vc:            float,
        freq:          float,
        active_power:  float = 450.0,
        reactive_power: float = 80.0,
        trip:          bool  = False,
        cb_closed:     bool  = True,
    ) -> None:
        """Update measurement values used in outgoing frames."""
        with self._lock:
            self._va             = va
            self._vb             = vb
            self._vc             = vc
            self._freq           = freq
            self._active_power   = active_power
            self._reactive_power = reactive_power
            self._trip           = trip
            self._cb_closed      = cb_closed
            # After first successful response, clear Device Restart IIN
            self._iin           &= ~IIN_DEVICE_RESTART

    # ── Thread control ────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running       = True
        self._open_socket()
        self._sender_thread = threading.Thread(target=self._send_loop,
                                               daemon=True, name="DNP3-Sender")
        self._listen_thread = threading.Thread(target=self._listen_loop,
                                               daemon=True, name="DNP3-Listener")
        self._sender_thread.start()
        self._listen_thread.start()
        logger.info(f"DNP3 simulator started → {self._target_ip}:{self._target_port}")

    def stop(self) -> None:
        self._running = False
        if self._sender_thread and self._sender_thread.is_alive():
            self._sender_thread.join(timeout=3.0)
        if self._listen_thread and self._listen_thread.is_alive():
            self._listen_thread.join(timeout=2.0)
        self._close_socket()
        logger.info("DNP3 simulator stopped")

    # ── Socket management ─────────────────────────────────────────────────────

    def _open_socket(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Try to bind to the DNP3 port for listener
            try:
                self._sock.bind(("0.0.0.0", self._bind_port))
                logger.info(f"DNP3 listening on UDP {self._bind_port}")
            except OSError:
                # Port might be in use — bind to any port for sending only
                self._sock.bind(("0.0.0.0", 0))
                logger.info("DNP3: could not bind to 20000, sending from ephemeral port")
            self._sock.settimeout(0.5)
        except Exception as e:
            logger.error(f"DNP3 socket error: {e}")
            self._sock = None

    def _close_socket(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    # ── Sender loop ───────────────────────────────────────────────────────────

    def _send_loop(self) -> None:
        interval = 1.0 / max(0.1, self._fps)

        while self._running:
            try:
                if self._sock:
                    frame = self._build_unsolicited()
                    self._sock.sendto(frame, (self._target_ip, self._target_port))
                    self.frames_sent += 1
                    self._app_seq       = (self._app_seq       + 1) & 0x0F
                    self._transport_seq = (self._transport_seq + 1) & 0x3F

                    if self._callback:
                        with self._lock:
                            self._callback({
                                "proto": "DNP3",
                                "va":    self._va,
                                "vb":    self._vb,
                                "vc":    self._vc,
                                "freq":  self._freq,
                                "trip":  self._trip,
                                "frames_sent": self.frames_sent,
                            })

            except Exception as exc:
                logger.debug(f"DNP3 send error: {exc}")

            time.sleep(interval)

    # ── Listener loop ─────────────────────────────────────────────────────────

    def _listen_loop(self) -> None:
        """Listen for incoming DNP3 frames (Read Requests) and respond."""
        while self._running:
            if not self._sock:
                time.sleep(0.1)
                continue
            try:
                data, addr = self._sock.recvfrom(4096)
                self.frames_received += 1
                self._handle_request(data, addr)
            except socket.timeout:
                continue
            except Exception as exc:
                if self._running:
                    logger.debug(f"DNP3 listen error: {exc}")

    def _handle_request(self, data: bytes, addr) -> None:
        """Parse incoming DNP3 frame and respond if it's a Read Request."""
        result = DNP3DataLink.decode_frame(data)
        if result is None:
            return

        dst_addr, src_addr, user_data = result
        if len(user_data) < 2:
            return

        # Transport byte
        transport = user_data[0]
        app_data  = user_data[1:]
        if len(app_data) < 2:
            return

        fc = app_data[1]
        if fc == FC_READ:
            # Send a response with current values
            resp = self._build_response(self._app_seq)
            try:
                self._sock.sendto(resp, addr)
                self.frames_sent += 1
            except Exception:
                pass

    # ── Frame builders ────────────────────────────────────────────────────────

    def _build_unsolicited(self) -> bytes:
        """Build a DNP3 Unsolicited Response frame."""
        with self._lock:
            analogs  = [self._va, self._vb, self._vc, self._freq,
                        self._active_power, self._reactive_power]
            binaries = [self._trip, self._cb_closed]
            iin      = self._iin

        return build_unsolicited_response(
            src_addr      = self.OUTSTATION_ADDR,
            dst_addr      = self.MASTER_ADDR,
            analog_values = analogs,
            binary_values = binaries,
            app_seq       = self._app_seq,
            transport_seq = self._transport_seq,
            iin           = iin,
        )

    def _build_response(self, seq: int) -> bytes:
        """Build a DNP3 Response frame to a Read Request."""
        with self._lock:
            analogs  = [self._va, self._vb, self._vc, self._freq,
                        self._active_power, self._reactive_power]
            binaries = [self._trip, self._cb_closed]

        objects = (
            encode_analog_inputs_float(analogs) +
            encode_binary_inputs(binaries, start_idx=len(analogs))
        )
        from protocols.dnp3 import FC_RESPONSE
        app = encode_app_layer(FC_RESPONSE, objects, app_seq=seq & 0x0F,
                               iin=self._iin)
        transport = encode_transport(app, seq=seq & 0x3F)
        dl = DNP3DataLink(
            control  = 0x44,
            dst_addr = self.MASTER_ADDR,
            src_addr = self.OUTSTATION_ADDR,
        )
        return dl.encode_frame(transport)
