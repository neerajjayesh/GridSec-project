"""
core/goose_simulator.py
========================
IEC 61850 GOOSE Publisher Thread

Sends GOOSE frames (EtherType 0x88B8) as raw Ethernet multicast.
Wireshark on any interface will see and fully dissect these frames.

Requires CAP_NET_RAW or root. Run setup once:
    sudo setcap cap_net_raw+eip $(readlink -f $(which python3))
Or simply run with sudo:
    sudo python main.py

GOOSE retransmission profile (IEC 61850-8-1 §B.2):
  - On state change:  resend immediately, then after T0, T1, T2, T2, T2... ms
  - No state change:  resend at Tmax (stable heartbeat)
"""

import logging
import math
import socket
import struct
import threading
import time
from typing import Callable, List, Optional

from protocols.goose import (
    GoosePDU, GooseBoolean, GooseFloat32,
    get_default_interface, get_src_mac,
    GOOSE_DEFAULT_DST_MAC, GOOSE_ETHERTYPE,
)

logger = logging.getLogger(__name__)


# ── Retransmission profile ────────────────────────────────────────────────────

RETRANSMIT_PROFILE_MS = [4, 8, 16, 32, 64, 128, 256, 500, 1000, 2000]
#  Tmax = 2000 ms (stable heartbeat)


class GOOSESimulator:
    """
    IEC 61850 GOOSE publisher.

    Sends periodic GOOSE multicast frames containing simulated
    power system measurements (Va, Vb, Vc, Frequency, Trip, CB_Status).

    Integrates with the PMU simulator to share live measurement values.

    Usage:
        sim = GOOSESimulator(interface="eth0")
        sim.start()
        sim.update_values(va=120.0, vb=119.5, vc=120.5, freq=50.02)
        ...
        sim.stop()
    """

    def __init__(
        self,
        interface:   str  = "",
        appid:       int  = 0x0001,
        ied_name:    str  = "GridSecSim_IED",
        cb_instance: str  = "GCB01",
        fps:         float = 1.0,       # GOOSE heartbeat rate (Hz) when stable
        callback:    Optional[Callable[[dict], None]] = None,
    ):
        self._interface  = interface or get_default_interface()
        self._appid      = appid
        self._ied_name   = ied_name
        self._cb_ref     = f"{ied_name}/LLN0$GO${cb_instance}"
        self._dat_set    = f"{ied_name}/LLN0$DS_PMU"
        self._go_id      = f"GOOSE_{ied_name}_01"
        self._fps        = fps
        self._callback   = callback

        # Measurement values (updated by PMU simulator)
        self._va   = 120.0
        self._vb   = 119.5
        self._vc   = 120.5
        self._freq = 50.0
        self._trip = False
        self._cb_closed = True
        self._lock = threading.Lock()

        # GOOSE PDU state
        self._pdu: Optional[GoosePDU] = None

        # Thread control
        self._running   = False
        self._thread:   Optional[threading.Thread] = None
        self._sock:     Optional[socket.socket]    = None

        # Stats
        self.frames_sent   = 0
        self.state_changes = 0
        self._active       = False
        self._error_msg    = ""

        # Retransmit state
        self._state_changed     = False
        self._retransmit_index  = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def update_values(
        self,
        va:        float,
        vb:        float,
        vc:        float,
        freq:      float,
        trip:      bool = False,
        cb_closed: bool = True,
    ) -> None:
        """Update the dataset values — triggers GOOSE retransmission profile."""
        with self._lock:
            changed = (
                abs(va   - self._va)   > 0.5 or
                abs(vb   - self._vb)   > 0.5 or
                abs(vc   - self._vc)   > 0.5 or
                abs(freq - self._freq) > 0.05 or
                trip      != self._trip or
                cb_closed != self._cb_closed
            )
            self._va        = va
            self._vb        = vb
            self._vc        = vc
            self._freq      = freq
            self._trip      = trip
            self._cb_closed = cb_closed

            if changed and self._pdu is not None:
                self._pdu.event_state_change()
                self._state_changed    = True
                self._retransmit_index = 0
                self.state_changes    += 1

    def trigger_trip(self) -> None:
        """Simulate a protection trip event (trip=True, then restore)."""
        with self._lock:
            self._trip = True
            if self._pdu:
                self._pdu.event_state_change()
                self._state_changed    = True
                self._retransmit_index = 0
                self.state_changes    += 1

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def error(self) -> str:
        return self._error_msg

    # ── Thread control ────────────────────────────────────────────────────────

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread  = threading.Thread(target=self._run, daemon=True,
                                          name="GOOSE-Publisher")
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        self._thread = None
        self._close_socket()
        self._active = False
        logger.info("GOOSE simulator stopped")

    # ── Raw socket ────────────────────────────────────────────────────────────

    def _open_socket(self) -> bool:
        """Open an AF_PACKET raw socket for GOOSE multicast sending."""
        try:
            # AF_PACKET requires CAP_NET_RAW or root
            self._sock = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(GOOSE_ETHERTYPE)
            )
            # Bind to network interface
            self._sock.bind((self._interface, 0))

            # Get actual source MAC from interface
            src_mac = get_src_mac(self._interface)
            logger.info(f"GOOSE: opened AF_PACKET on {self._interface}, src MAC={':'.join(f'{b:02x}' for b in src_mac)}")
            return True

        except PermissionError:
            self._error_msg = (
                "GOOSE requires CAP_NET_RAW or root.\n"
                "Fix with one of:\n"
                "  sudo python main.py\n"
                "  sudo setcap cap_net_raw+eip $(readlink -f $(which python3))"
            )
            logger.warning(f"GOOSE: {self._error_msg}")
            return False

        except OSError as e:
            self._error_msg = f"GOOSE socket error: {e}"
            logger.warning(self._error_msg)
            return False

    def _close_socket(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    # ── Publisher loop ────────────────────────────────────────────────────────

    def _build_pdu(self) -> None:
        """(Re)build the GoosePDU with current values."""
        with self._lock:
            src_mac = get_src_mac(self._interface)
            self._pdu = GoosePDU(
                gocbRef              = self._cb_ref,
                datSet               = self._dat_set,
                goID                 = self._go_id,
                appid                = self._appid,
                confRev              = 1,
                timeAllowedToLive_ms = 2000,
                src_mac              = src_mac,
                dst_mac              = bytes(GOOSE_DEFAULT_DST_MAC),
                dataset              = [
                    GooseFloat32(self._va),
                    GooseFloat32(self._vb),
                    GooseFloat32(self._vc),
                    GooseFloat32(self._freq),
                    GooseBoolean(self._trip),
                    GooseBoolean(self._cb_closed),
                ],
            )

    def _send_frame(self) -> None:
        """Build and send one GOOSE frame."""
        if self._sock is None or self._pdu is None:
            return
        try:
            with self._lock:
                # Update dataset values in PDU
                self._pdu.dataset = [
                    GooseFloat32(self._va),
                    GooseFloat32(self._vb),
                    GooseFloat32(self._vc),
                    GooseFloat32(self._freq),
                    GooseBoolean(self._trip),
                    GooseBoolean(self._cb_closed),
                ]
                frame = self._pdu.build_frame()
                self._pdu.increment_sq()

            self._sock.send(frame)
            self.frames_sent += 1

            if self._callback:
                with self._lock:
                    data = {
                        "va":   self._va,   "vb": self._vb,   "vc": self._vc,
                        "freq": self._freq, "trip": self._trip,
                        "cb":   self._cb_closed,
                        "stNum": self._pdu.stNum,
                        "sqNum": self._pdu.sqNum,
                    }
                self._callback(data)

        except OSError as e:
            logger.debug(f"GOOSE send error: {e}")

    def _run(self) -> None:
        """Publisher thread main loop."""
        if not self._open_socket():
            self._active = False
            return

        self._build_pdu()
        self._active = True
        logger.info(f"GOOSE publisher started on {self._interface}")

        tmax_ms = int(1000.0 / self._fps)   # heartbeat interval

        while self._running:
            try:
                self._send_frame()

                # Determine next send interval (retransmission profile)
                if self._state_changed:
                    if self._retransmit_index < len(RETRANSMIT_PROFILE_MS):
                        wait_ms = RETRANSMIT_PROFILE_MS[self._retransmit_index]
                        self._retransmit_index += 1
                    else:
                        wait_ms              = tmax_ms
                        self._state_changed  = False
                        self._retransmit_index = 0
                else:
                    wait_ms = tmax_ms

                time.sleep(wait_ms / 1000.0)

            except Exception as exc:
                logger.error(f"GOOSE publisher error: {exc}")
                time.sleep(0.5)

        self._close_socket()
        self._active = False
