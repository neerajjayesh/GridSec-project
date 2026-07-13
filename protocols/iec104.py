"""
protocols/iec104.py
===================
IEC 60870-5-104 (IEC 104) — stub implementation.

IEC 104 is the TCP/IP adaptation of IEC 60870-5-101 (serial),
widely used for substation-to-control-center communication in Europe.

Frame types:
  - I-frame (Information transfer)
  - S-frame (Supervisory)
  - U-frame (Unnumbered — STARTDT, STOPDT, TESTFR)

For GridSec Sim v1.0, IEC 104 links are displayed on the topology canvas
but live simulation is C37.118 only.

References: IEC 60870-5-104:2006 Ed2
"""

import struct
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

IEC104_START  = 0x68   # Start byte for all APDU frames

# U-frame control field values (byte 0 of control field)
U_STARTDT_ACT = 0x07
U_STARTDT_CON = 0x0B
U_STOPDT_ACT  = 0x13
U_STOPDT_CON  = 0x23
U_TESTFR_ACT  = 0x43
U_TESTFR_CON  = 0x83

# Type Identification (TypeID) for common ASDU types
TYPE_M_SP_NA_1  = 0x01   # Single-point information
TYPE_M_ME_NB_1  = 0x0B   # Measured value, scaled
TYPE_M_ME_NC_1  = 0x0D   # Measured value, short floating point
TYPE_C_SC_NA_1  = 0x2D   # Single command
TYPE_C_DC_NA_1  = 0x2E   # Double command


# ─────────────────────────────────────────────────────────────────────────────
# APDU (Application Protocol Data Unit)
# ─────────────────────────────────────────────────────────────────────────────

class IEC104Frame:
    """
    IEC 60870-5-104 APDU frame.

    Structure:
      [0]   Start (0x68)
      [1]   APDU length (number of bytes following, including 4 control bytes)
      [2-5] Control field (4 bytes — varies by frame type)
      [6+]  ASDU (Application Service Data Unit) — for I-frames only
    """

    def __init__(self, frame_type: str = "U", ctrl: bytes = b"\x07\x00\x00\x00", asdu: bytes = b""):
        """
        frame_type : 'I', 'S', or 'U'
        ctrl       : 4-byte control field
        asdu       : ASDU bytes (only for I-frames)
        """
        self.frame_type = frame_type
        self.ctrl       = ctrl[:4].ljust(4, b"\x00")
        self.asdu       = asdu

    def encode(self) -> bytes:
        apdu_body = self.ctrl + self.asdu
        length    = len(apdu_body)
        return bytes([IEC104_START, length]) + apdu_body

    @classmethod
    def decode(cls, raw: bytes) -> Optional["IEC104Frame"]:
        if len(raw) < 6:
            return None
        if raw[0] != IEC104_START:
            return None
        length = raw[1]
        ctrl   = raw[2:6]
        asdu   = raw[6:2 + length]

        # Determine frame type from control field bit 0-1
        b0 = ctrl[0]
        if b0 & 0x01 == 0:
            ftype = "I"
        elif b0 & 0x03 == 0x01:
            ftype = "S"
        else:
            ftype = "U"

        return cls(frame_type=ftype, ctrl=bytes(ctrl), asdu=bytes(asdu))


# ─────────────────────────────────────────────────────────────────────────────
# U-frame helpers
# ─────────────────────────────────────────────────────────────────────────────

def encode_startdt_act() -> bytes:
    """Encode STARTDT activation U-frame."""
    return IEC104Frame("U", bytes([U_STARTDT_ACT, 0x00, 0x00, 0x00])).encode()

def encode_startdt_con() -> bytes:
    return IEC104Frame("U", bytes([U_STARTDT_CON, 0x00, 0x00, 0x00])).encode()

def encode_testfr_act() -> bytes:
    return IEC104Frame("U", bytes([U_TESTFR_ACT, 0x00, 0x00, 0x00])).encode()

def encode_testfr_con() -> bytes:
    return IEC104Frame("U", bytes([U_TESTFR_CON, 0x00, 0x00, 0x00])).encode()


# ─────────────────────────────────────────────────────────────────────────────
# I-frame with ASDU helper
# ─────────────────────────────────────────────────────────────────────────────

def encode_i_frame(send_seq: int, recv_seq: int, asdu: bytes) -> bytes:
    """
    Encode an I-frame.

    send_seq, recv_seq : sequence numbers (0–32767).
    Control field bytes:
      [0] = (send_seq << 1) & 0xFF   (bit0 = 0 → I-frame)
      [1] = (send_seq >> 7) & 0xFF
      [2] = (recv_seq << 1) & 0xFF
      [3] = (recv_seq >> 7) & 0xFF
    """
    ctrl = struct.pack("<HH",
        (send_seq & 0x7FFF) << 1,
        (recv_seq & 0x7FFF) << 1,
    )
    return IEC104Frame("I", ctrl, asdu).encode()


def decode_frame(raw: bytes) -> Optional[dict]:
    frame = IEC104Frame.decode(raw)
    if frame is None:
        return None
    return {
        "frame_type": frame.frame_type,
        "ctrl_hex":   frame.ctrl.hex(),
        "asdu_hex":   frame.asdu.hex(),
    }


if __name__ == "__main__":
    print("IEC 60870-5-104 stub — encode/decode test")
    startdt = encode_startdt_act()
    print(f"STARTDT ACT ({len(startdt)} bytes): {startdt.hex().upper()}")
    parsed = decode_frame(startdt)
    print(f"Decoded: {parsed}")
    iframe = encode_i_frame(send_seq=1, recv_seq=0, asdu=b"\x0D\x01\x03\x00\x01\x00")
    print(f"I-frame ({len(iframe)} bytes): {iframe.hex().upper()}")
    parsed2 = decode_frame(iframe)
    print(f"Decoded I-frame: {parsed2}")
    print("IEC 104 stub OK")
