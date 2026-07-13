"""
protocols/dnp3.py
=================
DNP3 (Distributed Network Protocol 3) — stub implementation.

DNP3 is widely used in SCADA systems for substation automation.
This stub provides the frame structure and placeholder encode/decode.
Full implementation would require the DNP3 Application Layer,
Transport Layer, and Data Link Layer per IEEE 1815-2012.

For GridSec Sim v1.0, DNP3 links are displayed on the topology canvas
but live simulation is C37.118 only.
"""

import struct
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

DNP3_START1 = 0x05
DNP3_START2 = 0x64

# Function codes
FC_CONFIRM           = 0x00
FC_READ              = 0x01
FC_WRITE             = 0x02
FC_DIRECT_OPERATE    = 0x03
FC_RESPONSE          = 0x81
FC_UNSOLICITED_RESP  = 0x82

# Control byte directions
DNP3_DIR_FROM_MASTER = 0x80
DNP3_DIR_FROM_OUTSTATION = 0x00


# ─────────────────────────────────────────────────────────────────────────────
# CRC-16 for DNP3 (polynomial 0x3D65)
# ─────────────────────────────────────────────────────────────────────────────

def _crc16_dnp3(data: bytes) -> int:
    """CRC-16/DNP3 — polynomial 0x3D65, init 0x0000, input/output reflected."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


# ─────────────────────────────────────────────────────────────────────────────
# DNP3 Data Link Layer frame
# ─────────────────────────────────────────────────────────────────────────────

class DNP3Frame:
    """
    DNP3 Data Link Layer frame (simplified).

    Structure:
      [0]   Start byte 1 (0x05)
      [1]   Start byte 2 (0x64)
      [2]   LEN  — number of bytes after this field (up to CRC of user data)
      [3]   CTRL — control byte
      [4-5] DEST — destination address (little-endian)
      [6-7] SRC  — source address (little-endian)
      [8-9] CRC  — CRC of header bytes 0-7 (little-endian)
      [10+] User data blocks (16 bytes each + 2-byte CRC)
    """

    def __init__(
        self,
        src:  int = 1,
        dst:  int = 3,
        ctrl: int = DNP3_DIR_FROM_MASTER,
        data: bytes = b"",
    ):
        self.src  = src
        self.dst  = dst
        self.ctrl = ctrl
        self.data = data

    def encode(self) -> bytes:
        """Encode to binary DNP3 Data Link Layer frame."""
        # Header (without CRC)
        length  = 5 + len(self.data)   # CTRL + DST + SRC + data (approximate)
        header  = struct.pack("<BBHHH",
            DNP3_START1, DNP3_START2, length & 0xFF,
            self.ctrl, self.dst, self.src)
        hdr_crc = struct.pack("<H", _crc16_dnp3(header))

        # User data in 16-byte blocks with CRC
        out   = header + hdr_crc
        chunk = self.data
        while chunk:
            block = chunk[:16]
            chunk = chunk[16:]
            out  += block + struct.pack("<H", _crc16_dnp3(block))

        return out

    @classmethod
    def decode(cls, raw: bytes) -> Optional["DNP3Frame"]:
        """Minimal decode — extracts src, dst, ctrl, raw data."""
        if len(raw) < 10:
            return None
        if raw[0] != DNP3_START1 or raw[1] != DNP3_START2:
            return None
        ctrl = raw[3]
        dst  = struct.unpack_from("<H", raw, 4)[0]
        src  = struct.unpack_from("<H", raw, 6)[0]
        # Collect data bytes (skip block CRCs)
        data_out = b""
        offset   = 10
        while offset < len(raw):
            data_out += raw[offset:offset+16]
            offset   += 18   # 16 data + 2 CRC
        return cls(src=src, dst=dst, ctrl=ctrl, data=data_out)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def encode_read_request(src: int, dst: int, group: int, variation: int) -> bytes:
    """Create a DNP3 READ request (stub — for display/topology labeling only)."""
    app_data = bytes([0xC0, FC_READ, group, variation])
    return DNP3Frame(src=src, dst=dst, data=app_data).encode()


def decode_frame(raw: bytes) -> Optional[dict]:
    """Decode a raw DNP3 frame to a dict. Returns None if invalid."""
    frame = DNP3Frame.decode(raw)
    if frame is None:
        return None
    return {"src": frame.src, "dst": frame.dst, "ctrl": frame.ctrl, "data": frame.data.hex()}


if __name__ == "__main__":
    print("DNP3 stub — encode/decode test")
    pkt = encode_read_request(src=1, dst=3, group=30, variation=1)
    print(f"Encoded frame ({len(pkt)} bytes): {pkt.hex().upper()}")
    parsed = decode_frame(pkt)
    print(f"Decoded: {parsed}")
    print("DNP3 stub OK")
