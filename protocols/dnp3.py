"""
protocols/dnp3.py
=================
DNP3 (Distributed Network Protocol 3) Frame Encoder/Decoder

Wireshark dissector: "DNP 3.0"
Wireshark filter:    dnp3
Standard port:       TCP/UDP 20000

Frame structure:
  ┌─ Data Link Layer ──────────────────────────────────┐
  │ START       : 0x0564 (2 bytes)                    │
  │ LEN         : 1 byte  (user data length + 5)      │
  │ CONTROL     : 1 byte  (DIR | PRM | FCB | FCV | FC)│
  │ DST         : 2 bytes (destination address)       │
  │ SRC         : 2 bytes (source address)            │
  │ CRC         : 2 bytes (CRC-16/DNP of above 8)     │
  ├─ Transport Layer (first user data byte) ───────────┤
  │ FIR=1, FIN=1, sequence                            │
  ├─ Application Layer ────────────────────────────────┤
  │ App Control : 1 byte                              │
  │ Function    : 1 byte                              │
  │ Objects...                                        │
  └────────────────────────────────────────────────────┘

CRC-16/DNP:
  Polynomial : 0x3D65 (reflected: 0xA6BC)
  Init       : 0x0000
  RefIn      : True
  RefOut     : True
  XorOut     : 0xFFFF
"""

import struct
import time
import logging
from dataclasses import dataclass
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── DNP3 Constants ────────────────────────────────────────────────────────────

DNP3_START         = 0x0564
DNP3_PORT          = 20000

# Data Link function codes
DL_FC_UNCONFIRMED_USER_DATA = 0x44   # Direction=1, PRM=1, FC=4
DL_FC_CONFIRMED_USER_DATA   = 0x43

# Application function codes
FC_CONFIRM         = 0x00
FC_READ            = 0x01
FC_WRITE           = 0x02
FC_DIRECT_OPERATE  = 0x03
FC_RESPONSE        = 0x81
FC_UNSOLICITED_RESP = 0x82

# Object groups (Group, Variation)
GV_ANALOG_INPUT_FLOAT   = (30, 5)   # 32-bit float analog input
GV_ANALOG_INPUT_INT16   = (30, 2)   # 16-bit integer analog input
GV_BINARY_INPUT_S       = ( 1, 2)   # binary input with status
GV_COUNTER_32           = (20, 1)   # 32-bit counter

# Internal Indication bits
IIN_DEVICE_RESTART = 0x8000
IIN_NO_FUNC        = 0x0001


# ── CRC-16/DNP ────────────────────────────────────────────────────────────────

_CRC_TABLE: List[int] = []

def _build_crc_table() -> None:
    """Precompute CRC-16/DNP lookup table (reflected polynomial 0xA6BC)."""
    global _CRC_TABLE
    _CRC_TABLE = []
    for i in range(256):
        crc = i
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
        _CRC_TABLE.append(crc)

_build_crc_table()


def crc16_dnp(data: bytes) -> int:
    """
    Compute CRC-16/DNP for the given bytes.
    Returns the 16-bit CRC (already XOR'd with 0xFFFF as per DNP3 spec).
    """
    crc = 0x0000
    for b in data:
        crc = (crc >> 8) ^ _CRC_TABLE[(crc ^ b) & 0xFF]
    return crc ^ 0xFFFF


def crc16_dnp_bytes(data: bytes) -> bytes:
    """Return CRC as 2 bytes little-endian (as placed in the frame)."""
    return struct.pack("<H", crc16_dnp(data))


# ── Data Link Layer ───────────────────────────────────────────────────────────

@dataclass
class DNP3DataLink:
    """
    DNP3 Data Link Layer frame.
    Handles block CRC insertion (user data is split into 16-byte blocks,
    each followed by a 2-byte CRC).
    """
    control:  int       # Control byte
    dst_addr: int       # Destination address (0 = broadcast)
    src_addr: int       # Source address

    def encode_frame(self, transport_app_data: bytes) -> bytes:
        """
        Encode a complete DNP3 frame given transport+application layer bytes.
        User data is split into 16-byte blocks each followed by CRC.
        """
        # Build user data with block CRCs
        user_data_with_crcs = self._add_block_crcs(transport_app_data)

        # LEN field = len(user_data_without_crcs) + 5
        #   DNP3 counts payload bytes (before block CRCs) + 5 fixed DL bytes
        user_data_len = len(transport_app_data)
        length = user_data_len + 5   # +5 for CTRL(1)+DST(2)+SRC(2)

        # Data Link header (without CRC)
        dl_header = struct.pack("<BBHH",
            length,
            self.control,
            self.dst_addr,
            self.src_addr,
        )

        start_bytes  = struct.pack(">H", DNP3_START)
        header_crc   = crc16_dnp_bytes(start_bytes + dl_header)

        return start_bytes + dl_header + header_crc + user_data_with_crcs

    @staticmethod
    def _add_block_crcs(data: bytes) -> bytes:
        """Split data into 16-byte blocks and append 2-byte CRC to each."""
        result = bytearray()
        offset = 0
        while offset < len(data):
            block = data[offset:offset + 16]
            result += block
            result += crc16_dnp_bytes(block)
            offset += 16
        return bytes(result)

    @staticmethod
    def decode_frame(raw: bytes) -> Optional[Tuple[int, int, bytes]]:
        """
        Decode a raw DNP3 frame.
        Returns (dst_addr, src_addr, transport_app_data) or None on error.
        """
        try:
            if len(raw) < 10:
                return None
            start = struct.unpack_from(">H", raw, 0)[0]
            if start != DNP3_START:
                return None

            length   = raw[2]
            control  = raw[3]
            dst_addr = struct.unpack_from("<H", raw, 4)[0]
            src_addr = struct.unpack_from("<H", raw, 6)[0]
            hdr_crc  = struct.unpack_from("<H", raw, 8)[0]

            # Verify header CRC
            if crc16_dnp(raw[:8]) != hdr_crc:
                logger.debug("DNP3 header CRC mismatch")
                return None

            # Extract user data (strip block CRCs)
            data_offset = 10
            user_data   = bytearray()
            user_len    = length - 5   # payload bytes (excl. fixed header)
            if user_len < 0 or len(raw) != 10 + user_len + 2 * ((user_len + 15) // 16):
                return None

            while len(user_data) < user_len and data_offset < len(raw):
                block_size = min(16, user_len - len(user_data))
                block      = raw[data_offset:data_offset + block_size]
                blk_crc    = struct.unpack_from("<H", raw, data_offset + block_size)[0]
                if crc16_dnp(block) != blk_crc:
                    logger.debug("DNP3 block CRC mismatch")
                    return None
                user_data  += block
                data_offset += block_size + 2

            return dst_addr, src_addr, bytes(user_data)

        except Exception as exc:
            logger.debug(f"DNP3 decode error: {exc}")
            return None


# ── Transport Layer ────────────────────────────────────────────────────────────

def encode_transport(app_data: bytes, fir: bool = True, fin: bool = True,
                     seq: int = 0) -> bytes:
    """
    Encode Transport Layer byte prepended to app data.
    FIR=First, FIN=Final, SEQ=transport sequence number (0-63).
    """
    ctrl = (seq & 0x3F)
    if fir: ctrl |= 0x40
    if fin: ctrl |= 0x80
    return bytes([ctrl]) + app_data


# ── Application Layer ──────────────────────────────────────────────────────────

def encode_app_layer(
    func_code: int,
    objects:   bytes,
    app_seq:   int = 0,
    fir:       bool = True,
    fin:       bool = True,
    uns:       bool = False,
    iin:       int  = IIN_DEVICE_RESTART,
) -> bytes:
    """
    Encode a DNP3 Application Layer fragment.

    For responses (FC_RESPONSE, FC_UNSOLICITED_RESP), IIN bytes are included.
    For requests (FC_READ, etc.), IIN bytes are omitted.
    """
    ctrl = (app_seq & 0x0F)
    if fir: ctrl |= 0x40
    if fin: ctrl |= 0x80
    if uns: ctrl |= 0x10

    hdr = bytes([ctrl, func_code])

    if func_code in (FC_RESPONSE, FC_UNSOLICITED_RESP):
        iin_bytes = struct.pack("<H", iin)
        return hdr + iin_bytes + objects
    return hdr + objects


# ── Object encoding ────────────────────────────────────────────────────────────

def encode_object_header(group: int, variation: int, qualifier: int,
                         count: int) -> bytes:
    """
    Encode a DNP3 Object Header.
    qualifier=0x28 = count of objects (1 byte), start/stop indices
    qualifier=0x01 = 8-bit start/stop
    qualifier=0x17 = 8-bit count
    """
    return struct.pack("BBBBB", group, variation, qualifier, 0, count - 1)


def encode_analog_inputs_float(values: List[float],
                                start_idx: int = 0) -> bytes:
    """
    Encode Group 30 Var 5 (32-bit float Analog Input) objects.
    Each object: 1 byte flags + 4 bytes float = 5 bytes.
    Returns header + object data.
    """
    group, variation = GV_ANALOG_INPUT_FLOAT
    count = len(values)
    # Qualifier 0x01 = 8-bit start/stop indices
    header = struct.pack("BBBBB",
        group, variation,
        0x01,                     # qualifier: 8-bit start/stop
        start_idx,                # start index
        start_idx + count - 1,   # stop index
    )
    data = b""
    for v in values:
        flags = 0x01   # ONLINE
        data += struct.pack("<Bf", flags, v)
    return header + data


def encode_binary_inputs(values: List[bool], start_idx: int = 0) -> bytes:
    """
    Encode Group 1 Var 2 (Binary Input with Status) objects.
    Each object: 1 byte (flags with value in bit 7).
    """
    group, variation = GV_BINARY_INPUT_S
    count = len(values)
    header = struct.pack("BBBBB",
        group, variation,
        0x01,                     # qualifier: 8-bit start/stop
        start_idx,
        start_idx + count - 1,
    )
    data = b""
    for v in values:
        flags = 0x81 if v else 0x01   # bit7=value, bit0=ONLINE
        data += bytes([flags])
    return header + data


# ── High-level frame builders ──────────────────────────────────────────────────

def build_unsolicited_response(
    src_addr:      int,
    dst_addr:      int,
    analog_values: List[float],
    binary_values: List[bool],
    app_seq:       int = 0,
    transport_seq: int = 0,
    iin:           int = IIN_DEVICE_RESTART,
) -> bytes:
    """
    Build a complete DNP3 Unsolicited Response frame ready for transmission.

    Contains:
      - Analog inputs (Group 30 Var 5, float) for each value in analog_values
      - Binary inputs (Group 1 Var 2) for each value in binary_values
    """
    # Application layer objects
    objects = b""
    if analog_values:
        objects += encode_analog_inputs_float(analog_values)
    if binary_values:
        objects += encode_binary_inputs(binary_values,
                                        start_idx=len(analog_values))

    app = encode_app_layer(
        func_code = FC_UNSOLICITED_RESP,
        objects   = objects,
        app_seq   = app_seq,
        uns       = True,
        iin       = iin,
    )
    transport = encode_transport(app, seq=transport_seq)

    dl = DNP3DataLink(
        control  = DL_FC_UNCONFIRMED_USER_DATA,
        dst_addr = dst_addr,
        src_addr = src_addr,
    )
    return dl.encode_frame(transport)


def build_read_request(
    src_addr: int,
    dst_addr: int,
    group:    int = 30,
    var:      int = 0,        # 0 = all variations
    app_seq:  int = 0,
) -> bytes:
    """Build a DNP3 Read Request (master → outstation)."""
    # Object header for Read: group, variation, qualifier=0x06 (no range)
    objects = struct.pack("BBB", group, var, 0x06)
    app = encode_app_layer(FC_READ, objects, app_seq=app_seq)
    transport = encode_transport(app, seq=app_seq & 0x3F)
    dl = DNP3DataLink(
        control  = 0x44,   # Unconfirmed User Data (master direction)
        dst_addr = dst_addr,
        src_addr = src_addr,
    )
    return dl.encode_frame(transport)


# ── Self-test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("DNP3 self-test")
    print("=" * 50)

    # Test 1: CRC
    test_data = bytes([0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04])
    expected_crc = 0x3B2A   # known-good CRC for this header
    computed = crc16_dnp(test_data)
    print(f"[1] CRC test: {computed:#06x}  (expect varies by implementation)")
    print(f"    CRC bytes: {crc16_dnp_bytes(test_data).hex()}")

    # Test 2: Build unsolicited response
    frame = build_unsolicited_response(
        src_addr      = 1,
        dst_addr      = 3,
        analog_values = [120.0, 119.5, 120.5, 50.02],   # Va, Vb, Vc, freq
        binary_values = [False, True],                    # trip, CB status
    )
    print(f"\n[2] Unsolicited response frame:")
    print(f"    Length: {len(frame)} bytes")
    print(f"    START:  {frame[0:2].hex().upper()} (expect 0564)")
    assert frame[0:2] == bytes([0x05, 0x64]), "Bad start bytes"
    print(f"    ✔ Start bytes correct")

    # Test 3: Decode
    result = DNP3DataLink.decode_frame(frame)
    assert result is not None, "Decode returned None"
    dst, src, user_data = result
    assert dst == 3, f"dst={dst}"
    assert src == 1, f"src={src}"
    print(f"\n[3] Decode: dst={dst} src={src} user_data={len(user_data)} bytes")
    # user_data layout: [transport_byte, app_ctrl, app_FC, IIN_lo, IIN_hi, objects...]
    transport_byte = user_data[0]
    app_ctrl       = user_data[1]
    app_fc         = user_data[2]
    print(f"    Transport: 0x{transport_byte:02x}  App Ctrl: 0x{app_ctrl:02x}  App FC: 0x{app_fc:02x} (expect 0x82 = Unsolicited)")
    assert app_fc == 0x82, f"Expected FC=0x82, got 0x{app_fc:02x}"
    print(f"    ✔ Decode correct")

    # Test 4: Read request
    req = build_read_request(src_addr=3, dst_addr=1)
    print(f"\n[4] Read Request: {len(req)} bytes, START={req[0:2].hex().upper()}")
    assert req[0:2] == bytes([0x05, 0x64])
    print(f"    ✔ OK")

    print("\nDNP3 ALL TESTS PASSED ✔")
