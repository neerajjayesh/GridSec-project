"""
protocols/goose.py
==================
IEC 61850-8-1 GOOSE (Generic Object Oriented Substation Event) Protocol

Frame format: Raw Ethernet, EtherType 0x88B8
PDU encoded as ASN.1 BER

GOOSE multicast MAC: 01:0C:CD:01:xx:xx

Wireshark dissector: "GOOSE" — requires raw Ethernet (AF_PACKET socket)
Wireshark filter:    eth.type == 0x88b8

Frame layout:
  ┌─ Ethernet Header (14 bytes) ─────────────────────┐
  │ Dst MAC  : 01:0C:CD:01:00:01 (GOOSE multicast)  │
  │ Src MAC  : configurable                          │
  │ EtherType: 0x88B8                                │
  ├─ GOOSE Header (8 bytes) ─────────────────────────┤
  │ APPID    : 2 bytes                               │
  │ Length   : 2 bytes (total PDU+header length)     │
  │ Reserved1: 0x0000                                │
  │ Reserved2: 0x0000                                │
  ├─ IECGoosePdu (ASN.1 BER) ────────────────────────┤
  │ gocbRef          [0] VisibleString               │
  │ timeAllowedtoLive [1] INTEGER (ms)               │
  │ datSet           [2] VisibleString               │
  │ goID             [3] VisibleString               │
  │ t                [4] UtcTime (8 bytes)           │
  │ stNum            [5] INTEGER                     │
  │ sqNum            [6] INTEGER                     │
  │ simulation       [7] BOOLEAN                     │
  │ confRev          [8] INTEGER                     │
  │ ndsCom           [9] BOOLEAN                     │
  │ numDatSetEntries [10] INTEGER                    │
  │ allData          [11] SEQUENCE OF Data           │
  └──────────────────────────────────────────────────┘
"""

import math
import struct
import time
import socket
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Any

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

GOOSE_ETHERTYPE       = 0x88B8
GOOSE_MULTICAST_BASE  = "01:0C:CD:01:00:"   # last octet = APPID low byte
GOOSE_DEFAULT_DST_MAC = bytes([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01])
GOOSE_DEFAULT_SRC_MAC = bytes([0x00, 0x30, 0x48, 0x1A, 0x2B, 0x3C])

# ASN.1 context-specific implicit tags for IECGoosePdu
TAG_GOOSEPDU           = 0x61   # [APPLICATION 1] SEQUENCE
TAG_GOCBREF            = 0x80   # [0] VisibleString
TAG_TIME_ALLOWED       = 0x81   # [1] INTEGER
TAG_DATSET             = 0x82   # [2] VisibleString
TAG_GOID               = 0x83   # [3] VisibleString
TAG_T                  = 0x84   # [4] UtcTime
TAG_STNUM              = 0x85   # [5] INTEGER
TAG_SQNUM              = 0x86   # [6] INTEGER
TAG_SIMULATION         = 0x87   # [7] BOOLEAN
TAG_CONFREV            = 0x88   # [8] INTEGER
TAG_NDSCOM             = 0x89   # [9] BOOLEAN
TAG_NUM_ENTRIES        = 0x8A   # [10] INTEGER
TAG_ALL_DATA           = 0xAB   # [11] SEQUENCE

# MMS Data tags (used inside allData)
MMS_TAG_BOOLEAN        = 0x83
MMS_TAG_BIT_STRING     = 0x84
MMS_TAG_FLOAT32        = 0x85   # MMS FLOAT32: 1 byte exponent_width + 4 bytes IEEE754
MMS_TAG_OCTET_STRING   = 0x89
MMS_TAG_VISIBLE_STRING = 0x8A
MMS_TAG_UTC_TIME       = 0x91


# ── ASN.1 BER helpers ─────────────────────────────────────────────────────────

def _ber_length(n: int) -> bytes:
    """Encode a BER length field."""
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    raise OverflowError(f"BER length too large: {n}")


def _ber_tlv(tag: int, value: bytes) -> bytes:
    """Wrap value in a BER TLV (tag-length-value) triplet."""
    return bytes([tag]) + _ber_length(len(value)) + value


def _ber_integer_unsigned(n: int) -> bytes:
    """Encode non-negative integer as minimal BER INTEGER bytes."""
    if n == 0:
        return b'\x00'
    result = []
    while n:
        result.append(n & 0xFF)
        n >>= 8
    result.reverse()
    if result[0] & 0x80:       # ensure positive (no sign bit)
        result.insert(0, 0x00)
    return bytes(result)


def _ber_boolean(value: bool) -> bytes:
    return bytes([0xFF if value else 0x00])


def _mms_float32(value: float) -> bytes:
    """MMS FLOAT32: exponent_width byte (8) + 4 bytes big-endian IEEE 754."""
    return bytes([0x08]) + struct.pack('>f', value)


def _goose_utctime(t: Optional[float] = None) -> bytes:
    """
    Encode a GOOSE UtcTime (8 bytes):
      Bytes 0-3: seconds since Unix epoch (big-endian uint32)
      Bytes 4-6: sub-second fraction in units of 1/2^24 (big-endian uint24)
      Byte 7:    quality / TimeAccuracy byte
                   bit 7: LeapSecondsKnown
                   bit 6: ClockFailure
                   bit 5: ClockNotSynchronized
                   bits 0-4: TimeAccuracy (0x0D = 1ms)
    """
    if t is None:
        t = time.time()
    seconds  = int(t)
    fraction = t - seconds
    frac24   = int(fraction * (2 ** 24)) & 0xFFFFFF
    quality  = 0x0D   # LeapSecondsKnown=1, ClockFail=0, NotSync=0, Accuracy=13 (1ms)
    return struct.pack('>I', seconds) + struct.pack('>I', frac24)[1:] + bytes([quality])


# ── Dataset value types ───────────────────────────────────────────────────────

class GooseValue:
    """Base class for GOOSE dataset values."""
    def encode(self) -> bytes:
        raise NotImplementedError


class GooseBoolean(GooseValue):
    def __init__(self, value: bool):
        self.value = value

    def encode(self) -> bytes:
        return _ber_tlv(MMS_TAG_BOOLEAN, _ber_boolean(self.value))


class GooseFloat32(GooseValue):
    def __init__(self, value: float):
        self.value = value

    def encode(self) -> bytes:
        return _ber_tlv(MMS_TAG_FLOAT32, _mms_float32(self.value))


class GooseInteger(GooseValue):
    def __init__(self, value: int):
        self.value = value

    def encode(self) -> bytes:
        return _ber_tlv(MMS_TAG_FLOAT32, _mms_float32(float(self.value)))


# ── GOOSE PDU builder ─────────────────────────────────────────────────────────

@dataclass
class GoosePDU:
    """
    IECGoosePdu — all fields needed to construct a GOOSE frame.

    Typical usage:
        pdu = GoosePDU(
            gocbRef  = "IED001/LLN0$GO$GCB01",
            datSet   = "IED001/LLN0$DS_POWER",
            goID     = "GOOSE_POWER_01",
            appid    = 0x0001,
            confRev  = 1,
            dataset  = [GooseFloat32(120.0), GooseFloat32(50.0), GooseBoolean(False)],
        )
        raw_frame = pdu.build_frame()
    """
    gocbRef:             str   = "IED001/LLN0$GO$GCB01"
    datSet:              str   = "IED001/LLN0$DS_PMU"
    goID:                str   = "GOOSE_PMU_01"
    appid:               int   = 0x0001
    confRev:             int   = 1
    timeAllowedToLive_ms: int  = 2000      # ms — retransmit if not received within this
    dataset:             List[GooseValue] = field(default_factory=list)
    stNum:               int   = 1         # state number (increments on state change)
    sqNum:               int   = 0         # sequence number (increments every tx)
    simulation:          bool  = False
    ndsCom:              bool  = False
    src_mac:             bytes = field(default_factory=lambda: bytes(GOOSE_DEFAULT_SRC_MAC))
    dst_mac:             bytes = field(default_factory=lambda: bytes(GOOSE_DEFAULT_DST_MAC))

    def _encode_pdu(self) -> bytes:
        """Encode the IECGoosePdu as ASN.1 BER."""
        now = time.time()

        # allData SEQUENCE contents
        all_data_contents = b"".join(v.encode() for v in self.dataset)
        all_data = _ber_tlv(TAG_ALL_DATA, all_data_contents)

        # Build inner PDU fields
        fields = (
            _ber_tlv(TAG_GOCBREF,      self.gocbRef.encode("ascii")) +
            _ber_tlv(TAG_TIME_ALLOWED, _ber_integer_unsigned(self.timeAllowedToLive_ms)) +
            _ber_tlv(TAG_DATSET,       self.datSet.encode("ascii")) +
            _ber_tlv(TAG_GOID,         self.goID.encode("ascii")) +
            _ber_tlv(TAG_T,            _goose_utctime(now)) +
            _ber_tlv(TAG_STNUM,        _ber_integer_unsigned(self.stNum)) +
            _ber_tlv(TAG_SQNUM,        _ber_integer_unsigned(self.sqNum)) +
            _ber_tlv(TAG_SIMULATION,   _ber_boolean(self.simulation)) +
            _ber_tlv(TAG_CONFREV,      _ber_integer_unsigned(self.confRev)) +
            _ber_tlv(TAG_NDSCOM,       _ber_boolean(self.ndsCom)) +
            _ber_tlv(TAG_NUM_ENTRIES,  _ber_integer_unsigned(len(self.dataset))) +
            all_data
        )

        # Wrap in IECGoosePdu [APPLICATION 1]
        return _ber_tlv(TAG_GOOSEPDU, fields)

    def build_frame(self) -> bytes:
        """Build the complete raw Ethernet GOOSE frame."""
        pdu     = self._encode_pdu()
        # GOOSE header: APPID(2) + Length(2) + Reserved(4)
        # Length = 8 (header size) + len(pdu)
        hdr_len = 8 + len(pdu)
        goose_hdr = (
            struct.pack('>H', self.appid) +      # APPID
            struct.pack('>H', hdr_len) +          # Length
            b'\x00\x00' +                         # Reserved1
            b'\x00\x00'                           # Reserved2
        )

        # Ethernet header: dst(6) + src(6) + ethertype(2)
        eth_hdr = (
            self.dst_mac +
            self.src_mac +
            struct.pack('>H', GOOSE_ETHERTYPE)
        )

        return eth_hdr + goose_hdr + pdu

    def increment_sq(self) -> None:
        """Increment sequence number (called every retransmission)."""
        self.sqNum += 1

    def event_state_change(self) -> None:
        """Called when dataset values change — resets sqNum, increments stNum."""
        self.stNum += 1
        self.sqNum  = 0


# ── GOOSE decoder ─────────────────────────────────────────────────────────────

@dataclass
class DecodedGoose:
    src_mac:    str
    dst_mac:    str
    appid:      int
    gocbRef:    str
    datSet:     str
    goID:       str
    stNum:      int
    sqNum:      int
    simulation: bool
    confRev:    int
    ndsCom:     bool
    num_entries: int
    timestamp:  float
    data_raw:   bytes      # raw allData bytes for further parsing
    values:     List[Any]  # decoded values (float or bool)


def decode_frame(raw: bytes) -> Optional[DecodedGoose]:
    """
    Attempt to decode a raw Ethernet frame as GOOSE.
    Returns None if the frame is not a valid GOOSE frame.
    """
    try:
        if len(raw) < 14 + 8 + 4:
            return None

        # Ethernet header
        dst_mac = ":".join(f"{b:02x}" for b in raw[0:6])
        src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
        etype   = struct.unpack_from(">H", raw, 12)[0]

        if etype != GOOSE_ETHERTYPE:
            return None

        # GOOSE header
        offset = 14
        appid  = struct.unpack_from(">H", raw, offset)[0]
        length = struct.unpack_from(">H", raw, offset + 2)[0]
        if length < 8 or 14 + length > len(raw):
            return None
        offset += 8   # skip APPID + Length + 2×Reserved

        # PDU: expect TAG_GOOSEPDU (0x61)
        if raw[offset] != TAG_GOOSEPDU:
            return None

        offset += 1
        pdu_len, hdr_bytes = _decode_length(raw, offset)
        offset += hdr_bytes
        pdu_end  = offset + pdu_len
        if pdu_end != 14 + length:
            return None

        # Parse PDU fields
        fields = {}
        while offset < pdu_end:
            if offset >= len(raw):
                break
            tag = raw[offset]; offset += 1
            flen, hb = _decode_length(raw, offset); offset += hb
            if offset + flen > pdu_end:
                return None
            val = raw[offset:offset + flen]; offset += flen

            if tag == TAG_GOCBREF:
                fields["gocbRef"] = val.decode("ascii", errors="replace")
            elif tag == TAG_TIME_ALLOWED:
                fields["timeAllowed"] = int.from_bytes(val, "big")
            elif tag == TAG_DATSET:
                fields["datSet"] = val.decode("ascii", errors="replace")
            elif tag == TAG_GOID:
                fields["goID"] = val.decode("ascii", errors="replace")
            elif tag == TAG_T:
                secs    = struct.unpack_from(">I", val, 0)[0]
                frac24  = (val[4] << 16 | val[5] << 8 | val[6]) / (2**24)
                fields["t"] = secs + frac24
            elif tag == TAG_STNUM:
                fields["stNum"] = int.from_bytes(val, "big")
            elif tag == TAG_SQNUM:
                fields["sqNum"] = int.from_bytes(val, "big")
            elif tag == TAG_SIMULATION:
                fields["simulation"] = (val[0] != 0x00)
            elif tag == TAG_CONFREV:
                fields["confRev"] = int.from_bytes(val, "big")
            elif tag == TAG_NDSCOM:
                fields["ndsCom"] = (val[0] != 0x00)
            elif tag == TAG_NUM_ENTRIES:
                fields["numEntries"] = int.from_bytes(val, "big")
            elif tag == TAG_ALL_DATA:
                fields["allData"] = val

        values = _decode_all_data(fields.get("allData", b""))
        if len(values) != fields.get("numEntries", -1):
            return None

        return DecodedGoose(
            src_mac     = src_mac,
            dst_mac     = dst_mac,
            appid       = appid,
            gocbRef     = fields.get("gocbRef", ""),
            datSet      = fields.get("datSet", ""),
            goID        = fields.get("goID", ""),
            stNum       = fields.get("stNum", 0),
            sqNum       = fields.get("sqNum", 0),
            simulation  = fields.get("simulation", False),
            confRev     = fields.get("confRev", 0),
            ndsCom      = fields.get("ndsCom", False),
            num_entries = fields.get("numEntries", 0),
            timestamp   = fields.get("t", time.time()),
            data_raw    = fields.get("allData", b""),
            values      = values,
        )

    except Exception as exc:
        logger.debug(f"GOOSE decode error: {exc}")
        return None


def _decode_length(data: bytes, offset: int) -> Tuple[int, int]:
    """Decode BER length. Returns (length, bytes_consumed)."""
    b = data[offset]
    if b < 0x80:
        return b, 1
    elif b == 0x81:
        return data[offset + 1], 2
    elif b == 0x82:
        return (data[offset + 1] << 8 | data[offset + 2]), 3
    raise ValueError(f"Unsupported BER length byte: 0x{b:02X}")


def _decode_all_data(raw: bytes) -> List[Any]:
    """Decode the allData SEQUENCE OF Data bytes into Python values."""
    values = []
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            break
        tag = raw[offset]; offset += 1
        flen, hb = _decode_length(raw, offset); offset += hb
        val = raw[offset:offset + flen]; offset += flen

        if tag == MMS_TAG_BOOLEAN:
            values.append(val[0] != 0x00)
        elif tag == MMS_TAG_FLOAT32 and len(val) == 5:
            # val[0] is exponent_width (8), val[1:5] is IEEE 754
            values.append(struct.unpack(">f", val[1:5])[0])
        else:
            values.append(val.hex())
    return values


# ── Interface detection ────────────────────────────────────────────────────────

def get_default_interface() -> str:
    """Return the default network interface name (e.g., 'eth0')."""
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True, timeout=2
        )
        parts = result.stdout.split()
        if "dev" in parts:
            return parts[parts.index("dev") + 1]
    except Exception:
        pass
    return "eth0"


def get_src_mac(interface: str) -> bytes:
    """Return the MAC address bytes of the given interface."""
    try:
        path = f"/sys/class/net/{interface}/address"
        with open(path) as f:
            mac_str = f.read().strip()
        return bytes(int(x, 16) for x in mac_str.split(":"))
    except Exception:
        return bytes(GOOSE_DEFAULT_SRC_MAC)


# ── Self-test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("GOOSE protocol self-test")
    print("=" * 50)

    pdu = GoosePDU(
        gocbRef  = "IED001/LLN0$GO$GCB01",
        datSet   = "IED001/LLN0$DS_PMU",
        goID     = "GOOSE_PMU_01",
        appid    = 0x0001,
        confRev  = 1,
        dataset  = [
            GooseFloat32(120.0),   # Va
            GooseFloat32(119.5),   # Vb
            GooseFloat32(120.5),   # Vc
            GooseFloat32(50.02),   # Frequency
            GooseBoolean(False),   # Trip signal
            GooseBoolean(True),    # CB status (closed)
        ],
    )

    frame = pdu.build_frame()
    print(f"Frame length: {len(frame)} bytes")
    print(f"EtherType bytes: {frame[12:14].hex().upper()} (expect 88B8)")
    print(f"APPID: {struct.unpack_from('>H', frame, 14)[0]:#06x}")
    assert frame[12:14] == bytes([0x88, 0xB8]), "EtherType mismatch"

    # Decode it back
    decoded = decode_frame(frame)
    assert decoded is not None, "Decode returned None"
    assert decoded.appid == 0x0001
    assert decoded.gocbRef == "IED001/LLN0$GO$GCB01"
    assert decoded.goID    == "GOOSE_PMU_01"
    assert abs(decoded.values[0] - 120.0) < 0.001, f"Va mismatch: {decoded.values[0]}"
    assert abs(decoded.values[3] - 50.02) < 0.001, f"Freq mismatch: {decoded.values[3]}"
    assert decoded.values[4] == False, "Trip mismatch"
    assert decoded.values[5] == True,  "CB status mismatch"

    print(f"Decoded goID:   {decoded.goID}")
    print(f"Decoded values: {[round(v, 3) if isinstance(v, float) else v for v in decoded.values]}")
    print(f"stNum={decoded.stNum}  sqNum={decoded.sqNum}")
    print("\nGOOSE ALL TESTS PASSED ✔")
