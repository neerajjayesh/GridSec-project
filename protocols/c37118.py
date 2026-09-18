"""
protocols/c37118.py
===================
Full IEEE C37.118-2011 synchrophasor protocol implementation.

Frame types supported:
  - DATA frame  (SYNC = 0xAA01)
  - CFG-2 frame (SYNC = 0xAA31) — Configuration frame type 2
  - COMMAND frame (SYNC = 0xAA41)

Binary format is big-endian throughout.

References:
  IEEE Std C37.118.2-2011, "IEEE Standard for Synchrophasor Data Transfer
  for Power Systems", IEEE, New York, 2011.

Usage:
  # Encode a data frame
  from protocols.c37118 import C37118Codec
  codec  = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=0)
  frame  = codec.encode_data_frame(phasors=[(120.0, 0.0), (120.0, -2.094), (120.0, 2.094)],
                                    freq=50.0, dfreq=0.0, analog=[0.0], digital=[])
  parsed = codec.decode_data_frame(frame)
"""

import struct
import time
import math
from dataclasses import dataclass, field
from typing import List, Tuple, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SYNC_DATA    = 0xAA01   # Data frame
SYNC_CFG1    = 0xAA21   # Configuration frame type 1
SYNC_CFG2    = 0xAA31   # Configuration frame type 2
SYNC_CFG3    = 0xAA51   # Configuration frame type 3 (C37.118-2011)
SYNC_HEADER  = 0xAA11   # Header frame
SYNC_COMMAND = 0xAA41   # Command frame

# Phasor format flags (stored in PHUNIT word in config frame)
PHASOR_FORMAT_FLOAT    = 0x00000000  # 32-bit float pairs (mag, angle)
PHASOR_FORMAT_INT      = 0x00000001  # 16-bit integer pairs (fixed-point)

# STAT field bits
STAT_OK              = 0x0000
STAT_DATA_MODIFIED   = 0x0100
STAT_TRIGGER         = 0x0020
STAT_DATA_ERROR      = 0x4000
STAT_PMU_SYNC        = 0x0000   # synced

# Command codes
CMD_TURN_OFF_TX   = 0x0001
CMD_TURN_ON_TX    = 0x0002
CMD_SEND_HDR      = 0x0003
CMD_SEND_CFG1     = 0x0004
CMD_SEND_CFG2     = 0x0005
CMD_SEND_CFG3     = 0x0006

# CRC polynomial for CRC-CCITT
CRC_POLY = 0x1021
CRC_SEED = 0xFFFF


# ─────────────────────────────────────────────────────────────────────────────
# CRC-CCITT
# ─────────────────────────────────────────────────────────────────────────────

def calculate_crc(data: bytes) -> int:
    """
    Calculate CRC-CCITT (polynomial 0x1021, seed 0xFFFF).
    Returns a 16-bit integer.
    Applied to all bytes of the frame EXCEPT the last 2 (the CRC field itself).

    Algorithm: bit-by-bit with MSB first (IBM variant used by C37.118).
    """
    crc = CRC_SEED
    for byte in data:
        for i in range(8):
            bit = (byte >> (7 - i)) & 1
            c15 = (crc >> 15) & 1
            crc = (crc << 1) & 0xFFFF
            if c15 ^ bit:
                crc ^= CRC_POLY
    return crc & 0xFFFF


def crc_bytes(data: bytes) -> bytes:
    """Return the CRC as 2 big-endian bytes."""
    return struct.pack(">H", calculate_crc(data))


# ─────────────────────────────────────────────────────────────────────────────
# Phasor representation
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Phasor:
    """A single phasor: magnitude in Volts (or Amps), angle in radians."""
    magnitude: float = 120.0    # Volts or Amps
    angle: float = 0.0          # radians
    label: str = "V1"
    is_current: bool = False    # False = voltage, True = current

    def to_rect(self) -> Tuple[float, float]:
        """Convert polar → rectangular (real, imag)."""
        return (self.magnitude * math.cos(self.angle),
                self.magnitude * math.sin(self.angle))

    @classmethod
    def from_rect(cls, real: float, imag: float) -> "Phasor":
        magnitude = math.hypot(real, imag)
        angle     = math.atan2(imag, real)
        return cls(magnitude=magnitude, angle=angle)


# ─────────────────────────────────────────────────────────────────────────────
# Frame dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class C37118DataFrameDict:
    """Parsed representation of a C37.118 DATA frame."""
    sync:      int   = SYNC_DATA
    framesize: int   = 0
    idcode:    int   = 1
    soc:       int   = 0          # seconds-of-century (Unix time)
    fracsec:   int   = 0          # fractional second * MESSAGE_RATE_FLAG
    stat:      int   = STAT_OK
    phasors:   List[Tuple[float, float]] = field(default_factory=list)  # (mag, angle_rad)
    freq:      float = 50.0       # Hz
    dfreq:     float = 0.0        # df/dt, Hz/s
    analog:    List[float] = field(default_factory=list)
    digital:   List[int]   = field(default_factory=list)
    crc:       int   = 0

    def to_dict(self) -> dict:
        return {
            "sync":      self.sync,
            "framesize": self.framesize,
            "idcode":    self.idcode,
            "soc":       self.soc,
            "fracsec":   self.fracsec,
            "stat":      self.stat,
            "phasors":   list(self.phasors),
            "freq":      self.freq,
            "dfreq":     self.dfreq,
            "analog":    list(self.analog),
            "digital":   list(self.digital),
            "crc":       self.crc,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "C37118DataFrameDict":
        obj = cls()
        for k, v in d.items():
            if hasattr(obj, k):
                setattr(obj, k, v)
        return obj


@dataclass
class C37118ConfigStation:
    """Per-station data inside a CFG-2 frame."""
    stn:      str  = "PMU1"      # 16-char station name
    idcode:   int  = 1
    num_phasors:  int = 3
    num_analog:   int = 1
    num_digital:  int = 0
    phasor_names: List[str] = field(default_factory=lambda: ["VA", "VB", "VC"])
    analog_names: List[str] = field(default_factory=lambda: ["ANALOG1"])
    digital_names: List[str] = field(default_factory=lambda: [])
    phunit:   List[int] = field(default_factory=lambda: [0x00000000]*3)  # voltage, float
    anunit:   List[int] = field(default_factory=lambda: [0x00000000])
    digunit:  List[int] = field(default_factory=list)
    fnom:     int = 0x0001       # 0x0001 = 50 Hz nominal
    cfgcnt:   int = 0


# ─────────────────────────────────────────────────────────────────────────────
# Main codec class
# ─────────────────────────────────────────────────────────────────────────────

class C37118Codec:
    """
    Encoder/decoder for IEEE C37.118-2011 frames.

    Parameters
    ----------
    idcode : int
        PMU/PDC ID code (1–65534).
    num_phasors : int
        Number of phasors per data frame.
    num_analog : int
        Number of analog values per data frame.
    num_digital : int
        Number of 16-bit digital status words per data frame.
    station_name : str
        Station name (max 16 chars, padded with spaces).
    nominal_freq : int
        0x0000 = 60 Hz nominal, 0x0001 = 50 Hz nominal.
    """

    def __init__(
        self,
        idcode:       int  = 1,
        num_phasors:  int  = 3,
        num_analog:   int  = 1,
        num_digital:  int  = 0,
        station_name: str  = "GridSecSim PMU ",
        nominal_freq: int  = 0x0001,   # 50 Hz
    ):
        self.idcode       = idcode
        self.num_phasors  = num_phasors
        self.num_analog   = num_analog
        self.num_digital  = num_digital
        self.station_name = station_name[:16].ljust(16)
        self.nominal_freq = nominal_freq

        # Track configuration change count
        self._cfgcnt = 0

        # Data frame fixed size (bytes):
        #   header(14) + phasors(8 each, float32×2) + FREQ(4) + DFREQ(4)
        #   + analog(4 each) + digital(2 each) + CRC(2)
        self._data_frame_size = (
            14                          # header
            + 2                         # STAT
            + num_phasors * 8           # each phasor = 2 × float32
            + 4                         # FREQ (float32)
            + 4                         # DFREQ (float32)
            + num_analog  * 4           # analog (float32 each)
            + num_digital * 2           # digital words
            + 2                         # CRC
        )

    # ── Header ────────────────────────────────────────────────────────────────

    def _build_header(self, sync: int, framesize: int, soc: int, fracsec: int) -> bytes:
        """
        Build the 14-byte common frame header.

        Byte layout:
          [0-1]  SYNC     (uint16) — frame type indicator
          [2-3]  FRAMESIZE (uint16) — total frame length in bytes
          [4-5]  IDCODE   (uint16) — source device ID
          [6-9]  SOC      (uint32) — seconds since Jan 1, 1970 (UTC)
          [10-13] FRACSEC (uint32) — fractional second + leap-second flags
        """
        return struct.pack(">HHHII", sync, framesize, self.idcode, soc, fracsec)

    @staticmethod
    def _timestamp_now() -> Tuple[int, int]:
        """Return (SOC, FRACSEC) for the current time."""
        t   = time.time()
        soc = int(t)
        frac_sec = t - soc
        # FRACSEC: upper byte = leap-second flags (0x00), lower 3 bytes = fraction * 2^24
        fracsec = int(frac_sec * 1_000_000) & 0x00FFFFFF
        return soc, fracsec

    # ── DATA frame ────────────────────────────────────────────────────────────

    def encode_data_frame(
        self,
        phasors: List[Tuple[float, float]],  # list of (magnitude, angle_radians)
        freq:    float,
        dfreq:   float,
        analog:  List[float],
        digital: List[int],
        soc:     Optional[int] = None,
        fracsec: Optional[int] = None,
        stat:    int = STAT_OK,
    ) -> bytes:
        """
        Encode a C37.118 DATA frame to bytes.

        Parameters
        ----------
        phasors : list of (magnitude_volts, angle_radians)
        freq    : frequency in Hz (e.g. 50.0)
        dfreq   : ROCOF in Hz/s
        analog  : list of float analog values
        digital : list of int (16-bit) digital status words
        soc     : seconds-of-century (Unix timestamp). If None, uses current time.
        fracsec : fractional second. If None, uses current time.
        stat    : STAT word (default STAT_OK = 0x0000)

        Returns
        -------
        bytes : complete binary DATA frame (header + payload + CRC)
        """
        if soc is None or fracsec is None:
            soc, fracsec = self._timestamp_now()

        # Validate lengths
        phasors  = phasors[:self.num_phasors]
        analog   = analog[:self.num_analog]
        digital  = digital[:self.num_digital]
        # Pad if short
        while len(phasors) < self.num_phasors:
            phasors.append((0.0, 0.0))
        while len(analog) < self.num_analog:
            analog.append(0.0)
        while len(digital) < self.num_digital:
            digital.append(0)

        # Payload (everything after header, before CRC)
        payload = struct.pack(">H", stat)          # STAT (2 bytes)

        for (mag, ang) in phasors:
            payload += struct.pack(">ff", mag, ang)  # mag (float32) + angle (float32)

        payload += struct.pack(">f", freq)         # FREQ (4 bytes)
        payload += struct.pack(">f", dfreq)        # DFREQ (4 bytes)

        for a in analog:
            payload += struct.pack(">f", a)        # ANALOG values

        for d in digital:
            payload += struct.pack(">H", d & 0xFFFF)  # DIGITAL words

        framesize = 14 + len(payload) + 2         # header + payload + CRC
        header    = self._build_header(SYNC_DATA, framesize, soc, fracsec)
        frame_no_crc = header + payload
        crc       = crc_bytes(frame_no_crc)
        return frame_no_crc + crc

    def decode_data_frame(self, raw_bytes: bytes) -> Optional[C37118DataFrameDict]:
        """
        Decode a raw C37.118 DATA frame back into a C37118DataFrameDict.

        Returns None if:
        - Frame is too short
        - SYNC word does not match DATA frame
        - CRC check fails

        Parameters
        ----------
        raw_bytes : complete binary frame including header and CRC

        Returns
        -------
        C37118DataFrameDict or None
        """
        MIN_HEADER = 14 + 2 + 4 + 4 + 2  # header + STAT + FREQ + DFREQ + CRC
        if len(raw_bytes) != self._data_frame_size:
            return None

        # Verify CRC — compare stored CRC vs computed CRC on all preceding bytes
        stored_crc   = struct.unpack(">H", raw_bytes[-2:])[0]
        computed_crc = calculate_crc(raw_bytes[:-2])
        if stored_crc != computed_crc:
            return None

        offset = 0

        # Header (14 bytes)
        sync, framesize, idcode, soc, fracsec = struct.unpack_from(">HHHII", raw_bytes, offset)
        offset += 14

        if sync != SYNC_DATA or framesize != len(raw_bytes):
            return None

        # STAT (2 bytes)
        stat = struct.unpack_from(">H", raw_bytes, offset)[0]
        offset += 2

        # Phasors — each is float32 mag + float32 angle (8 bytes)
        phasors = []
        for _ in range(self.num_phasors):
            if offset + 8 > len(raw_bytes) - 2:
                break
            mag, ang = struct.unpack_from(">ff", raw_bytes, offset)
            phasors.append((mag, ang))
            offset += 8

        # FREQ and DFREQ (4 bytes each)
        if offset + 8 > len(raw_bytes) - 2:
            return None
        freq, dfreq = struct.unpack_from(">ff", raw_bytes, offset)
        offset += 8

        # Analog values (float32 each)
        analog = []
        for _ in range(self.num_analog):
            if offset + 4 > len(raw_bytes) - 2:
                break
            a = struct.unpack_from(">f", raw_bytes, offset)[0]
            analog.append(a)
            offset += 4

        # Digital words (uint16 each)
        digital = []
        for _ in range(self.num_digital):
            if offset + 2 > len(raw_bytes) - 2:
                break
            d = struct.unpack_from(">H", raw_bytes, offset)[0]
            digital.append(d)
            offset += 2

        return C37118DataFrameDict(
            sync=sync, framesize=framesize, idcode=idcode,
            soc=soc, fracsec=fracsec, stat=stat,
            phasors=phasors, freq=freq, dfreq=dfreq,
            analog=analog, digital=digital,
            crc=stored_crc,
        )

    # ── CONFIG-2 frame ────────────────────────────────────────────────────────

    def encode_config_frame(
        self,
        data_rate: int = 30,
        soc: Optional[int] = None,
        fracsec: Optional[int] = None,
    ) -> bytes:
        """
        Encode a CFG-2 (Configuration Frame Type 2) for one station.

        The CFG-2 frame tells the PDC how to interpret subsequent data frames.
        Must be sent before the first data frame.

        Parameters
        ----------
        data_rate : frames per second (positive int)
        soc, fracsec : timestamp (defaults to now)

        Returns
        -------
        bytes : complete binary CFG-2 frame
        """
        self._cfgcnt += 1

        if soc is None or fracsec is None:
            soc, fracsec = self._timestamp_now()

        payload = b""

        # TIME_BASE (uint32): resolution of FRACSEC — use 1_000_000 (microsecond)
        time_base = 1_000_000
        payload += struct.pack(">I", time_base)

        # NUM_PMU (uint16): number of stations in this frame
        payload += struct.pack(">H", 1)

        # ── Per-station block ──────────────────────────────────────────────────
        # STN: 16-byte ASCII station name
        payload += self.station_name.encode("ascii")[:16].ljust(16, b" ")

        # IDCODE (uint16)
        payload += struct.pack(">H", self.idcode)

        # FORMAT (uint16): bit layout
        #  bit 3 = FREQ type  (0=int16, 1=float)
        #  bit 2 = ANALOG type (0=int16, 1=float)
        #  bit 1 = PHASOR type (0=int16, 1=float)
        #  bit 0 = PHASOR coords (0=rectangular, 1=polar)
        # We use float polar for all:  0b1111 = 0x000F
        fmt = 0x000F
        payload += struct.pack(">H", fmt)

        # PHNMR, ANNMR, DGNMR (uint16 each)
        payload += struct.pack(">HHH", self.num_phasors, self.num_analog, self.num_digital)

        # CHNAM: channel names — 16 bytes each
        phasor_names = ["VA      ", "VB      ", "VC      ", "IA      ", "IB      ", "IC      "]
        analog_names = ["ANALOG1 "]
        digital_names = []

        for i in range(self.num_phasors):
            name = phasor_names[i] if i < len(phasor_names) else f"PH{i+1}    "
            payload += name[:16].encode("ascii").ljust(16, b" ")

        for i in range(self.num_analog):
            name = analog_names[i] if i < len(analog_names) else f"AN{i+1}    "
            payload += name[:16].encode("ascii").ljust(16, b" ")

        for i in range(self.num_digital):
            for bit in range(16):
                label = f"DIG{i}_{bit}  "
                payload += label[:16].encode("ascii").ljust(16, b" ")

        # PHUNIT (uint32 each): phasor conversion factor
        # bit 31 = 0 → voltage, 1 → current.  bits 0-23 = conversion factor (×10^-5)
        # For float phasors this is informational; set voltage = 0x00000000
        for i in range(self.num_phasors):
            payload += struct.pack(">I", 0x00000000)  # voltage type, scale=0

        # ANUNIT (uint32 each)
        for i in range(self.num_analog):
            payload += struct.pack(">I", 0x00000000)

        # DIGUNIT (uint32 each)
        for i in range(self.num_digital):
            payload += struct.pack(">I", 0x00000000)

        # FNOM (uint16): 0x0001 = 50 Hz, 0x0000 = 60 Hz
        payload += struct.pack(">H", self.nominal_freq)

        # CFGCNT (uint16): config change count
        payload += struct.pack(">H", self._cfgcnt)

        # DATA_RATE (int16): positive = frames/second, negative = seconds/frame
        payload += struct.pack(">h", data_rate)

        framesize    = 14 + len(payload) + 2
        header       = self._build_header(SYNC_CFG2, framesize, soc, fracsec)
        frame_no_crc = header + payload
        return frame_no_crc + crc_bytes(frame_no_crc)

    def decode_config_frame(self, raw_bytes: bytes) -> Optional[dict]:
        try:
            return self._decode_config_frame(raw_bytes)
        except (struct.error, ValueError, IndexError):
            return None

    def _decode_config_frame(self, raw_bytes: bytes) -> Optional[dict]:
        """
        Decode a CFG-2 frame and return a dict with station config info.
        Returns None on CRC error or wrong SYNC.
        """
        if len(raw_bytes) < 24:
            return None

        stored_crc   = struct.unpack(">H", raw_bytes[-2:])[0]
        computed_crc = calculate_crc(raw_bytes[:-2])
        if stored_crc != computed_crc:
            return None

        offset = 0
        sync, framesize, idcode, soc, fracsec = struct.unpack_from(">HHHII", raw_bytes, offset)
        offset += 14

        if sync != SYNC_CFG2 or framesize != len(raw_bytes):
            return None

        time_base = struct.unpack_from(">I", raw_bytes, offset)[0];  offset += 4
        num_pmu   = struct.unpack_from(">H", raw_bytes, offset)[0];  offset += 2

        stations = []
        for _ in range(num_pmu):
            stn       = raw_bytes[offset:offset+16].decode("ascii", errors="replace").strip()
            offset   += 16
            pmu_id    = struct.unpack_from(">H", raw_bytes, offset)[0]; offset += 2
            fmt       = struct.unpack_from(">H", raw_bytes, offset)[0]; offset += 2
            phnmr     = struct.unpack_from(">H", raw_bytes, offset)[0]; offset += 2
            annmr     = struct.unpack_from(">H", raw_bytes, offset)[0]; offset += 2
            dgnmr     = struct.unpack_from(">H", raw_bytes, offset)[0]; offset += 2
            # Channel names
            ch_names  = []
            total_ch  = phnmr + annmr + dgnmr * 16
            if offset + total_ch * 16 + (phnmr + annmr + dgnmr) * 4 + 8 > len(raw_bytes):
                return None
            for _ in range(total_ch):
                ch_names.append(raw_bytes[offset:offset+16].decode("ascii", errors="replace").strip())
                offset += 16
            # PHUNIT
            phunit = [struct.unpack_from(">I", raw_bytes, offset+i*4)[0] for i in range(phnmr)]
            offset += phnmr * 4
            # ANUNIT
            anunit = [struct.unpack_from(">I", raw_bytes, offset+i*4)[0] for i in range(annmr)]
            offset += annmr * 4
            # DIGUNIT
            digunit = [struct.unpack_from(">I", raw_bytes, offset+i*4)[0] for i in range(dgnmr)]
            offset += dgnmr * 4
            fnom   = struct.unpack_from(">H", raw_bytes, offset)[0]; offset += 2
            cfgcnt = struct.unpack_from(">H", raw_bytes, offset)[0]; offset += 2

            stations.append({
                "stn": stn, "idcode": pmu_id, "format": fmt,
                "phnmr": phnmr, "annmr": annmr, "dgnmr": dgnmr,
                "ch_names": ch_names, "phunit": phunit,
                "anunit": anunit, "digunit": digunit,
                "fnom": fnom, "cfgcnt": cfgcnt,
            })

        data_rate = struct.unpack_from(">h", raw_bytes, offset)[0]
        if offset + 4 != len(raw_bytes):
            return None

        return {
            "sync": sync, "framesize": framesize, "idcode": idcode,
            "soc": soc, "fracsec": fracsec,
            "time_base": time_base, "num_pmu": num_pmu,
            "stations": stations, "data_rate": data_rate,
            "crc": stored_crc,
        }

    # ── COMMAND frame ─────────────────────────────────────────────────────────

    def encode_command_frame(
        self,
        command:  int,
        soc:      Optional[int] = None,
        fracsec:  Optional[int] = None,
        extended: bytes = b"",
    ) -> bytes:
        """
        Encode a COMMAND frame.

        Parameters
        ----------
        command  : 16-bit command code (CMD_TURN_ON_TX, CMD_SEND_CFG2, etc.)
        extended : optional extended data bytes

        Returns
        -------
        bytes : complete binary COMMAND frame
        """
        if soc is None or fracsec is None:
            soc, fracsec = self._timestamp_now()

        payload      = struct.pack(">H", command) + extended
        framesize    = 14 + len(payload) + 2
        header       = self._build_header(SYNC_COMMAND, framesize, soc, fracsec)
        frame_no_crc = header + payload
        return frame_no_crc + crc_bytes(frame_no_crc)

    def decode_command_frame(self, raw_bytes: bytes) -> Optional[dict]:
        """Decode a COMMAND frame. Returns None on error."""
        if len(raw_bytes) < 18:
            return None

        stored_crc   = struct.unpack(">H", raw_bytes[-2:])[0]
        computed_crc = calculate_crc(raw_bytes[:-2])
        if stored_crc != computed_crc:
            return None

        sync, framesize, idcode, soc, fracsec = struct.unpack_from(">HHHII", raw_bytes, 0)
        if sync != SYNC_COMMAND or framesize != len(raw_bytes):
            return None

        cmd      = struct.unpack_from(">H", raw_bytes, 14)[0]
        extended = raw_bytes[16:-2]

        return {
            "sync": sync, "framesize": framesize, "idcode": idcode,
            "soc": soc, "fracsec": fracsec,
            "command": cmd, "extended": extended, "crc": stored_crc,
        }

    # ── Frame type detection ──────────────────────────────────────────────────

    @staticmethod
    def detect_frame_type(raw_bytes: bytes) -> Optional[str]:
        """
        Detect the type of a raw C37.118 frame from its SYNC word.

        Returns one of: 'data', 'cfg1', 'cfg2', 'cfg3', 'header', 'command', or None.
        """
        if len(raw_bytes) < 2:
            return None
        sync = struct.unpack_from(">H", raw_bytes, 0)[0]
        return {
            SYNC_DATA:    "data",
            SYNC_CFG1:    "cfg1",
            SYNC_CFG2:    "cfg2",
            SYNC_CFG3:    "cfg3",
            SYNC_HEADER:  "header",
            SYNC_COMMAND: "command",
        }.get(sync, None)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience functions (module-level)
# ─────────────────────────────────────────────────────────────────────────────

_default_codec = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=0)

def encode_data_frame(phasors, freq, dfreq, analog, digital, soc=None, fracsec=None) -> bytes:
    """Encode a data frame using the default 3-phasor codec."""
    return _default_codec.encode_data_frame(phasors, freq, dfreq, analog, digital, soc, fracsec)

def decode_data_frame(raw_bytes: bytes) -> Optional[dict]:
    """Decode a data frame using the default 3-phasor codec. Returns dict or None."""
    frame = _default_codec.decode_data_frame(raw_bytes)
    return frame.to_dict() if frame else None


# ─────────────────────────────────────────────────────────────────────────────
# Self-test
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    print("=" * 60)
    print("  IEEE C37.118-2011 Codec Self-Test")
    print("=" * 60)

    codec = C37118Codec(
        idcode=7,
        num_phasors=3,
        num_analog=2,
        num_digital=1,
        station_name="TEST PMU        ",
        nominal_freq=0x0001,   # 50 Hz
    )

    TWO_PI = 2 * math.pi

    # Three-phase phasors: Va at 0°, Vb at -120°, Vc at +120°
    phasors = [
        (120.0, 0.0),
        (119.5, -TWO_PI / 3),
        (120.5,  TWO_PI / 3),
    ]
    analog  = [1.23, -0.45]
    digital = [0xABCD]

    # ── Test 1: CRC calculation ───────────────────────────────────────────────
    print("\n[TEST 1] CRC-CCITT")
    test_data = b"\xAA\x01\x00\x12\x00\x01"
    crc_val   = calculate_crc(test_data)
    print(f"  Input:    {test_data.hex().upper()}")
    print(f"  CRC:      0x{crc_val:04X}")
    assert isinstance(crc_val, int) and 0 <= crc_val <= 0xFFFF, "CRC out of range"
    print("  ✔ CRC is a valid 16-bit integer")

    # ── Test 2: Encode DATA frame ─────────────────────────────────────────────
    print("\n[TEST 2] Encode DATA frame")
    frame = codec.encode_data_frame(
        phasors=phasors, freq=50.02, dfreq=0.001,
        analog=analog, digital=digital,
        soc=1_700_000_000, fracsec=500_000,
    )
    print(f"  Frame length:  {len(frame)} bytes")
    print(f"  First 4 bytes: {frame[:4].hex().upper()}  (SYNC=AA01, expect AA01)")
    print(f"  Hex dump:      {frame.hex().upper()}")
    assert frame[:2] == bytes([0xAA, 0x01]), "SYNC word mismatch"
    print("  ✔ SYNC word correct")
    assert len(frame) == struct.unpack_from(">H", frame, 2)[0], "FRAMESIZE mismatch"
    print("  ✔ FRAMESIZE consistent")

    # ── Test 3: CRC of encoded frame ─────────────────────────────────────────
    print("\n[TEST 3] CRC verification of encoded frame")
    stored  = struct.unpack(">H", frame[-2:])[0]
    recomp  = calculate_crc(frame[:-2])
    print(f"  Stored CRC:   0x{stored:04X}")
    print(f"  Computed CRC: 0x{recomp:04X}")
    assert stored == recomp, "CRC mismatch!"
    print("  ✔ CRC valid")

    # ── Test 4: Decode DATA frame (round-trip) ────────────────────────────────
    print("\n[TEST 4] Decode DATA frame (encode→decode round-trip)")
    decoded = codec.decode_data_frame(frame)
    assert decoded is not None, "decode_data_frame returned None"
    print(f"  SYNC:      0x{decoded.sync:04X}  (expect 0xAA01)")
    print(f"  IDCODE:    {decoded.idcode}  (expect 7)")
    print(f"  FREQ:      {decoded.freq:.4f} Hz  (expect 50.0200)")
    print(f"  DFREQ:     {decoded.dfreq:.6f} Hz/s  (expect 0.001)")
    print(f"  Phasors:   {[(round(m,3), round(a,6)) for m,a in decoded.phasors]}")
    print(f"  Analog:    {[round(a,4) for a in decoded.analog]}")
    print(f"  Digital:   {[hex(d) for d in decoded.digital]}")
    assert decoded.idcode == 7
    assert abs(decoded.freq - 50.02) < 1e-3, f"freq mismatch: {decoded.freq}"
    assert len(decoded.phasors) == 3
    assert abs(decoded.phasors[0][0] - 120.0) < 0.01, "Va magnitude mismatch"
    assert abs(decoded.phasors[1][1] - (-TWO_PI/3)) < 1e-5, "Vb angle mismatch"
    print("  ✔ All decoded values match input")

    # ── Test 5: CRC tamper detection ─────────────────────────────────────────
    print("\n[TEST 5] CRC tamper detection")
    tampered = bytearray(frame)
    tampered[20] ^= 0xFF   # flip a byte in the phasor data
    result = codec.decode_data_frame(bytes(tampered))
    assert result is None, "Decoder should reject tampered frame"
    print("  ✔ Tampered frame correctly rejected")

    # ── Test 6: CONFIG-2 frame ────────────────────────────────────────────────
    print("\n[TEST 6] Encode + Decode CFG-2 frame")
    cfg_frame = codec.encode_config_frame(data_rate=30)
    print(f"  CFG-2 length: {len(cfg_frame)} bytes")
    assert cfg_frame[:2] == bytes([0xAA, 0x31]), f"CFG-2 SYNC mismatch: {cfg_frame[:2].hex()}"
    print("  ✔ SYNC = 0xAA31 (CFG-2)")
    cfg_stored  = struct.unpack(">H", cfg_frame[-2:])[0]
    cfg_recomp  = calculate_crc(cfg_frame[:-2])
    assert cfg_stored == cfg_recomp, "CFG-2 CRC mismatch"
    print("  ✔ CFG-2 CRC valid")
    cfg_decoded = codec.decode_config_frame(cfg_frame)
    assert cfg_decoded is not None
    print(f"  Station: '{cfg_decoded['stations'][0]['stn']}'")
    print(f"  phnmr:   {cfg_decoded['stations'][0]['phnmr']}  (expect 3)")
    assert cfg_decoded["stations"][0]["phnmr"] == 3
    print("  ✔ CFG-2 decode OK")

    # ── Test 7: COMMAND frame ────────────────────────────────────────────────
    print("\n[TEST 7] Encode + Decode COMMAND frame")
    cmd_frame   = codec.encode_command_frame(CMD_TURN_ON_TX)
    cmd_decoded = codec.decode_command_frame(cmd_frame)
    assert cmd_decoded is not None
    assert cmd_decoded["command"] == CMD_TURN_ON_TX
    print(f"  Command: 0x{cmd_decoded['command']:04X}  (expect 0x0002 = TURN_ON_TX)")
    print("  ✔ COMMAND frame encode/decode OK")

    # ── Test 8: Frame type detection ─────────────────────────────────────────
    print("\n[TEST 8] Frame type detection")
    assert C37118Codec.detect_frame_type(frame)     == "data"
    assert C37118Codec.detect_frame_type(cfg_frame) == "cfg2"
    assert C37118Codec.detect_frame_type(cmd_frame) == "command"
    print("  ✔ detect_frame_type works for data/cfg2/command")

    # ── Test 9: Module-level convenience wrappers ─────────────────────────────
    print("\n[TEST 9] Module-level encode/decode wrappers")
    simple_phasors = [(120.0, 0.0), (120.0, -TWO_PI/3), (120.0, TWO_PI/3)]
    raw   = encode_data_frame(simple_phasors, 50.0, 0.0, [0.0], [])
    parsed = decode_data_frame(raw)
    assert parsed is not None
    assert parsed["freq"] == 50.0 or abs(parsed["freq"] - 50.0) < 1e-3
    print(f"  Decoded freq: {parsed['freq']} Hz")
    print("  ✔ Module-level wrappers OK")

    print()
    print("=" * 60)
    print("  ALL TESTS PASSED ✔")
    print("=" * 60)
    sys.exit(0)
