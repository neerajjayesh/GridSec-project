"""
core/packet_parser.py
=====================
Parse raw binary C37.118 packets and rebuild them after modification.

This module is a thin wrapper around protocols.c37118 that provides
a unified interface for the proxy pipeline.  It auto-detects the frame
type and uses the correct codec to parse/rebuild each frame.
"""

import struct
import logging
from typing import Optional, Tuple

from protocols.c37118 import (
    C37118Codec, C37118DataFrameDict,
    SYNC_DATA, SYNC_CFG2, SYNC_COMMAND,
    calculate_crc, crc_bytes,
)

logger = logging.getLogger(__name__)

# Default codec — configurable at runtime by the proxy
_active_codec: C37118Codec = C37118Codec(
    idcode=1,
    num_phasors=3,
    num_analog=1,
    num_digital=0,
)


def set_codec(codec: C37118Codec) -> None:
    """Replace the active codec (e.g., when num_phasors changes)."""
    global _active_codec
    _active_codec = codec


def get_codec() -> C37118Codec:
    return _active_codec


def parse_frame(raw_bytes: bytes) -> Optional[dict]:
    """
    Parse a raw C37.118 binary frame to a Python dict.

    The returned dict always contains at minimum:
      - 'frame_type' : 'data' | 'cfg2' | 'command' | 'unknown'
      - 'raw'        : original bytes (for pass-through when not decoded)

    For DATA frames, all C37.118 fields are present.

    Returns None only if the bytes are completely invalid (< 4 bytes).
    """
    if len(raw_bytes) < 4:
        return None

    frame_type = C37118Codec.detect_frame_type(raw_bytes)

    if frame_type == "data":
        decoded = _active_codec.decode_data_frame(raw_bytes)
        if decoded is None:
            logger.warning("parse_frame: DATA frame failed CRC or length check")
            return {"frame_type": "data_invalid", "raw": raw_bytes}
        d = decoded.to_dict()
        d["frame_type"] = "data"
        d["raw"] = raw_bytes
        return d

    elif frame_type in ("cfg2", "cfg1", "cfg3"):
        decoded = _active_codec.decode_config_frame(raw_bytes)
        if decoded is None:
            return {"frame_type": "cfg_invalid", "raw": raw_bytes}
        decoded["frame_type"] = frame_type
        decoded["raw"] = raw_bytes
        return decoded

    elif frame_type == "command":
        decoded = _active_codec.decode_command_frame(raw_bytes)
        if decoded is None:
            return {"frame_type": "cmd_invalid", "raw": raw_bytes}
        decoded["frame_type"] = "command"
        decoded["raw"] = raw_bytes
        return decoded

    else:
        logger.debug(f"parse_frame: unknown SYNC 0x{struct.unpack_from('>H', raw_bytes, 0)[0]:04X}")
        return {"frame_type": "unknown", "raw": raw_bytes}


def rebuild_frame(frame_dict: dict) -> bytes:
    """
    Re-encode a (possibly modified) frame dict back to binary bytes.

    Only DATA frames are re-encoded; all other types pass through unchanged.
    CRC is recalculated automatically.

    Parameters
    ----------
    frame_dict : dict as returned by parse_frame(), possibly mutated by attack engine

    Returns
    -------
    bytes : valid C37.118 binary frame
    """
    frame_type = frame_dict.get("frame_type", "unknown")

    if frame_type != "data":
        # Pass non-data frames through unchanged
        return frame_dict.get("raw", b"")

    # Re-encode from the (possibly modified) dict fields
    try:
        return _active_codec.encode_data_frame(
            phasors = frame_dict.get("phasors", [(0.0, 0.0)]),
            freq    = frame_dict.get("freq",    50.0),
            dfreq   = frame_dict.get("dfreq",   0.0),
            analog  = frame_dict.get("analog",  []),
            digital = frame_dict.get("digital", []),
            soc     = frame_dict.get("soc",     None),
            fracsec = frame_dict.get("fracsec", None),
            stat    = frame_dict.get("stat",    0x0000),
        )
    except Exception as exc:
        logger.error(f"rebuild_frame failed: {exc}")
        return frame_dict.get("raw", b"")


def frame_summary(frame_dict: dict) -> str:
    """
    Return a short human-readable summary of a parsed frame dict.
    Used for packet log display.
    """
    if frame_dict is None:
        return "None"

    ft = frame_dict.get("frame_type", "?")

    if ft == "data":
        ph = frame_dict.get("phasors", [])
        freq  = frame_dict.get("freq",  0.0)
        mags  = [f"{m:.1f}V" for m, a in ph[:3]]
        return f"DATA  freq={freq:.3f}Hz  mags=[{', '.join(mags)}]"

    elif ft in ("cfg2", "cfg1"):
        stns = frame_dict.get("stations", [{}])
        stn_name = stns[0].get("stn", "?") if stns else "?"
        return f"CFG-2  stn='{stn_name}'  rate={frame_dict.get('data_rate', '?')}fps"

    elif ft == "command":
        cmd_map = {0x0001: "STOP_TX", 0x0002: "START_TX", 0x0005: "SEND_CFG2"}
        cmd = frame_dict.get("command", 0)
        return f"CMD   0x{cmd:04X} ({cmd_map.get(cmd, 'unknown')})"

    else:
        raw = frame_dict.get("raw", b"")
        return f"{ft.upper()}  {len(raw)} bytes"


if __name__ == "__main__":
    import math
    print("packet_parser self-test")

    codec = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=0)
    set_codec(codec)

    TWO_PI = 2 * math.pi
    phasors = [(120.0, 0.0), (120.0, -TWO_PI/3), (120.0, TWO_PI/3)]
    raw     = codec.encode_data_frame(phasors, 50.0, 0.0, [1.5], [], 1_700_000_000, 0)

    parsed  = parse_frame(raw)
    assert parsed is not None
    assert parsed["frame_type"] == "data"
    print(f"Parsed: {frame_summary(parsed)}")

    # Modify freq and rebuild
    parsed["freq"] = 49.5
    rebuilt = rebuild_frame(parsed)
    reparsed = parse_frame(rebuilt)
    assert reparsed is not None
    assert abs(reparsed["freq"] - 49.5) < 0.01, f"freq mismatch: {reparsed['freq']}"
    print(f"Rebuilt & re-parsed: {frame_summary(reparsed)}")
    print("packet_parser OK ✔")
