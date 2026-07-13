"""
protocols/modbus.py
===================
Modbus TCP Protocol Encoder/Decoder

Wireshark dissector: "Modbus/TCP"
Wireshark filter:    modbus
Standard port:       TCP 502

Frame structure:
  ┌─ MBAP Header (7 bytes) ──────────────────────────┐
  │ Transaction ID : 2 bytes (echoed by server)      │
  │ Protocol ID    : 2 bytes (always 0x0000)         │
  │ Length         : 2 bytes (remaining bytes count) │
  │ Unit ID        : 1 byte  (slave/device address)  │
  ├─ PDU ────────────────────────────────────────────┤
  │ Function Code  : 1 byte                          │
  │ Data           : N bytes                         │
  └──────────────────────────────────────────────────┘

Supported function codes:
  0x01  Read Coils
  0x02  Read Discrete Inputs
  0x03  Read Holding Registers
  0x04  Read Input Registers
  0x05  Write Single Coil
  0x06  Write Single Register
  0x0F  Write Multiple Coils
  0x10  Write Multiple Registers

For Wireshark: Modbus/TCP is auto-dissected on port 502 (TCP).
               It also recognises 8×FC as the exception code.
"""

import struct
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MODBUS_PORT      = 502
MODBUS_PROTOCOL  = 0x0000   # always 0 for Modbus/TCP

# Function codes
FC_READ_COILS           = 0x01
FC_READ_DISCRETE        = 0x02
FC_READ_HOLDING_REGS    = 0x03
FC_READ_INPUT_REGS      = 0x04
FC_WRITE_SINGLE_COIL    = 0x05
FC_WRITE_SINGLE_REG     = 0x06
FC_WRITE_MULTI_COILS    = 0x0F
FC_WRITE_MULTI_REGS     = 0x10

# Exception codes (add 0x80 to FC for exception response)
EX_ILLEGAL_FUNCTION     = 0x01
EX_ILLEGAL_DATA_ADDRESS = 0x02
EX_ILLEGAL_DATA_VALUE   = 0x03
EX_SLAVE_DEVICE_FAILURE = 0x04

# Register map for our simulated power system device
# Input Registers (FC 0x04) — read-only measurements
REG_VA_MAGNITUDE   = 0    # Va voltage magnitude (raw: V × 10)
REG_VB_MAGNITUDE   = 1    # Vb voltage magnitude
REG_VC_MAGNITUDE   = 2    # Vc voltage magnitude
REG_FREQUENCY_X100 = 3    # Frequency × 100 (e.g., 5002 = 50.02 Hz)
REG_ACTIVE_POWER   = 4    # Active power (kW)
REG_REACTIVE_POWER = 5    # Reactive power (kVar)
REG_CURRENT_A      = 6    # Phase A current (A × 10)
REG_CURRENT_B      = 7    # Phase B current
REG_CURRENT_C      = 8    # Phase C current
REG_POWER_FACTOR   = 9    # Power factor × 1000

# Holding Registers (FC 0x03) — read/write settings
REG_SETPOINT_V     = 100  # Voltage setpoint
REG_SETPOINT_F     = 101  # Frequency setpoint × 100


# ── MBAP Header ───────────────────────────────────────────────────────────────

@dataclass
class MBAPHeader:
    transaction_id: int = 0
    protocol_id:    int = MODBUS_PROTOCOL
    length:         int = 0     # set during encode
    unit_id:        int = 1

    def encode(self) -> bytes:
        return struct.pack(">HHHB",
            self.transaction_id,
            self.protocol_id,
            self.length,
            self.unit_id,
        )

    @staticmethod
    def decode(raw: bytes) -> Optional["MBAPHeader"]:
        if len(raw) < 7:
            return None
        tid, pid, length, uid = struct.unpack_from(">HHHB", raw, 0)
        if pid != MODBUS_PROTOCOL:
            return None
        return MBAPHeader(tid, pid, length, uid)


# ── PDU builders ──────────────────────────────────────────────────────────────

def _mbap_wrap(pdu: bytes, transaction_id: int = 0, unit_id: int = 1) -> bytes:
    """Wrap a PDU in an MBAP header to create a complete Modbus/TCP frame."""
    # Length = unit_id (1) + PDU bytes
    length = 1 + len(pdu)
    hdr = struct.pack(">HHHB",
        transaction_id,
        MODBUS_PROTOCOL,
        length,
        unit_id,
    )
    return hdr + pdu


# ── Request builders (master → slave) ─────────────────────────────────────────

def build_read_input_registers_request(
    start_reg:      int,
    count:          int,
    transaction_id: int = 0,
    unit_id:        int = 1,
) -> bytes:
    """Build a Read Input Registers (FC=0x04) request frame."""
    pdu = struct.pack(">BHH", FC_READ_INPUT_REGS, start_reg, count)
    return _mbap_wrap(pdu, transaction_id, unit_id)


def build_read_holding_registers_request(
    start_reg:      int,
    count:          int,
    transaction_id: int = 0,
    unit_id:        int = 1,
) -> bytes:
    """Build a Read Holding Registers (FC=0x03) request frame."""
    pdu = struct.pack(">BHH", FC_READ_HOLDING_REGS, start_reg, count)
    return _mbap_wrap(pdu, transaction_id, unit_id)


def build_write_single_register_request(
    reg_addr:       int,
    value:          int,
    transaction_id: int = 0,
    unit_id:        int = 1,
) -> bytes:
    """Build a Write Single Register (FC=0x06) request frame."""
    pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REG, reg_addr, value & 0xFFFF)
    return _mbap_wrap(pdu, transaction_id, unit_id)


# ── Response builders (slave → master) ────────────────────────────────────────

def build_read_registers_response(
    register_values: List[int],
    transaction_id:  int = 0,
    unit_id:         int = 1,
    fc:              int = FC_READ_INPUT_REGS,
) -> bytes:
    """
    Build a Read Input/Holding Registers response frame.
    register_values: list of uint16 values.
    """
    byte_count = len(register_values) * 2
    pdu = bytes([fc, byte_count])
    for v in register_values:
        pdu += struct.pack(">H", v & 0xFFFF)
    return _mbap_wrap(pdu, transaction_id, unit_id)


def build_exception_response(
    fc:             int,
    exception_code: int,
    transaction_id: int = 0,
    unit_id:        int = 1,
) -> bytes:
    """Build a Modbus exception response (FC | 0x80, exception_code)."""
    pdu = bytes([fc | 0x80, exception_code])
    return _mbap_wrap(pdu, transaction_id, unit_id)


def build_write_register_response(
    reg_addr:       int,
    value:          int,
    transaction_id: int = 0,
    unit_id:        int = 1,
) -> bytes:
    """Echo back the write command as response (FC=0x06)."""
    pdu = struct.pack(">BHH", FC_WRITE_SINGLE_REG, reg_addr, value & 0xFFFF)
    return _mbap_wrap(pdu, transaction_id, unit_id)


# ── Decoder ────────────────────────────────────────────────────────────────────

@dataclass
class ModbusFrame:
    transaction_id: int
    unit_id:        int
    fc:             int
    is_request:     bool
    is_exception:   bool
    register_start: int       = 0
    register_count: int       = 0
    register_values: List[int] = field(default_factory=list)
    exception_code:  int      = 0
    raw_pdu:         bytes    = b""


def decode_frame(raw: bytes) -> Optional[ModbusFrame]:
    """Decode a complete Modbus/TCP frame (MBAP + PDU)."""
    try:
        if len(raw) < 8:
            return None

        tid, pid, length, uid = struct.unpack_from(">HHHB", raw, 0)
        if pid != MODBUS_PROTOCOL:
            return None

        pdu = raw[7:7 + length - 1]   # length includes uid byte
        if len(pdu) < 1:
            return None

        fc          = pdu[0]
        is_except   = bool(fc & 0x80)
        actual_fc   = fc & 0x7F

        frame = ModbusFrame(
            transaction_id = tid,
            unit_id        = uid,
            fc             = actual_fc,
            is_request     = False,
            is_exception   = is_except,
            raw_pdu        = pdu,
        )

        if is_except:
            frame.exception_code = pdu[1] if len(pdu) > 1 else 0
            return frame

        if actual_fc in (FC_READ_INPUT_REGS, FC_READ_HOLDING_REGS):
            if len(pdu) >= 3:
                if pdu[1] % 2 == 0 and len(pdu) == 2 + pdu[1]:
                    # Response: [FC, byte_count, reg_hi, reg_lo, ...]
                    byte_count = pdu[1]
                    num_regs   = byte_count // 2
                    frame.register_values = [
                        struct.unpack_from(">H", pdu, 2 + i * 2)[0]
                        for i in range(num_regs)
                    ]
                else:
                    # Request: [FC, start_hi, start_lo, count_hi, count_lo]
                    frame.is_request     = True
                    frame.register_start = struct.unpack_from(">H", pdu, 1)[0]
                    frame.register_count = struct.unpack_from(">H", pdu, 3)[0]

        elif actual_fc == FC_WRITE_SINGLE_REG:
            frame.register_start  = struct.unpack_from(">H", pdu, 1)[0]
            frame.register_values = [struct.unpack_from(">H", pdu, 3)[0]]

        return frame

    except Exception as exc:
        logger.debug(f"Modbus decode error: {exc}")
        return None


# ── Register value helpers ─────────────────────────────────────────────────────

def float_to_reg(value: float, scale: float = 10.0) -> int:
    """Convert a float to a scaled uint16 register value."""
    return max(0, min(0xFFFF, int(round(value * scale))))


def reg_to_float(reg: int, scale: float = 10.0) -> float:
    """Convert a uint16 register value back to float."""
    return reg / scale


def build_power_system_registers(
    va: float,
    vb: float,
    vc: float,
    frequency: float,
    active_power:   float = 500.0,
    reactive_power: float = 100.0,
    ia: float = 10.0,
    ib: float = 10.0,
    ic: float = 10.0,
    power_factor: float = 0.95,
) -> List[int]:
    """
    Build a list of 10 input register values for a simulated power system.
    Register indices match REG_* constants above.
    """
    return [
        float_to_reg(va,            10.0),    # 0: Va ×10
        float_to_reg(vb,            10.0),    # 1: Vb ×10
        float_to_reg(vc,            10.0),    # 2: Vc ×10
        float_to_reg(frequency,    100.0),    # 3: freq ×100
        float_to_reg(active_power,   1.0),    # 4: kW
        float_to_reg(reactive_power, 1.0),    # 5: kVar
        float_to_reg(ia,            10.0),    # 6: Ia ×10
        float_to_reg(ib,            10.0),    # 7: Ib ×10
        float_to_reg(ic,            10.0),    # 8: Ic ×10
        float_to_reg(power_factor, 1000.0),   # 9: PF ×1000
    ]


# ── Self-test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Modbus/TCP self-test")
    print("=" * 50)

    # Test 1: Read Input Registers request
    req = build_read_input_registers_request(
        start_reg=0, count=10, transaction_id=1, unit_id=1
    )
    print(f"[1] Request: {len(req)} bytes | {req.hex()}")
    assert req[0:2] == b'\x00\x01', "Transaction ID mismatch"
    assert req[2:4] == b'\x00\x00', "Protocol ID mismatch"
    assert req[7]   == FC_READ_INPUT_REGS, f"FC mismatch: {req[7]:#04x}"
    print(f"    ✔ MBAP correct, FC=0x{FC_READ_INPUT_REGS:02X}")

    # Test 2: Build register values for typical grid data
    regs = build_power_system_registers(
        va=120.5, vb=119.8, vc=120.2,
        frequency=50.02,
        active_power=450.0, reactive_power=80.0,
    )
    print(f"\n[2] Register values: {regs}")
    assert regs[0] == float_to_reg(120.5, 10.0)
    assert regs[3] == float_to_reg(50.02, 100.0)
    print(f"    Va reg={regs[0]} → {reg_to_float(regs[0], 10.0)} V")
    print(f"    Freq reg={regs[3]} → {reg_to_float(regs[3], 100.0)} Hz")
    print(f"    ✔ Scaling correct")

    # Test 3: Build + decode response
    resp = build_read_registers_response(
        register_values=regs, transaction_id=1, unit_id=1
    )
    print(f"\n[3] Response: {len(resp)} bytes | {resp[:14].hex()}...")
    decoded = decode_frame(resp)
    assert decoded is not None
    assert decoded.fc == FC_READ_INPUT_REGS
    assert not decoded.is_request
    assert decoded.register_values[0] == regs[0]
    print(f"    Decoded FC=0x{decoded.fc:02X}")
    print(f"    Decoded Va reg: {decoded.register_values[0]} → {reg_to_float(decoded.register_values[0], 10.0)} V")
    print(f"    ✔ Encode/decode round-trip OK")

    # Test 4: Decode request
    req_decoded = decode_frame(req)
    assert req_decoded is not None
    assert req_decoded.is_request
    assert req_decoded.register_start == 0
    assert req_decoded.register_count == 10
    print(f"\n[4] Decoded request: start={req_decoded.register_start}, count={req_decoded.register_count} ✔")

    # Test 5: Exception response
    exc_resp = build_exception_response(FC_READ_INPUT_REGS, EX_ILLEGAL_DATA_ADDRESS, 1)
    exc_dec  = decode_frame(exc_resp)
    assert exc_dec is not None
    assert exc_dec.is_exception
    assert exc_dec.exception_code == EX_ILLEGAL_DATA_ADDRESS
    print(f"\n[5] Exception response: FC=0x{exc_dec.fc:02X}|0x80, code={exc_dec.exception_code} ✔")

    print("\nModbus/TCP ALL TESTS PASSED ✔")
