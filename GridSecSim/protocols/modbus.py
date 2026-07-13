"""
protocols/modbus.py
===================
Modbus TCP — stub implementation.

Modbus TCP wraps the classic Modbus PDU in a TCP/IP wrapper called
the "Modbus Application Protocol" (MBAP) header.

For GridSec Sim v1.0, Modbus links are displayed on the topology canvas
but live simulation is C37.118 only.

References: Modbus Application Protocol Specification V1.1b3 (2012)
"""

import struct
from typing import Optional, List


# ─────────────────────────────────────────────────────────────────────────────
# Function codes
# ─────────────────────────────────────────────────────────────────────────────

FC_READ_COILS             = 0x01
FC_READ_DISCRETE_INPUTS   = 0x02
FC_READ_HOLDING_REGISTERS = 0x03
FC_READ_INPUT_REGISTERS   = 0x04
FC_WRITE_SINGLE_COIL      = 0x05
FC_WRITE_SINGLE_REGISTER  = 0x06
FC_WRITE_MULTIPLE_COILS   = 0x0F
FC_WRITE_MULTIPLE_REGS    = 0x10

# Exception codes
EX_ILLEGAL_FUNCTION       = 0x01
EX_ILLEGAL_DATA_ADDRESS   = 0x02
EX_ILLEGAL_DATA_VALUE     = 0x03
EX_SERVER_DEVICE_FAILURE  = 0x04


# ─────────────────────────────────────────────────────────────────────────────
# MBAP Header + PDU
# ─────────────────────────────────────────────────────────────────────────────

class ModbusTCPFrame:
    """
    Modbus TCP Application Data Unit (ADU).

    MBAP Header (7 bytes):
      [0-1] Transaction Identifier (uint16 big-endian)
      [2-3] Protocol Identifier   (always 0x0000 for Modbus)
      [4-5] Length                (number of following bytes = unit_id + PDU)
      [6]   Unit Identifier       (slave/device address, 0xFF for broadcast)

    PDU:
      [0]   Function Code (uint8)
      [1+]  Data
    """

    def __init__(
        self,
        transaction_id: int = 1,
        unit_id:        int = 1,
        function_code:  int = FC_READ_HOLDING_REGISTERS,
        data:           bytes = b"",
    ):
        self.transaction_id = transaction_id
        self.unit_id        = unit_id
        self.function_code  = function_code
        self.data           = data

    def encode(self) -> bytes:
        pdu    = bytes([self.function_code]) + self.data
        length = 1 + len(pdu)   # unit_id byte + PDU
        mbap   = struct.pack(">HHH", self.transaction_id, 0x0000, length)
        return mbap + bytes([self.unit_id]) + pdu

    @classmethod
    def decode(cls, raw: bytes) -> Optional["ModbusTCPFrame"]:
        if len(raw) < 8:
            return None
        tid, proto, length = struct.unpack_from(">HHH", raw, 0)
        if proto != 0x0000:
            return None
        unit_id = raw[6]
        func    = raw[7]
        data    = raw[8:6 + length]
        return cls(transaction_id=tid, unit_id=unit_id, function_code=func, data=data)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def encode_read_holding_registers(
    transaction_id: int,
    unit_id: int,
    start_address: int,
    quantity: int,
) -> bytes:
    """Encode a Read Holding Registers (FC=03) request."""
    data = struct.pack(">HH", start_address, quantity)
    return ModbusTCPFrame(
        transaction_id=transaction_id,
        unit_id=unit_id,
        function_code=FC_READ_HOLDING_REGISTERS,
        data=data,
    ).encode()


def encode_write_single_register(
    transaction_id: int,
    unit_id: int,
    address: int,
    value: int,
) -> bytes:
    """Encode a Write Single Register (FC=06) request."""
    data = struct.pack(">HH", address, value)
    return ModbusTCPFrame(
        transaction_id=transaction_id,
        unit_id=unit_id,
        function_code=FC_WRITE_SINGLE_REGISTER,
        data=data,
    ).encode()


def decode_frame(raw: bytes) -> Optional[dict]:
    """Decode a raw Modbus TCP frame."""
    frame = ModbusTCPFrame.decode(raw)
    if frame is None:
        return None
    return {
        "transaction_id": frame.transaction_id,
        "unit_id":        frame.unit_id,
        "function_code":  frame.function_code,
        "data_hex":       frame.data.hex(),
    }


if __name__ == "__main__":
    print("Modbus TCP stub — encode/decode test")
    req  = encode_read_holding_registers(1, 1, 0, 10)
    print(f"Read Holding Regs ({len(req)} bytes): {req.hex().upper()}")
    parsed = decode_frame(req)
    print(f"Decoded: {parsed}")
    req2 = encode_write_single_register(2, 1, 5, 1234)
    print(f"Write Single Reg ({len(req2)} bytes): {req2.hex().upper()}")
    print("Modbus stub OK")
