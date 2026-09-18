"""
core/pcap_writer.py
====================
libpcap-format file writer for GridSec Sim.

Writes captured ICS/SCADA packets (C37.118, DNP3, Modbus/TCP, GOOSE)
to a .pcap file or a named FIFO pipe so Wireshark, Zeek, Security Onion,
Arkime, and any pcap-compatible tool can consume them.

Supported capture modes:
  1. File mode  — writes to a static .pcap file
  2. FIFO mode  — writes to a Linux named pipe (mkfifo); Wireshark connects
                  with:  wireshark -k -i /tmp/gridsec_live.pcap

Frame construction:
  Each ICS packet is wrapped in genuine Ethernet + IPv4 + Transport headers
  so Wireshark dissectors trigger automatically.

  C37.118 (synchrophasor):  Ethernet + IPv4 + UDP  (dst port 4712)
  DNP3:                     Ethernet + IPv4 + UDP  (dst port 20000)
  Modbus/TCP:               Ethernet + IPv4 + TCP  (dst port 502)
  GOOSE (IEC 61850):        Raw Ethernet           (EtherType 0x88B8)

Wireshark usage:
  # Static file:
  wireshark /tmp/gridsec_capture.pcap

  # Live FIFO:
  wireshark -k -i /tmp/gridsec_live.pcap

Zeek usage:
  zeek -r /tmp/gridsec_capture.pcap local
"""

import os
import errno
import stat
import socket
import struct
import threading
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── libpcap constants ──────────────────────────────────────────────────────────

PCAP_MAGIC         = 0xA1B2C3D4    # little-endian pcap
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN       = 65535
PCAP_LINKTYPE_ETHERNET = 1         # Ethernet II

# Protocol numbers
IPPROTO_TCP = 6
IPPROTO_UDP = 17

# EtherTypes
ETH_TYPE_IPV4  = 0x0800
ETH_TYPE_GOOSE = 0x88B8

# Fake MAC addresses for constructed frames
MAC_SRC_PMU  = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x01])
MAC_SRC_PDC  = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x02])
MAC_DST_BC   = bytes([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF])
MAC_DST_MCAST_GOOSE = bytes([0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01])


# ── Checksum helpers ──────────────────────────────────────────────────────────

def _ip_checksum(header: bytes) -> int:
    """Compute RFC 791 IPv4 header checksum."""
    if len(header) % 2:
        header += b'\x00'
    total = 0
    for i in range(0, len(header), 2):
        total += (header[i] << 8) + header[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _udp_checksum(src_ip: bytes, dst_ip: bytes, udp_data: bytes) -> int:
    """Compute RFC 768 UDP checksum using pseudo-header."""
    pseudo = src_ip + dst_ip + bytes([0, IPPROTO_UDP]) + struct.pack('>H', len(udp_data))
    data = pseudo + udp_data
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    result = (~total) & 0xFFFF
    return result if result != 0 else 0xFFFF


# ── Frame builders ────────────────────────────────────────────────────────────

def build_ethernet_header(dst_mac: bytes, src_mac: bytes, ethertype: int) -> bytes:
    """Build a 14-byte Ethernet II header."""
    return dst_mac + src_mac + struct.pack('>H', ethertype)


def build_ipv4_header(src_ip: str, dst_ip: str, proto: int, payload_len: int,
                      pkt_id: int = 0) -> bytes:
    """Build a 20-byte IPv4 header (no options)."""
    src = bytes(int(x) for x in src_ip.split('.'))
    dst = bytes(int(x) for x in dst_ip.split('.'))
    total_len = 20 + payload_len
    # Build without checksum first
    hdr = struct.pack('>BBHHHBBH4s4s',
        0x45,        # version=4, IHL=5
        0x00,        # DSCP + ECN
        total_len,
        pkt_id & 0xFFFF,
        0x4000,      # Don't Fragment flag
        64,          # TTL
        proto,
        0,           # checksum placeholder
        src,
        dst,
    )
    chk = _ip_checksum(hdr)
    # Insert real checksum
    return hdr[:10] + struct.pack('>H', chk) + hdr[12:]


def build_udp_header(src_port: int, dst_port: int, payload: bytes,
                     src_ip: str, dst_ip: str) -> bytes:
    """Build an 8-byte UDP header with checksum."""
    length = 8 + len(payload)
    src    = bytes(int(x) for x in src_ip.split('.'))
    dst    = bytes(int(x) for x in dst_ip.split('.'))
    udp_no_chk = struct.pack('>HHHH', src_port, dst_port, length, 0) + payload
    chk = _udp_checksum(src, dst, udp_no_chk)
    return struct.pack('>HHHH', src_port, dst_port, length, chk)


def build_tcp_header(src_port: int, dst_port: int, seq: int = 1,
                     ack: int = 0, flags: int = 0x018) -> bytes:
    """
    Build a 20-byte TCP header (no options).
    flags: 0x002=SYN, 0x010=ACK, 0x018=PSH+ACK, 0x001=FIN
    """
    data_offset = 5   # 5 × 4 bytes = 20 bytes, no options
    return struct.pack('>HHIIHHHH',
        src_port,
        dst_port,
        seq,
        ack,
        (data_offset << 12) | flags,
        65535,    # window size
        0,        # filled using the IPv4 pseudo-header in build_tcp_packet
        0,        # urgent pointer
    )


def build_udp_packet(
    src_ip:   str,
    dst_ip:   str,
    src_port: int,
    dst_port: int,
    payload:  bytes,
    src_mac:  bytes = MAC_SRC_PMU,
    dst_mac:  bytes = MAC_DST_BC,
    pkt_id:   int   = 0,
) -> bytes:
    """Build complete Ethernet+IPv4+UDP frame."""
    udp_hdr = build_udp_header(src_port, dst_port, payload, src_ip, dst_ip)
    udp_pkt = udp_hdr + payload
    ip_hdr  = build_ipv4_header(src_ip, dst_ip, IPPROTO_UDP, len(udp_pkt), pkt_id)
    eth_hdr = build_ethernet_header(dst_mac, src_mac, ETH_TYPE_IPV4)
    return eth_hdr + ip_hdr + udp_pkt


def build_tcp_packet(
    src_ip:   str,
    dst_ip:   str,
    src_port: int,
    dst_port: int,
    payload:  bytes,
    seq:      int   = 1,
    flags:    int   = 0x018,   # PSH + ACK
    src_mac:  bytes = MAC_SRC_PMU,
    dst_mac:  bytes = MAC_SRC_PDC,
    pkt_id:   int   = 0,
) -> bytes:
    """Build complete Ethernet+IPv4+TCP frame."""
    tcp_hdr = build_tcp_header(src_port, dst_port, seq, flags=flags)
    tcp_pkt = tcp_hdr + payload
    pseudo = struct.pack(">4s4sBBH", socket.inet_aton(src_ip),
                         socket.inet_aton(dst_ip), 0, IPPROTO_TCP, len(tcp_pkt))
    checksum = _ip_checksum(pseudo + tcp_pkt)
    tcp_pkt = tcp_pkt[:16] + struct.pack(">H", checksum) + tcp_pkt[18:]
    ip_hdr  = build_ipv4_header(src_ip, dst_ip, IPPROTO_TCP, len(tcp_pkt), pkt_id)
    eth_hdr = build_ethernet_header(dst_mac, src_mac, ETH_TYPE_IPV4)
    return eth_hdr + ip_hdr + tcp_pkt


# ── pcap writer ───────────────────────────────────────────────────────────────

class PcapWriter:
    """
    Thread-safe libpcap file writer.

    Usage:
        writer = PcapWriter("/tmp/gridsec.pcap")
        writer.write_udp("10.0.0.1", "10.0.0.2", 49000, 4712, payload_bytes)
        writer.close()

    Named pipe (live Wireshark):
        writer = PcapWriter("/tmp/gridsec_live.pcap", use_fifo=True)
        # In another terminal: wireshark -k -i /tmp/gridsec_live.pcap
    """

    def __init__(self, path: str, use_fifo: bool = False):
        self._path      = path
        self._use_fifo  = use_fifo
        self._lock      = threading.Lock()
        self._file      = None
        self._pkt_id    = 0
        self._pkt_count = 0
        self._error     = ""
        self._active    = False
        self._closed = threading.Event()
        self._fifo_thread = None
        self._owns_fifo = False

        self._open()

    def _open(self) -> None:
        try:
            parent = os.path.dirname(os.path.abspath(self._path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            if self._use_fifo:
                if not hasattr(os, "mkfifo"):
                    raise OSError("Live FIFO capture requires Linux/WSL; use a PCAP file on Windows")
                if os.path.lexists(self._path):
                    if not stat.S_ISFIFO(os.lstat(self._path).st_mode):
                        raise OSError("Refusing to replace an existing file with a FIFO")
                else:
                    os.mkfifo(self._path, 0o600)
                    self._owns_fifo = True
                logger.info(f"pcap: FIFO created at {self._path}")
                logger.info(f"pcap: Run: wireshark -k -i {self._path}")
                # Open in a thread to avoid blocking (open blocks until reader connects)
                self._file = None
                self._fifo_thread = threading.Thread(target=self._open_fifo, daemon=True)
                self._fifo_thread.start()
            else:
                self._file = open(self._path, 'wb')
                self._write_global_header()
                self._active = True
                logger.info(f"pcap: Writing to {self._path}")
        except Exception as e:
            self._error = str(e)
            logger.error(f"pcap: Failed to open {self._path}: {e}")

    def _open_fifo(self) -> None:
        """Wait for a reader without leaving an uninterruptible worker behind."""
        try:
            logger.info(f"pcap: Waiting for Wireshark to connect to {self._path}...")
            while not self._closed.is_set():
                try:
                    fd = os.open(self._path, os.O_WRONLY | os.O_NONBLOCK)
                    break
                except OSError as exc:
                    if exc.errno != errno.ENXIO:
                        raise
                    self._closed.wait(0.1)
            else:
                return
            with self._lock:
                if self._closed.is_set():
                    os.close(fd)
                    return
                self._file = os.fdopen(fd, 'wb', buffering=0)
                self._write_global_header()
                self._active = True
            logger.info(f"pcap: Wireshark connected to FIFO")
        except Exception as e:
            self._error = str(e)
            logger.error(f"pcap: FIFO open error: {e}")

    def _write_global_header(self) -> None:
        """Write the 24-byte pcap global header."""
        hdr = struct.pack('<IHHiIII',
            PCAP_MAGIC,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,              # thiszone (GMT offset)
            0,              # sigfigs
            PCAP_SNAPLEN,
            PCAP_LINKTYPE_ETHERNET,
        )
        self._file.write(hdr)
        self._file.flush()

    def _write_packet(self, raw_frame: bytes, ts: Optional[float] = None) -> None:
        """Write one pcap packet record (header + data)."""
        if self._file is None or not self._active:
            return
        if ts is None:
            ts = time.time()

        ts_sec  = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        caplen  = min(len(raw_frame), PCAP_SNAPLEN)

        rec_hdr = struct.pack('<IIII', ts_sec, ts_usec, caplen, len(raw_frame))
        try:
            with self._lock:
                if self._closed.is_set() or not self._file:
                    return
                blob = rec_hdr + raw_frame[:caplen]
                if self._file.write(blob) != len(blob):
                    raise OSError("Capture writer could not write a complete packet")
                self._file.flush()
                self._pkt_count += 1
        except BrokenPipeError:
            self._active = False
            logger.info("pcap: Reader disconnected (BrokenPipe)")
        except Exception as e:
            self._error = str(e)
            self._active = False
            logger.debug(f"pcap write error: {e}")

    # ── Public write methods ──────────────────────────────────────────────────

    def write_udp(
        self,
        src_ip:   str,
        dst_ip:   str,
        src_port: int,
        dst_port: int,
        payload:  bytes,
        ts:       Optional[float] = None,
        src_mac:  bytes = MAC_SRC_PMU,
        dst_mac:  bytes = MAC_DST_BC,
    ) -> None:
        """Write a UDP packet wrapped in Ethernet+IPv4 headers."""
        self._pkt_id = (self._pkt_id + 1) & 0xFFFF
        frame = build_udp_packet(src_ip, dst_ip, src_port, dst_port,
                                  payload, src_mac, dst_mac, self._pkt_id)
        self._write_packet(frame, ts)

    def write_tcp(
        self,
        src_ip:   str,
        dst_ip:   str,
        src_port: int,
        dst_port: int,
        payload:  bytes,
        ts:       Optional[float] = None,
        seq:      int = 1,
        flags:    int = 0x018,
        src_mac:  bytes = MAC_SRC_PMU,
        dst_mac:  bytes = MAC_SRC_PDC,
    ) -> None:
        """Write a TCP packet wrapped in Ethernet+IPv4 headers."""
        self._pkt_id = (self._pkt_id + 1) & 0xFFFF
        frame = build_tcp_packet(src_ip, dst_ip, src_port, dst_port,
                                  payload, seq, flags, src_mac, dst_mac, self._pkt_id)
        self._write_packet(frame, ts)

    def write_ethernet(self, raw_eth_frame: bytes, ts: Optional[float] = None) -> None:
        """Write a pre-built raw Ethernet frame (e.g. GOOSE)."""
        self._write_packet(raw_eth_frame, ts)

    def write_c37118(self, payload: bytes,
                     src_ip: str = "10.0.0.1",
                     dst_ip: str = "10.0.0.2",
                     ts: Optional[float] = None) -> None:
        """Write a C37.118 packet (UDP/4712)."""
        self.write_udp(src_ip, dst_ip, 49000, 4712, payload, ts)

    def write_dnp3(self, payload: bytes,
                   src_ip: str = "10.0.0.1",
                   dst_ip: str = "10.0.0.3",
                   ts: Optional[float] = None) -> None:
        """Write a DNP3 packet (UDP/20000)."""
        self.write_udp(src_ip, dst_ip, 20001, 20000, payload, ts)

    def write_modbus(self, payload: bytes,
                     src_ip: str = "10.0.0.3",
                     dst_ip: str = "10.0.0.1",
                     ts: Optional[float] = None,
                     seq: int = 1) -> None:
        """Write a Modbus/TCP packet (TCP/502)."""
        self.write_tcp(src_ip, dst_ip, 50002, 502, payload, ts, seq=seq)

    def write_goose(self, raw_frame: bytes, ts: Optional[float] = None) -> None:
        """Write a raw GOOSE Ethernet frame."""
        self.write_ethernet(raw_frame, ts)

    # ── Status / control ──────────────────────────────────────────────────────

    @property
    def packet_count(self) -> int:
        return self._pkt_count

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def error(self) -> str:
        return self._error

    @property
    def path(self) -> str:
        return self._path

    def close(self) -> None:
        """Flush and close the pcap file/FIFO."""
        self._closed.set()
        self._active = False
        if self._fifo_thread:
            self._fifo_thread.join(timeout=1)
        with self._lock:
            if self._file:
                try:
                    self._file.flush()
                    self._file.close()
                except Exception:
                    pass
                self._file = None
        if self._owns_fifo and os.path.exists(self._path) and stat.S_ISFIFO(os.lstat(self._path).st_mode):
            try:
                os.remove(self._path)
            except Exception:
                pass
        logger.info(f"pcap: Closed ({self._pkt_count} packets written)")


# ── Self-test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import tempfile
    print("PcapWriter self-test")
    print("=" * 50)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        path = f.name

    writer = PcapWriter(path)
    assert writer.is_active, "Writer not active"

    # Write test packets
    writer.write_udp("10.0.0.1", "10.0.0.2", 49000, 4712, b"TEST_C37.118_DATA_123456789")
    writer.write_udp("10.0.0.1", "10.0.0.3", 20001, 20000, b"\x05\x64TEST_DNP3_FRAME")
    writer.write_tcp("10.0.0.3", "10.0.0.1", 50002, 502, b"\x00\x01\x00\x00\x00\x06\x01\x04\x00\x00\x00\x0a")

    writer.close()

    # Verify pcap file
    with open(path, 'rb') as f:
        data = f.read()

    assert len(data) > 24, "File too small"
    magic = struct.unpack('<I', data[:4])[0]
    assert magic == PCAP_MAGIC, f"Bad magic: {magic:#010x}"
    linktype = struct.unpack('<I', data[20:24])[0]
    assert linktype == PCAP_LINKTYPE_ETHERNET, f"Bad linktype: {linktype}"
    print(f"File size: {len(data)} bytes")
    print(f"Magic: 0x{magic:08X} ✔")
    print(f"Link type: {linktype} (Ethernet) ✔")
    print(f"Packets: {writer.packet_count} ✔")

    os.unlink(path)
    print("\nPcapWriter ALL TESTS PASSED ✔")
