"""Offline C37.118 transformation example. Run from any directory.

python docs/examples/inspect_frame.py
python docs/examples/inspect_frame.py --pcap sample-frame.pcap

No network sockets are opened. Optional capture output contains synthesized
Ethernet/IP/UDP headers, not packets observed on a network interface.
"""

import argparse
import math
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from core.attack_engine import AttackEngine, AttackType
from core.packet_parser import parse_frame, rebuild_frame, set_codec
from core.pcap_writer import PcapWriter
from protocols.c37118 import C37118Codec


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--pcap', type=Path, help='Create a new sample PCAP file')
    args = parser.parse_args()
    if args.pcap and args.pcap.exists():
        parser.error('Capture path already exists; choose a new output filename.')

    # Explicitly align parser/generator counts, including the digital word.
    codec = C37118Codec(idcode=1, num_phasors=3, num_analog=1, num_digital=1)
    set_codec(codec)
    original_raw = codec.encode_data_frame(
        phasors=[(120.0, 0.0), (119.5, -2 * math.pi / 3),
                 (120.5, 2 * math.pi / 3)],
        freq=50.0, dfreq=0.0, analog=[500.0], digital=[0xA5A5],
        soc=1700000000, fracsec=0,
    )
    original = parse_frame(original_raw)
    assert original is not None and original['frame_type'] == 'data'

    engine = AttackEngine()
    engine.set_attack(AttackType.SCALE, {'scale_factor': 2.0})
    modified, changed, dropped = engine.apply(original)
    modified_raw = rebuild_frame(modified)
    decoded = codec.decode_data_frame(modified_raw)

    assert changed and not dropped
    assert decoded is not None, 'Rebuilt frame must decode with a valid CRC'
    assert len(original_raw) == len(modified_raw) == 56
    assert math.isclose(decoded.phasors[0][0], 240.0)
    assert math.isclose(decoded.freq, 50.0)
    assert decoded.digital == [0xA5A5], 'Digital word must survive rebuilding'
    assert decoded.soc == 1700000000
    print('PASS: 56-byte frame; Va 120.0 -> 240.0 V; frequency, time, digital word preserved.')

    if args.pcap:
        writer = PcapWriter(str(args.pcap.resolve()))
        try:
            if not writer.is_active:
                raise RuntimeError(writer.error or 'PCAP writer did not become active')
            for offset, payload in enumerate((original_raw, modified_raw)):
                writer.write_udp('192.0.2.1', '192.0.2.2', 49000, 4712,
                                 payload, ts=1700000000.0 + offset)
            assert writer.packet_count == 2
        finally:
            writer.close()
        print(f'Created two-packet sample: {args.pcap.resolve()}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
