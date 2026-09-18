"""Serve one synthetic GridSec incident on loopback; no protocol simulators.

python docs/examples/serve_api.py
python docs/examples/serve_api.py --port 18081 --duration 10

The printed token grants access to this example server. Remote attack hooks
are deliberately unset. Disconnect SSE clients before shutting the server down.
"""

import argparse
from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from core.integration_manager import IntegrationManager
from core.pdc_proxy import PacketRecord


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=18080)
    parser.add_argument('--duration', type=float, default=0,
                        help='Exit after N seconds; zero waits for Ctrl+C')
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error('Choose an unprivileged port from 1024 through 65535.')
    if args.duration < 0:
        parser.error('Duration must be nonnegative.')

    manager = IntegrationManager()
    manager.record_packet(
        PacketRecord(
            timestamp=time.time(),
            original={'frame_type': 'data', 'freq': 50.0, 'phasors': [[120.0, 0.0]]},
            modified={'frame_type': 'data', 'freq': 50.0, 'phasors': [[240.0, 0.0]]},
            status='attacked', attack_type='SCALE',
            description='Synthetic documentation example',
        ),
        protocol='C37.118', src_ip='192.0.2.1', dst_ip='192.0.2.2',
    )
    manager.configure_rest_api(host='127.0.0.1', port=args.port)
    result = manager.start()
    if not result.get('rest_api', '').startswith('listening on port '):
        manager.stop()
        print(f'Server failed to start: {result}', file=sys.stderr)
        return 1

    try:
        print(f'URL: http://127.0.0.1:{args.port}/api/v1/status', flush=True)
        print(f'Bearer token: {manager.api_key}', flush=True)
        print('One synthetic incident; simulation stopped; attack hooks unset. Ctrl+C to exit.', flush=True)
        deadline = time.monotonic() + args.duration if args.duration else None
        while deadline is None or time.monotonic() < deadline:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        manager.stop()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
