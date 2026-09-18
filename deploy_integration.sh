#!/usr/bin/env bash
# Legacy entry point, retained safely. Integrations are no longer patched in WSL.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ./scripts/python-runtime.sh
export QT_QPA_PLATFORM=offscreen
exec "$GRIDSEC_PYTHON" -m unittest discover -s tests -v
