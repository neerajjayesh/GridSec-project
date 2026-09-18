#!/usr/bin/env bash
# Tests the current checkout; never copies an old source tree over it.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ./scripts/python-runtime.sh
export QT_QPA_PLATFORM=offscreen
"$GRIDSEC_PYTHON" -m unittest discover -s tests -p test_gui_workflows.py -v
