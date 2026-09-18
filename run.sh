#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
source ./scripts/python-runtime.sh
if [[ "${QT_QPA_PLATFORM:-}" == "offscreen" || "${QT_QPA_PLATFORM:-}" == "minimal" ]]; then
    echo "Refusing an invisible desktop launch. Unset QT_QPA_PLATFORM and use a WSLg session." >&2
    exit 1
fi
echo "Starting GridSec from $PWD using $GRIDSEC_PYTHON"
exec "$GRIDSEC_PYTHON" main.py "$@"
