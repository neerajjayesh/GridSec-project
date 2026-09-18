#!/usr/bin/env bash
# Sourced from a script that has already changed into the project directory.
# The interpreter can live elsewhere; application source always comes from here.
if [[ -z "${GRIDSEC_PYTHON:-}" ]]; then
    for candidate in "$PWD/.venv/bin/python" "$PWD/venv/bin/python" "$HOME/GridSecSim/venv/bin/python" python3; do
        if "$candidate" -c 'from PyQt6.QtWidgets import QApplication; import matplotlib, numpy' >/dev/null 2>&1; then
            GRIDSEC_PYTHON="$candidate"
            break
        fi
    done
fi
if [[ -z "${GRIDSEC_PYTHON:-}" ]]; then
    echo "No working Qt Python environment found. Run install.sh or set GRIDSEC_PYTHON." >&2
    exit 1
fi
export GRIDSEC_PYTHON
