#!/usr/bin/env bash
# Legacy entry point, retained safely. Run this checkout directly in WSL.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
echo "No source files will be overwritten; testing the current checkout."
exec bash ./test_all.sh
