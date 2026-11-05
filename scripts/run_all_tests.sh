#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${ROOT}/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
    PYTHON="python3"
fi

echo "=========================================================="
echo "  Running Full Test Suite with $PYTHON"
echo "=========================================================="
"$PYTHON" -m unittest discover -s "${ROOT}/tests" -v

