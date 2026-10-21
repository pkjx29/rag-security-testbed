#!/usr/bin/env bash
# One command: set up the environment, build the index, run all attacks x defences.
#   ./run_all.sh            full run (~45 min the first time on an M1, seconds when cached)
#   ./run_all.sh --quick    smoke test on a subset of every suite
# Needs: macOS on Apple silicon (MLX), Python 3.10+, ~3 GB free disk.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x .venv/bin/python ]; then
  python3 -m venv .venv
  .venv/bin/pip install --upgrade pip
  .venv/bin/pip install -r requirements.txt
fi

PYTHONPATH=src .venv/bin/python -m pytest -q tests
PYTHONPATH=src .venv/bin/python -m testbed.run "$@"
