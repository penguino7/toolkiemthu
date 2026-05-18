#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON_BIN="python3"
if [[ -x ".venv/bin/python" ]]; then
  PYTHON_BIN=".venv/bin/python"
else
  echo "[*] Creating virtualenv .venv"
  if python3 -m venv .venv; then
    PYTHON_BIN=".venv/bin/python"
  else
    echo "[!] Could not create .venv; falling back to system python3"
    PYTHON_BIN="python3"
  fi
fi

export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8

exec "$PYTHON_BIN" -B -m toolcli "$@"

