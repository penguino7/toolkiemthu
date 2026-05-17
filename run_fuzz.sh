#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ $# -lt 1 ]]; then
  cat <<'EOF'
Usage:
  bash run_fuzz.sh INVENTORY_JSON [options]

Examples:
  bash run_fuzz.sh recon-output/inventory.json --xss
  bash run_fuzz.sh recon-output/inventory.json --sqli
  bash run_fuzz.sh recon-output/inventory.json --xss --sqli
  bash run_fuzz.sh recon-output/inventory.json --xss --dry-run
EOF
  exit 2
fi

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

CMD=("$PYTHON_BIN" -B -m fuzztool "$@")
echo "[*] Running: ${CMD[*]}"
"${CMD[@]}"
