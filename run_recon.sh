#!/usr/bin/env bash
set -euo pipefail

BASE_URL="http://127.0.0.1:8080"
OUTPUT_DIR="recon-output"
CONFIG_FILE="config.example.json"
DYNAMIC=0
INSTALL_PLAYWRIGHT=0
EXTRA_ARGS=()

usage() {
  cat <<'EOF'
Usage:
  ./run_recon.sh [base_url] [options]

Examples:
  ./run_recon.sh
  ./run_recon.sh http://127.0.0.1:8080
  ./run_recon.sh http://127.0.0.1:8080 --dynamic
  ./run_recon.sh http://127.0.0.1:8080 --dynamic --install-playwright
  ./run_recon.sh http://127.0.0.1:8080 --out recon-newshub

Options:
  --dynamic              Bat Playwright dynamic crawler.
  --install-playwright   Tu cai Python package va Chromium cho Playwright.
  --out DIR              Thu muc output.
  --config FILE          File config JSON.
  --no-static            Tat static crawler.
  --help                 Hien huong dan.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dynamic)
      DYNAMIC=1
      shift
      ;;
    --install-playwright)
      INSTALL_PLAYWRIGHT=1
      shift
      ;;
    --out)
      OUTPUT_DIR="${2:?Missing value for --out}"
      shift 2
      ;;
    --config)
      CONFIG_FILE="${2:?Missing value for --config}"
      shift 2
      ;;
    --no-static)
      EXTRA_ARGS+=("--no-static")
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    http://*|https://*)
      BASE_URL="$1"
      shift
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

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

if [[ "$INSTALL_PLAYWRIGHT" -eq 1 ]]; then
  echo "[*] Installing optional Playwright dependency"
  "$PYTHON_BIN" -m pip install --upgrade pip
  "$PYTHON_BIN" -m pip install -r requirements.txt
  "$PYTHON_BIN" -m playwright install chromium
fi

CMD=("$PYTHON_BIN" -B -m recontool -c "$CONFIG_FILE" --base-url "$BASE_URL" --out "$OUTPUT_DIR")

if [[ "$DYNAMIC" -eq 1 ]]; then
  CMD+=("--dynamic")
fi

CMD+=("${EXTRA_ARGS[@]}")

echo "[*] Running: ${CMD[*]}"
"${CMD[@]}"

echo
echo "[+] Done"
echo "[+] JSON:     $OUTPUT_DIR/inventory.json"
echo "[+] Markdown: $OUTPUT_DIR/inventory.md"
echo "[+] Params:   $OUTPUT_DIR/params.txt"
echo "[+] Plan:     $OUTPUT_DIR/test_plan.md"
