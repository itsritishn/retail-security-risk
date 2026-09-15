#!/usr/bin/env bash
#
# SentinelFloor developer helper.
#
#   ./scripts/dev.sh setup     create the venv and install core dependencies
#   ./scripts/dev.sh seed      create the demo store, users, cameras, and fobs
#   ./scripts/dev.sh test      run the test suite
#   ./scripts/dev.sh serve     start the core service on 127.0.0.1:8000
#   ./scripts/dev.sh demo      replay a synthetic shift through the pipeline
#   ./scripts/dev.sh duress    simulate a duress fob activation
#   ./scripts/dev.sh reset     delete the local database and start over
#   ./scripts/dev.sh check     verify the install without starting anything
#
# Quoted throughout: the project directory contains a space, and unquoted paths would
# silently break in ways that take twenty minutes to diagnose.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

cd "${ROOT_DIR}"

info()  { printf '\033[0;36m==>\033[0m %s\n' "$*"; }
warn()  { printf '\033[0;33m!!\033[0m %s\n' "$*"; }
fail()  { printf '\033[0;31mxx\033[0m %s\n' "$*" >&2; exit 1; }

ensure_venv() {
  if [[ ! -d "${VENV_DIR}" ]]; then
    fail "No virtualenv found. Run: ./scripts/dev.sh setup"
  fi
}

activate() {
  ensure_venv
  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"
}

cmd_setup() {
  info "Creating virtualenv at ${VENV_DIR}"
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"

  # shellcheck disable=SC1091
  source "${VENV_DIR}/bin/activate"

  info "Upgrading pip"
  python -m pip install --quiet --upgrade pip

  info "Installing core dependencies"
  python -m pip install --quiet -r requirements.txt

  if [[ ! -f "${ROOT_DIR}/.env" ]]; then
    info "Creating .env from .env.example with a generated secret key"
    cp "${ROOT_DIR}/.env.example" "${ROOT_DIR}/.env"
    SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
    # Portable in-place edit: BSD sed on macOS and GNU sed disagree about -i.
    python - "$SECRET" <<'PYTHON'
import pathlib
import sys

secret = sys.argv[1]
path = pathlib.Path(".env")
text = path.read_text(encoding="utf-8")
text = text.replace(
    "SENTINEL_SECRET_KEY=CHANGE_ME_dev_only_do_not_use_in_production",
    f"SENTINEL_SECRET_KEY={secret}",
)
path.write_text(text, encoding="utf-8")
print("  .env written with a unique secret key")
PYTHON
    chmod 600 "${ROOT_DIR}/.env"
  else
    info ".env already exists, leaving it alone"
  fi

  info "Done. Next: ./scripts/dev.sh seed"
}

cmd_seed() {
  activate
  python -m core.seed
}

cmd_test() {
  activate
  info "Running the test suite"
  python -m pytest -q "$@"
}

cmd_serve() {
  activate
  info "Starting on http://127.0.0.1:8000  (Ctrl-C to stop)"
  exec python -m uvicorn core.main:app --host 127.0.0.1 --port 8000 --reload
}

cmd_demo() {
  activate
  shift || true
  python -m scripts.demo_replay "$@"
}

cmd_duress() {
  activate
  shift || true
  python -m scripts.duress_fob_sim "$@"
}

cmd_check() {
  activate
  info "Verifying imports"
  python - <<'PYTHON'
import importlib

modules = [
    "core.main", "core.models", "core.policy", "core.security", "core.audit",
    "core.duress", "core.alerting", "core.retention", "core.seed",
    "edge.pipeline", "edge.features", "edge.scoring", "edge.privacy",
    "edge.tracking", "edge.publisher", "edge.backends.synthetic",
    "analytics.metrics", "analytics.shrink",
]
for name in modules:
    importlib.import_module(name)
    print(f"  ok  {name}")
print("\nAll modules import cleanly.")
PYTHON
}

cmd_reset() {
  warn "This deletes the local database and generated secrets."
  read -r -p "Type 'yes' to continue: " confirm
  [[ "${confirm}" == "yes" ]] || fail "Aborted"
  rm -f "${ROOT_DIR}/sentinelfloor.db" "${ROOT_DIR}/sentinelfloor.db-wal" "${ROOT_DIR}/sentinelfloor.db-shm"
  rm -rf "${ROOT_DIR}/secrets"
  info "Reset. Run ./scripts/dev.sh seed to rebuild."
}

case "${1:-help}" in
  setup)  cmd_setup ;;
  seed)   cmd_seed ;;
  test)   shift; cmd_test "$@" ;;
  serve)  cmd_serve ;;
  demo)   cmd_demo "$@" ;;
  duress) cmd_duress "$@" ;;
  check)  cmd_check ;;
  reset)  cmd_reset ;;
  *)
    sed -n '3,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    ;;
esac
