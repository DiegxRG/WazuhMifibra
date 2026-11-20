#!/bin/bash
set -euo pipefail
umask 077

PROJECT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_DIR"
RUNTIME="$PROJECT_DIR/runtime/wazuh"
mkdir -p "$RUNTIME"
exec >> "$RUNTIME/cron.log" 2>&1

PYTHON=/usr/bin/python3
if [[ -x "$PROJECT_DIR/.venv/bin/python" ]]; then
    PYTHON="$PROJECT_DIR/.venv/bin/python"
fi

printf '\n[%s] Wazuh semanal iniciado\n' "$(date -Iseconds)"
if /usr/bin/flock -w 300 -E 75 "$RUNTIME/weekly.lock" "$PYTHON" -B - <<'PY'
from pathlib import Path

from wazuh_pull.cli import main
from wazuh_pull.config import load_settings

env_file = Path(".env")
if not load_settings(env_file).backend_enabled:
    print("Envío semanal omitido: BACKEND_ENABLED=false", flush=True)
    raise SystemExit(0)

raise SystemExit(main(["--env-file", str(env_file), "--once"]))
PY
then
    printf '[%s] Wazuh semanal terminó con exit=0\n' "$(date -Iseconds)"
else
    status=$?
    if (( status == 75 )); then
        printf '[%s] Wazuh semanal alcanzó el límite de espera del bloqueo\n' "$(date -Iseconds)"
    fi
    printf '[%s] Wazuh semanal terminó con exit=%s\n' "$(date -Iseconds)" "$status"
    exit "$status"
fi
