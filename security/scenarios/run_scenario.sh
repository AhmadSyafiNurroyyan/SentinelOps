#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "Pemakaian: $0 <nama_skenario> -- <command...>"
  exit 1
fi

SCENARIO_NAME="$1"
shift
if [ "${1:-}" == "--" ]; then
  shift
fi

LOG_FILE="scenario_log.csv"
if [ ! -f "$LOG_FILE" ]; then
  echo "scenario,start_utc,end_utc,command,exit_code" > "$LOG_FILE"
fi

START=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
echo "[run_scenario] Mulai '$SCENARIO_NAME' pada $START (UTC)"
echo "[run_scenario] Command: $*"
echo "----------------------------------------"

set +e
"$@"
EXIT_CODE=$?
set -e

END=$(date -u +"%Y-%m-%dT%H:%M:%S%z")
echo "----------------------------------------"
echo "[run_scenario] Selesai pada $END (UTC), exit code $EXIT_CODE"

CMD_ESCAPED=$(printf '%s' "$*" | sed 's/"/""/g')
echo "\"$SCENARIO_NAME\",\"$START\",\"$END\",\"$CMD_ESCAPED\",\"$EXIT_CODE\"" >> "$LOG_FILE"

echo "[run_scenario] Tercatat di $LOG_FILE"
