#!/usr/bin/env bash
# Full local verification: shell syntax, optional shellcheck, Python + shell + PowerShell tests, dependency report.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$(command -v python3 || command -v python || true)"
[ -n "$PYTHON" ] || { echo 'Python 3.8+ is required.' >&2; exit 1; }

scripts=("$ROOT/zero-deck.sh" "$ROOT/setup-kali.sh" "$ROOT/scripts/test-deck.sh" "$ROOT"/lib/*.sh "$ROOT"/modules/*.sh)
for s in "${scripts[@]}"; do bash -n "$s"; done
echo "bash -n: ${#scripts[@]} scripts OK"

if command -v shellcheck >/dev/null 2>&1; then shellcheck -x "${scripts[@]}"; echo 'shellcheck: OK'
else echo 'shellcheck not installed: skipped (optional)'; fi

"$PYTHON" -B -I -m unittest discover -s "$ROOT/tests" -v
bash "$ROOT/zero-deck.sh" --check || true
printf '\nAll local tests completed. Physical USB boot compatibility is NOT tested by this script.\n'
