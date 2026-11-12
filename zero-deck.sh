#!/usr/bin/env bash
# ZERO CyberSec Deck - keyboard-driven, scope-gated terminal dashboard.
#   bash zero-deck.sh              interactive dashboard
#   bash zero-deck.sh --check      dependency + data-folder + filesystem report (exit 1 if a core dependency, the data folder or safe publishing is unavailable)
#   bash zero-deck.sh --init-data  create/complete the separate data folder (ZERO-DATA); probes the filesystem first; never overwrites or deletes anything
#   bash zero-deck.sh --plain      numbered menus instead of raw keyboard mode
# The application folder holds code only. Results, notes, evidence, your scope file and the audit log live in the data folder.
set -uo pipefail
ZD_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export ZD_ROOT

case "${1:-}" in
  -h | --help) sed -n '2,8p' "${BASH_SOURCE[0]}"; exit 0 ;;
  --plain) export ZD_PLAIN=1 ;;
esac

# shellcheck source=lib/common.sh
source "$ZD_ROOT/lib/common.sh"
# shellcheck source=lib/ui.sh
source "$ZD_ROOT/lib/ui.sh"
for _m in "$ZD_ROOT"/modules/*.sh; do
  # shellcheck source=/dev/null
  source "$_m"
done

case "${1:-}" in
  --check) deps_report; rc=$?; data_status; [ "$DATA_READY" = 1 ] || rc=1; [ "${PUBLISH_OK:-0}" = 1 ] || rc=1; exit "$rc" ;;
  --init-data)
    [ -n "$PY" ] || { say 'Python 3.8+ is required.'; exit 1; }
    "$PY" "$ZD_ROOT/scripts/datadir.py" init --data "$DATA" --app "$ZD_ROOT"; exit $? ;;
  --version) say "ZERO Deck $ZD_VERSION"; exit 0 ;;
esac
ui_main
