#!/usr/bin/env bash
# ZERO CyberSec Deck - keyboard-driven, scope-gated terminal dashboard.
#   bash zero-deck.sh            interactive dashboard
#   bash zero-deck.sh --check    dependency report (exit 1 if a core dependency is missing)
#   bash zero-deck.sh --plain    numbered menus instead of raw keyboard mode
set -uo pipefail
ZD_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
export ZD_ROOT

case "${1:-}" in
  -h | --help) sed -n '2,5p' "${BASH_SOURCE[0]}"; exit 0 ;;
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
  --check) deps_report; exit $? ;;
  --version) say "ZERO Deck $ZD_VERSION"; exit 0 ;;
esac
ui_main
