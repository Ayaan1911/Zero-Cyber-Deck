# shellcheck shell=bash
# Utilities: dependency check, scope management, self-test.

deps_report() { # returns non-zero when a core dependency is missing
  local t core_missing=0
  for t in bash python3 nmap dig curl openssl timeout tshark wireshark burpsuite msfconsole smartctl lsblk testdisk file; do
    if have "$t"; then printf '[ok]      %-11s\n' "$t"
    else
      printf '[missing] %-11s -> %s\n' "$t" "$(hint "$t")"
      case "$t" in bash | python3) core_missing=1 ;; esac
    fi
  done
  [ "$core_missing" = 0 ] || say 'Core dependency missing: the deck cannot run scope-gated actions.'
  return "$core_missing"
}

show_scope() {
  say "Scope file: $SCOPE"
  "$PY" "$ROOT/scripts/scope_guard.py" "$SCOPE" validate || say 'Fix config/scope.txt before using gated actions.'
  grep -v '^[[:space:]]*\(#\|$\)' "$SCOPE" 2>/dev/null || say '(no entries)'
}

self_test() { bash "$ROOT/scripts/test-deck.sh"; }

reg "Utilities" "Check installed tools + install hints" deps_report ""
reg "Utilities" "Show + validate authorized scope" show_scope "python3"
reg "Utilities" "Run built-in self-tests" self_test "python3"
