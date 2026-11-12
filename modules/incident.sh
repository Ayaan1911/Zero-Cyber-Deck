# shellcheck shell=bash
# Incident response: read-only local triage, audit review, Markdown reports.

snap() { # snap <file> <command...>: append command output, tolerate missing tools
  local f="$1"; shift
  if command -v "$1" >/dev/null 2>&1; then { printf '$ %s\n' "$*"; "$@" 2>&1; printf '\n'; } >>"$f"
  else printf '(not available: %s)\n\n' "$1" >>"$f"; fi
}

triage_linux() {
  local d; d="$RESULTS/triage_$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$d" || { say 'Cannot create triage folder.'; return 0; }
  say "Read-only triage into $d (no changes are made to this system)."
  snap "$d/system.txt" date -u; snap "$d/system.txt" uname -a; snap "$d/system.txt" uptime; snap "$d/system.txt" id
  snap "$d/users.txt" who; snap "$d/users.txt" last -n 30; snap "$d/users.txt" getent passwd
  snap "$d/processes.txt" ps auxww
  snap "$d/network.txt" ip -brief address; snap "$d/network.txt" ip route; snap "$d/network.txt" ip neigh; snap "$d/network.txt" ss -tunap
  snap "$d/persistence.txt" crontab -l; snap "$d/persistence.txt" ls -la /etc/cron.d /etc/cron.daily
  snap "$d/persistence.txt" systemctl list-timers --all --no-pager
  snap "$d/persistence.txt" systemctl list-units --type=service --state=running --no-pager
  snap "$d/files.txt" find /tmp /var/tmp -maxdepth 2 -type f -mtime -3 -ls
  snap "$d/system.txt" lsmod; snap "$d/system.txt" mount
  "$PY" "$ROOT/scripts/evidence.py" manifest "$d" "$d/MANIFEST.sha256"
  audit triage_linux local local RUN "triage saved to $d"
  say 'Process lists and sockets may reveal secrets/command lines: treat the folder as sensitive. Run as root for full socket owners.'
}

make_report() {
  local title op
  read -r -p 'Report title [ZERO Deck session report]: ' title
  read -r -p 'Operator name: ' op
  "$PY" "$ROOT/scripts/report.py" --results "$RESULTS" --scope "$SCOPE" --title "${title:-ZERO Deck session report}" --operator "${op:-unspecified}"
}

view_audit() {
  [ -s "$RESULTS/audit.log" ] || { say 'Audit log is empty.'; return 0; }
  say 'time | user | action | kind | target | verdict | scope-hash | detail'
  tail -n 40 "$RESULTS/audit.log" | tr '\t' '|'
}

ir_checklist() { show_doc "$ROOT/docs/IR-CHECKLIST.md"; }

reg "Incident Response" "Local triage snapshot (read-only, hashed)" triage_linux "python3"
reg "Incident Response" "Generate Markdown session report" make_report "python3"
reg "Incident Response" "View audit log" view_audit ""
reg "Incident Response" "Incident-response checklist" ir_checklist ""
