# shellcheck shell=bash
# ZERO Deck shared library: environment, registry, scope gate, logging. Source only; never run directly.

ZD_VERSION="3.0.0"
ROOT="${ZD_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
export PYTHONDONTWRITEBYTECODE=1   # never write __pycache__ into the application folder (it must match SHA256SUMS.txt)
umask 077

# ---- application folder (ROOT) vs data folder (DATA) -----------------------------------------------------------------
# ROOT holds code only and must match the release manifest. DATA (default: sibling folder ZERO-DATA, or $ZD_DATA) holds
# results, notes, evidence, the operator's scope file and the audit log. The data folder is NEVER created implicitly:
# run `bash zero-deck.sh --init-data` once. Nothing in ROOT is ever written by the deck.
DATA="${ZD_DATA:-$(cd -- "$ROOT/.." && pwd)/ZERO-DATA}"
RESULTS="${ZD_RESULTS:-$DATA/results}"
NOTES="${ZD_NOTES:-$DATA/notes}"
EVIDENCE="${ZD_EVIDENCE:-$DATA/evidence}"
if [ -n "${ZD_SCOPE:-}" ]; then SCOPE="$ZD_SCOPE"
elif [ -f "$DATA/config/scope.local.txt" ]; then SCOPE="$DATA/config/scope.local.txt"  # operator-owned, outside the app folder
else SCOPE="$ROOT/config/scope.txt"; fi                                                  # the empty release template: everything is denied

PY=""
for _c in python3 python py; do
  if command -v "$_c" >/dev/null 2>&1 && "$_c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    PY="$_c"; break
  fi
done
unset _c

# DATA_READY=1 only if the data folder exists, is marked as a ZERO data folder and is compatible with this application.
# Everything that writes (audit log, results, notes, evidence) refuses to run otherwise.
DATA_READY=0
DATA_MSG="Python 3.8+ is required"
if [ -n "$PY" ]; then
  if DATA_MSG="$("$PY" "$ROOT/scripts/datadir.py" check --data "$DATA" --app "$ROOT" 2>&1)"; then DATA_READY=1; fi
fi
legacy_data_present() { # old in-tree layout: operator files inside the application folder
  local f
  for f in "$ROOT"/results/* "$ROOT"/notes/* "$ROOT/config/scope.local.txt"; do
    [ -e "$f" ] || continue
    case "$f" in */README.md) ;; *) return 0 ;; esac
  done
  return 1
}

say() { printf '%s\n' "$*"; }
pause() { [ -n "${ZD_NO_PAUSE:-}" ] || read -r -p $'\nPress Enter to continue... ' _ || true; }

# ---- tool availability -------------------------------------------------------------------
have() { case "$1" in python3) [ -n "$PY" ] ;; *) command -v "$1" >/dev/null 2>&1 ;; esac; }
hint() {
  case "$1" in
    python3) echo "sudo apt install python3" ;; nmap) echo "sudo apt install nmap" ;;
    dig) echo "sudo apt install dnsutils" ;; curl) echo "sudo apt install curl" ;;
    openssl) echo "sudo apt install openssl" ;; timeout | tar) echo "sudo apt install coreutils tar" ;;
    wireshark) echo "sudo apt install wireshark" ;; tshark) echo "sudo apt install tshark" ;;
    burpsuite) echo "sudo apt install burpsuite  (or download from portswigger.net)" ;;
    msfconsole) echo "sudo apt install metasploit-framework" ;;
    smartctl) echo "sudo apt install smartmontools" ;; lsblk) echo "sudo apt install util-linux" ;;
    testdisk) echo "sudo apt install testdisk" ;; file) echo "sudo apt install file" ;;
    ss | ip) echo "sudo apt install iproute2" ;; whois) echo "sudo apt install whois" ;;
    traceroute) echo "sudo apt install traceroute" ;; gpg) echo "sudo apt install gnupg" ;;
    *) echo "install '$1' with your package manager" ;;
  esac
}
missing_of() { local t m=(); for t in $1; do have "$t" || m+=("$t"); done; printf '%s' "${m[*]:-}"; }
need_tool() {
  have "$1" && return 0
  say "Missing tool: $1"; say "  install: $(hint "$1")  (live USB without persistence loses installs on reboot)"
  return 1
}

# ---- registry: reg/regm <category> <label> <function> [deps] ---------------------------------
# regm registers a MANUAL tool: it is launched interactively and is NOT constrained by the scope gate.
ZD_CATS=("Network" "Web Security" "Forensics" "Incident Response" "CTF / Learning" "System Recovery" "Utilities")
ZD_REG=()
reg() { ZD_REG+=("$1|$2|$3|${4:-}"); }
regm() { ZD_REG+=("$1|[MANUAL] $2|$3|${4:-}"); }

# ---- audit log (plain text: records activity, does NOT prevent tampering) ----------------------
# audit <action> <kind> <target> <verdict> <detail>. Written by scripts/auditlog.py through held directory handles
# (the whole path is walked without following links; no check-then-write by name). Returns 1 when the entry cannot be
# written: callers MUST stop.
audit() {
  if [ "$DATA_READY" != 1 ]; then printf 'AUDIT UNAVAILABLE: %s
' "$DATA_MSG" >&2; return 1; fi
  "$PY" "$ROOT/scripts/auditlog.py" append --results "$RESULTS" --action="$1" --kind="$2" --target="$3" --verdict="$4" --detail="$5"     --scope "$SCOPE" >/dev/null || { printf 'AUDIT WRITE FAILED (%s): refusing to continue.
' "$RESULTS" >&2; return 1; }
}

confirm_word() { local c; read -r -p "$2 [type $1]: " c || return 1; [ "$c" = "$1" ]; }
confirm_yes() { confirm_word YES "$1"; }
prompt_target() { read -r -p "$1: " TARGET || return 1; [ -n "${TARGET//[[:space:]]/}" ] || { say 'No target supplied.'; return 1; }; }

# ---- unique, never-overwritten outputs --------------------------------------------------------
unique_file() { # unique_file <dir> <stem> <ext>: atomically claims and prints a new empty file path
  local dir="$1" stem="$2" ext="$3" n=0 p
  while [ "$n" -lt 1000 ]; do
    if [ "$n" -eq 0 ]; then p="$dir/${stem}${ext}"; else p="$dir/${stem}_$n${ext}"; fi
    if (set -C; : >"$p") 2>/dev/null; then printf '%s' "$p"; return 0; fi
    n=$((n + 1))
  done
  return 1
}
unique_dir() { # unique_dir <dir> <stem>: atomically creates and prints a new directory path
  local n=0 p
  while [ "$n" -lt 1000 ]; do
    if [ "$n" -eq 0 ]; then p="$1/$2"; else p="$1/${2}_$n"; fi
    if mkdir "$p" 2>/dev/null; then printf '%s' "$p"; return 0; fi
    n=$((n + 1))
  done
  return 1
}
stamp() { date -u +%Y%m%dT%H%M%SZ; }
result_path() { unique_file "$RESULTS" "$(stamp)_$1" .txt; }

# ---- scope gate -------------------------------------------------------------------------------------
_gate_parse() {
  local k v
  while IFS='=' read -r k v; do
    v="${v%$'\r'}"
    case "$k" in host) G_HOST="$v" ;; addr) G_ADDR="$v" ;; addrs) G_ADDRS="$v" ;; port) G_PORT="$v" ;; url) G_URL="$v" ;; logurl) G_LOGURL="$v" ;; esac
  done <<<"$1"
}

# gate <host|network|url> <target> <action>
# 1) static pre-check, NO DNS  2) operator types YES  3) resolve + verify (every answer must be in scope)
# Sets G_HOST G_ADDR G_ADDRS G_PORT G_URL G_LOGURL (G_URL may hold secrets: only ever display G_LOGURL).
gate() {
  local kind="$1" target="$2" action="$3" out
  G_HOST=""; G_ADDR=""; G_ADDRS=""; G_PORT=""; G_URL=""; G_LOGURL=""
  [ -n "$PY" ] || { say 'Python 3.8+ is required for the scope gate.'; return 1; }
  say 'Only use on systems you own or have explicit written permission to test.'
  out="$("$PY" "$ROOT/scripts/scope_guard.py" --no-resolve --audit "$RESULTS/audit.log" --action "$action" "$SCOPE" "$kind" -- "$target")" || return 1
  _gate_parse "$out"
  [ -n "$G_HOST" ] || { say 'Scope gate returned no target.'; return 1; }
  say "Pre-check passed (no DNS lookup made yet): ${G_LOGURL:-$G_HOST}"
  if ! confirm_yes 'Confirm you are authorized for this exact target (this also authorizes a DNS lookup of a listed name)'; then
    audit "$action" "$kind" "${G_LOGURL:-$G_HOST}" CANCELLED "operator declined" || true; say 'Cancelled.'; return 1
  fi
  audit "$action" "$kind" "${G_LOGURL:-$G_HOST}" CONFIRMED "operator confirmed" || return 1
  out="$("$PY" "$ROOT/scripts/scope_guard.py" --audit "$RESULTS/audit.log" --action "$action" "$SCOPE" "$kind" -- "$target")" || return 1
  _gate_parse "$out"
  say "Verified target: $G_HOST${G_ADDRS:+ -> $G_ADDRS}"
}

# logrun <slug> <command...>: audit BEFORE running (fail closed), unique output file, secrets redacted on screen/log.
logrun() {
  local slug="$1" path shown; shift
  path="$(result_path "$slug")" || { say 'Cannot create a result file; refusing to run.'; return 1; }
  shown="$*"
  [ -z "${G_URL:-}" ] || shown="${shown//"$G_URL"/"$G_LOGURL"}"
  audit "$slug" run "${G_HOST:-local}" RUN "$shown" || { rm -f -- "$path"; say 'Not running: the audit entry could not be written.'; return 1; }
  say "Running: $shown"
  LAST_RESULT="$path"
  "$@" 2>&1 | tee "$path"
  say "Saved: $path (UNENCRYPTED; treat as sensitive)"
}

# launch_manual <tool> <notice> [args...]: interactive tools. These are NOT limited by the scope gate.
launch_manual() {
  local tool="$1" notice="$2"; shift 2
  need_tool "$tool" || return 0
  printf '%s*** MANUAL TOOL: OUTSIDE THE SCOPE GATE ***%s\n' "${C_BAD:-}" "${C_RST:-}"
  say "The deck cannot restrict what $tool does or where it connects. You alone are responsible for staying in scope."
  say "Scope file in use: $SCOPE"
  say "$notice"
  confirm_word MANUAL "Type MANUAL to acknowledge and launch $tool" || { say 'Cancelled.'; return 0; }
  audit "launch_$tool" manual local LAUNCH "interactive tool started by operator (outside scope gate)" || { say 'Not launching: audit log unavailable.'; return 0; }
  "$tool" "$@"
}
show_doc() { # show_doc <file>
  [ -f "$1" ] || { say "Missing document: $1"; return 0; }
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -R -- "$1"; else cat -- "$1"; fi
}
