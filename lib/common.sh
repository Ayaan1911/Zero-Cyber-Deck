# shellcheck shell=bash
# ZERO Deck shared library: environment, registry, scope gate, logging. Source only; never run directly.

ZD_VERSION="2.0.0"
ROOT="${ZD_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
SCOPE="${ZD_SCOPE:-$ROOT/config/scope.txt}"
RESULTS="${ZD_RESULTS:-$ROOT/results}"
NOTES="${ZD_NOTES:-$ROOT/notes}"
umask 077
mkdir -p "$RESULTS" 2>/dev/null || printf 'warning: cannot create %s (read-only media?)\n' "$RESULTS" >&2

PY=""
for _c in python3 python py; do
  if command -v "$_c" >/dev/null 2>&1 && "$_c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    PY="$_c"; break
  fi
done
unset _c

say() { printf '%s\n' "$*"; }
pause() { [ -n "${ZD_NO_PAUSE:-}" ] || read -r -p $'\nPress Enter to continue... ' _ || true; }

# ---- tool availability -------------------------------------------------------------------
have() { case "$1" in python3) [ -n "$PY" ] ;; *) command -v "$1" >/dev/null 2>&1 ;; esac; }
hint() {
  case "$1" in
    python3) echo "sudo apt install python3" ;; nmap) echo "sudo apt install nmap" ;;
    dig) echo "sudo apt install dnsutils" ;; curl) echo "sudo apt install curl" ;;
    openssl) echo "sudo apt install openssl" ;; timeout) echo "sudo apt install coreutils" ;;
    wireshark) echo "sudo apt install wireshark" ;; tshark) echo "sudo apt install tshark" ;;
    burpsuite) echo "sudo apt install burpsuite  (or download from portswigger.net)" ;;
    msfconsole) echo "sudo apt install metasploit-framework" ;;
    smartctl) echo "sudo apt install smartmontools" ;; lsblk) echo "sudo apt install util-linux" ;;
    testdisk) echo "sudo apt install testdisk" ;; file) echo "sudo apt install file" ;;
    ss|ip) echo "sudo apt install iproute2" ;; whois) echo "sudo apt install whois" ;;
    traceroute) echo "sudo apt install traceroute" ;; gpg) echo "sudo apt install gnupg" ;; tar) echo "sudo apt install tar" ;; *) echo "install '$1' with your package manager" ;;
  esac
}
missing_of() { local t m=(); for t in $1; do have "$t" || m+=("$t"); done; printf '%s' "${m[*]:-}"; }
need_tool() {
  have "$1" && return 0
  say "Missing tool: $1"; say "  install: $(hint "$1")  (live USB without persistence loses installs on reboot)"
  return 1
}

# ---- registry: reg <category> <label> <function> [deps...] ---------------------------------
ZD_CATS=("Network" "Web Security" "Forensics" "Incident Response" "CTF / Learning" "System Recovery" "Utilities")
ZD_REG=()
reg() { ZD_REG+=("$1|$2|$3|${4:-}"); }

# ---- audit + scope gate --------------------------------------------------------------------
audit() { # audit <action> <kind> <target> <verdict> <detail>
  local clean="${5//[$'\t\r\n']/ }"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t-\t%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${USER:-${USERNAME:-unknown}}" \
    "$1" "$2" "${3//[$'\t\r\n']/ }" "$4" "$clean" >>"$RESULTS/audit.log" 2>/dev/null || true
}
confirm_yes() { local c; read -r -p "$1 [type YES]: " c || return 1; [ "$c" = YES ]; }
prompt_target() { read -r -p "$1: " TARGET || return 1; [ -n "${TARGET//[[:space:]]/}" ] || { say 'No target supplied.'; return 1; }; }

# gate <host|network|url> <target> <action>; sets G_HOST G_ADDR G_PORT G_URL on success.
gate() {
  local kind="$1" target="$2" action="$3" out k v
  G_HOST=""; G_ADDR=""; G_PORT=""; G_URL=""
  [ -n "$PY" ] || { say 'Python 3.8+ is required for the scope gate.'; return 1; }
  say 'Only use on systems you own or have explicit written permission to test.'
  out="$("$PY" "$ROOT/scripts/scope_guard.py" --audit "$RESULTS/audit.log" --action "$action" "$SCOPE" "$kind" -- "$target")" || return 1
  while IFS='=' read -r k v; do
    case "$k" in host) G_HOST="${v%$'\r'}" ;; addr) G_ADDR="${v%$'\r'}" ;; port) G_PORT="${v%$'\r'}" ;; url) G_URL="${v%$'\r'}" ;; esac
  done <<<"$out"
  [ -n "$G_HOST" ] || { say 'Scope gate returned no target.'; return 1; }
  say "Verified target: $G_HOST${G_ADDR:+ -> $G_ADDR}"
  if confirm_yes 'Confirm you are authorized for this exact target'; then
    audit "$action" "$kind" "$G_HOST" CONFIRMED "operator confirmed"; return 0
  fi
  audit "$action" "$kind" "$G_HOST" CANCELLED "operator declined"; say 'Cancelled.'; return 1
}

result_path() { printf '%s/%s_%s.txt' "$RESULTS" "$(date -u +%Y%m%dT%H%M%SZ)" "$1"; }
logrun() { # logrun <slug> <command...>
  local slug="$1" path; shift
  path="$(result_path "$slug")"
  say "Running: $*"; audit "$slug" run "${G_HOST:-local}" RUN "$*"
  "$@" 2>&1 | tee "$path"
  say "Saved: $path (UNENCRYPTED; treat as sensitive)"
}
launch_manual() { # launch_manual <tool> <notice> [args...]
  local tool="$1" notice="$2"; shift 2
  need_tool "$tool" || return 0
  say "$notice"
  confirm_yes "Launch $tool" || { say 'Cancelled.'; return 0; }
  audit "launch_$tool" manual local LAUNCH "interactive session started by operator"
  "$tool" "$@"
}
show_doc() { # show_doc <file>
  [ -f "$1" ] || { say "Missing document: $1"; return 0; }
  if [ -t 1 ] && command -v less >/dev/null 2>&1; then less -R -- "$1"; else cat -- "$1"; fi
}
