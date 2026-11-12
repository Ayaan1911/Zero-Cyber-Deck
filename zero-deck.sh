#!/usr/bin/env bash
# ZERO CyberSec Deck v1.0 - intentional, scope-gated diagnostics.
set -uo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCOPE="$ROOT/config/scope.txt"
RESULTS="$ROOT/results"
umask 077
mkdir -p "$RESULTS"

say() { printf '%s\n' "$*"; }
need() { if ! command -v "$1" >/dev/null 2>&1; then say "Missing tool: $1. See SETUP.md."; return 1; fi; }
pause() { read -r -p $'\nPress Enter to continue... ' _ || true; }
prompt_target() { read -r -p "$1: " TARGET; [ -n "${TARGET// /}" ] || { say 'No target supplied.'; return 1; }; }
gate() {
  say 'Only use these actions on networks/sites you own or have explicit permission to test.'
  need python3 || return 1
  python3 "$ROOT/scripts/scope_guard.py" "$SCOPE" "$1" "$2" || return 1
  read -r -p 'Confirm you are authorized for this exact target [type YES]: ' confirm
  [ "$confirm" = "YES" ] || { say 'Cancelled.'; return 1; }
}
logrun() {
  local slug="$1"; shift
  local stamp path
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  path="$RESULTS/${stamp}_${slug}.txt"
  say "Running: $*"
  "$@" 2>&1 | tee "$path"
  say "Output saved to: $path (UNENCRYPTED; treat as sensitive)"
}
show_status() {
  say 'ZERO CyberSec Deck | local diagnostics'
  say '--- system ---'
  date -u
  uname -a
  if command -v ip >/dev/null 2>&1; then
    ip -brief address
    ip route
  fi
  if command -v ss >/dev/null 2>&1; then ss -tuln; fi
  if command -v df >/dev/null 2>&1; then df -h "$ROOT"; fi
}
system_snapshot() {
  local stamp path
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  path="$RESULTS/${stamp}_local_inventory.txt"
  show_status 2>&1 | tee "$path"
  say "Saved: $path"
}
network_discovery() {
  need nmap && prompt_target 'Enter AUTHORIZED IPv4 CIDR (max /24)' && gate network "$TARGET" && logrun host_discovery nmap -sn "$TARGET"
}
port_scan() {
  need nmap && prompt_target 'Enter AUTHORIZED single IP or hostname' && gate host "$TARGET" && logrun service_inventory nmap -sT -sV --version-light --top-ports 100 --open "$TARGET"
}
dns_lookup() {
  need dig && prompt_target 'Enter AUTHORIZED hostname' && gate host "$TARGET" && logrun dns_records dig "$TARGET" A +noall +answer
}
http_headers() {
  need curl && prompt_target 'Enter AUTHORIZED http(s) URL' && gate url "$TARGET" && logrun http_headers curl --head --silent --show-error --connect-timeout 5 --max-time 20 --max-redirs 0 "$TARGET"
}
tls_info() {
  need openssl && prompt_target 'Enter AUTHORIZED HTTPS hostname (not URL)' && gate host "$TARGET" || return 0
  local path stamp
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  path="$RESULTS/${stamp}_tls_certificate.txt"
  if command -v timeout >/dev/null 2>&1; then
    timeout 15 openssl s_client -connect "${TARGET}:443" -servername "$TARGET" < /dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>&1 | tee "$path"
  else
    say 'Missing timeout; install coreutils before doing TLS checks.'
    return 0
  fi
  say "Saved: $path"
}
file_hash() {
  need sha256sum || return 0
  local file
  read -r -p 'Local file path to SHA-256 hash: ' file
  [ -f "$file" ] || { say 'File not found.'; return 0; }
  logrun file_sha256 sha256sum -- "$file"
}
check_tools() {
  local tool
  for tool in bash python3 nmap curl dig openssl sha256sum whois traceroute tcpdump tshark wireshark msfconsole burpsuite zaproxy; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf '[ok]      %-12s %s\n' "$tool" "$(command -v "$tool")"
    else
      printf '[missing] %s\n' "$tool"
    fi
  done
}
launch() {
  local tool="$1"
  if need "$tool"; then
    say "Launching $tool. Use only in authorized environments. No attack is run automatically."
    "$tool"
  fi
}

while :; do
  printf '\n\033[1;36m'
  cat <<'MENU'
  +---------------------------------------------------+
  |   ZERO / CYBERSEC DECK v1.0                      |
  |   Offline-first • Explicit scope • Human control |
  +---------------------------------------------------+
    1  System + network inventory (local)
    2  Discover authorized LAN hosts (Nmap -sn)
    3  Inspect top 100 TCP ports/services (Nmap)
    4  DNS A-record lookup
    5  Inspect HTTP response headers
    6  Inspect HTTPS TLS certificate
    7  Hash a local file (SHA-256)
    8  Check installed tools
    9  Open Metasploit console (manual use)
   10  Open Wireshark (manual use)
   11  Open Burp Suite (manual use)
   12  Print configured authorized scope
    0  Quit
MENU
  printf '\033[0m'
  read -r -p 'Choose: ' choice || break
  case "$choice" in
    1) system_snapshot ;; 2) network_discovery ;; 3) port_scan ;;
    4) dns_lookup ;; 5) http_headers ;; 6) tls_info ;;
    7) file_hash ;; 8) check_tools ;; 9) launch msfconsole ;;
    10) launch wireshark ;; 11) launch burpsuite ;;
    12) cat "$SCOPE" ;; 0) break ;; *) say 'Choose a listed number.' ;;
  esac
  [ "$choice" = 0 ] || pause
done
