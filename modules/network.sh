# shellcheck shell=bash
# Network: inventory, scope-gated Nmap workflows, Wireshark and Metasploit (MANUAL, outside the scope gate).

local_inventory() {
  local path
  audit local_inventory local local RUN "read-only local inventory" || return 0
  path="$(result_path local_inventory)" || { say 'Cannot create a result file.'; return 0; }
  {
    date -u; uname -a
    have ip && { ip -brief address; ip route; }
    have ss && ss -tuln
    have df && df -h "$ROOT"
  } 2>&1 | tee "$path"
  say "Saved: $path (UNENCRYPTED)"
}

nmap_discovery() {
  prompt_target 'Enter AUTHORIZED IPv4 CIDR (max /24)' && gate network "$TARGET" nmap_discovery || return 0
  logrun host_discovery nmap -sn --host-timeout 30s "$G_HOST"
}

nmap_top_ports() {
  prompt_target 'Enter AUTHORIZED single IP or hostname' && gate host "$TARGET" nmap_top_ports || return 0
  say "Scanning the verified address $G_ADDR (not a fresh DNS lookup)."
  [ "$G_ADDR" = "$G_ADDRS" ] || say "Note: $G_HOST has several verified addresses ($G_ADDRS); only the first is scanned. Re-run per address if needed."
  logrun service_inventory nmap -sT -sV --version-light --top-ports 100 --open --host-timeout 5m --max-retries 2 "$G_ADDR"
}

# valid_ports: 1-65535, single, ranges, comma lists; nothing else reaches nmap
valid_ports() {
  local spec="$1" part lo hi
  [[ "$spec" =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] && [ "${#spec}" -le 200 ] || return 1
  local IFS=,
  for part in $spec; do
    lo="${part%-*}"; hi="${part#*-}"
    ((10#$lo >= 1 && 10#$lo <= 65535 && 10#$hi >= 1 && 10#$hi <= 65535 && 10#$lo <= 10#$hi)) || return 1
  done
}

nmap_custom_ports() {
  local ports
  prompt_target 'Enter AUTHORIZED single IP or hostname' && gate host "$TARGET" nmap_custom_ports || return 0
  read -r -p 'Ports (e.g. 22,80,443 or 1-1024): ' ports
  valid_ports "$ports" || { say 'Invalid port list. Use numbers 1-65535, ranges and commas only.'; return 0; }
  logrun custom_ports nmap -sT -sV --version-light -p "$ports" --open --host-timeout 5m --max-retries 2 "$G_ADDR"
}

wireshark_launch() {
  launch_manual wireshark 'Capture only on networks you are authorized to monitor. Captures may contain credentials; store them encrypted.'
}

metasploit_launch() {
  say 'Authorized scope listed in the scope file (Metasploit will NOT check it):'
  grep -v '^[[:space:]]*\(#\|$\)' "$SCOPE" 2>/dev/null || say '  (empty)'
  launch_manual msfconsole "Interactive console only; nothing runs automatically. Set RHOSTS only to systems listed above.
Tip inside msfconsole: spool $RESULTS/msf_session.log" -q
}

reg "Network" "Local system + network inventory" local_inventory ""
reg "Network" "Discover LAN hosts (Nmap -sn, /24 max)" nmap_discovery "nmap python3"
reg "Network" "Top-100 TCP port + service inventory (Nmap)" nmap_top_ports "nmap python3"
reg "Network" "Custom port list (Nmap, validated)" nmap_custom_ports "nmap python3"
regm "Network" "Wireshark" wireshark_launch "wireshark"
regm "Network" "Metasploit console (lab only)" metasploit_launch "msfconsole"
