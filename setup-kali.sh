#!/usr/bin/env bash
# Optional, intentionally interactive installer; no auto-run.
set -euo pipefail
PACKAGES=(nmap curl openssl dnsutils whois traceroute iproute2 net-tools jq coreutils file smartmontools testdisk gnupg)
cat <<'TXT'
ZERO Deck's scripts do not need all packages in advance.
For stock Kali Live, many may already exist.
This installer deliberately does NOT install Metasploit, Burp, or large metapackages.
USB 2.0 persistence can be very slow. Consider installing in a VM/SSD instead.

TXT
printf 'Small diagnostic packages: %s\n' "${PACKAGES[*]}"
if [ "${1:-}" != '--install' ]; then
  echo 'DRY RUN ONLY. To install: bash setup-kali.sh --install'
  exit 0
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo 'apt-get not available. Use this only in Kali/Debian-based Linux.' >&2
  exit 1
fi
read -r -p 'Type INSTALL to run sudo apt-get update && install on THIS system: ' answer
if [ "$answer" != INSTALL ]; then echo Cancelled.; exit 0; fi
sudo apt-get update
sudo apt-get install --no-install-recommends "${PACKAGES[@]}"
echo 'Completed. Confirm available tools via the deck menu.'
