#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
bash -n "$ROOT/zero-deck.sh"
bash -n "$ROOT/setup-kali.sh"
python3 -m unittest discover -s "$ROOT/tests" -v
printf '\nAll local tests completed. Physical USB boot compatibility is NOT tested.\n'
