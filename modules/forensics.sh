# shellcheck shell=bash
# Forensics: hashing, manifests, verified evidence copies, pcap summaries. Sources are only read.
# Links/junctions anywhere in a path are refused (every folder is opened once and held: scripts/safefs.py); existing manifests/evidence are never overwritten.

EV="$ROOT/scripts/evidence.py"

hash_file() {
  local f; read -r -e -p 'Local file path to SHA-256 hash: ' f
  [ -f "$f" ] || { say 'File not found.'; return 0; }
  logrun file_sha256 "$PY" "$EV" hash "$f"
}

verify_file_hash() {
  local f h
  read -r -e -p 'File path: ' f; read -r -p 'Expected SHA-256 (64 hex): ' h
  [ -f "$f" ] || { say 'File not found.'; return 0; }
  logrun verify_file "$PY" "$EV" verify-file "$f" "$h"
}

manifest_create() {
  local d; read -r -e -p 'Directory to hash: ' d
  [ -d "$d" ] || { say 'Directory not found.'; return 0; }
  audit manifest_create local "$d" RUN "write MANIFEST.sha256" || return 0
  "$PY" "$EV" manifest "$d" "$d/MANIFEST.sha256"
}

manifest_verify() {
  local m; read -r -e -p 'Path to MANIFEST.sha256: ' m
  [ -f "$m" ] || { say 'Manifest not found.'; return 0; }
  logrun manifest_verify "$PY" "$EV" verify "$m"
}

evidence_acquire() {
  local src dest case examiner
  read -r -e -p 'Evidence source (file or folder, read-only): ' src
  [ -e "$src" ] || { say 'Source not found.'; return 0; }
  read -r -e -p "Destination folder [$EVIDENCE]: " dest; dest="${dest:-$EVIDENCE}"
  read -r -p 'Case ID: ' case; read -r -p 'Examiner name: ' examiner
  [ -n "$case" ] && [ -n "$examiner" ] || { say 'Case ID and examiner are required.'; return 0; }
  audit evidence_acquire local "$src" RUN "case=$case" || return 0
  "$PY" "$EV" acquire "$src" "$dest" --case "$case" --examiner "$examiner"
  say 'Copies are hash-verified and read-only; custody log: custody.jsonl (plain text, not tamper-proof). For disks, image with a write-blocker and ddrescue/dc3dd.'
}

pcap_summary() {
  local f; read -r -e -p 'Path to a .pcap/.pcapng file: ' f
  [ -f "$f" ] || { say 'File not found.'; return 0; }
  logrun pcap_summary tshark -r "$f" -q -z io,phs -z conv,ip
}

file_type() {
  local f; read -r -e -p 'File to identify: ' f
  [ -f "$f" ] || { say 'File not found.'; return 0; }
  logrun file_type file -- "$f"
}

reg "Forensics" "SHA-256 of a file" hash_file "python3"
reg "Forensics" "Verify a file against an expected SHA-256" verify_file_hash "python3"
reg "Forensics" "Create hash manifest for a folder (never overwrites)" manifest_create "python3"
reg "Forensics" "Verify folder against its manifest (fails on extra files)" manifest_verify "python3"
reg "Forensics" "Acquire evidence copy (verified, read-only, custody log)" evidence_acquire "python3"
reg "Forensics" "Summarize a pcap (tshark)" pcap_summary "tshark"
reg "Forensics" "Identify file type (file)" file_type "file"
