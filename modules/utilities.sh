# shellcheck shell=bash
# Utilities: dependency check, scope management, self-test, encrypted results archive.

deps_report() { # returns non-zero when a core dependency is missing; see docs/DEPENDENCIES.md
  local t core_missing=0
  for t in bash python3 nmap dig curl openssl timeout tshark wireshark burpsuite msfconsole smartctl lsblk testdisk file gpg tar; do
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
  say "Scope file in use: $SCOPE"
  "$PY" "$ROOT/scripts/scope_guard.py" "$SCOPE" validate || say 'Fix the scope file before using gated actions.'
  grep -v '^[[:space:]]*\(#\|$\)' "$SCOPE" 2>/dev/null || say '(no entries)'
}

self_test() { bash "$ROOT/scripts/test-deck.sh"; }

# Rehearses the exact publish sequence (zero-byte file) in the results folder. Sets PUBLISH_OK=1/0. Evidence, manifests, reports and
# migration need hard links; exFAT/FAT32 have none, so they are refused there instead of failing halfway.
publish_capability() {
  PUBLISH_OK=0
  [ "$DATA_READY" = 1 ] || return 1
  local out
  if out="$("$PY" "$ROOT/scripts/fscaps.py" rehearse --dir "$RESULTS" 2>&1)"; then
    PUBLISH_OK=1; say "Publish capability: OK - $out"
  else
    say "Publish capability: UNAVAILABLE - evidence, manifests, reports and migration will be refused on this filesystem."
    say "$out"
  fi
  [ "$PUBLISH_OK" = 1 ]
}

data_status() {
  say "Application folder (code only, never written): $ROOT"
  say "Data folder (results, notes, evidence, scope, audit log): $DATA"
  if [ "$DATA_READY" = 1 ]; then say "Status: READY - $DATA_MSG"; else say "Status: NOT READY - $DATA_MSG"; say "Initialize or repair it with:  bash zero-deck.sh --init-data"; fi
  publish_capability || true
  legacy_data_present && say "NOTE: operator files were found INSIDE the application folder (old layout). They are not used. Copy them with: $PY scripts/migrate_data.py --from \"$ROOT\" --to \"$DATA\"   (see SETUP.md; back up first)"
  return 0
}

verify_release() {
  local extra=""
  [ -e "$ROOT/.git" ] && { extra="--allow-extra"; say "(development checkout: unlisted files such as .git are tolerated)"; }
  "$PY" "$ROOT/scripts/verify_release.py" --app "$ROOT" $extra
}

# Symmetric AES-256 gpg archive of results/ and evidence/. Output goes to <data>/archives and never overwrites.
encrypt_results() {
  local out
  [ "$DATA_READY" = 1 ] || { say "Data folder not ready: $DATA_MSG"; return 0; }
  audit encrypt_results local "$DATA" RUN "gpg archive" || return 0
  out="$(unique_file "${ZD_ARCHIVE_DIR:-$DATA/archives}" "results_$(stamp)" .tar.gz.gpg)" || { say 'Cannot create archive file.'; return 0; }
  rm -f -- "$out"  # gpg refuses to overwrite silently; the name is unique so remove only our empty placeholder
  say "Archiving results/ and evidence/ -> $out (you will be asked for a passphrase; remember it, there is no recovery)."
  tar -C "$DATA" -czf - results evidence | gpg --symmetric --cipher-algo AES256 -o "$out" &&
    say "Created $out. Verify it decrypts before deleting the plaintext data."
}

reg "Utilities" "Check installed tools + install hints" deps_report ""
reg "Utilities" "Data folder status (and migration hint)" data_status ""
reg "Utilities" "Verify the installed release against SHA256SUMS.txt" verify_release "python3"
reg "Utilities" "Show + validate authorized scope" show_scope "python3"
reg "Utilities" "Run built-in self-tests" self_test "python3"
reg "Utilities" "Encrypt results/ into a passphrase-protected archive (gpg)" encrypt_results "gpg tar"
