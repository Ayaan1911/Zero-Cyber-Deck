# shellcheck shell=bash
# CTF / learning: offline resource index and note taking.

learning_index() { show_doc "$ROOT/docs/LEARNING.md"; }

new_note() {
  local slug file
  read -r -p 'Note slug (letters, digits, - and _): ' slug
  [[ "$slug" =~ ^[A-Za-z0-9_-]{1,60}$ ]] || { say 'Invalid slug.'; return 0; }
  mkdir -p "$NOTES"
  file="$NOTES/$(date -u +%Y%m%d)-$slug.md"
  [ -e "$file" ] && { say "Already exists: $file"; return 0; }
  printf '# %s\n\n- Date: %s\n- Platform/CTF:\n- Category:\n\n## Approach\n\n## Flag / result (no real client data)\n\n## Lessons\n' "$slug" "$(date -u +%F)" >"$file"
  say "Created $file"
}

list_notes() {
  ls -1 "$NOTES" 2>/dev/null | grep -v '^README.md$' || say '(no notes yet)'
}

reg "CTF / Learning" "Learning resources + lab ideas (offline index)" learning_index ""
reg "CTF / Learning" "Create a CTF/lab note" new_note ""
reg "CTF / Learning" "List my notes" list_notes ""
