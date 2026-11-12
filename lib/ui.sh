# shellcheck shell=bash
# Keyboard-driven terminal UI (pure bash + ANSI; no dialog/ncurses needed). Source only.
# Raw mode when stdin is a TTY (or ZD_FORCE_TTY=1); numbered prompt otherwise (pipes, logs, tests).

if [ -n "${ZD_FORCE_TTY:-}" ] || { [ -t 0 ] && [ -z "${ZD_PLAIN:-}" ]; }; then ZD_RAW=1; else ZD_RAW=""; fi
if [ -n "$ZD_RAW" ] || [ -t 1 ]; then
  C_RST=$'\e[0m'; C_DIM=$'\e[2m'; C_REV=$'\e[7m'; C_OK=$'\e[32m'; C_BAD=$'\e[31m'; C_HEAD=$'\e[1;36m'
else
  C_RST=""; C_DIM=""; C_REV=""; C_OK=""; C_BAD=""; C_HEAD=""
fi

ui_header() {
  printf '%s+----------------------------------------------------+\n|  ZERO // CYBERSEC DECK  v%-8s                  |\n|  Offline-first · Explicit scope · Human in control |\n+----------------------------------------------------+%s\n' \
    "$C_HEAD" "$ZD_VERSION" "$C_RST"
}
ui_key() { # sets KEY: up down enter back or the literal character
  local k rest=""
  IFS= read -rsn1 k || { KEY=back; return 1; }
  if [ "$k" = $'\e' ]; then
    IFS= read -rsn2 -t 0.05 rest || true
    case "$rest" in '[A') KEY=up ;; '[B') KEY=down ;; '') KEY=back ;; *) KEY=other ;; esac
  elif [ -z "$k" ]; then KEY=enter
  else KEY="$k"; fi
}

# ui_pick <title> <label...>  -> PICK (0-based index); returns 1 when the user goes back
ui_pick() {
  local title="$1"; shift
  local -a labels=("$@"); local n=${#labels[@]} sel=0 i ans
  if [ -z "$ZD_RAW" ]; then
    while :; do
      printf '\n== %s ==\n' "$title"
      for ((i = 0; i < n; i++)); do printf ' %2d) %s\n' $((i + 1)) "${labels[i]}"; done
      printf '  0) Back / Quit\n'
      read -r -p 'Choose: ' ans || return 1
      [ "$ans" = 0 ] && return 1
      if [[ "$ans" =~ ^[0-9]+$ ]] && ((ans >= 1 && ans <= n)); then PICK=$((ans - 1)); return 0; fi
      say 'Choose a listed number.'
    done
  fi
  while :; do
    printf '\033[H\033[2J'; ui_header
    printf '\n %s%s%s\n\n' "$C_HEAD" "$title" "$C_RST"
    for ((i = 0; i < n; i++)); do
      if ((i == sel)); then printf ' %s> %s%s%s\n' "$C_REV" "${labels[i]}" "$C_RST" ""; else printf '   %s\n' "${labels[i]}"; fi
    done
    printf '\n%s[+] ready  [-] missing dependency   ↑/↓ j/k move · Enter select · 1-9 jump · q back%s\n' "$C_DIM" "$C_RST"
    ui_key || return 1
    case "$KEY" in
      up | k) sel=$(((sel + n - 1) % n)) ;;
      down | j) sel=$(((sel + 1) % n)) ;;
      enter) PICK=$sel; return 0 ;;
      back | q | Q | 0) return 1 ;;
      [1-9]) if ((KEY <= n)); then PICK=$((KEY - 1)); return 0; fi ;;
    esac
  done
}

run_item() { # run_item <label> <function> <deps>
  local label="$1" func="$2" miss t
  miss="$(missing_of "$3")"
  [ -n "$ZD_RAW" ] && printf '\033[H\033[2J'
  printf '%s== %s ==%s\n' "$C_HEAD" "$label" "$C_RST"
  if [ -n "$miss" ]; then
    say "This tool needs software that is not available here:"
    for t in $miss; do say "  - $t  ->  $(hint "$t")"; done
  else
    "$func"
  fi
  pause
}

ui_category() {
  local cat="$1" i c label func deps miss mark
  local -a idx=() labels=()
  for i in "${!ZD_REG[@]}"; do
    IFS='|' read -r c label func deps <<<"${ZD_REG[i]}"
    [ "$c" = "$cat" ] || continue
    idx+=("$i"); miss="$(missing_of "$deps")"
    label="${label/#\[MANUAL\]/${C_BAD}[MANUAL]${C_RST}}"  # manual tools are visibly outside the scope gate
    if [ -z "$miss" ]; then mark="${C_OK}[+]${C_RST}"; labels+=("$mark $label"); else mark="${C_BAD}[-]${C_RST}"; labels+=("$mark $label ${C_DIM}(needs: $miss)${C_RST}"); fi
  done
  [ "${#idx[@]}" -gt 0 ] || { say "No tools registered for $cat."; pause; return 0; }
  while ui_pick "$cat" "${labels[@]}"; do
    IFS='|' read -r _ label func deps <<<"${ZD_REG[${idx[PICK]}]}"
    run_item "$label" "$func" "$deps"
  done
}

ui_main() {
  local i c cat label func deps ready total
  local -a labels=()
  while :; do
    labels=()
    for c in "${ZD_CATS[@]}"; do
      ready=0; total=0
      for i in "${!ZD_REG[@]}"; do
        IFS='|' read -r cat label func deps <<<"${ZD_REG[i]}"
        [ "$cat" = "$c" ] || continue
        total=$((total + 1)); [ -z "$(missing_of "$deps")" ] && ready=$((ready + 1))
      done
      labels+=("$(printf '%-20s %s%d/%d ready%s' "$c" "$C_DIM" "$ready" "$total" "$C_RST")")
    done
    ui_pick "Main menu" "${labels[@]}" || break
    ui_category "${ZD_CATS[PICK]}"
  done
  [ -n "$ZD_RAW" ] && printf '\033[H\033[2J'
  say 'Session ended. Results in: '"$RESULTS"
}
