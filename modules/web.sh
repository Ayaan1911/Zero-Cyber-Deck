# shellcheck shell=bash
# Web security diagnostics: DNS, HTTP headers, TLS certificate; Burp Suite is a MANUAL launcher.

# DNS policy: the gate already resolved the listed name once and verified every answer. dig is informational;
# any answer outside the verified set means DNS changed since verification and is flagged loudly.
dns_lookup() {
  prompt_target 'Enter AUTHORIZED hostname' && gate host "$TARGET" dns_lookup || return 0
  logrun dns_records dig +time=5 +tries=1 +short "$G_HOST" A || return 0
  local ip drift=""
  for ip in $(grep -Eo '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' "$LAST_RESULT" 2>/dev/null); do
    case ",$G_ADDRS," in *",$ip,"*) ;; *) drift="$drift $ip" ;; esac
  done
  if [ -n "$drift" ]; then
    say "WARNING: DNS now returns address(es) that were NOT verified in scope:$drift. Do not scan this name; re-run the gate."
    audit dns_lookup run "$G_HOST" DRIFT "unverified answers:$drift" || true
  fi
}

http_headers() {
  prompt_target 'Enter AUTHORIZED http(s) URL (no [] {} or spaces)' && gate url "$TARGET" http_headers || return 0
  # --globoff: no curl URL globbing; --resolve pins the verified address; no proxy, no redirects.
  # The URL (which may carry secrets) is shown and logged only in redacted form by logrun.
  logrun http_headers curl --head --silent --show-error --globoff --noproxy '*' --proto '=http,https' \
    --connect-timeout 5 --max-time 20 --max-redirs 0 --resolve "$G_HOST:$G_PORT:$G_ADDR" "$G_URL"
  say 'Note: saved response headers can contain Set-Cookie values or tokens; handle the result file as sensitive.'
}

tls_certificate() {
  prompt_target 'Enter AUTHORIZED HTTPS hostname (not URL)' && gate host "$TARGET" tls_certificate || return 0
  local out sni=()
  out="$(result_path tls_certificate)" || { say 'Cannot create a result file.'; return 0; }
  [ "$G_HOST" != "$G_ADDR" ] && sni=(-servername "$G_HOST")
  audit tls_certificate run "$G_HOST" RUN "openssl s_client $G_ADDR:443" || { rm -f -- "$out"; return 0; }
  timeout 15 openssl s_client -connect "$G_ADDR:443" ${sni[@]+"${sni[@]}"} </dev/null 2>/dev/null |
    openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>&1 | tee "$out"
  say "Saved: $out (UNENCRYPTED)"
}

burp_launch() {
  launch_manual burpsuite 'Set Target > Scope to authorized hosts only and keep intercept off until needed. Project files hold session data; store them encrypted.'
}

reg "Web Security" "DNS A-record lookup (gated, drift-checked)" dns_lookup "dig python3"
reg "Web Security" "HTTP response headers" http_headers "curl python3"
reg "Web Security" "TLS certificate summary" tls_certificate "openssl timeout python3"
regm "Web Security" "Burp Suite" burp_launch "burpsuite"
