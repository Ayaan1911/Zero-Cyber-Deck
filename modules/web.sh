# shellcheck shell=bash
# Web security diagnostics: DNS, HTTP headers, TLS certificate, Burp Suite launcher.

dns_lookup() {
  prompt_target 'Enter AUTHORIZED hostname' && gate host "$TARGET" dns_lookup || return 0
  logrun dns_records dig +time=5 +tries=1 "$G_HOST" A +noall +answer
}

http_headers() {
  prompt_target 'Enter AUTHORIZED http(s) URL (no [] {} or spaces)' && gate url "$TARGET" http_headers || return 0
  # --globoff: no curl URL globbing; --resolve pins the verified address; no proxy, no redirects.
  logrun http_headers curl --head --silent --show-error --globoff --noproxy '*' --proto '=http,https' \
    --connect-timeout 5 --max-time 20 --max-redirs 0 --resolve "$G_HOST:$G_PORT:$G_ADDR" "$G_URL"
}

tls_certificate() {
  prompt_target 'Enter AUTHORIZED HTTPS hostname (not URL)' && gate host "$TARGET" tls_certificate || return 0
  local out sni=()
  out="$(result_path tls_certificate)"
  [ "$G_HOST" != "$G_ADDR" ] && sni=(-servername "$G_HOST")
  audit tls_certificate run "$G_HOST" RUN "openssl s_client $G_ADDR:443"
  timeout 15 openssl s_client -connect "$G_ADDR:443" ${sni[@]+"${sni[@]}"} </dev/null 2>/dev/null |
    openssl x509 -noout -subject -issuer -dates -fingerprint -sha256 2>&1 | tee "$out"
  say "Saved: $out (UNENCRYPTED)"
}

burp_launch() {
  launch_manual burpsuite 'Burp Suite: set Target > Scope to authorized hosts only and keep intercept off until needed. Project files hold session data; store encrypted.'
}

reg "Web Security" "DNS A-record lookup (scope + resolution gated)" dns_lookup "dig python3"
reg "Web Security" "HTTP response headers" http_headers "curl python3"
reg "Web Security" "TLS certificate summary" tls_certificate "openssl timeout python3"
reg "Web Security" "Open Burp Suite (manual)" burp_launch "burpsuite"
