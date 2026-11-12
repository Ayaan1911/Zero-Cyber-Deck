#!/usr/bin/env python3
"""Turn raw `curl --head` output (stdin) into a SANITIZED summary (stdout). Raw HTTP output is treated as secret.

Response headers can carry secrets: Location/Refresh/Link with tokens in the URL, Set-Cookie session ids, auth headers,
custom X-* tokens, and curl error text echoes the request URL. Rules:
  * the status line is kept
  * a small allowlist of descriptive headers is shown verbatim (type, length, server, cache, security headers ...)
  * URL-bearing headers are shown with the URL redacted (whole query / fragment / userinfo / token-like segments)
  * Set-Cookie keeps the cookie NAME and its attributes (Secure, HttpOnly, SameSite ...) but never the value
  * every other header is listed by name only with [REDACTED]
  * free text (curl errors) has the request URL and any URL-looking token redacted
The raw output is never written anywhere by the deck. The exact request URL may be passed in $ZD_SECRET_URL."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from redaction import redact_text  # noqa: E402

SAFE = {"content-type", "content-length", "content-encoding", "content-language", "server", "date", "cache-control", "expires",
        "last-modified", "etag", "vary", "allow", "accept-ranges", "connection", "transfer-encoding", "age", "pragma",
        "strict-transport-security", "x-frame-options", "x-content-type-options", "x-xss-protection", "referrer-policy",
        "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "cross-origin-embedder-policy",
        "access-control-allow-methods", "access-control-allow-credentials", "access-control-max-age", "x-powered-by", "via"}
URLISH = {"location", "content-location", "refresh", "link", "content-security-policy", "content-security-policy-report-only",
          "access-control-allow-origin", "report-to", "reporting-endpoints", "origin", "referer", "alt-svc"}
COOKIE_ATTRS = {"secure", "httponly", "samesite", "path", "domain", "expires", "max-age", "partitioned", "priority"}


def _cookie(value: str) -> str:
    parts = [p.strip() for p in value.split(";")]
    name = parts[0].split("=", 1)[0] if parts and parts[0] else ""
    kept = [f"{name}=[REDACTED]"]
    for attr in parts[1:]:
        key = attr.split("=", 1)[0].strip().lower()
        kept.append(attr if key in COOKIE_ATTRS else f"{attr.split('=', 1)[0]}=[REDACTED]" if "=" in attr else attr)
    return "; ".join(kept)


def summarize(raw: str, secret_url: str = "") -> str:
    out = []
    for line in raw.splitlines():
        line = line.rstrip("\r")
        if not line.strip():
            continue
        if line.upper().startswith("HTTP/"):
            out.append(redact_text(line, secret_url)[:200])
        elif ":" in line and not line.lower().startswith("curl:"):
            name, _, value = line.partition(":")
            key, value = name.strip().lower(), value.strip()
            if key in SAFE:
                out.append(f"{name.strip()}: {redact_text(value, secret_url)[:300]}")
            elif key == "set-cookie":
                out.append(f"{name.strip()}: {_cookie(value)}")
            elif key in URLISH:
                out.append(f"{name.strip()}: {redact_text(value, secret_url)[:300]}")
            else:
                out.append(f"{name.strip()}: [REDACTED]")
        else:
            out.append(redact_text(line, secret_url)[:300])
    return "\n".join(out) + ("\n" if out else "")


def main() -> int:
    raw = sys.stdin.buffer.read().decode("utf-8", errors="replace")
    sys.stdout.write(summarize(raw, os.environ.get("ZD_SECRET_URL", "")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
