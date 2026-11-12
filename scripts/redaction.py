"""Secret redaction for anything that reaches a log, a report or the terminal (stdlib only, Python 3.8+)."""
from __future__ import annotations

import re

_USERINFO_RE = re.compile(r"(//)[^/@\s]*@")
_PATH_PARAM_RE = re.compile(r";[^/?#\s]*")
_LONG_SEGMENT_RE = re.compile(r"(?<=/)[A-Za-z0-9_\-.~%]{24,}(?=/|$)")
_URL_TOKEN_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def redact(text: str) -> str:
    """Best-effort removal of secrets from a URL-ish string before it reaches any log or terminal summary.

    * everything after the first '?' (the WHOLE query, keyed or not: `?token=x`, `?SECRET`, `?a&b`) and after '#'
      is replaced, whatever its syntax
    * userinfo (user:password@), path parameters (;jsessionid=...) and long token-like path segments are replaced
    Best effort: a secret in an ordinary short path segment cannot be recognised."""
    text = _USERINFO_RE.sub(r"\1REDACTED@", text)
    cut = min((i for i in (text.find("?"), text.find("#")) if i != -1), default=-1)
    tail = ""
    if cut != -1:
        tail = text[cut] + "REDACTED"
        text = text[:cut]
    if "/" in text:  # path rules only for URL-shaped strings: a ';' in an ordinary message is not a path parameter
        text = _PATH_PARAM_RE.sub(";REDACTED", text)
        text = _LONG_SEGMENT_RE.sub("REDACTED", text)
    return text + tail


def redact_text(text: str, secret_url: str = "") -> str:
    """Redact free text (tool output, error messages): the exact secret URL if known, then every URL-looking token."""
    if secret_url:
        text = text.replace(secret_url, redact(secret_url))
    return _URL_TOKEN_RE.sub(lambda m: redact(m.group(0)), text)
