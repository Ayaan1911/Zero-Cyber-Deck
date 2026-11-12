#!/usr/bin/env python3
"""Scope gate for ZERO CyberSec Deck: the single policy engine for Kali and Windows (Python 3.8+).

A guardrail, not proof of permission. Rules:
  * scope entries (IPv4 / IPv4 CIDR no broader than /24 / exact FQDN) come from the scope file
  * DNS policy (two phases, so nothing is looked up before the operator agrees):
      --no-resolve   static check only: syntax, listed name or in-network IP. NO DNS query is made.
      (default)      resolve the listed name; EVERY IPv4 answer must lie inside a listed network.
    The caller then connects to the printed, verified address (addr=/addrs=), never to a fresh lookup.
  * every decision can be appended to an audit log; if a required entry cannot be written the gate fails closed.
    The audit log is a plain text file: it records, it does not prevent tampering.
  * URL secrets (query values, userinfo, long token-like path segments, fragments) are redacted in logs.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import socket
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import auditlog  # noqa: E402
from redaction import redact  # noqa: E402,F401  (re-exported: tests and callers import it from here)

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")
URL_BAD_RE = re.compile(r"[^\x21-\x7e]|[\\\[\]{}<>^`|\"']")  # non-printable, whitespace, curl globs, quotes
MAX_ADDRESSES = 256  # /24


class OutOfScope(Exception):
    """Target is syntactically valid but not authorised."""


@dataclass(frozen=True)
class Decision:
    host: str                     # normalized IP, FQDN, or CIDR
    addrs: tuple = ()             # verified IPv4 addresses to connect to (empty before resolution)
    port: "int | None" = None
    url: str = ""                 # normalized URL (kind == url); may contain secrets: never log it, log redact(url)


Resolver = Callable[[str], list]


def resolve_ipv4(host: str) -> list:
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except (OSError, UnicodeError) as err:
        raise ValueError(f"Cannot resolve {host}: {err}") from err
    return sorted({info[4][0] for info in infos})


def _is_fqdn(host: str) -> bool:
    return bool(HOST_RE.fullmatch(host)) and "." in host and not host.rsplit(".", 1)[1].isdigit()


def _network(text: str):
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def parse_allowed(path: Path):
    if not path.is_file():
        raise ValueError(f"Scope file not found: {path}")
    try:
        text = path.read_bytes().decode("utf-8-sig")  # tolerate a Notepad BOM
    except UnicodeDecodeError as err:
        raise ValueError("Scope file is not valid UTF-8") from err
    networks, domains = [], set()
    for rownum, raw in enumerate(text.splitlines(), 1):
        line = raw.partition("#")[0].strip().lower().rstrip(".")
        if not line:
            continue
        net = _network(line)
        if net is not None:
            if net.version != 4:
                raise ValueError(f"Line {rownum}: IPv6 is not supported")
            if net.num_addresses > MAX_ADDRESSES:
                raise ValueError(f"Line {rownum}: {line} is broader than /24")
            networks.append(net)
        elif _is_fqdn(line):
            domains.add(line)
        else:
            raise ValueError(f"Line {rownum}: invalid scope entry {line!r}")
    return networks, domains


def classify_host(host: str):
    host = host.strip().lower().rstrip(".")
    if not host or host.startswith("-") or any(c.isspace() for c in host):
        raise ValueError("A single IP or hostname is required")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if address.version != 4:
            raise ValueError("IPv6 is not supported")
        return "ip", str(address)
    if not _is_fqdn(host):
        raise ValueError("Invalid hostname; use an FQDN such as lab.example")
    return "domain", host


def _parse_url(target: str):
    if URL_BAD_RE.search(target):
        raise ValueError("URL contains whitespace, control, glob or quote characters")
    parts = urlsplit(target)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.netloc or parts.username or parts.password:
        raise ValueError("Only http:// or https:// URLs without embedded credentials are supported")
    try:
        port = parts.port
    except ValueError as err:
        raise ValueError("Invalid URL port") from err
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Invalid URL port")
    return scheme, parts.hostname or "", port or (443 if scheme == "https" else 80), parts.path + (f"?{parts.query}" if parts.query else "")


def evaluate(scope_file: Path, target: str, kind: str, resolver: Resolver = resolve_ipv4, resolve: bool = True) -> Decision:
    """Return the Decision, raise OutOfScope, or raise ValueError for bad input.
    resolve=False performs the static checks only and never calls the resolver."""
    networks, domains = parse_allowed(scope_file)
    if not networks and not domains:
        raise ValueError("Scope is empty. Add your explicitly authorized IPs/CIDRs/domains to the scope file")

    if kind == "network":
        net = _network(target.strip())
        if net is None or net.version != 4:
            raise ValueError("Specify an IPv4 CIDR, such as 192.168.56.0/24")
        if net.num_addresses > MAX_ADDRESSES:
            raise ValueError("Discovery is restricted to IPv4 networks no larger than /24")
        if not any(net.subnet_of(item) for item in networks):
            raise OutOfScope(f"{net} is not inside a listed network")
        return Decision(host=str(net))

    port = None
    url = ""
    if kind == "url":
        scheme, host_part, port, path = _parse_url(target)
        kind_host, host = classify_host(host_part)
        netloc = host if port == (443 if scheme == "https" else 80) else f"{host}:{port}"
        url = f"{scheme}://{netloc}{path or '/'}"
    elif kind == "host":
        kind_host, host = classify_host(target)
    else:
        raise ValueError("Unknown target type")

    if kind_host == "ip":
        if not any(ipaddress.ip_address(host) in net for net in networks):
            raise OutOfScope(f"{host} is not inside a listed network")
        return Decision(host=host, addrs=(host,), port=port, url=url)

    if host not in domains:
        raise OutOfScope(f"{host} is not a listed domain")
    if not resolve:
        return Decision(host=host, port=port, url=url)
    addrs = resolver(host)
    if not addrs:
        raise ValueError(f"{host} resolved to no IPv4 address")
    stray = [a for a in addrs if not any(ipaddress.ip_address(a) in net for net in networks)]
    if stray:
        raise OutOfScope(f"{host} resolves to address(es) outside scope: {', '.join(stray)}; list their IPs in the scope file if authorized")
    return Decision(host=host, addrs=tuple(addrs), port=port, url=url)


def approved(scope_file: Path, target: str, kind: str, resolver: Resolver = resolve_ipv4) -> bool:
    try:
        evaluate(scope_file, target, kind, resolver)
        return True
    except OutOfScope:
        return False


def _audit(path: Path, action: str, kind: str, target: str, verdict: str, detail: str, scope_file: Path) -> None:
    """Append through the shared safefs-based writer. Any failure is an OSError so the caller fails closed."""
    try:
        auditlog.append_row(path.parent, auditlog.format_row(action, kind, target, verdict, detail, scope_file), name=path.name)
    except ValueError as exc:  # UnsafePathError / UnsupportedConfigurationError are ValueErrors
        raise OSError(str(exc)) from None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--audit", type=Path, help="append the decision to this audit log (fail closed)")
    parser.add_argument("--action", default="check")
    parser.add_argument("--no-resolve", action="store_true", help="static checks only; perform NO DNS lookup")
    parser.add_argument("scope", type=Path)
    parser.add_argument("kind", choices=["host", "network", "url", "validate"])
    parser.add_argument("target", nargs="?", default="")
    args = parser.parse_args(argv)

    def log(verdict, detail=""):
        if args.audit:
            _audit(args.audit, args.action, args.kind, args.target, verdict, detail, args.scope)

    try:
        if args.kind == "validate":
            networks, domains = parse_allowed(args.scope)
            print(f"scope OK: {len(networks)} network(s), {len(domains)} domain(s)")
            return 0
        decision = evaluate(args.scope, args.target, args.kind, resolve=not args.no_resolve)
        if args.no_resolve:
            log("PRECHECK", "static check only; no DNS performed")
        else:
            log("ALLOW", f"host={decision.host} addrs={','.join(decision.addrs)}")
    except OutOfScope as exc:
        print(f"OUT OF SCOPE: {exc}", file=sys.stderr)
        verdict, detail = "DENY", str(exc)
    except ValueError as exc:
        print(f"SCOPE ERROR: {exc}", file=sys.stderr)
        verdict, detail = "ERROR", str(exc)
    except OSError as exc:
        print(f"SCOPE ERROR: cannot write audit log (failing closed): {exc}", file=sys.stderr)
        return 2
    else:
        print("IN SCOPE")
        print(f"host={decision.host}")
        if decision.addrs:
            print(f"addr={decision.addrs[0]}")
            print(f"addrs={','.join(decision.addrs)}")
        if decision.port:
            print(f"port={decision.port}")
        if decision.url:
            print(f"url={decision.url}")
            print(f"logurl={redact(decision.url)}")
        return 0
    try:
        log(verdict, detail)
    except OSError as exc:
        print(f"warning: audit log not written: {exc}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
