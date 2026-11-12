#!/usr/bin/env python3
"""Explicit scope gate for ZERO CyberSec Deck interactive diagnostics.

This gate is a guardrail, not proof of permission or a security boundary.
"""
from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

HOST_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$")


def parse_allowed(path: Path):
    networks = []
    domains = set()
    if not path.is_file():
        raise ValueError(f"Scope file not found: {path}")
    for rownum, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.partition("#")[0].strip().lower().rstrip(".")
        if not line:
            continue
        try:
            network = ipaddress.ip_network(line, strict=False)
            if network.version != 4:
                raise ValueError("IPv6 is not supported in v1")
            networks.append(network)
            continue
        except ValueError as err:
            if "IPv6 is not supported" in str(err):
                raise ValueError(f"Line {rownum}: {err}") from err
        if not HOST_RE.fullmatch(line) or "." not in line or line.startswith("-"):
            raise ValueError(f"Line {rownum}: invalid scope entry {line!r}")
        domains.add(line)
    return networks, domains


def valid_host(host: str) -> tuple[str, object]:
    host = host.strip().lower().rstrip(".")
    if not host or any(c.isspace() for c in host) or host.startswith("-"):
        raise ValueError("A single IP or hostname is required")
    try:
        address = ipaddress.ip_address(host)
        if address.version != 4:
            raise ValueError("IPv6 is not supported in v1")
        return "ip", address
    except ValueError as err:
        if "IPv6 is not supported" in str(err):
            raise
    if not HOST_RE.fullmatch(host) or "." not in host:
        raise ValueError("Invalid hostname; use an FQDN, e.g. lab.example")
    return "domain", host


def approved(scope_file: Path, target: str, kind: str):
    networks, domains = parse_allowed(scope_file)
    if not networks and not domains:
        raise ValueError("Scope is empty. Add your explicitly authorized IPs/CIDRs/domains to config/scope.txt")
    if kind == "url":
        parsed = urlsplit(target)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password:
            raise ValueError("Only http:// or https:// URLs without embedded credentials are supported")
        try:
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                raise ValueError("Invalid port")
        except ValueError as err:
            raise ValueError("Invalid URL port") from err
        target = parsed.hostname or ""
        kind = "host"
    if kind == "network":
        try:
            network = ipaddress.ip_network(target.strip(), strict=False)
        except ValueError as err:
            raise ValueError("Specify an IPv4 CIDR, such as 192.168.56.0/24") from err
        if network.version != 4 or network.num_addresses > 256:
            raise ValueError("Discovery in v1 is restricted to IPv4 networks no larger than /24")
        return any(network.subnet_of(item) for item in networks)
    if kind != "host":
        raise ValueError("Unknown target type")
    type_, value = valid_host(target)
    if type_ == "ip":
        return any(value in item for item in networks)
    return value in domains


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope", type=Path)
    parser.add_argument("kind", choices=["host", "network", "url"])
    parser.add_argument("target")
    args = parser.parse_args()
    try:
        if approved(args.scope, args.target, args.kind):
            print("IN SCOPE")
            return 0
        print("OUT OF SCOPE: target does not match config/scope.txt", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"SCOPE ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
