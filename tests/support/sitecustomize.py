"""Offline sandbox for python SUBPROCESSES started by tests (put this directory on PYTHONPATH, no `-I`).

* socket.getaddrinfo is replaced: lookups are appended to $ZD_DNSLOG and answered only from $ZD_FAKE_DNS
  ("name=ip1,ip2;name2=ip3"); every other name raises gaierror. Nothing ever reaches a real resolver.
* socket connects are blocked.
"""
import os
import socket


def _log(line):
    path = os.environ.get("ZD_DNSLOG")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")


def _fake_getaddrinfo(host, *args, **kwargs):
    _log("lookup " + str(host))
    table = dict(item.split("=", 1) for item in os.environ.get("ZD_FAKE_DNS", "").split(";") if "=" in item)
    if host in table:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in table[host].split(",")]
    raise socket.gaierror("sandbox: no fake answer for " + str(host))


def _blocked(*_args, **_kwargs):
    raise OSError("sandbox: network connect blocked")


socket.getaddrinfo = _fake_getaddrinfo
socket.gethostbyname = _blocked
socket.create_connection = _blocked
socket.socket.connect = _blocked
socket.socket.connect_ex = lambda *_a, **_k: 1
