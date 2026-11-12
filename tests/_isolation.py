"""Imported first by every test module: any accidental real network/DNS use in-process fails the test loudly.

Subprocesses (the scope guard, evidence tools, PowerShell -> python) are covered by tests/support/sitecustomize.py,
which tests put on PYTHONPATH. External programs (nmap, curl, dig, ...) are covered by the stub directory in test_shell.py.
"""
import socket


def _deny(*_args, **_kwargs):
    raise AssertionError("test attempted real network/DNS access")


socket.getaddrinfo = _deny
socket.gethostbyname = _deny
socket.create_connection = _deny
socket.socket.connect = _deny
socket.socket.connect_ex = _deny
