# Dependencies

Run `bash zero-deck.sh --check` (Kali) or `powershell -NoProfile -File .\Start-ZeroDeck.ps1 -Check` (Windows) for a live report with install hints. `-Check` exits non-zero when something required is missing or the scope file is invalid.

## Required

| Component | Version | Platform | Needed for |
|---|---|---|---|
| Python (`python3`; `python` or `py` on Windows) | **3.8 or newer** (standard library only; no `pip install`) | Kali + Windows | scope gate, evidence, reports; every scoped action refuses to run without it |
| bash | 4.4+ recommended | Kali (Git Bash on Windows for the test-suite) | dashboard `zero-deck.sh` |
| Windows PowerShell | 5.1 (built into Windows 10/11) | Windows | `Start-ZeroDeck.ps1`, `Install-ZeroDeck.ps1` |
| coreutils (`date`, `tee`, `mkdir`, `sha256sum` not required), `grep`, `sed`, `tr`, `tail` | any | Kali | dashboard internals; present on Kali |

## Optional tools (the matching dashboard item is greyed out `[-]` and explains itself when missing)

| Tool | Debian/Kali package | Used by |
|---|---|---|
| `nmap` | `nmap` | Network: host discovery, top-100 ports, custom ports |
| `dig` | `dnsutils` | Web Security: DNS lookup |
| `curl` | `curl` | Web Security: HTTP headers |
| `openssl`, `timeout` | `openssl`, `coreutils` | Web Security: TLS certificate summary |
| `tshark` | `tshark` | Forensics: pcap summary |
| `file` | `file` | Forensics: file type |
| `wireshark` | `wireshark` | **Manual** launcher |
| `burpsuite` | `burpsuite` (or portswigger.net) | **Manual** launcher |
| `msfconsole` | `metasploit-framework` | **Manual** launcher |
| `lsblk` | `util-linux` | System Recovery: disk overview |
| `smartctl` | `smartmontools` | System Recovery: SMART health (needs root) |
| `testdisk` | `testdisk` | **Manual** launcher (can write to disks) |
| `gpg`, `tar` | `gnupg`, `tar` | Utilities: encrypted results archive |
| `ip`, `ss`, `ps`, `who`, `last`, `getent`, `crontab`, `systemctl`, `mount`, `lsmod`, `find` | `iproute2`, `procps`, `util-linux`, `libc-bin`, `cron`, `systemd`, `findutils` | Incident Response: Linux triage (missing ones are noted and skipped) |
| `nmap`, `wireshark`, `tshark` | (Windows installers) | optional on Windows; not required by the Windows menu |

Nothing is installed automatically. `bash setup-kali.sh` prints the small optional package list (dry run) and installs only with `--install` plus typing `INSTALL`. A live Kali session without persistence forgets installs on reboot.

## Development / test-suite only

- Python `unittest` (standard library). No pytest, no network, no real tools: every external program is stubbed (see `tests/test_shell.py`).
- Bash (Git Bash on Windows) for the shell tests; `powershell.exe` for the Windows tests. Missing ones cause those tests to be **skipped**, and the runner reports the skip count.
- Optional static analysis if you install them: `shellcheck` (used automatically by `scripts/test-deck.sh` when present), `ruff`/`pyflakes`.

## Platform support of the safe-file layer (`scripts/safefs.py`)

- Linux (verified on Ubuntu under WSL; Kali not yet): `os.O_NOFOLLOW`, `dir_fd` support in `os.open`/`os.link`/`os.mkdir` (standard on Linux).
- Windows: `ctypes` (standard library) calling `kernel32`; local fixed/removable volumes only. No third-party package is needed anywhere.
- Refused with a diagnostic: macOS, UNC/network paths, `subst` drives, non-canonical (8.3) spellings.

## Compatibility notes

- Python 3.8 is the floor: no `match`, no `X | Y` at runtime, no `Path.write_text(newline=)` (3.10+), no `removeprefix`. `tests/test_py38_compat.py` enforces this statically (an interpreter older than 3.11 was not available when this was written).
- Windows file symlinks need a privilege ordinary users often lack; junctions do not. The deck rejects both. Tests that need real file symlinks are skipped where they cannot be created.
