# ZERO CyberSec Deck v2.0

A portable, offline-first, scope-gated collection of security and forensics tooling for **Kali Linux Live (from a Ventoy USB)** and **Windows**. It wraps established tools (Nmap, tshark, Wireshark, Burp Suite, Metasploit, dig, curl, openssl) with authorization checks, logging and reporting. For your own devices, lab environments and explicitly authorized assessments only.

**Not included:** Linux ISOs, Ventoy, Metasploit, Burp, or any third-party binaries. Download them from the official projects (see `SETUP.md`). Nothing here formats disks, installs packages, exploits, brute-forces, captures credentials, or scans on startup.

## Quick start

Kali (or any bash + Python 3.8+):
```bash
bash zero-deck.sh --check     # dependency report with install hints
bash zero-deck.sh             # keyboard dashboard (arrows/jk, Enter, 1-9, q)
bash zero-deck.sh --plain     # numbered menus (also used automatically without a TTY)
```
Windows:
```powershell
powershell -NoProfile -File .\Start-ZeroDeck.ps1
powershell -NoProfile -File .\Start-ZeroDeck.ps1 -Check
```
Put your authorized targets in `config/scope.txt` first. Full USB build steps: `SETUP.md`.

## Dashboard categories

| Category | Items |
|---|---|
| Network | local inventory; Nmap host discovery (/24 max); top-100 port/service inventory; validated custom ports; Wireshark; Metasploit console (manual) |
| Web Security | DNS A lookup; HTTP headers; TLS certificate summary; Burp Suite (manual) |
| Forensics | SHA-256; verify against expected hash; folder manifests + verification; hash-verified read-only evidence copy with custody log; pcap summary (tshark); file type |
| Incident Response | read-only local triage snapshot (hashed); Markdown session report; audit-log viewer; IR checklist |
| CTF / Learning | offline resource index; note templates |
| System Recovery | lsblk overview; SMART health; recovery playbook; TestDisk (manual) |
| Utilities | dependency check; scope validation; self-tests; gpg-encrypted results archive |

`[+]` = ready, `[-]` = a dependency is missing (the tool and its `apt` package are shown; the item will not run).

## How authorization works

Every active action goes through `scripts/scope_guard.py` (same engine on Kali and Windows):

1. Scope entries: IPv4, IPv4 CIDR **no broader than /24**, exact FQDN. IPv6 and malformed entries are rejected.
2. Targets are validated and **normalized**; option-like, whitespace, shell metacharacter and malformed inputs are rejected.
3. A hostname must be listed **and every IPv4 address it resolves to must be inside a listed network**: DNS cannot widen scope. The tool then connects to the **verified IP** (pinned: `curl --resolve`, Nmap on the address), not a fresh lookup.
4. URLs: http/https only, no credentials, no curl globbing characters (`[]{}`), no whitespace/quotes; `curl --globoff --noproxy '*' --max-redirs 0`.
5. You must type `YES` per run. Every decision (ALLOW/DENY/ERROR/CONFIRMED/CANCELLED/RUN) is appended to `results/audit.log` with time, user, action, target and scope-file hash. If the audit log cannot be written the gate **fails closed**.

The scope file is an operator guardrail, **not** an authorization mechanism. Permission must be real and written.

## Project layout

```
zero-deck.sh        dashboard entry point        Start-ZeroDeck.ps1   Windows companion
lib/common.sh       registry, gate, logging      Install-ZeroDeck.ps1 safe copy-only USB deploy
lib/ui.sh           keyboard UI (pure bash)      setup-kali.sh        optional, confirmed apt install
modules/*.sh        one file per category        config/              scope.txt, Ventoy example
scripts/            scope_guard.py evidence.py report.py test-deck.sh
tests/              Python unittest suites       docs/                learning, recovery, IR checklist
```

Add a tool by writing a function and one `reg "<Category>" "<label>" <function> "<deps>"` line in a module.

## Verification status

Run `bash scripts/test-deck.sh` (or `python -B -I -m unittest discover -s tests`). The suites cover the scope guard (malformed targets, out-of-scope/DNS-widening, URL globbing, BOM/encoding, injection strings, audit/fail-closed), evidence and report utilities, the shell dashboard and gates with stubbed tools, and PowerShell parsing/gates on Windows.

**Not verified:** booting from the USB, Ventoy, Kali Live on the ASUS laptop, persistence, real Nmap/tshark/Wireshark/Burp/Metasploit behavior, the raw-key UI in a real Kali terminal, and `gpg` encryption. These need a human with the hardware (`SETUP.md` section 6).

## Known limitations and security notes

- **Results are plaintext** on the (usually exFAT) stick. `chmod`/`umask` do nothing on exFAT. Encrypt with the Utilities gpg item before moving data off the stick. Ventoy provides no encrypted persistence.
- Triage snapshots (`ps`, sockets) can contain secrets; treat as sensitive.
- The DNS pinning check is a point-in-time resolution. A host that changes DNS answers between the check and the scan cannot redirect the scan (pinned IP), but you must still list the right IPs.
- Nmap is invoked with `-sT` (no root needed). No UDP, no scripts, no OS detection by design.
- Metasploit, Wireshark, Burp and TestDisk are launched interactively; their own actions are outside the scope gate and under your control and responsibility.
- Live Kali without persistence forgets installs and settings on reboot. USB 2.0 is slow; do heavy work on an SSD or VM.

## Boundaries

No exploitation, credential harvesting or guessing, stealth, exfiltration, mass or internet-wide scanning, unattended attacks, or automatic downloads. Third-party tools keep their own licenses.
