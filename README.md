# ZERO CyberSec Deck v2.1

A portable, offline-first, scope-gated collection of security and forensics tooling for **Kali Linux Live (from a Ventoy USB)** and **Windows**. It wraps established tools (Nmap, tshark, Wireshark, Burp Suite, Metasploit, dig, curl, openssl) with authorization checks, logging and reporting. For your own devices, lab environments and explicitly authorized assessments only.

**Not included:** Linux ISOs, Ventoy, Metasploit, Burp, or any third-party binaries. Download them from the official projects (see `SETUP.md`). Nothing here formats disks, installs packages, exploits, brute-forces, captures credentials, or scans on startup.

## Requirements

Python 3.8+ (standard library only), bash on Kali, Windows PowerShell 5.1 on Windows. Everything else is optional and the dashboard tells you what is missing and which package provides it. Full table: [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md).

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
powershell -NoProfile -File .\Start-ZeroDeck.ps1 -Check     # exit 1 on any problem, including an invalid scope file
```
Put your authorized targets in **`config/scope.local.txt`** (untracked, git-ignored; it takes precedence). `config/scope.txt` is the empty template and must stay empty in git. Full USB build steps: `SETUP.md`.

## Dashboard categories

| Category | Items |
|---|---|
| Network | local inventory; Nmap host discovery (/24 max); top-100 port/service inventory; validated custom ports; **[MANUAL]** Wireshark; **[MANUAL]** Metasploit console |
| Web Security | DNS A lookup (drift-checked); HTTP headers; TLS certificate summary; **[MANUAL]** Burp Suite |
| Forensics | SHA-256; verify against expected hash; folder manifests + verification; hash-verified read-only evidence copy with custody log; pcap summary (tshark); file type |
| Incident Response | read-only local triage snapshot (hashed); Markdown session report; audit-log viewer; IR checklist |
| CTF / Learning | offline resource index; note templates |
| System Recovery | lsblk overview; SMART health; recovery playbook; **[MANUAL]** TestDisk |
| Utilities | dependency check; scope validation; self-tests; gpg-encrypted results archive |

`[+]` = ready, `[-]` = a dependency is missing (the tool and its `apt` package are shown; the item will not run).

## How authorization works

Scoped (automated) actions go through `scripts/scope_guard.py`, the same engine on Kali and Windows:

1. **Scope entries:** IPv4, IPv4 CIDR **no broader than /24**, exact FQDN. IPv6 and malformed entries are rejected.
2. **Inputs** are validated and **normalized**; option-like, whitespace, shell-metacharacter and malformed targets are rejected before any tool runs.
3. **DNS policy (three steps, nothing is looked up before you agree):**
   1. *Pre-check, no DNS:* syntax, listed name or in-network IP.
   2. *You type `YES`.* For a listed name this also authorizes one DNS lookup of that name.
   3. *Resolve and verify:* every IPv4 answer must lie inside a listed network, otherwise the run is denied. The tool then connects to the **verified IP** (`curl --resolve`, Nmap on the address), never to a fresh lookup.
   `dig` and `Resolve-DnsName` are informational: any answer outside the verified set is flagged as **DNS drift** and logged. An unlisted name is denied without being resolved.
4. **URLs:** http/https only, no credentials, no curl globbing characters (`[]{}`), no whitespace or quotes; `curl --globoff --noproxy '*' --max-redirs 0`. The **entire query string** (keyed or not: `?token=x`, `?SECRET`), the fragment, userinfo, path parameters (`;jsessionid=`) and long token-like path segments are **redacted** on screen and in every log; the tool itself still receives the real URL. Redaction is best-effort: a secret in an ordinary short path segment cannot be recognised, and raw tool output (e.g. a curl error) may echo a URL. Response headers saved in `results/` may contain cookies or tokens.
5. **Fail closed:** every run writes its audit entry *before* the command starts. If `results/audit.log` cannot be written (full or read-only media, a directory or link in its place), the action is refused. Result and report files get unique names and are never overwritten.

**Manual tools are different.** Wireshark, Burp Suite, Metasploit and TestDisk are interactive programs the deck cannot constrain. They are marked **[MANUAL]**, require typing `MANUAL` (not `YES`), print an explicit "outside the scope gate" banner, and are audited as `manual`/`LAUNCH`. Metasploit starts as `msfconsole -q` only: no resource scripts, no `-x`, no automation.

The scope file is an operator guardrail, **not** an authorization mechanism. Permission must be real and written.

### What the logs are and are not
`results/audit.log`, custody logs, hash manifests and reports are **plain text files**. They help you reconstruct what happened and detect accidental changes; they are **not tamper-proof**. Anyone with write access to the stick can edit or delete them, and the scope hash in each row only identifies which scope file version was in use. For integrity that matters, hash and store copies elsewhere (the manifest feature helps) or sign them with your own tooling.

Nmap runs with `-n` (no reverse DNS) against the verified IP, so a scan produces no name-resolution traffic of its own. Everything that writes or creates something (notes, reports, triage, manifests, evidence copies, encrypted archives, the Windows SHA-256 report) writes its audit entry first and is refused if that fails.

## Path safety
- A symlink, junction or other reparse point **anywhere** in an input or output path, including ancestor folders (`alias\evidence` where `alias` is a link), is rejected. Nothing is resolved through links; paths are normalized lexically and every existing component is checked.
- **Linux/macOS:** creation walks the path with `O_NOFOLLOW` and directory file descriptors, so a link swapped in while the operation runs is refused by the OS (no check-then-use race).
- **Windows:** there is no equivalent primitive here, so each step is *validate chain, exclusive create, re-validate*. A link swapped in during the few milliseconds between validation and creation is detected afterwards and the file just created is removed, but data could briefly exist at the redirected location. Mitigation: do not run the deck on a stick or folder that another process can modify concurrently.
- Paths that legitimately traverse a link (macOS `/var`, OneDrive placeholders, `subst` drives) are refused; resolve them yourself and pass the real path.
- Outputs (manifests, reports, evidence copies, result files) are created exclusively and never overwritten.

## Release checksums
`SHA256SUMS.txt` lists every git-tracked file except itself (a test enforces exact coverage; regenerate with `bash scripts/make-sums.sh` as the last step before a commit). It shows your copy is consistent with the list; it is **not** an authenticity proof, because anyone who can change a file can regenerate the list. To check authenticity compare the commit hash against one obtained from the repository through a trusted channel.

## Evidence handling rules
- Symlinks, junctions and other reparse points are **rejected** (never followed) by evidence acquisition, manifests, verification, reports and the USB installer.
- Manifests and evidence copies are never overwritten. `verify` fails on changed, missing **and unlisted** files (`--allow-extra` to relax).
- Acquisition copies are read-only and hash-verified, with a JSONL custody log.

## Project layout

```
zero-deck.sh        dashboard entry point        Start-ZeroDeck.ps1   Windows companion
lib/common.sh       registry, gate, logging      Install-ZeroDeck.ps1 staged, verified USB copy (no formatting)
lib/ui.sh           keyboard UI (pure bash)      setup-kali.sh        optional, confirmed apt install
modules/*.sh        one file per category        config/              scope.txt (template), Ventoy example
scripts/            scope_guard.py evidence.py report.py pathsafe.py test-deck.sh
tests/              unittest suites + offline sandbox   docs/          dependencies, learning, recovery, IR checklist
```

Add a tool by writing a function and one `reg` (scoped) or `regm` (manual) line in a module.

## Verification status

Run `bash scripts/test-deck.sh` (or `python -B -I -m unittest discover -s tests`). No test can scan, touch a disk or reach the network. The shell tests run with a **restricted PATH**: only stubs (every network, disk and host-inspection tool, including `uname`, `uptime`, `id`, `df`, `ls`) and a short allowlist of benign text utilities exist; anything else triggers `command_not_found_handle` and fails the test. Stub precedence is verified before each run. Python children run with fake DNS and blocked connects, in-process sockets are blocked, and the Windows tests mock all disk queries. The USB update is covered by fault injection at every step (staging, user-data copy, verification, each rename, each rollback step, real `Copy-Item`/`Rename-Item` failures) against disposable folders, asserting by SHA-256 that no evidence file disappears or changes. Python 3.8 compatibility is checked statically (`tests/test_py38_compat.py`). Repository hygiene (no secrets, results, ISOs, persistence files) is checked against what git would commit and against history.

**Not verified (needs a human, Kali, or hardware):** booting from the USB, Ventoy, Kali Live on the ASUS laptop, persistence, real Nmap/tshark/Wireshark/Burp/Metasploit behavior, the raw-key UI in a real Kali terminal, `gpg` encryption, `shellcheck`, running on an actual Python 3.8 interpreter, and the tests that need real file symlinks (skipped where the privilege is missing).

## Known limitations and security notes

- **Results are plaintext** on the (usually exFAT) stick. `chmod`/`umask` do nothing on exFAT. Encrypt with the Utilities gpg item before moving data off the stick. Ventoy provides no encrypted persistence.
- Triage snapshots (`ps`, sockets) can contain secrets; treat as sensitive.
- Redaction is best-effort: it covers query values, fragments, userinfo and long token-like path segments, not every possible secret location.
- Nmap uses `-sT` (no root). No UDP, scripts or OS detection by design. When a name has several verified addresses only the first is scanned (the dashboard says so).
- Live Kali without persistence forgets installs and settings on reboot. USB 2.0 is slow; do heavy work on an SSD or VM.

## Boundaries

No exploitation, credential harvesting or guessing, stealth, exfiltration, mass or internet-wide scanning, unattended attacks, or automatic downloads. Third-party tools keep their own licenses.
