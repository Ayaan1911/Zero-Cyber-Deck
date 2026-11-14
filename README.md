# ZERO CyberSec Deck v2.1

A portable, offline-first, scope-gated collection of security and forensics tooling for **Kali Linux Live (from a Ventoy USB)** and **Windows**. It wraps established tools (Nmap, tshark, Wireshark, Burp Suite, Metasploit, dig, curl, openssl) with authorization checks, logging and reporting. For your own devices, lab environments and explicitly authorized assessments only.

**Not included:** Linux ISOs, Ventoy, Metasploit, Burp, or any third-party binaries. Download them from the official projects (see `SETUP.md`). Nothing here formats disks, installs packages, exploits, brute-forces, captures credentials, or scans on startup.

## Requirements

Python 3.8+ (standard library only), bash on Kali, Windows PowerShell 5.1 on Windows. Everything else is optional and the dashboard tells you what is missing and which package provides it. Full table: [`docs/DEPENDENCIES.md`](docs/DEPENDENCIES.md).

## Quick start

Kali (or any bash + Python 3.8+):
```bash
bash zero-deck.sh --check     # dependency + data-folder report with install hints
bash zero-deck.sh --init-data # once: create the separate data folder (ZERO-DATA); never overwrites anything
bash zero-deck.sh             # keyboard dashboard (arrows/jk, Enter, 1-9, q)
bash zero-deck.sh --plain     # numbered menus (also used automatically without a TTY)
```
Windows:
```powershell
powershell -NoProfile -File .\Start-ZeroDeck.ps1
powershell -NoProfile -File .\Start-ZeroDeck.ps1 -InitData  # once: create the data folder
powershell -NoProfile -File .\Start-ZeroDeck.ps1 -Check     # exit 1 on any problem, including an invalid scope file or an uninitialised data folder
```
Put your authorized targets in **`ZERO-DATA/config/scope.local.txt`** (your data folder, outside the application). `config/scope.txt` in the application folder is the empty release template and is never edited. Architecture and upgrade steps: below and `SETUP.md`.

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
5. **Fail closed:** every run writes its audit entry *before* the command starts. If `ZERO-DATA/results/audit.log` cannot be written (data folder missing or incompatible, full or read-only media, a directory or link anywhere on its path), the action is refused. The audit log is written by one component, `scripts/auditlog.py`, for bash, PowerShell and the scope guard. Result and report files get unique names and are never overwritten.

**Manual tools are different.** Wireshark, Burp Suite, Metasploit and TestDisk are interactive programs the deck cannot constrain. They are marked **[MANUAL]**, require typing `MANUAL` (not `YES`), print an explicit "outside the scope gate" banner, and are audited as `manual`/`LAUNCH`. Metasploit starts as `msfconsole -q` only: no resource scripts, no `-x`, no automation.

The scope file is an operator guardrail, **not** an authorization mechanism. Permission must be real and written.

### What the logs are and are not
`ZERO-DATA/results/audit.log`, custody logs, hash manifests and reports are **plain text files**. They help you reconstruct what happened and detect accidental changes; they are **not tamper-proof**. Anyone with write access to the stick can edit or delete them, and the scope hash in each row only identifies which scope file version was in use. For integrity that matters, hash and store copies elsewhere (the manifest feature helps) or sign them with your own tooling.

Nmap runs with `-n` (no reverse DNS) against the verified IP, so a scan produces no name-resolution traffic of its own. Everything that writes or creates something (notes, reports, triage, manifests, evidence copies, encrypted archives, the Windows SHA-256 report) writes its audit entry first and is refused if that fails.

## Architecture: code and data are separate
```
ZERO-Deck\   the APPLICATION. Code only. Exactly the files in SHA256SUMS.txt. Replaceable. The deck never writes here.
ZERO-DATA\   YOUR data: results\  notes\  evidence\  config\scope.local.txt  archives\  migrations\  + .zerodeck-data (format marker)
```
- The updater (`Install-ZeroDeck.ps1`) installs the application only. It never reads, copies, moves, deletes or replaces anything in `ZERO-DATA`; it only checks the format marker for compatibility *before* activating (a data folder newer than the release is refused) and creates the folder if it does not exist at all. No user data is ever carried into a new application tree, so nothing can go stale or be lost in an update.
- The data folder is found next to the application (`ZERO-DATA`), or via the `ZD_DATA` environment variable. It is **never created implicitly**: run `bash zero-deck.sh --init-data` (or `Start-ZeroDeck.ps1 -InitData`) once. Until then everything that writes (audit log, results, notes, evidence) refuses to run.
- **Migrating from the old layout** (data inside `ZERO-Deck`): `scripts/migrate_data.py --from OLD --to DATA` *copies* (never moves), hash-verifies, refuses links/junctions anywhere, never overwrites, reports a source that changed during the copy, and leaves the original untouched. Back up first: see `SETUP.md`.
- Because the application folder never holds operator files, an installed deployment always verifies against the unmodified release manifest: `python scripts/verify_release.py` (menu: Utilities). The manifest describes the release only; runtime data has its own inventories (evidence manifests, custody logs, migration receipts, session reports).

## Path safety
One mechanism, `scripts/safefs.py`, is used for everything that reads or writes sensitive paths (evidence acquisition, manifests, reports, the audit log, data-folder creation, migration, release verification). It does **not** validate a path and later reopen it by name: each folder is opened once, by walking the whole path without following links, and kept open; every later operation is relative to those held folders.
- **Linux:** `O_NOFOLLOW` + directory file descriptors (`openat`/`mkdirat`/`linkat` semantics). A link at any level, even one swapped in while running, is refused by the OS or leaves us bound to the original folder; `verify_bound()` then reports that the folder at the path is no longer the one we used. New files are created exclusively under a random temporary name, verified by re-reading through the same descriptor, and published with `link()` (never replaces a name). Cleanup unlinks only if the name still refers to the object we created (device + inode). *Residual:* that check and the unlink are two syscalls; the name is 128 random bits created with `O_EXCL`, so replacing it needs write access to the folder *and* the name.
- **Windows (local NTFS/ReFS/exFAT volumes):** every folder from the drive root down is opened with `FILE_FLAG_OPEN_REPARSE_POINT` and **held without `FILE_SHARE_DELETE`**, so while the deck works nobody can rename, delete or replace those folders (or their ancestors) with a junction - tests prove the attacker's `rmdir`/rename fails with a sharing violation. Reparse points are detected on the handle and refused. Files are created with `CREATE_NEW`, delete-on-close armed on *our* handle (failure or a crash removes exactly the object we created, whatever the name now means), verified through the same handle, then disarmed. *Residual:* `chmod`-style read-only marking afterwards is by path; NTFS alternate-stream names, device names and trailing dots are rejected.
- **Refused with a diagnostic instead of claimed safe:** UNC/network paths, non-fixed volumes, `subst`/8.3/non-canonical spellings (the handle's real path must equal the requested path), and macOS. Windows file-sharing behaviour on **exFAT** (the USB data partition) follows the I/O manager but was **not tested on real exFAT**; exFAT has no junctions of its own, so link attacks there can only come from ancestors on NTFS.
- This does not protect against someone who already controls the folder (they can edit the plain-text logs anyway), against a malicious kernel/driver, or provide tamper-proof logs. Outputs (manifests, reports, evidence copies, the audit log) are created or appended through this layer; ordinary result files written by shell redirection into the operator-owned `results` folder (nmap/dig output etc.) are not (documented limitation).
- Paths that legitimately traverse a link are refused; resolve them yourself and pass the real path.

## Raw tool output is sensitive
`curl --head` output is held in memory only and never displayed or saved raw. `scripts/httpsummary.py` shows a sanitized summary: status line, descriptive headers, URL-bearing headers with the URL redacted (entire query, fragment, userinfo, token-like path segments), **cookie names and flags but never values**, and `[REDACTED]` for every other header. curl error text that echoes the request URL is redacted too. Other tools' output (nmap, dig, openssl) is saved as produced; it contains hostnames and addresses of authorized targets and is covered by the "results are plaintext" warning.

## Release checksums
`SHA256SUMS.txt` lists every git-tracked file except itself (a test enforces exact coverage; regenerate with `bash scripts/make-sums.sh` as the last step before a commit). `scripts/verify_release.py` checks an installed application folder against it *exactly* (changed, missing and unlisted files all fail). This shows your copy is consistent with the list; it is **not** an authenticity proof, because anyone who can change a file can regenerate the list. To check authenticity compare the commit hash against one obtained from the repository through a trusted channel.

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
scripts/            safefs.py scope_guard.py evidence.py report.py auditlog.py datadir.py migrate_data.py verify_release.py httpsummary.py redaction.py
tests/              unittest suites + offline sandbox   docs/          dependencies, learning, recovery, IR checklist
```

Add a tool by writing a function and one `reg` (scoped) or `regm` (manual) line in a module.

## Verification status

Run `bash scripts/test-deck.sh` (or `python -B -I -m unittest discover -s tests`). No test can scan, touch a disk or reach the network. The shell tests run with a **restricted PATH**: only stubs (every network, disk and host-inspection tool, including `uname`, `uptime`, `id`, `df`, `ls`) and a short allowlist of benign text utilities exist; anything else triggers `command_not_found_handle` and fails the test. Stub precedence is verified before each run. Python children run with fake DNS and blocked connects, in-process sockets are blocked, and the Windows tests mock all disk queries. The USB installer is covered by fault injection at every step (staging, verification, each rename, each rollback step, real `Copy-Item`/`Rename-Item` failures) against disposable folders, asserting by SHA-256 that nothing in `ZERO-DATA` ever changes and the old application is either intact or preserved. Race tests simulate a link swapped in at the exact windows (between validation passes, while the source is open, during an audit append): on Windows they prove the attacker's rename/delete is *blocked*; on Linux they prove nothing leaks and the swap is detected. Python 3.8 compatibility is checked statically (`tests/test_py38_compat.py`). Repository hygiene (no secrets, results, ISOs, persistence files) is checked against what git would commit and against history.

**Verified on physical hardware:** Ventoy 1.1.18 booted Kali 2026.3 Live, and ZERO Deck v3.0.0 launched from the USB; all 17 checked dependencies, the dashboard and Utilities submenu worked. The Ventoy partition was mounted read-only through `/dev/mapper/VentoyPart`; ZERO-DATA correctly reported NOT READY. See `docs/PHYSICAL-USB-BOOT.md`.

**Not verified:** ZERO-DATA persistence, Secure Boot operation, real Nmap/tshark/Wireshark/Burp/Metasploit behavior, `gpg` encryption, `shellcheck`, running on an actual Python 3.8 interpreter, Windows sharing rules on real exFAT media, and tests requiring real file symlinks on Windows (skipped there without the privilege; they run on Linux).

## Known limitations and security notes

- **exFAT/FAT32 cannot hold ZERO-DATA on Linux.** They have no hard links, which the safe publish step requires, so `--init-data`, evidence acquisition, manifests, reports and migration are **refused there with a diagnostic** (`scripts/fscaps.py`, `bash zero-deck.sh --check`) rather than falling back to a weaker method. Keep the application on exFAT; put the Linux `ZERO-DATA` on ext4 (SETUP.md 'Storage layout'). Hard-link failure is only simulated in the offline tests; real exFAT is not tested yet (docs/KALI-VM-CHECKLIST.md).
- **Results are plaintext** on the (usually exFAT) stick. `chmod`/`umask` do nothing on exFAT. Encrypt with the Utilities gpg item before moving data off the stick. Ventoy provides no encrypted persistence.
- Triage snapshots (`ps`, sockets) can contain secrets; treat as sensitive.
- Redaction is best-effort: it covers the whole query, fragments, userinfo, path parameters and long token-like path segments, not every possible secret location.
- **Platform guarantees are narrower than the code looks.** The race-free file layer is Linux (verified on Ubuntu under WSL, not yet on Kali) and local Windows volumes (verified on NTFS only, not on real exFAT). Network paths, `subst` drives and macOS are refused. Result files produced by shell redirection (nmap, dig, openssl output) are written into the operator-owned results folder by name, not through the safe layer.
- A crash or power cut during an application update can leave `.staging-`/`.bak-` folders and needs the manual steps in `SETUP.md`; exFAT has no journal.
- Nmap uses `-sT` (no root). No UDP, scripts or OS detection by design. When a name has several verified addresses only the first is scanned (the dashboard says so).
- Live Kali without persistence forgets installs and settings on reboot. USB 2.0 is slow; do heavy work on an SSD or VM.

## Boundaries

No exploitation, credential harvesting or guessing, stealth, exfiltration, mass or internet-wide scanning, unattended attacks, or automatic downloads. Third-party tools keep their own licenses.
