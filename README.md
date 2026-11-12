# ZERO CyberSec Deck v1.0 — starter kit

An offline-first, user-controlled collection of portable **diagnostic** scripts and launchers for Windows and Kali Linux. Intended for your own devices, CTF labs, and explicitly authorized assessments.

**This ZIP does not include a Linux ISO, Ventoy binary, MediCat, Metasploit, or other third-party software.** Download verified releases from the official projects. This package doesn't automatically format, partition, install, exploit, or scan anything.

## What's in the kit?
- `zero-deck.sh`: Kali/Linux terminal menu; local inventory; authorized Nmap host discovery, top-100 port and light service inventory; DNS, HTTP headers, HTTPS TLS metadata, SHA-256; interactive launchers for Metasploit, Wireshark, Burp.
- `Start-ZeroDeck.ps1`: Windows PowerShell companion for local inventory, DNS, traceroute, SHA-256.
- `Install-ZeroDeck.ps1`: optional **copy-only** helper that refuses non-USB disks and requests confirmation.
- `config/scope.txt`: empty allowlist; populate with IP/CIDR/exact domains that you are authorized to test.
- `setup-kali.sh`: optional explicitly confirmed package install for basic utilities (no tools auto-installed).
- `scripts/scope_guard.py`: target parser and allowlist gate for Linux scans.
- `scripts/test-deck.sh`: syntax checks and unit tests.
- `SETUP.md`: build steps for Windows + Ventoy + USB.
- `CODEX_BRIEF.md`: prompt for adding tested modules to the project.

## Quick start

1. **Before modifying the USB:** Back up data. Your 64 GB SanDisk Cruzer Blade SDCZ50 is **USB 2.0**, so Linux boot and persistence will be slower than on an SSD.
2. On Windows, extract this ZIP to your laptop. From PowerShell in the extracted `ZERO-Deck` directory:
   ```powershell
   .\Install-ZeroDeck.ps1 -DriveLetter E
   ```
   This copies files and *does not* install Ventoy. If script execution is blocked, use File Explorer to copy the `ZERO-Deck` folder instead.
3. Or run the Windows companion from the extracted folder:
   ```powershell
   powershell -NoProfile -File .\Start-ZeroDeck.ps1
   ```
4. Install Ventoy **manually**, targeting only the correct USB disk, then copy the ISO files to `E:\ISO\` and this `ZERO-Deck` folder to `E:\ZERO-Deck\`. Note that **the first Ventoy install erases the USB**. The drive letter may change.
5. Boot a Kali **Live** ISO from Ventoy. Find/mount the Ventoy data partition (typically exFAT). From within `ZERO-Deck`, run:
   ```bash
   bash zero-deck.sh
   ```
6. Edit `config/scope.txt` with your *own* authorized targets before using scanning actions. Actions ask for confirmation; none run on startup.

See `SETUP.md` for step-by-step and persistence cautions.

## Boundaries
- Network discovery in this version is capped at IPv4 /24.
- No exploitation, credential harvesting, automated vulnerability probing, uncontrolled multi-host scans, packet capture, or internet-wide scanning is shipped.
- The allowlist is an **operator guardrail**, not an authorization mechanism or security boundary. Permission must be real.
- Results are saved to `results/` in **plaintext**, often on an exFAT-formatted flash drive. Treat these as sensitive; encrypt or move off-device as needed.
- Storage is **not** inherently encrypted. Encrypt confidential results and use backups.
- Live Kali without persistence will not retain packages/settings; the shared Ventoy data partition can keep the `ZERO-Deck` scripts/logs if mounted read-write.
- Most USB drives cannot boot into Kali by simply being plugged in after Windows starts. Use the boot menu/UEFI. The Windows companion can run without rebooting.

## Next roadmap
- v1.1: per-target markdown/JSON reports and offline vulnerability reference list.
- v1.2: safer Wireshark/pcap metadata workflows, offline forensics helpers, Windows Sysinternals launcher (downloaded separately).
- v2.0: optional TUI with profiles, integrity checks, user-approved package management.

Third-party tools retain their own licenses and conditions.
