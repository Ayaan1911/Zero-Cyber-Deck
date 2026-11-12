# Setup and manual USB deployment (SanDisk Cruzer Blade 64 GB, USB 2.0)

> **Status:** nothing below has been tested on real hardware. The scripts are tested with automated tests only (see README "Verification status"). Boot/persistence steps follow the vendors' documentation and must be verified by you, one step at a time.

## 0. Strategy

Ventoy + Kali **Live** + SystemRescue (+ optional Hiren's BootCD PE, Clonezilla) + this ZERO-Deck folder. Skip Parrot and giant bundles: USB 2.0 flash makes a fully persistent workstation slow. Get plain Live booting first; add persistence later, optionally. For a daily-driver persistent Kali use a USB 3.x SSD.

## 1. Prepare on Windows (all manual unless noted)

1. **Verify this project**: from Git Bash run `sha256sum -c SHA256SUMS.txt` and the self-tests (`bash scripts/test-deck.sh`).
2. **Back up the USB.** Identify it by *model, size and disk number* in Disk Management, not by drive letter.
3. **Install Ventoy (manual, ERASES the USB).** Download from https://www.ventoy.net/en/download.html, verify its checksum, run `Ventoy2Disk.exe` as administrator, confirm the right disk, and install. Do not touch your internal disk. The big data partition (default label `Ventoy`, exFAT) holds ISOs and ZERO-Deck.
4. **Download ISOs from the official sites only** and verify their SHA-256 against the publisher's value (use the deck: `python scripts\evidence.py verify-file <iso> <sha256>`):
   - Kali **Live** (not installer): https://www.kali.org/get-kali/
   - SystemRescue: https://www.system-rescue.org/Download/
   - optional Hiren's BootCD PE https://www.hirensbootcd.org/download/ , Clonezilla https://clonezilla.org/downloads.php
   Copy them into `ISO\` on the Ventoy data partition.
5. **Copy ZERO-Deck (scripted, no admin needed):**
   ```powershell
   .\Install-ZeroDeck.ps1 -DriveLetter E -DryRun     # lists files; writes nothing
   .\Install-ZeroDeck.ps1 -DriveLetter E             # type COPY; every file is SHA-256 verified after copying
   .\Install-ZeroDeck.ps1 -DriveLetter E -Update     # later refresh; keeps your scope.txt and notes
   ```
   It refuses non-USB disks, refuses a volume not labelled like Ventoy (override with `-AllowNonVentoyLabel` if you renamed it), never copies `results\`, `.git`, or logs, and never formats or installs anything. If script execution is blocked, copy the folder in File Explorer (skip `results\` and `.git`) instead; do not weaken the system execution policy.

Expected layout: see `USB-LAYOUT.txt`.

## 2. Boot your ASUS laptop (manual)

1. With the USB inserted, restart and open the ASUS boot menu (often **Esc** or **F8**, model dependent). Choose the USB, then the Kali **Live** ISO in the Ventoy menu.
2. If Secure Boot blocks Ventoy, follow Ventoy's current Secure Boot documentation (MOK enrollment). Do not change UEFI settings casually; record what you changed.
3. In Kali Live open a terminal. Find the data partition (`lsblk -f`, label `Ventoy`); mount it read-write if not auto-mounted: `udisksctl mount -b /dev/<verified-partition>`. **Never run a command on a `/dev/sdX` you have not verified.**
4. `cd` to the mounted `ZERO-Deck` folder and run `bash zero-deck.sh` (use `bash`; exFAT has no execute bit). Run `bash zero-deck.sh --check` first to see which tools exist.
5. Edit `config/scope.txt` with ONLY your authorized lab targets (list a lab hostname **and** its IP). Test with local inventory first; then your own lab.

Keys in the dashboard: arrows or `j`/`k` move, `Enter` selects, `1`-`9` jump, `q`/Esc goes back. `bash zero-deck.sh --plain` uses numbered menus.

## 3. Persistence (optional; verify against current vendor docs)

Ventoy persistence docs: https://www.ventoy.net/en/plugin_persistence.html ; Kali: https://www.kali.org/docs/usb/usb-persistence/

1. Boot Kali Live non-persistent first and confirm the deck works and can write `results/`.
2. On a Linux machine/VM, use Ventoy's `CreatePersistentImg.sh` (included in the Ventoy Linux tarball) to create an ext4 backend file labelled `persistence` (start with 4-8 GiB) in `persistence/` on the data partition. Inside the filesystem, `persistence.conf` must contain `/ union` (Kali's documented format).
3. Copy `config/ventoy.persistence.EXAMPLE.json` to `ventoy/ventoy.json` on the stick and set `image` to your exact Kali ISO path and `backend` to your `.dat` path. The example file is inactive in `config/`.
4. Boot Kali, select the persistence option if the menu offers one (Kali's menu: "Live USB Persistence"); confirm a test file survives a reboot. Whether Ventoy's injection works for your Kali release must be tested.
5. Cautions: persistence writes wear and slow USB 2.0 flash; keep backups; installed packages persist only if persistence works.
6. **Encryption:** Ventoy's persistence plugin does not provide encrypted persistence, and this kit does not provision any. Protect data with the deck's Utilities item "Encrypt results/ (gpg, AES-256)" before moving it, or use full-disk-encrypted storage you set up yourself on a separate partition (manual, advanced, untested here).

## 4. Daily workflow

- **No reboot (Windows):** `powershell -NoProfile -File .\Start-ZeroDeck.ps1` for hashing, scope-gated DNS/traceroute, triage, reports.
- **USB boot:** Ventoy -> Kali Live -> mount data partition -> `bash zero-deck.sh`.
- **Heavy work:** use a Kali VM on the laptop SSD; keep the scripts on the stick.
- Metasploit/Wireshark/Burp are only launched by you, after typing YES. The deck never runs exploits.

## 5. Troubleshooting

- Kali won't boot: check ISO checksum, UEFI/Secure Boot, newer Ventoy, try SystemRescue to isolate hardware issues.
- Files vanish after reboot: you used non-persistent Live; save to the mounted data partition.
- `Missing tool`: the dashboard shows the apt package. `bash setup-kali.sh` prints the optional package list (dry run) and installs only with `--install` plus typing INSTALL. Installs in Live mode vanish at reboot.
- `OUT OF SCOPE` / `SCOPE ERROR`: edit `config/scope.txt` (see rules inside). Never add a target just to get past the check.
- A hostname is refused although listed: its resolved IPs must be listed too (shown in the message).
- Windows won't run `.ps1`: use `powershell -NoProfile -ExecutionPolicy Bypass -File ...` for that single run, or copy via Explorer.
- Extremely slow boots: expected on USB 2.0.
- Unmount before unplugging (`sync`, then `umount`).

## 6. Hardware verification checklist (you do this; record results)

- [ ] Ventoy installed on the correct disk; ISOs checksum-verified
- [ ] Laptop boots the Ventoy menu (UEFI; Secure Boot state noted)
- [ ] Kali Live boots to desktop; time to boot noted
- [ ] Data partition mounts read-write; `bash zero-deck.sh --check` runs
- [ ] Local inventory works; results written to `results/`
- [ ] Scope-gated lab scan against your own lab VM works and an out-of-scope target is refused
- [ ] (optional) persistence survives a reboot
