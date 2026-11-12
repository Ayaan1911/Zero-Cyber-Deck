# Setup and manual USB deployment (SanDisk Cruzer Blade 64 GB, USB 2.0)

> **Status:** nothing below has been tested on real hardware. The scripts are tested with automated tests only (see README "Verification status"). Boot/persistence steps follow the vendors' documentation and must be verified by you, one step at a time.

## 0. Strategy

Ventoy + Kali **Live** + SystemRescue (+ optional Hiren's BootCD PE, Clonezilla) + this ZERO-Deck folder. Skip Parrot and giant bundles: USB 2.0 flash makes a fully persistent workstation slow. Get plain Live booting first; add persistence later, optionally. For a daily-driver persistent Kali use a USB 3.x SSD.

## 1. Prepare on Windows (all manual unless noted)

1. **Verify this project**: from Git Bash run `sha256sum -c SHA256SUMS.txt` and the self-tests (`bash scripts/test-deck.sh`). `SHA256SUMS.txt` lists every git-tracked release file except itself; it proves your copy is *consistent* with the list, **not authentic**: anyone able to change a file can change the list too. For authenticity compare the commit hash with one you obtained from the repository over a channel you trust.
2. **Back up the USB.** Identify it by *model, size and disk number* in Disk Management, not by drive letter.
3. **Install Ventoy (manual, ERASES the USB).** Download from https://www.ventoy.net/en/download.html, verify its checksum, run `Ventoy2Disk.exe` as administrator, confirm the right disk, and install. Do not touch your internal disk. The big data partition (default label `Ventoy`, exFAT) holds ISOs and ZERO-Deck.
4. **Download ISOs from the official sites only** and verify their SHA-256 against the publisher's value (use the deck: `python scripts\evidence.py verify-file <iso> <sha256>`):
   - Kali **Live** (not installer): https://www.kali.org/get-kali/
   - SystemRescue: https://www.system-rescue.org/Download/
   - optional Hiren's BootCD PE https://www.hirensbootcd.org/download/ , Clonezilla https://clonezilla.org/downloads.php
   Copy them into `ISO\` on the Ventoy data partition.
5. **Install the application (scripted, no admin needed).** The stick holds TWO separate folders:
   - `ZERO-Deck\` - the application: code only, exactly the files listed in `SHA256SUMS.txt`. Replaceable.
   - `ZERO-DATA\` - **yours**: results, notes, evidence, your scope file, the audit log, archives, migration receipts. The installer never reads, copies, moves, deletes or replaces anything in it.
   ```powershell
   .\Install-ZeroDeck.ps1 -DriveLetter E -DryRun     # verifies the release, shows the plan; writes nothing
   .\Install-ZeroDeck.ps1 -DriveLetter E             # first install (type COPY)
   .\Install-ZeroDeck.ps1 -DriveLetter E -Update     # replace the application; the old one is kept
   ```
   **How an install/update works.** (1) The release you run it from is verified against its own `SHA256SUMS.txt`. (2) Exactly the listed files (plus the manifest) are copied into `ZERO-Deck.staging-<time>` and each is hash-verified; the staged tree must be *exactly* the release. (3) The data folder's format marker is *checked* (never its contents); a data folder that is newer than this release is refused ("do not downgrade"). (4) Two directory renames: old `ZERO-Deck` -> `ZERO-Deck.bak-<time>`, stage -> `ZERO-Deck`. (5) The installed tree is verified against the manifest again. (6) `ZERO-DATA` is created, with its marker, **only if it does not exist at all**. If any step fails, the renames are undone (a bad new tree is renamed to `ZERO-Deck.failed-<time>`, never removed); if even that fails, the script stops with exact recovery instructions. Your data is not involved in any of it, and no user data is ever copied into the new application folder. Old application versions are kept as `.bak-` folders for manual recovery; delete them yourself when you are satisfied.
   It also refuses a destination or parent that is a link/junction, refuses a source containing a link/junction or any file that differs from its manifest, refuses non-USB disks and volumes not labelled like Ventoy (override with `-AllowNonVentoyLabel` if you renamed it), and never formats or installs anything. If script execution is blocked, copy the release folder in File Explorer instead; do not weaken the system execution policy.
6. **Upgrading from the old layout (data inside `ZERO-Deck\`).** The installer detects it (names only; contents are never read) and **refuses to activate** until you have copied your data out, because the new release would not see it. Do this once:
   1. **Back up first**: copy the whole old `ZERO-Deck\` folder somewhere else (File Explorer, to your laptop's disk). Close the deck and anything using the stick.
   2. `python scripts\migrate_data.py --from E:\ZERO-Deck --to E:\ZERO-DATA --dry-run`, then without `--dry-run`. It **copies** `results\`, `notes\` and your scope files, hash-verifies every file, never overwrites (identical files are skipped, different ones are a CONFLICT that aborts before anything is written), refuses links/junctions anywhere (including a `config` that is a junction), re-checks the source afterwards (exit 3 = it changed while migrating; re-run), and writes a receipt in `ZERO-DATA\migrations\`. The original is never touched.
   3. Check your files in `ZERO-DATA\`. An edited old `config\scope.txt` arrives as `config\legacy-scope.txt` for you to review; your `scope.local.txt` arrives as is.
   4. Run the `-Update` install. The old application (with your original data) stays in `ZERO-Deck.bak-<time>` as your safety copy. (`-AcknowledgeLegacyData` overrides the check if you have deliberately decided not to migrate.)

   **Back up your data before migrating or deleting anything**: copy `ZERO-DATA\` (and, for the old layout, the old `ZERO-Deck\`) to another disk; verify with `python scripts\evidence.py manifest <folder> <out>` and `verify`.

   **Recovering from an interrupted or failed install/update (manual).**
   - Message `UPDATE ABORTED, NOTHING CHANGED`: the application folder was not touched. Inspect, then delete the named `.staging-` folder when you wish.
   - Message `UPDATE ROLLED BACK`: the original application folder is back in place; the unverified new tree is at the named `.failed-` folder.
   - Message `MANUAL RECOVERY REQUIRED`: **no data was deleted** (and the data folder was never involved). The message names where your original application folder is (normally `ZERO-Deck.bak-<time>`). Rename that folder back to `ZERO-Deck`, after moving any other `ZERO-Deck` folder out of the way.
   - Power loss, crash or unplugging **between the two renames** leaves `ZERO-Deck.bak-<time>` and no `ZERO-Deck`: rename the `.bak-` folder back to `ZERO-Deck`. `ZERO-DATA` is unaffected.

   **Limits.** Folder renames are not an atomic transaction and exFAT has no journal: after a crash you may need the manual steps above, and a half-copied `.staging-` folder may remain. The design guarantees that the installer never deletes or moves anything and never touches `ZERO-DATA`; it does not guarantee that a power cut leaves the stick tidy. A folder open in another program (Explorer window, antivirus scan) can make a rename fail; the script then rolls back or asks for manual recovery. exFAT behaviour of the sharing rules the safety layer relies on was not tested on real exFAT (see README "Path safety"). Disk space for the staged copy (about 1.2x the release) is required.

Expected layout: see `USB-LAYOUT.txt`.

## 2. Boot your ASUS laptop (manual)

1. With the USB inserted, restart and open the ASUS boot menu (often **Esc** or **F8**, model dependent). Choose the USB, then the Kali **Live** ISO in the Ventoy menu.
2. If Secure Boot blocks Ventoy, follow Ventoy's current Secure Boot documentation (MOK enrollment). Do not change UEFI settings casually; record what you changed.
3. In Kali Live open a terminal. Find the data partition (`lsblk -f`, label `Ventoy`); mount it read-write if not auto-mounted: `udisksctl mount -b /dev/<verified-partition>`. **Never run a command on a `/dev/sdX` you have not verified.**
4. `cd` to the mounted `ZERO-Deck` folder (the sibling `ZERO-DATA` is found automatically; override with `ZD_DATA=/path`) and run `bash zero-deck.sh` (use `bash`; exFAT has no execute bit). Run `bash zero-deck.sh --check` first to see which tools exist.
5. Initialise the data folder once (`bash zero-deck.sh --init-data`; the installer already did it if it was absent), then create `ZERO-DATA/config/scope.local.txt` with ONLY your authorized lab targets (list a lab hostname **and** its IP). The `config/scope.txt` inside the application folder is the empty release template and is never edited. Test with local inventory first; then your own lab. Wireshark, Burp, Metasploit and TestDisk are **[MANUAL]** items: the scope gate cannot constrain them.

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
- Wireshark, Burp, Metasploit and TestDisk are **[MANUAL]** items: you must type `MANUAL` (not `YES`) to launch them, they are audited as `manual`, and the scope gate cannot constrain what they do. Scoped actions (Nmap, DNS, HTTP headers, TLS) ask for `YES` after a no-DNS pre-check and then resolve and verify the target. The deck never runs exploits.

## 5. Troubleshooting

- Kali won't boot: check ISO checksum, UEFI/Secure Boot, newer Ventoy, try SystemRescue to isolate hardware issues.
- Files vanish after reboot: you used non-persistent Live; save to the mounted data partition.
- `Missing tool`: the dashboard shows the apt package. `bash setup-kali.sh` prints the optional package list (dry run) and installs only with `--install` plus typing INSTALL. Installs in Live mode vanish at reboot.
- `OUT OF SCOPE` / `SCOPE ERROR`: edit your scope file (`config/scope.local.txt`; rules are in the template `config/scope.txt`). Never add a target just to get past the check.
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
- [ ] `Install-ZeroDeck.ps1 -DryRun`, then a real install, then `-Update`: your own test file in `results\` is still there, byte-identical, and a `.bak-` folder exists
- [ ] (optional) persistence survives a reboot
