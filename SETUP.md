# Setup guide: SanDisk Cruzer Blade SDCZ50 (64GB, USB 2.0)

## 0. Recommended strategy

Build **Ventoy + Kali Live + SystemRescue + optional Hiren's BootCD PE + scripts**. Skip Parrot and the giant MediCat bundle for v1: they overlap with Kali/recovery tools and slow storage makes a fully persistent workstation unpleasant. Test a plain Kali Live boot before configuring persistence. Use a later USB 3.x SSD for a persistent daily-driver Kali.

## 1. Prepare safely on Windows

1. Confirm the USB in File Explorer and Disk Management by *model, capacity, and disk number*, not just `E:` (drive letters can change). Ensure **nothing on the USB needs saving**.
2. Download Ventoy from **https://www.ventoy.net/en/download.html**. Verify the official download and release checksum/signature if available.
3. Extract Ventoy, run `Ventoy2Disk.exe` as administrator. Confirm the **correct USB disk** before clicking Install. It erases existing USB partitions/data. Do not touch the internal SSD.
4. Ventoy creates a large USB data partition and a small boot partition. Only copy ISO files to the **large data partition**. It is typically exFAT.
5. Create `ISO` and copy in a Kali **Live** ISO from **https://www.kali.org/get-kali/**, and SystemRescue ISO from **https://www.system-rescue.org/Download/**. Optionally add Hiren's BootCD PE **https://www.hirensbootcd.org/download/** and Clonezilla **https://clonezilla.org/downloads.php**.
6. Check each release's SHA-256 checksum as provided by the official publisher. Don't use random re-packed ISOs, especially recovery or security suites.
7. Copy the whole `ZERO-Deck` folder alongside `ISO`. You can copy via Windows Explorer or `Install-ZeroDeck.ps1 -DriveLetter E` **after Ventoy**. The optional helper copies only; does not erase anything.

Expected layout on Ventoy data partition:

```text
[USB data partition]/
├── ISO/
│   ├── kali-linux-...-live-amd64.iso
│   ├── systemrescue-....iso
│   └── hirens-....iso        (optional)
├── ZERO-Deck/
│   ├── zero-deck.sh
│   ├── Start-ZeroDeck.ps1
│   ├── config/scope.txt
│   ├── results/
│   └── ...
└── ventoy/                   (ONLY when configuring optional persistence)
```

## 2. Boot on your ASUS laptop

1. Leave the USB inserted. Shut down/restart, open the ASUS boot menu (commonly **Esc**, but model-dependent).
2. Choose the USB in the boot menu, then select the Kali **Live** ISO inside Ventoy. Avoid the Kali installer when you only want a live environment.
3. If blocked by Secure Boot, check Ventoy's current Secure Boot documentation. Enrollment/boot settings vary by firmware; don't change UEFI settings casually.
4. Boot Kali Live. This does not intentionally install Kali or overwrite Windows.
5. Locate and mount the large Ventoy data partition as read-write. `lsblk -f` helps identify it. It may be auto-mounted in the file manager; otherwise mount the **correct** exFAT partition using the GUI or `udisksctl mount -b /dev/sdX1` after verifying the device name. **Never blindly run any `/dev/sdX` command; the letters can change.**
6. Open a terminal at the mounted `ZERO-Deck` folder and run `bash zero-deck.sh`. Since exFAT does not preserve Linux execute permission flags, use `bash` rather than relying on `./zero-deck.sh`.
7. Add only explicitly authorized target networks/IPs/domains to `config/scope.txt`; to edit, use a Linux text editor or Windows Notepad. Example format is in the file.
8. Test a local inventory command first; then use your *own lab* for the scope-gated Nmap features.

## 3. Persistence is OPTIONAL and must be tested

Ventoy's plugin supports an external persistence backend and a matching `ventoy/ventoy.json`, but support depends on exact Kali Live release. Official Ventoy documentation: **https://www.ventoy.net/en/plugin_persistence.html**. Official Kali persistence documentation: **https://www.kali.org/docs/usb/usb-persistence/**.

- First get plain Ventoy + Kali Live to boot and confirm read/write access to ZERO-Deck.
- If desired, use an ~4–8 GiB persistence file, NOT 16–24 GiB on a small USB 2.0 stick initially.
- The included `config/ventoy.persistence.EXAMPLE.json` is **not active**. It is illustrative only: edit the exact Kali ISO filename and correct backend file path, and consult Ventoy's current Kali-specific instructions (backend filesystem label `persistence`, `persistence.conf` content `/ union`, and Kali's "Live USB Persistence" option). Do not merely rename the example and expect persistence to work.
- Back up before trying persistence. Frequent package writes can be frustrating/slow and increase flash wear.
- Encrypted persistence needs separate setup; no encrypted storage is provisioned by this kit.

## 4. Daily workflow

**No reboot:** On Windows run `Start-ZeroDeck.ps1` for file hashing, DNS, local inventory, traceroute. For advanced commands, use installed Windows tools or a separate VM/WSL instance.

**USB boot:** Restart -> Ventoy -> Kali Live -> mount USB data partition -> `bash zero-deck.sh` -> select a module -> explicitly approve target.

**Large testing workflows:** On this USB 2.0 device, use a Kali VM on laptop SSD for speed while keeping `ZERO-Deck` scripts on USB. Metasploit is launched manually; this kit does not launch exploits.

## 5. Troubleshooting

- Kali not booting: try plain live ISO; check checksum, UEFI/Secure Boot, Ventoy version, alternate boot mode; test SystemRescue.
- Files changed in Kali but disappear: you used non-persistent Live; save scripts/reports to mounted Ventoy data or configure persistence properly.
- `nmap` missing: run `bash setup-kali.sh` to see package choices; install only after review.
- `Out of scope`: edit `config/scope.txt` to list authorized targets. Never auto-add targets just to bypass checks.
- Extremely slow boots: expected with USB 2.0 flash memory; use a USB 3.x SSD for faster persistent OS.
- Windows won't run `.ps1`: PowerShell execution policy can restrict scripts; use File Explorer for copying or run with explicit one-session approval if you understand the policy. Avoid changing system-wide policy.
- The ZIP isn't a runnable complete Kali system: it contains scripts and guides, **not ISO files** or the third-party software.
