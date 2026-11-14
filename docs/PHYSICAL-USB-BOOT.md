# Physical USB boot checkpoint (Phase 1)

ZERO Deck v3.0.0 launched on physical hardware from a 64 GB USB stick with Ventoy 1.1.18 and Kali Linux 2026.3 Live. Ventoy booted the Kali Live ISO from its exFAT data partition; the same partition held the ZERO-Deck application and Ventoy's boot partitions remained intact. This verifies the boot and application launch path, not persistent ZERO-DATA.

In Kali Live, the Ventoy data partition was accessed through `/dev/mapper/VentoyPart` and mounted read-only. Identify the mapping and check for an existing mount before using these commands; do not mount the underlying partition a second time:

```bash
lsblk -f
findmnt -S /dev/mapper/VentoyPart
sudo mkdir -p /mnt/zero-usb
sudo mount -t exfat -o ro /dev/mapper/VentoyPart /mnt/zero-usb
findmnt -T /mnt/zero-usb -o TARGET,SOURCE,FSTYPE,OPTIONS
```

If it is already mounted, use that mountpoint instead of repeating `mount`. From the mounted application directory:

```bash
cd /mnt/zero-usb/ZERO-Deck
bash zero-deck.sh --check
bash zero-deck.sh
```

All 17 checked dependencies were detected. The interactive dashboard and Utilities submenu worked. ZERO-DATA had not been initialized, so **NOT READY** and a nonzero `--check` result were expected. No results persistence was demonstrated.

Secure Boot operation was not established by this checkpoint. If Secure Boot blocks Ventoy, follow its current Secure Boot guidance; this record makes no claim that enrollment or a Secure Boot boot succeeded.

For shutdown, leave the application directory (`cd /`), close anything using the mount, then run `sync` and `sudo umount /mnt/zero-usb`. If it is busy, close the users of the mount; do not force an unmount or unplug the stick. Shut Kali down normally.

**Phase 2 remains pending:** ZERO-DATA needs a separately mounted filesystem that passes the application's capability checks and survives a reboot. The current exFAT directory cannot be used as Linux ZERO-DATA. No filesystem image, partition change, or Kali persistence backend was part of this checkpoint.
