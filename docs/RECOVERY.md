# System recovery playbook

The deck itself only does read-only inspection. Repair tools come from the other ISOs on the stick (SystemRescue, optional Hiren's BootCD PE, Clonezilla).

## Golden rules
1. Stop writing to a failing disk. Every extra write can destroy recoverable data.
2. Image first, repair the image: `ddrescue` (GNU ddrescue, in Kali/SystemRescue) from the failing disk to a file on a DIFFERENT healthy disk, with a map file.
3. Identify devices by size/model/serial (`lsblk -o NAME,SIZE,MODEL,SERIAL`), never by name alone: `/dev/sdX` letters change between boots.
4. Never run repair tools on the Ventoy USB or on the only copy of your data.

## Quick triage (deck: System Recovery menu)
- Disk + partition overview: shows filesystems, labels, mount points.
- SMART health: `smartctl -H -i /dev/sdX` (needs root; many USB bridges do not pass SMART through).
- Reallocated/pending sectors rising = replace the disk.

## Common scenarios
| Symptom | First safe step |
|---|---|
| Windows will not boot | Boot SystemRescue/Hiren's; back up user data from the Windows partition read-only (`mount -o ro`) before any repair |
| Deleted/lost partition | Image the disk, then run TestDisk on the image |
| Forgotten Windows password | Out of scope for this deck; use the vendor's account recovery |
| Filesystem errors | Unmounted + read-only check first: `fsck -n /dev/sdXN` (or `ntfsfix --no-action`); repair only on an image or after a backup |
| Slow/unstable USB | Test the port/cable; check SMART; rewrite from backup |

## Clean shutdown of removable media
Unmount before unplugging (`sync` then `umount`) so exFAT on the Ventoy data partition is not left dirty.
