# shellcheck shell=bash
# System recovery: read-only disk overview and health, playbook; TestDisk is a MANUAL launcher.

disk_overview() { logrun disk_overview lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,MOUNTPOINTS; }

smart_health() {
  local dev
  read -r -p 'Device (e.g. /dev/sda): ' dev
  [[ "$dev" =~ ^/dev/[a-z0-9]+$ ]] || { say 'Invalid device path.'; return 0; }
  [ -b "$dev" ] || { say 'Not a block device.'; return 0; }
  logrun smart_health smartctl -H -i "$dev"
}

recovery_playbook() { show_doc "$ROOT/docs/RECOVERY.md"; }

testdisk_launch() {
  launch_manual testdisk 'TestDisk can WRITE to disks. Image the failing disk first (ddrescue) and work on the copy. Never run it on the Ventoy USB or your only copy of data.'
}

reg "System Recovery" "Disk + partition overview (lsblk, read-only)" disk_overview "lsblk"
reg "System Recovery" "SMART health of a disk (read-only)" smart_health "smartctl"
reg "System Recovery" "Recovery playbook (offline)" recovery_playbook ""
regm "System Recovery" "TestDisk (can write to disks)" testdisk_launch "testdisk"
