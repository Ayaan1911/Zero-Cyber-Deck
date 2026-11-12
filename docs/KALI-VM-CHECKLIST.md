# First Kali Linux VM validation checklist

Goal: check the Linux behaviour that the automated tests on Windows and Ubuntu-under-WSL cannot prove. **Use a throw-away VM with a snapshot. Do not use the physical USB, real targets or valuable evidence.** Nothing here installs Kali or downloads ISOs for you.

## Before you start
- [ ] Kali VM created by you from an ISO you verified yourself; take a snapshot named `clean`.
- [ ] Network: host-only or none. The tests need no network. If you want a scan target, use a second VM you own on the host-only network and put only its IP in your scope file.
- [ ] Copy the project into the VM (shared folder or a clone of the checkpoint commit). Do not copy real data.

## 1. Versions (record them)
```
python3 --version         # needs 3.8 or newer
bash --version | head -1  # 4.4 or newer recommended
uname -sr; id -un; findmnt -no FSTYPE,OPTIONS -T .   # filesystem type of the project folder
```
- [ ] Python >= 3.8 and bash >= 4.4. Optional tools (nmap, tshark, gpg ...) may be missing: `--check` lists them.

## 2. Offline automated tests (no scans, no network, no disk operations)
```
sha256sum -c SHA256SUMS.txt            # every line OK
python3 -B -I -m unittest discover -s tests
```
- [ ] Record the exact `Ran N tests` and `OK (skipped=M)` lines. Windows-only tests are skipped; investigate (record, do not edit) any FAIL or ERROR.

## 3. Dashboard startup and dependency detection
- [ ] `bash zero-deck.sh --check` prints a dependency table and the data-folder status. With no data folder it says NOT READY and exits 1 (expected).
- [ ] `bash zero-deck.sh --plain` opens and `q` quits. Then `bash zero-deck.sh` (raw-key mode): arrows, Enter, Esc and `q` work in the VM terminal.

## 4. Data initialisation on a SUPPORTED filesystem (ext4 in the VM's home)
```
export ZD_DATA="$HOME/ZERO-DATA-test"
bash zero-deck.sh --init-data     # expect: OK ... data format 1
bash zero-deck.sh --check         # expect: READY, "Publish capability: OK", exit 0
mkdir "$HOME/zd-probe" && python3 scripts/fscaps.py probe --dir "$HOME/zd-probe" --approve-disposable-dir   # expect VERDICT: SUPPORTED; folder empty afterwards
```
- [ ] Run `--init-data` again: succeeds and changes nothing. Put a file in `$ZD_DATA/notes`, run it again: the file is still there.

## 5. Data initialisation on an UNSUPPORTED filesystem (expected refusal)
Only with a disposable image you create inside the VM yourself (a loopback **file** formatted exFAT with `mkfs.exfat`, never a real disk). Mount it, then:
```
ZD_DATA=<mountpoint>/ZERO-DATA bash zero-deck.sh --init-data
```
- [ ] Expect a refusal that names hard links, and no `ZERO-DATA` folder left behind. This is the first test on the **real** exFAT kernel driver: record the message and the `fscaps.py probe` output, because the real driver may differ from the simulation.
- [ ] Optionally repeat on an NTFS image (`mkfs.ntfs` on a file) and note whether the probe says supported, unsupported or unverified.

## 6. Local tool launch (no network targets)
- [ ] Utilities > local inventory and triage run, files appear under `$ZD_DATA/results`, and the audit log gets its line first.
- [ ] A scoped action against an address **outside** your scope file is refused before anything runs. With a second VM you own: the typed `YES` is required and then it runs.
- [ ] Manual tools (Wireshark, Burp, Metasploit) show "MANUAL" and launch nothing automatically.

## 7. Evidence and report (throw-away files only)
- [ ] Acquire a small test folder into `$ZD_DATA/evidence`, verify the manifest, build a report; compare hashes with `sha256sum` yourself.
- [ ] The same commands against the unsupported mount from step 5 refuse and write nothing.

## Stop conditions
Stop and report if a test fails, a command asks for credentials or a real target, anything needs a `/dev/...` path, or anything writes outside the project and data folders. Revert the VM to the `clean` snapshot afterwards.
