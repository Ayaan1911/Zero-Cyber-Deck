# Incident-response checklist (first hour)

Authority first: confirm you are authorized to examine this system and who owns the decision to isolate it.

1. **Record** time (UTC), who/what reported it, symptoms, your name. (Deck: audit log + report.)
2. **Preserve volatile data before changing anything**: run the deck's Local triage (processes, connections, logins, persistence). It is read-only and writes a hashed snapshot.
3. **Contain** with the owner's approval: unplug network / isolate VLAN. Do not power off if memory evidence matters and policy allows.
4. **Collect** logs and suspect files with "Acquire evidence copy" (hash-verified, read-only copy, custody log). Image disks with a write blocker where possible.
5. **Hash everything** (Forensics -> manifest). Store the manifest separately from the evidence.
6. **Analyze on copies** only. Summarize pcaps with tshark; identify files with `file`.
7. **Eradicate and recover** per the owner's plan: rotate credentials, patch, rebuild from known-good.
8. **Report**: generate the Markdown report, add findings and a timeline, and encrypt the results archive before it leaves the USB.

Notes: results written by the deck are unencrypted. `ps`/network snapshots can contain secrets in command lines. Handle as sensitive data.
