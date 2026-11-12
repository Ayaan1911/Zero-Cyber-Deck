# Codex collaboration brief — ZERO CyberSec Deck

Open this directory in VS Code/Codex. Treat this as a cross-platform, portable collection of diagnostics, **not** a backdoor, autorun or exploitation framework.

## Non-negotiable engineering requirements
1. Never auto-format disks, partition USB drives, change boot order, disable protections, or install packages without explicit interactive user consent.
2. No automatic scanning on startup. All network actions must be tied to scope allowlist and a confirmation for each run.
3. Never ship exploits, credential capture/guessing, persistence on someone else's system, stealth, exfiltration, mass scanning, or unattended attacks.
4. Quote paths and inputs, never `eval` shell input. Validate targets and URLs; avoid shell injection.
5. Preserve Windows and Bash compatibility. Stay offline-first. Produce a README and unit tests for each module.
6. Encrypt or minimize sensitive assessment data. Default logs are unencrypted; tell the operator. Avoid logging passwords or credentials.
7. Maintain third-party licensing boundaries. Do not bundle copyrighted or unverified security software.
8. Do not claim testing against real hardware until a human actually tests the boot/USB behavior.

## Suggested first Codex task
"Review this repository for Windows PowerShell and Bash correctness, add a safe report index command for authorized sessions, extend the unit tests to cover malformed scope entries and URL edge cases, and run the local tests. Do not touch attached disks or run scans. Return a diff summary and manual verification checklist."

## Example second task
"Add a local, offline file-integrity manifest generator (SHA-256) that does not hash sensitive test logs unless explicitly requested; include tests and update documentation."
