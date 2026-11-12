#!/usr/bin/env bash
# Maintainer tool: regenerate SHA256SUMS.txt for every git-tracked (or about-to-be-tracked) file except itself.
# Run it as the LAST step before committing: tests/test_repo_hygiene.py fails if the list is stale or incomplete.
# The list proves consistency of a copy with this list, NOT authenticity.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
git ls-files --cached --others --exclude-standard | grep -v '^SHA256SUMS.txt$' | LC_ALL=C sort | xargs sha256sum --text > SHA256SUMS.txt
echo "SHA256SUMS.txt: $(wc -l < SHA256SUMS.txt) entries"
