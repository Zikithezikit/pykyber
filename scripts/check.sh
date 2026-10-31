#!/usr/bin/env bash
# The gate every commit must pass (AGENTS.md "Before saying you're done").
# Run from the repo root inside the virtualenv that holds requirements-dev.txt.
# Check each commit locally with `git rebase --exec scripts/check.sh <base>`.
set -euo pipefail

# External vectors (never committed). CI runs this script from the tip over
# older commits too, so skip it where the script does not exist yet.
if [ -f scripts/fetch_vectors.py ]; then python scripts/fetch_vectors.py; fi

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked --no-fail-fast
maturin develop
python -m pytest python/tests
