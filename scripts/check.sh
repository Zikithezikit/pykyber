#!/usr/bin/env bash
# The gate every commit must pass (AGENTS.md "Before saying you're done").
# Run from the repo root inside the virtualenv that holds requirements-dev.txt.
# CI runs this per commit via `git rebase --exec scripts/check.sh <base>`.
set -euo pipefail

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked --no-fail-fast
maturin develop
python -m pytest python/tests
