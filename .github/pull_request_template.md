<!--
One work package (or smaller) per PR, opened against `dev-v2` from a
`wp<N>-*` branch. Title in Conventional Commits style
(feat:|fix:|test:|ci:|docs:|security:|refactor:). Fold review fixes into the
commit that introduced the problem (--fixup + autosquash); no "fix review"
commits. Mark checklist items n.a. where they don't apply and say why.
-->

## What does this PR do?

## How was it tested?

<!--
Record what you ran and the results. Every commit must pass on its own:

cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --no-fail-fast
maturin develop && pytest python/tests
git rebase --exec '<the same chain>' dev-v2
-->

## Checklist (from AGENTS.md)

- [ ] Spec sections cited in code for new crypto logic
- [ ] Legacy golden vectors pass unchanged
- [ ] No secret-dependent branches, divisions, or indexing (asm checked: yes/no/n.a.)
- [ ] Secret intermediates zeroized on all paths
- [ ] Inputs validated before secret-dependent work
- [ ] No new runtime deps; no unsafe; no panics on untrusted input
- [ ] Tests added (vectors for crypto); fmt/clippy/test/pytest green on every commit (`git rebase --exec`)
- [ ] Review fixes folded into the commits they fix (no "fix review" commits); rebased on current `dev-v2`
- [ ] CHANGELOG updated (if user-visible)
- [ ] Sources checked: <url>, <date>, <result>
