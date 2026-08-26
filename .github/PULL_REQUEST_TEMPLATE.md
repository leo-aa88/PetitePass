<!--
Thanks for contributing to PetitePass. This is a password manager, so
security-relevant changes are held to the invariants in docs/DESIGN.md §9.
Do NOT include real passwords or vault files anywhere in this PR.
-->

## Summary

<!-- What does this change do, and why? -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] Security fix (also consider whether this warranted a private report — see SECURITY.md)

## Security invariants

<!-- Which invariants in docs/DESIGN.md §9 does this touch, and how do the tests
     exercise them? Write "none" if the change is purely cosmetic/docs. -->

## Checklist

- [ ] `make lint` passes (ruff)
- [ ] `make typecheck` passes (mypy)
- [ ] `make test` passes (pytest against real SQLCipher)
- [ ] Headless GUI smoke test passes if the GUI changed
- [ ] New behavior has tests covering the failure paths, and they would fail if the change were reverted
- [ ] No new runtime dependency (or it is justified above)
- [ ] Docstrings / README / docs are truthful to the code
