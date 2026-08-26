---
name: bugfix
description: Use when fixing a reported bug or regression in PetitePass (the SQLCipher password manager). Enforces reproduce-first, root-cause fixes, and a regression test that fails if the fix is reverted.
icon: bug
---

# Fix a bug

Guided workflow for fixing a defect in PetitePass. Reproduce before you fix;
prove the fix with a test.

## When to use

Use this when something is broken or behaves incorrectly. For adding new
functionality use `implement-feature`; for reviewing a diff use `code-review`.

## Instructions

1. **Reproduce.** Write a failing test (pytest against real SQLCipher, or a case
   in `tests/smoke_gui.py`) that demonstrates the bug. Do not change any code
   until you have a red test or a reproduction you can run. For
   crypto/auth/vault-file bugs, reproduce against **real SQLCipher** in a
   throwaway venv running the actual code path.

2. **Diagnose the root cause, not the symptom.** Read
   [docs/DESIGN.md](../../../docs/DESIGN.md) and check whether the bug is a
   violation of an existing invariant (§9): authentication is decryption; no
   hand-built `PRAGMA`; reject empty/NUL master; atomic vault replacement;
   distinct post-commit errors; the GUI never touches the ORM; the list never
   loads password ciphertext.

3. **Fix.** Make the smallest change that addresses the root cause. If the bug
   was a contract lie (a docstring/README claim the code does not meet), fix the
   code to meet the claim — do not soften the claim. Keep ruff and mypy clean.

4. **Verify.** The reproduction test now passes and would fail again if the fix
   were reverted. Add regression coverage for adjacent failure paths the bug
   hinted at. Run `make lint && make typecheck && make test` and the headless
   GUI smoke test.

## Output

The fix plus a regression test, all checks green. Commit subject describes the
fix; the body explains the root cause and the failure scenario, and references
the issue if there is one.
