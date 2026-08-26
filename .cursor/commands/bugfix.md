# Fix a bug

Fix the reported bug in PetitePass. Reproduce before you fix; prove the fix with
a test.

## 1. Reproduce
- Write a failing test (pytest against real SQLCipher, or a case in
  `tests/smoke_gui.py`) that demonstrates the bug. Do not fix anything until you
  have a red test or a reproduction you can run.
- For crypto/auth/vault-file bugs, reproduce against **real SQLCipher** — set up
  a throwaway venv and run the actual code path.

## 2. Diagnose
- Find the root cause, not the symptom. Read [docs/DESIGN.md](../../docs/DESIGN.md)
  to check whether the bug is a violation of an existing invariant (auth =
  decryption, atomic replacement, no hand-built PRAGMA, reject empty/NUL master,
  distinct post-commit errors, GUI never touches the ORM).

## 3. Fix
- Make the smallest change that addresses the root cause.
- If the bug was a contract lie (docstring/README claims more than the code
  does), fix the code to meet the claim — do not soften the claim.
- Keep ruff and mypy clean.

## 4. Verify
- The reproduction test now passes; it would fail again if the fix were reverted.
- Add regression coverage for adjacent failure paths the bug hinted at.
- Run: `make lint && make typecheck && make test` and the headless GUI smoke test.

## 5. Deliver
- Commit: subject describes the fix; body explains the root cause and the failure
  scenario. Reference the issue if there is one.
