---
name: code-review
description: Use when reviewing a diff or pull request for PetitePass (the SQLCipher password manager). Adversarial, evidence-driven review prioritizing security invariants, contract-vs-implementation honesty, and failure-path/atomicity coverage.
icon: shield
---

# Code review

Review the current change (diff / PR) for PetitePass with a password-manager
mindset. Be adversarial and evidence-driven. A green CI is not proof of
correctness — ask what contract the tests do *not* exercise.

## When to use

Use this when asked to review a change, evaluate a PR, or audit a diff before
merge. For writing a feature use `implement-feature`; for fixing a defect use
`bugfix`.

## Instructions — priorities in order

1. **Security invariants** ([docs/DESIGN.md §9](../../../docs/DESIGN.md#9-invariants-do-not-regress)).
   Check the change does not regress any of:
   - Authentication is decryption (no sidecar verifier, no boolean auth flag).
   - Master password reaches SQLCipher only via peewee's escaping API — no
     `f"PRAGMA key = '{...}'"`.
   - Empty / NUL master rejected before any file is created or replaced.
   - Vault replacement is atomic: verified copy → fatal `fsync` → `os.replace`.
     *Before* the commit a failure leaves the previous vault openable; *after* it
     the new vault is in place.
   - A reopen failure *after* the commit raises `VaultRotatedError` /
     `VaultRestoredError` (not an auth error, not "unchanged"). The old master no
     longer opens the vault.
   - GUI never touches the ORM; the service translates `DatabaseError` into
     `VaultError`; GUI catches `VaultError`.
   - The credential list does not load password ciphertext.

2. **Contract vs. implementation.** Does any docstring / README / PR sentence
   claim more than the code does? Name the exact line and the runtime behavior
   that contradicts it. Treat a misleading comment as a bug.

3. **Failure paths & atomicity.** What happens on wrong/empty/NUL master, a crash
   between copy and `os.replace`, an fsync failure, a post-commit reopen failure,
   a backup dest equal to the live vault? Are these tested, or only the happy
   path?

4. **Tests.** Would each test fail if the behavior it names were reverted, or is
   it a tautology? Are security tests run against real SQLCipher, not mocks?

5. **Correctness & hygiene.** Broad `except` swallowing real errors; leaked
   peewee exceptions; resource leaks; ruff/mypy cleanliness; unnecessary runtime
   dependencies (`pip-audit` gates CI).

Reproduce the important findings before asserting them.

## Output

Report findings most-severe first. For each: file and line, the concrete failure
scenario (inputs → wrong result), the root cause, and a specific fix. Distinguish
BLOCKING (a real security/correctness defect) from advisory. If nothing is wrong,
say so plainly.
