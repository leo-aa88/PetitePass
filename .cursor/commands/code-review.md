# Code review

Review the current change (diff / PR) for PetitePass with a password-manager
mindset. Be adversarial and evidence-driven. A green CI is not proof of
correctness — ask what contract the tests do *not* exercise.

## Priorities, in order

1. **Security invariants** ([docs/DESIGN.md §9](../../docs/DESIGN.md#9-invariants-do-not-regress)).
   For each, check the change does not regress it:
   - Authentication is decryption (no sidecar verifier, no boolean auth flag).
   - Master password reaches SQLCipher only via peewee's escaping API — no
     `f"PRAGMA key = '{...}'"`.
   - Empty / NUL master rejected before any file is created or replaced.
   - Vault replacement is atomic: verified copy → fatal `fsync` → `os.replace` →
     best-effort post-commit. A failure leaves the previous vault openable.
   - Post-commit failures raise `VaultRotatedError` / `VaultRestoredError`, not an
     auth error.
   - GUI never touches the ORM; the service translates `DatabaseError` into
     `VaultError`; GUI catches `VaultError`.
   - The credential list does not load password ciphertext.

2. **Contract vs. implementation.** Does any docstring / README / PR sentence
   claim more than the code does? Name the exact line and the runtime behavior
   that contradicts it. Treat a misleading comment as a bug.

3. **Failure paths & atomicity.** What happens on wrong/empty/NUL master, a crash
   between copy and `os.replace`, an fsync failure, a post-commit reopen failure,
   a dest that equals the live vault? Are these tested, or only the happy path?

4. **Tests.** Would each test fail if the behavior it names were reverted, or is
   it a tautology (e.g. asserting a dataclass lacks a field it never had)? Are
   security tests run against real SQLCipher rather than mocks?

5. **Correctness & hygiene.** Broad `except` swallowing real errors; leaked
   peewee exceptions; resource leaks; ruff/mypy cleanliness; unnecessary runtime
   dependencies.

## Output

Report findings most-severe first. For each: file and line, the concrete failure
scenario (inputs → wrong result), the root cause, and a specific fix. Reproduce
the important ones before asserting them. Distinguish BLOCKING (a real
security/correctness defect) from advisory. If nothing is wrong, say so plainly.
