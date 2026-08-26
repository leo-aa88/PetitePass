# Implement a feature

Implement the feature described in the request for PetitePass, a local SQLCipher
password manager. Follow this workflow.

## 1. Understand before coding
- Read [AGENTS.md](../../AGENTS.md) and [docs/DESIGN.md](../../docs/DESIGN.md).
- Identify which invariants (DESIGN §9) the feature touches. If it touches the
  crypto/auth path or any vault-file operation, treat those invariants as hard
  constraints.

## 2. Design
- Put logic in `src/petitepass/core/` (usually the `Vault`), not in GUI widgets.
  The GUI is a thin shell that calls `VAULT.*` and catches `VaultError`.
- Domain data returned to the GUI should be passwordless where possible
  (`Credential`); fetch a secret only when it is actually needed.
- If the feature replaces or writes the vault file, reuse the existing commit
  discipline: verified copy → `fsync` (fatal) → `os.replace` → best-effort
  post-commit → distinct post-commit error type.

## 3. Implement
- Keep the change focused. Add typed errors to the service rather than leaking
  peewee exceptions.
- Maintain mypy cleanliness on `core`; keep ruff clean.

## 4. Test (against real SQLCipher)
- Add pytest cases covering the happy path **and** the failure paths (wrong /
  empty / NUL master where relevant, crash between copy and replace, post-commit
  reopen failure).
- Prefer tests that fail if the contract is reverted (assert the mechanism, not
  a tautology).
- Cover GUI behavior in `tests/smoke_gui.py` if applicable.
- Run: `make lint && make typecheck && make test` and the headless smoke test.

## 5. Document
- Update the README feature list / usage and `docs/TUTORIAL.md` if user-facing.
- Update `docs/DESIGN.md` if the architecture or an invariant changes.

## 6. Deliver
- Commit with an imperative subject and a body explaining *why*.
- In the PR, state which invariants the change touches and how the tests
  exercise them.
