---
name: implement-feature
description: Use when adding a new feature or capability to PetitePass (the SQLCipher password manager). Enforces the security-invariant workflow — logic in the Vault service, real-SQLCipher tests for happy and failure paths, and truthful docs.
icon: rocket
---

# Implement a feature

Guided workflow for adding a feature to PetitePass, a local SQLCipher password
manager. Apply a password-manager bar, not an ordinary-app bar.

## When to use

Use this when the task is to add or extend user-facing or service-level
functionality (a new Vault operation, a GUI action, a policy, a generator
option). For fixing broken behavior use `bugfix`; for reviewing a change use
`code-review`.

## Instructions

1. **Understand first.** Read [AGENTS.md](../../../AGENTS.md) and
   [docs/DESIGN.md](../../../docs/DESIGN.md). Identify which invariants
   (DESIGN §9) the feature touches. If it touches the crypto/auth path or any
   vault-file operation, treat those invariants as hard constraints. If the
   requirements are ambiguous, ask the user before coding.

2. **Design.**
   - Put logic in `src/petitepass/core/` (usually the `Vault`), never in GUI
     widgets. The GUI is a thin shell that calls `VAULT.*` and catches
     `VaultError`; it must not import `peewee` or the model.
   - Return passwordless domain data (`Credential`) where possible; fetch a
     secret only when it is actually needed.
   - If the feature writes or replaces the vault file, reuse the existing commit
     discipline: verified copy → fatal `fsync` → atomic `os.replace` →
     best-effort post-commit → a distinct post-commit error type.

3. **Implement.** Keep the change focused. Add typed `VaultError` subclasses to
   the service instead of leaking `peewee` exceptions. Keep ruff and mypy clean
   (`core` is type-checked; the GUI is not).

4. **Test against real SQLCipher.** Cover the happy path **and** the failure
   paths (wrong / empty / NUL master where relevant, crash between copy and
   `os.replace`, post-commit reopen failure). Write tests that would fail if the
   contract were reverted — assert the mechanism, not a tautology. Cover GUI
   behavior in `tests/smoke_gui.py` if applicable. Run
   `make lint && make typecheck && make test` and the headless GUI smoke test.

5. **Document.** Update the README and `docs/TUTORIAL.md` if user-facing, and
   `docs/DESIGN.md` if the architecture or an invariant changes. Keep every
   claim truthful to the code.

## Output

A focused change plus tests, all checks green. In the commit/PR, state which
invariants the change touches and how the tests exercise them. Use an imperative
commit subject and explain *why* in the body.
