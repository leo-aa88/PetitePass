# CLAUDE.md

This file guides Claude Code (and other Claude-based agents) working in this repository.

**Start with [AGENTS.md](AGENTS.md)** — it holds the build/test commands, the project layout, the coding conventions, and the non-negotiable security invariants. Everything there applies here.

## Quick reference

```bash
make install-dev     # set up the active venv
make lint            # ruff
make typecheck       # mypy (core only)
make test            # pytest against real SQLCipher
make smoke           # headless GUI smoke test (offscreen)
make check           # all of the above — run before opening a PR
```

## This is a password manager

Apply a substantially higher bar than an ordinary desktop app. Before touching `src/petitepass/core/vault.py`, `paths.py`, `strength.py`, or the crypto/auth path, read [docs/DESIGN.md](docs/DESIGN.md) and treat its §16 invariants as hard constraints:

- Authentication is decryption — never a sidecar hash.
- Key material reaches SQLCipher only through a reviewed, injection-safe keying path — today peewee's escaping `passphrase=` / `rekey()` API. Never build `f"PRAGMA key = '{...}'"` yourself.
- Reject empty/NUL master passwords before creating or replacing a file.
- Vault-file replacements (rekey, restore, legacy relocation) are atomic, committing at a single `os.replace` (`fsync` of the copy is fatal). *Before* the commit a failure leaves the old vault openable; *after* it the new vault is in place — see the next point. In-database schema changes don't replace the file; they use a transaction (DESIGN §12).
- A reopen failure *after* the commit raises `VaultRotatedError` / `VaultRestoredError` (never an auth error): the change committed and the old master no longer opens the vault. Don't report it as "unchanged" or swallow it.
- The `except Exception` handlers in `Vault.create` / `rekey` / `restore_from` are deliberate (they stop a NUL/`ValueError` from leaving a half-written file); don't narrow them. The GUI catches `VaultError` only.
- The GUI never touches the ORM; it goes through `VAULT.*` and catches `VaultError`.

## Working style

- Verify behavior against **real SQLCipher** rather than reasoning in the abstract — set up a throwaway venv (`sqlcipher3`, `peewee`, `platformdirs`, `zxcvbn`, and `PyQt5` for the smoke test) and run the actual code.
- When a review raises an issue, reproduce it before fixing, and add a test that would fail if the fix were reverted.
- Test success paths for real, not only mocked failures — platform-sensitive durability code must actually run on the OS it targets (see AGENTS.md → Testing expectations).
- Keep docstrings and README claims true to what the code does. If they diverge, fix the code, not the claim.
- Don't add runtime dependencies casually; the runtime set is intentionally minimal and `pip-audit` gates CI.
