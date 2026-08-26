# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. This is a **password manager**: hold changes to a higher standard than an ordinary CRUD app.

## What this project is

PetitePass is a local, offline password manager. Credentials live in a single SQLCipher-encrypted database. The master password is never stored; authentication is proven by decrypting the vault. Read [docs/DESIGN.md](docs/DESIGN.md) before changing anything security-relevant.

## Setup, build, test

```bash
make install-dev                       # runtime + dev tooling in the active venv
make lint                              # ruff check src tests
make typecheck                         # mypy (scoped to src/petitepass/core)
make test                              # pytest against real SQLCipher
QT_QPA_PLATFORM=offscreen python tests/smoke_gui.py   # headless GUI smoke test
```

The pytest suite links against **real SQLCipher** (`sqlcipher3-binary`). Do not mock the database in security tests — the whole point is to exercise real encryption. SQLCipher prints `hmac check failed` lines to stderr on wrong-key tests; that is expected.

## Project layout

- `src/petitepass/core/vault.py` — the `Vault`: auth, rekey, backup/restore, CRUD. Almost all logic lives here.
- `src/petitepass/core/{database,credential,paths,strength,utils}.py` — schema, domain object, filesystem, policy, generator.
- `src/petitepass/gui/` — PyQt5 dialogs and `mainWindow`. Presentation only.
- `tests/` — pytest suite + `smoke_gui.py` (a runnable headless script, not a pytest module).
- `docs/` — `DESIGN.md` (architecture + threat model + invariants), `TUTORIAL.md`.

## Non-negotiable invariants

These are also listed in [docs/DESIGN.md §9](docs/DESIGN.md#9-invariants-do-not-regress). A change that breaks one is a security regression even if CI is green:

1. **Authentication = decryption.** A session is valid only if the vault decrypts *and* the `password` table is present. Never reintroduce a sidecar verifier.
2. **No hand-built PRAGMA.** The master password reaches SQLCipher only through peewee's escaping `passphrase=` / `rekey()` API. Never `execute_sql(f"PRAGMA key = '{...}'")`.
3. **Reject empty/NUL master** before creating or replacing any file (an empty passphrase yields a plaintext database).
4. **Atomic vault replacement.** Rekey/restore/migration work on a verified copy and commit at a single `os.replace`. The `fsync` of the copy is fatal (never swallowed). *Before* the commit, a failure leaves the previous vault openable under the current master. *After* the commit, the vault is the new one — see #5. (Only `paths._migrate`, whose post-commit work is pure cleanup, never flips its result.)
5. **Distinct post-commit errors.** A reopen failure *after* the `os.replace` commit is `VaultRotatedError` (rekey) / `VaultRestoredError` (restore) — never an auth error. The change committed; the old master no longer opens the vault. This is a real failure of the operation; do not report it as "unchanged" or swallow it.
6. **GUI never touches the ORM.** All credential access goes through `VAULT.*`. The GUI catches `VaultError` (and subclasses) only; the service translates every peewee `DatabaseError` into `VaultError`.
7. **Don't load ciphertext to draw the list.** `list_credentials()` selects non-password columns only.

## Conventions

- **Style:** ruff (`E`, `F`, `I`; line length 100, `E501` ignored). Run `make lint` before committing.
- **Types:** mypy is clean on `src/petitepass/core`. Keep it that way. The GUI is intentionally not type-checked (PyQt5 ships no stubs).
- **Dependencies:** the runtime set is deliberately tiny (`requirements.txt`). Do not add a runtime dependency without a strong reason; `pip-audit` gates CI. `pip freeze` is not dependency management.
- **GUI module names** are camelCase by pre-existing convention (`authDialog.py`); leave them.
- **Broad `except Exception` lives in the `Vault`, on purpose.** `create` / `rekey` / `restore_from` catch `Exception` to translate an *unexpected* failure into a `VaultError` — most importantly so a non-`DatabaseError` (e.g. a NUL master raising `ValueError`) cannot leave a half-written file that `exists()` would treat as a vault. Do not narrow those handlers back to `DatabaseError`. GUI slots, by contrast, catch `VaultError` (and subclasses) only — the service is the boundary.
- **Commits:** imperative subject; explain *why* in the body. End with the `Co-Authored-By` trailer if an agent made the change. Never commit secrets, real vault files, or built binaries.

## Testing expectations

- New security-relevant behavior ships with tests against real SQLCipher, including the failure paths (wrong/empty/NUL master, crash between copy and replace, post-commit reopen failure).
- Prefer tests that would fail if the contract were reverted — assert the *mechanism*, not a tautology (e.g. spy the SELECT columns, don't just check a dataclass shape).
- GUI-level behavior is covered by `tests/smoke_gui.py`, which redirects `HOME` / `XDG_DATA_HOME` / `USERPROFILE` / `WIN_PD_OVERRIDE_LOCAL_APPDATA` so it never touches a real vault.

## Pull requests

Follow [CONTRIBUTING.md](CONTRIBUTING.md). Keep PRs focused. State clearly which invariants a change touches and how the tests exercise them. Do not weaken a claim in a docstring or the README to match code that does less than advertised — fix the code.
