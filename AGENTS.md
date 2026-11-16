# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository. This is a **password manager**: hold changes to a higher standard than an ordinary CRUD app.

## What this project is

PetitePass is a local, offline password manager. Credentials live in a single SQLCipher-encrypted database. The master password is never stored; authentication is proven by decrypting the vault. Read [docs/DESIGN.md](docs/DESIGN.md) before changing anything security-relevant.

## Setup, build, test

```bash
make setup                             # create .venv (then activate it)
make install-dev                       # runtime + dev tooling in the active venv
make lint                              # ruff check src tests
make typecheck                         # mypy (scoped to src/petitepass/core)
make test                              # pytest against real SQLCipher
make smoke                             # headless GUI smoke test (offscreen)
make check                             # lint + typecheck + test + smoke — run before a PR
```

The pytest suite links against **real SQLCipher** (`sqlcipher3`, which ships cross-platform wheels). Do not mock the database in security tests — the whole point is to exercise real encryption. SQLCipher prints `hmac check failed` lines to stderr on wrong-key tests; that is expected.

## Project layout

- `src/petitepass/app.py` — entry point (`petitepass`): `--version`, `--help`, and a Qt-free `--selftest` (a real SQLCipher create → add → reopen → read round-trip, plus a wordlist check) that the release workflow runs against every built binary.
- `src/petitepass/core/vault.py` — the `Vault`: auth, rekey, backup/restore, CRUD. Almost all logic lives here.
- `src/petitepass/core/{database,credential,paths,strength,utils}.py` — schema, domain object, filesystem, policy, generator.
- `src/petitepass/core/data/10k-most-common.txt` — the bundled common-password blocklist. It is package data (`pyproject.toml`) and `make build` passes it to PyInstaller with `--add-data`; if it goes missing, `is_common()` quietly returns `False`, so keep both in sync (`--selftest` checks it).
- `src/petitepass/gui/` — PyQt5 dialogs, `mainWindow`, and `theme.py` (app-wide style). Presentation only.
- `tests/` — pytest suite + `smoke_gui.py` (a runnable headless script, not a pytest module).
- `docs/` — `DESIGN.md` (architecture + threat model + invariants), `TUTORIAL.md`.
- `SECURITY.md` — how to report vulnerabilities (not via public issues). `AUDIT.md` — the historical audit of the *pre-rework* code; it describes the old design, not the current one.

## Non-negotiable invariants

These are also listed in [docs/DESIGN.md §16](docs/DESIGN.md#16-invariants-do-not-regress) (12 in total; the subset below is the day-to-day core). A change that breaks one is a security regression even if CI is green:

1. **Authentication = decryption.** A session is valid only if the vault decrypts *and* the `password` table is present. Never reintroduce a sidecar verifier.
2. **Safe key path; no hand-built PRAGMA.** Key material reaches SQLCipher only through a reviewed, injection-safe keying path. Today that is peewee's escaping `passphrase=` / `rekey()` API. Never interpolate key material into SQL yourself — e.g. `execute_sql(f"PRAGMA key = '{...}'")`. (A future raw-key vault format would need its own reviewed path; see DESIGN §7 and invariant 2.)
3. **Reject empty/NUL master** before creating or replacing any file (an empty passphrase yields a plaintext database).
4. **Atomic vault-file replacement.** Rekey, restore, and legacy-vault relocation (`paths._migrate`) work on a verified copy and commit at a single `os.replace`. The `fsync` of the copy is fatal (never swallowed). *Before* the commit, a failure leaves the previous vault openable under the current master. *After* the commit, the vault is the new one — see #5. (Only `paths._migrate`, whose post-commit work is pure cleanup, never flips its result.) This protocol is for *replacing the file*. An in-database schema change (adding an index or column) is not a file replacement: it should run inside a database transaction, without copying the vault (DESIGN §12).
5. **Distinct post-commit errors.** A reopen failure *after* the `os.replace` commit is `VaultRotatedError` (rekey) / `VaultRestoredError` (restore) — never an auth error. The change committed; the old master no longer opens the vault. This is a real failure of the operation; do not report it as "unchanged" or swallow it.
6. **GUI never touches the ORM.** All credential access goes through `VAULT.*`. The GUI catches `VaultError` (and subclasses) only; the service translates every peewee `DatabaseError` into `VaultError`.
7. **Don't load ciphertext to draw the list.** `list_credentials()` selects non-password columns only.

(These seven are the security core; the full set of 12 is in [docs/DESIGN.md §16](docs/DESIGN.md#16-invariants-do-not-regress) and includes offline-only operation, no secondary auth oracle, no silent data loss, and no dishonest guarantees.)

## Scope: prefer saying no

PetitePass optimizes for **maximum security per line of code, dependency, and feature** — a small set of strong, understandable mechanisms, not a large feature set. Before adding functionality, weigh it against the explicit **non-goals** ([docs/DESIGN.md §2](docs/DESIGN.md#2-non-goals)) and run the **feature-admission checklist** ([docs/DESIGN.md §4](docs/DESIGN.md#4-feature-admission-criteria)). Declining a feature (especially anything that adds networking, a second source of truth, a new long-lived secret, or untrusted parsing) is a legitimate, expected outcome.

## Conventions

- **Style:** ruff (`E`, `F`, `I`; line length 100, `E501` ignored). Run `make lint` before committing.
- **Types:** mypy is clean on `src/petitepass/core`. Keep it that way. The GUI is intentionally not type-checked (PyQt5 ships no stubs).
- **Dependencies:** the runtime set is deliberately tiny (`requirements.txt`). Do not add a runtime dependency without a strong reason; `pip-audit` gates CI. `pip freeze` is not dependency management.
- **GUI module names** are camelCase by pre-existing convention (`authDialog.py`); leave them.
- **Broad `except Exception` lives in the `Vault`, on purpose.** `create` / `rekey` / `restore_from` catch `Exception` to translate an *unexpected* failure into a `VaultError` — most importantly so a non-`DatabaseError` (e.g. a NUL master raising `ValueError`) cannot leave a half-written file that `exists()` would treat as a vault. Do not narrow those handlers back to `DatabaseError`. GUI slots, by contrast, catch `VaultError` (and subclasses) only — the service is the boundary.
- **Commits:** imperative subject; explain *why* in the body. End with the `Co-Authored-By` trailer if an agent made the change. Never commit secrets, real vault files, or built binaries.

## Testing expectations

- New security-relevant behavior ships with tests against real SQLCipher, including the failure paths (wrong/empty/NUL master, crash between copy and replace, post-commit reopen failure).
- Failure-path tests that mock `fsync` / `os.replace` are not enough on their own: each vault-replacing operation must also be shown to *succeed*, unmocked, on every supported OS (DESIGN §15). The Windows `fsync` bug (#38) passed every mocked test. CI's pytest job currently runs on Linux only, and the release workflow's Windows job only runs `--selftest` (which doesn't exercise rekey/backup/restore) — so a change to platform-sensitive durability code needs a real run on the affected OS until per-OS coverage lands (#47).
- Prefer tests that would fail if the contract were reverted — assert the *mechanism*, not a tautology (e.g. spy the SELECT columns, don't just check a dataclass shape).
- GUI-level behavior is covered by `tests/smoke_gui.py`, which redirects `HOME` / `XDG_DATA_HOME` / `USERPROFILE` / `WIN_PD_OVERRIDE_LOCAL_APPDATA` so it never touches a real vault.

## Pull requests

Follow [CONTRIBUTING.md](CONTRIBUTING.md). Keep PRs focused. State clearly which invariants a change touches and how the tests exercise them. Do not weaken a claim in a docstring or the README to match code that does less than advertised — fix the code.
