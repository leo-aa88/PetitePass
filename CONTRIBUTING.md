# Contributing to PetitePass

Thanks for your interest in improving PetitePass. Because this is a **password
manager**, contributions are held to a higher bar than a typical app — a subtle
mistake in the crypto, auth, or vault-file handling can lose or expose someone's
credentials.

Please also read [AGENTS.md](AGENTS.md) and [docs/DESIGN.md](docs/DESIGN.md); the
security invariants there are hard constraints.

## Ways to contribute

- **Report a bug** — open a [Bug report](https://github.com/leo-aa88/PetitePass/issues/new/choose).
- **Request a feature** — open a [Feature request](https://github.com/leo-aa88/PetitePass/issues/new/choose).
- **Ask a question** — open a [Question](https://github.com/leo-aa88/PetitePass/issues/new/choose).
- **Report a vulnerability** — do **not** open a public issue; follow [SECURITY.md](SECURITY.md).
- **Send a pull request** — see below.

## Development setup

Requires Python 3.10+.

```bash
git clone https://github.com/leo-aa88/PetitePass.git
cd PetitePass
make setup && . .venv/bin/activate
make install-dev
```

Useful targets:

```bash
make lint            # ruff check src tests
make typecheck       # mypy (scoped to src/petitepass/core)
make test            # pytest against real SQLCipher
QT_QPA_PLATFORM=offscreen python tests/smoke_gui.py   # headless GUI smoke test
```

## Pull request checklist

Before opening a PR, make sure:

- [ ] `make lint`, `make typecheck`, and `make test` all pass.
- [ ] The headless GUI smoke test passes if you touched the GUI.
- [ ] New behavior has tests **against real SQLCipher** — including the failure
      paths (wrong / empty / NUL master, crash between copy and replace,
      post-commit reopen failure) where relevant.
- [ ] Tests would fail if the behavior were reverted (assert the mechanism, not a
      tautology).
- [ ] No new runtime dependency without a strong justification (`pip-audit` gates
      CI; the runtime set is intentionally small).
- [ ] Docstrings, the README, and `docs/` are truthful to what the code does.
- [ ] The change does not regress any invariant in [docs/DESIGN.md §9](docs/DESIGN.md#9-invariants-do-not-regress);
      the PR description says which invariants it touches and how the tests
      exercise them.

## Coding conventions

- **Style:** ruff (`E`, `F`, `I`; line length 100). Run `make lint`.
- **Types:** keep mypy clean on `src/petitepass/core`. The GUI is intentionally
  not type-checked (PyQt5 ships no stubs).
- **Architecture:** logic lives in `core/` (usually the `Vault`); the GUI is a
  thin shell that calls `VAULT.*` and catches `VaultError`. The GUI never imports
  `peewee` or the model.
- **Errors:** the `Vault` raises typed `VaultError` subclasses and never leaks
  peewee exceptions; GUI slots may use a broad `except` as a last-resort error
  boundary (show a dialog, don't crash).
- **Commits:** imperative subject line; explain *why* in the body. Never commit
  secrets, real vault files, or built binaries.

## Reviews

Every change is reviewed against the security invariants and for
contract-vs-implementation honesty. Expect questions about failure paths and
atomicity. Keeping PRs small and focused makes this faster for everyone.

## License

By contributing, you agree that your contributions are licensed under the
project's [GPL-3.0](LICENSE) license.
