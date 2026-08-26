# PetitePass

> A lightweight, local, offline password manager where authentication *is* decryption.

[![CI](https://github.com/leo-aa88/PetitePass/actions/workflows/python-app.yml/badge.svg)](https://github.com/leo-aa88/PetitePass/actions/workflows/python-app.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Types: mypy](https://img.shields.io/badge/types-mypy-blue.svg)](https://mypy-lang.org/)
[![Tests: pytest](https://img.shields.io/badge/tests-pytest-0A9EDC.svg)](https://docs.pytest.org/)

PetitePass stores your credentials in a single [SQLCipher](https://www.zetetic.net/sqlcipher/)-encrypted database on your own machine. There is no cloud, no account, and no telemetry. The master password is never stored anywhere: you are "logged in" only when the vault actually decrypts.

- [Why PetitePass?](#why-petitepass)
- [Features](#features)
- [Security model](#security-model)
- [Install](#install)
- [Usage](#usage)
- [How it works](#how-it-works)
- [Where your data lives](#where-your-data-lives)
- [Development](#development)
- [Project layout](#project-layout)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

* * *

## Why PetitePass?

Most password managers ask you to trust a server. PetitePass asks you to trust one encrypted file that never leaves your computer unless you copy it there yourself.

|                        | PetitePass **is**                                             | PetitePass **is not**                                  |
| ---------------------- | ------------------------------------------------------------- | ------------------------------------------------------ |
| **Storage**            | One local SQLCipher database (AES-256, per-DB salt)           | A cloud service or browser extension                   |
| **Authentication**     | Proven by decrypting the vault                                | A password compared against a sidecar hash             |
| **Master password**    | Only ever held in memory while unlocked                       | Stored, transmitted, or recoverable                    |
| **Network**            | None — fully offline                                          | A sync engine                                          |
| **Trust boundary**     | Your user account and your disk                               | A vendor                                               |

* * *

## Features

- **Encrypted storage** — credentials live in a SQLCipher database (AES-256-CBC, PBKDF2-HMAC-SHA512 × 256 000, HMAC-SHA512), with cipher parameters pinned in code.
- **Authentication = decryption** — a login succeeds only if the master password decrypts the vault and the application schema is present. There is no sidecar verifier to desynchronize.
- **Atomic master-password rotation** — rekey happens on a verified temporary copy and is swapped in with an atomic `os.replace`; a failure never leaves you locked out.
- **Encrypted backup & restore** — export the vault to a backup file and restore from one; the backup is verified as decryptable before it is trusted.
- **Password generator** — cryptographically secure (`secrets`), with selectable character sets.
- **Strength estimation** — [zxcvbn](https://github.com/dropbox/zxcvbn)-based guessability, not a meaningless character-class checklist.
- **Clipboard safety** — copied passwords auto-clear, and only if the clipboard still holds them (a value you copied afterwards is never wiped).
- **Auto-lock** — the vault closes after a period of inactivity and returns you to the login screen.
- **Search, per-row copy, in-place edit** — filter by name/username, copy username or password, double-click a row to edit.
- **Cross-platform storage** — data lives in the OS-standard per-user directory (Linux/macOS/Windows), with a one-time migration from older layouts.

## Screenshot

![screenshot](Screenshot.png)

* * *

## Security model

PetitePass is built around one invariant: **the only proof of authentication is that the vault decrypts.** A short summary of what it defends against, and what it fundamentally cannot, is below; the full threat model is in [docs/DESIGN.md](docs/DESIGN.md).

| Threat                                              | Posture                                                                                 |
| --------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Stolen vault file                                   | Protected — strength reduces to your master password against SQLCipher's KDF.           |
| Stolen vault + auxiliary files                      | No extra oracle exists; there is no sidecar hash to attack.                              |
| Malicious process under **your** user account       | Cannot fully protect — any local app can read your session once the vault is unlocked.   |
| Filesystem attacker                                 | Files are `0600`, the data dir `0700`; writes are atomic.                                |
| Corrupt / wrong-key / hollow vault                  | Refused at unlock; never accepted as an empty vault.                                     |

If you believe you have found a vulnerability, please read [SECURITY.md](SECURITY.md).

* * *

## Install

Requires **Python 3.10+**. The clipboard is handled by Qt — no external `xsel` is needed.

Clone the repository:

```bash
git clone https://github.com/leo-aa88/PetitePass.git
cd PetitePass
```

**Option A — install as a package** (provides a `petitepass` command):

```bash
pip install .
petitepass
```

**Option B — standalone single-file binary** (no Python at runtime):

```bash
make setup && . .venv/bin/activate
make install-dev      # includes PyInstaller, which `make build` needs
make build            # produces dist/petitepass
```

**Run from a checkout without installing** (the package lives under `src/`):

```bash
pip install -r requirements.txt
PYTHONPATH=src python -m petitepass.app
```

* * *

## Usage

On first launch, PetitePass asks you to create a master password. It must be at least 12 characters, must not be a common password, and must clear a minimum zxcvbn score — passphrases are encouraged.

> **The master password cannot be recovered.** If you forget it, the vault cannot be decrypted. If you delete the vault file, the data is gone.

Once unlocked:

- **Right-click the table** for actions: add / update / delete / generate / check strength / modify master password / back up / restore.
- **Double-click a row** to edit that entry.
- **Copy** or **Copy user** buttons put the password or username on the clipboard; a copied password auto-clears after a short interval.
- **Filter** entries with the search box.
- The vault **auto-locks** after inactivity; you will be asked to log in again.

A step-by-step walkthrough is in [docs/TUTORIAL.md](docs/TUTORIAL.md).

* * *

## How it works

```
  master password
        │
        ▼
  ┌───────────────┐   PRAGMA key (quote-escaped by peewee)     ┌──────────────────┐
  │  AuthDialog   │ ─────────────────────────────────────────▶ │  SQLCipher vault │
  └───────────────┘   sentinel query forces page-1 decrypt      │  (.db, 0600)     │
        │  decrypt OK = authenticated                            └──────────────────┘
        ▼                                                                 ▲
  ┌───────────────┐    list / add / update / delete / get           bind │
  │   MainWindow  │ ───────────────────────────────────────────▶  ┌──────┴───────┐
  │  (PyQt5 GUI)  │            (no ORM access in the GUI)          │ Vault service│
  └───────────────┘ ◀───────── Credential summaries (no password) └──────────────┘
```

Every credential operation goes through the `Vault` service; the GUI never touches the ORM. Vault-mutating operations (rekey, restore) run on a verified temporary copy and commit with a single atomic `os.replace`: a failure *before* the commit leaves the previous vault openable, and a failure *after* it is reported distinctly (the new vault is already in place — you unlock with the new master). See [docs/DESIGN.md §5](docs/DESIGN.md#5-vault-file-operations-and-durability) for the full commit/durability discipline.

* * *

## Where your data lives

The encrypted vault is a single file, `48cccca3bab2ad18832233ee8dff1b0b.db`, in the platform's per-user data directory:

| Platform | Location                                            |
| -------- | --------------------------------------------------- |
| Linux    | `~/.local/share/PetitePass/`                        |
| macOS    | `~/Library/Application Support/PetitePass/`          |
| Windows  | `%LOCALAPPDATA%\PetitePass\`                         |

A vault from an older version stored under `~/PetitePass/` is migrated automatically on first launch. Back it up (encrypted) with the **Back up vault** action, or copy the file itself — it is useless without your master password.

* * *

## Development

```bash
make install-dev      # runtime + dev tooling (ruff, mypy, pytest, pip-audit, pyinstaller)
make lint             # ruff
make typecheck        # mypy (scoped to the logic core)
make test             # pytest against real SQLCipher

# headless GUI smoke test
QT_QPA_PLATFORM=offscreen python tests/smoke_gui.py
```

CI runs ruff, mypy, `pip-audit`, the pytest suite, the headless GUI smoke test, and a packaged-install check on every push and pull request. Contribution conventions are in [CONTRIBUTING.md](CONTRIBUTING.md); agent-specific guidance is in [AGENTS.md](AGENTS.md).

* * *

## Project layout

```
PetitePass/
├── src/petitepass/
│   ├── app.py                 # Qt application entry point (petitepass command)
│   ├── core/
│   │   ├── vault.py           # the Vault: auth, rekey, backup/restore, CRUD
│   │   ├── database.py        # peewee model (owned by the Vault)
│   │   ├── credential.py      # passwordless domain object for listing
│   │   ├── paths.py           # data dir, permissions, legacy migration
│   │   ├── strength.py        # zxcvbn policy + common-password list
│   │   ├── utils.py           # CSPRNG password generator
│   │   └── data/              # bundled common-password list
│   └── gui/                   # PyQt5 dialogs and main window
├── tests/                     # pytest suite (real SQLCipher) + GUI smoke test
├── docs/                      # DESIGN.md, TUTORIAL.md
├── .cursor/
│   ├── skills/                # Agent Skills: implement-feature, bugfix, code-review
│   └── rules/                 # always-on project rules (security invariants)
└── AGENTS.md, CLAUDE.md       # agent guidance
```

* * *

## Roadmap

- Password history / audit trail per entry
- Configurable auto-lock timeout and clipboard TTL in the UI
- Optional key file / hardware-token second factor
- Import from other password managers (CSV / JSON)

* * *

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md). Because this is a password manager, security-relevant changes are held to the invariants described in [docs/DESIGN.md](docs/DESIGN.md) and must ship with tests against real SQLCipher.

## Security

Please report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do not open a public issue for a security report.

## License

PetitePass is licensed under the **GNU General Public License v3.0** — see [LICENSE](LICENSE).
