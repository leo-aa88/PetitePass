# Security Policy

PetitePass is a password manager. We take security reports seriously and
appreciate responsible disclosure.

## Supported versions

PetitePass is developed on the `main` branch, and fixes land there. Please test
against the latest `main` before reporting.

## Reporting a vulnerability

**Do not open a public issue, pull request, or discussion for a security
vulnerability.**

Report privately through either of:

- **GitHub Security Advisories** — [open a private report](https://github.com/leo-aa88/PetitePass/security/advisories/new)
  (Security → Report a vulnerability). This is preferred.
- **Email** — `leonardo.aa88@gmail.com` with a subject beginning `PetitePass
  security:`.

Please include, as best you can:

- a description of the issue and its impact,
- the version / commit you tested,
- step-by-step reproduction (a failing test or script is ideal), and
- any suggested remediation.

You will get an acknowledgement as soon as possible. Please give a reasonable
window to develop and release a fix before any public disclosure, and avoid
accessing or modifying data that is not yours while investigating.

## Scope

In scope — issues that break the project's security invariants
([docs/DESIGN.md §9](docs/DESIGN.md#9-invariants-do-not-regress)), for example:

- authentication succeeding without the vault actually decrypting;
- a path that produces a plaintext (unencrypted) vault;
- master-password rotation, restore, or migration that can lose the vault or
  lock a user out on failure;
- injection through the master password into SQLCipher `PRAGMA`s;
- plaintext secrets written to disk, logs, or process arguments.

Out of scope — threats PetitePass fundamentally cannot defend against, primarily
**another process running under the same user account** once the vault is
unlocked (see the threat model in [docs/DESIGN.md](docs/DESIGN.md#8-threat-model)).
Reports about a lost/forgotten master password are also out of scope: by design
it cannot be recovered.

## A note on expectations

PetitePass protects an at-rest, encrypted vault. It cannot protect decrypted
secrets from code running as you, and it cannot recover a forgotten master
password. Choose a strong master password and keep backups.
