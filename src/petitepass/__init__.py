"""PetitePass — a lightweight, local, offline SQLCipher password manager."""

# Single source of truth for the version. pyproject reads this via
# `[tool.setuptools.dynamic]`, the release workflow bumps it, and
# `petitepass --version` prints it.
__version__ = "2.0.5"
