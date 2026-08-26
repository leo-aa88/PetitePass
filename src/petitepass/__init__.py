"""PetitePass — a lightweight, local, offline SQLCipher password manager."""

# Version floor for source installs. pyproject reads this via
# `[tool.setuptools.dynamic]`, so `pip install .` reports it. Releases, however,
# are cut as git tags: the release workflow stamps the tag's version into this
# file at build time, so a published binary's `petitepass --version` matches its
# tag even though this committed value is only bumped in a normal PR.
__version__ = "2.0.5"
