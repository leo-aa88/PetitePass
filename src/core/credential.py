"""Plain domain object for a stored credential.

Deliberately carries no password: the GUI lists these for display and asks the
Vault for a secret only when the user copies or reveals one, so plaintext is
not held in memory for every row merely to draw the table.
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class Credential:
    name: str
    username: str
    created: str
    updated: str
