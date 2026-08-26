"""The vault's data model.

Only the schema lives here now. All the old module-level CLI functions
(``create_password``/``update_password``/``change_db_password``/...) that used
``except Exception: create_anyway`` control flow and hand-built ``PRAGMA`` SQL
have been removed; credential operations belong to :mod:`core.vault`.
"""
import datetime

from peewee import DateTimeField, Model, TextField


class Password(Model):
    # ``unique=True`` enforces name uniqueness at the database level instead of
    # relying on a racy application-level ``Password.get()`` pre-check.
    name = TextField(unique=True)
    username = TextField(null=True)
    password = TextField()
    timestamp = DateTimeField(default=datetime.datetime.now)
    updated = DateTimeField(null=True)

    class Meta:
        # The database is bound at runtime by core.vault.Vault when the vault
        # is opened, so a wrong/absent key can never masquerade as an
        # authenticated session.
        pass
