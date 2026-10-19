"""
Custom user model with two NIST-driven behaviours:

* Unicode passwords are NFC-normalised before hashing and before checking
  ("the verifier SHOULD apply the normalization process for stabilized strings
  using NFC"), so a password typed on a keyboard that emits decomposed
  characters still verifies.
* ``password_compromised_at`` records evidence of compromise. NIST forbids
  periodic expiry but requires a forced change when there is such evidence;
  ``CompromisedPasswordMiddleware`` enforces it.
"""

from __future__ import annotations

import unicodedata

from django.contrib.auth.models import AbstractUser
from django.db import models


def normalize_password(raw_password: str | None) -> str | None:
    if raw_password is None:
        return None
    return unicodedata.normalize("NFC", raw_password)


class User(AbstractUser):
    password_compromised_at = models.DateTimeField(
        null=True,
        blank=True,
        help_text="Set when there is evidence this password was compromised; the user must change it before continuing.",
    )

    def set_password(self, raw_password):
        super().set_password(normalize_password(raw_password))

    def check_password(self, raw_password):
        return super().check_password(normalize_password(raw_password))

    @property
    def must_change_password(self) -> bool:
        return self.password_compromised_at is not None

    def mark_password_compromised(self, when=None, save: bool = True) -> None:
        from django.utils import timezone

        self.password_compromised_at = when or timezone.now()
        if save:
            self.save(update_fields=["password_compromised_at"])

    def clear_password_compromised(self, save: bool = True) -> None:
        self.password_compromised_at = None
        if save:
            self.save(update_fields=["password_compromised_at"])
