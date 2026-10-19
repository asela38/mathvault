"""Every path that sets a password must run validate_password(). Django only
validates inside its forms and the createsuperuser/changepassword commands, so
a REST endpoint or admin action calling set_password() directly would bypass
the whole chain. This guard fails CI when such a call appears outside the
allow-list."""

import pathlib
import re

PASSWORD_SETTERS = re.compile(r"\b(set_password|make_password|create_user|create_superuser)\s*\(")

# module -> why it is allowed
ALLOWED = {
    "accounts/models.py": "defines set_password itself (NFC normalisation), does not set passwords",
    "problems/management/commands/seed_demo.py": "calls validate_password() first",
}


def test_no_unvalidated_password_setters():
    offenders = []
    for path in pathlib.Path(".").rglob("*.py"):
        parts = path.parts
        if ".venv" in parts or "tests" in parts or "migrations" in parts:
            continue
        rel = path.as_posix()
        if rel in ALLOWED:
            continue
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            if PASSWORD_SETTERS.search(line) and not line.lstrip().startswith("#"):
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, "password set without validate_password():\n" + "\n".join(offenders)


def test_allowed_modules_really_validate():
    seed = pathlib.Path("problems/management/commands/seed_demo.py").read_text()
    assert "validate_password(" in seed
