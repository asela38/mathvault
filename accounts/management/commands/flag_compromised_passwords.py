"""
Record evidence of compromise for specific accounts (e.g. after a breach
notification or a credential-stuffing incident). Flagged users are forced to
change their password at their next request; nobody is ever forced to change
on a schedule.

    manage.py flag_compromised_passwords alice bob
    manage.py flag_compromised_passwords --from-file leaked_usernames.txt
    manage.py flag_compromised_passwords --clear alice
"""

from pathlib import Path

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Flag (or clear) users whose passwords are known to be compromised."

    def add_arguments(self, parser):
        parser.add_argument("usernames", nargs="*")
        parser.add_argument("--from-file", help="file with one username or e-mail per line")
        parser.add_argument("--clear", action="store_true", help="clear the flag instead of setting it")

    def handle(self, *args, **opts):
        User = get_user_model()
        idents = list(opts["usernames"])
        if opts["from_file"]:
            idents += [ln.strip() for ln in Path(opts["from_file"]).read_text().splitlines() if ln.strip()]
        users = User.objects.filter(username__in=idents) | User.objects.filter(email__in=idents)
        n = 0
        for user in users.distinct():
            if opts["clear"]:
                user.clear_password_compromised()
            else:
                user.mark_password_compromised()
            n += 1
        self.stdout.write(self.style.SUCCESS(f"{'Cleared' if opts['clear'] else 'Flagged'} {n} user(s)."))
