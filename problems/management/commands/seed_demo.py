"""Create a demo user and a few classic problems so the site is not empty."""

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.management.base import BaseCommand

from problems.models import Problem

DEMO_USER = "hypatia"
# Long passphrase: passes every validator (length ≥ 15, not breached, not a bare maths term).
DEMO_PASSWORD = "correct-horse-ellipse-perimeter-9"

PROBLEMS = [
    ("Sum of the first n odd numbers", Problem.Topic.NUMBER_THEORY, 1,
     "Prove that $1 + 3 + 5 + \\dots + (2n-1) = n^2$ for every positive integer $n$."),
    ("The Basel problem", Problem.Topic.ANALYSIS, 2,
     "Show that $$\\sum_{n=1}^{\\infty} \\frac{1}{n^2} = \\frac{\\pi^2}{6}.$$ Euler's original argument factors $\\sin x / x$; a rigorous route uses Fourier series or Parseval."),
    ("Infinitely many primes", Problem.Topic.NUMBER_THEORY, 1,
     "Give two different proofs that there are infinitely many primes: Euclid's, and one using the divergence of $\\sum 1/p$."),
    ("Irrationality of $\\sqrt{2}$", Problem.Topic.ALGEBRA, 1,
     "Prove that $\\sqrt{2}$ is irrational. Then generalise: for which integers $n$ is $\\sqrt{n}$ rational?"),
    ("Pigeonhole on a chessboard", Problem.Topic.COMBINATORICS, 2,
     "Remove two opposite corners from an $8 \\times 8$ chessboard. Can the remaining 62 squares be tiled by $1 \\times 2$ dominoes? Prove your answer."),
    ("Collatz conjecture", Problem.Topic.NUMBER_THEORY, 3,
     "Define $f(n) = n/2$ if $n$ is even and $3n+1$ if $n$ is odd. Does every orbit reach 1? (Open.) Post partial results and heuristics."),
]


class Command(BaseCommand):
    help = "Seed a demo user and classic problems."

    def handle(self, *args, **options):
        User = get_user_model()
        user, created = User.objects.get_or_create(username=DEMO_USER, defaults={"email": "hypatia@example.org"})
        if created:
            validate_password(DEMO_PASSWORD, user)  # keep the demo honest: the chain must pass
            user.set_password(DEMO_PASSWORD)
            user.save()
            self.stdout.write(f"Created user {DEMO_USER!r} with password {DEMO_PASSWORD!r}")
        for title, topic, difficulty, statement in PROBLEMS:
            Problem.objects.get_or_create(title=title, defaults={"topic": topic, "difficulty": difficulty, "statement": statement, "author": user})
        self.stdout.write(self.style.SUCCESS(f"{Problem.objects.count()} problems available."))
