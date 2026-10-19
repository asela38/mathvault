import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import reverse

from problems.models import Problem

pytestmark = pytest.mark.django_db


def test_seed_and_browse(client):
    call_command("seed_demo")
    assert Problem.objects.count() == 6
    html = client.get(reverse("problems:list")).content.decode()
    assert "Basel problem" in html
    p = Problem.objects.get(title="The Basel problem")
    assert "\\frac{\\pi^2}{6}" in client.get(p.get_absolute_url()).content.decode()


def test_posting_requires_login_and_works(client):
    user = get_user_model().objects.create_user("cantor", password="the continuum has many cardinalities")
    assert client.get(reverse("problems:create")).status_code == 302
    client.force_login(user)
    r = client.post(reverse("problems:create"), {"title": "Diagonal", "topic": "analysis", "difficulty": 1, "statement": "Prove $|\\mathbb{R}| > |\\mathbb{N}|$."})
    assert r.status_code == 302
    problem = Problem.objects.get(title="Diagonal")
    r = client.post(problem.get_absolute_url(), {"body": "Assume an enumeration and flip the diagonal."})
    assert r.status_code == 302 and problem.solutions.count() == 1
