"""NIST SP 800-63B Rev. 4 §3.2.2: no more than 100 consecutive failed attempts
on one account. Enforced by django-axes (see config/settings.py)."""

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.urls import reverse

pytestmark = pytest.mark.django_db

PASSWORD = "the kernel of a homomorphism is normal"


def test_account_locks_at_the_nist_cap(client):
    assert settings.AXES_FAILURE_LIMIT <= 100
    assert "username" in settings.AXES_LOCKOUT_PARAMETERS
    get_user_model().objects.create_user("gauss", password=PASSWORD)
    url = reverse("login")
    for i in range(settings.AXES_FAILURE_LIMIT - 1):
        r = client.post(url, {"username": "gauss", "password": f"wrong-{i}"})
        assert r.status_code == 200, f"attempt {i + 1} should just fail, not lock"
    # attempt #limit: still a plain failure, but it trips the limit
    client.post(url, {"username": "gauss", "password": "wrong-last"})
    # now even the correct password is refused
    r = client.post(url, {"username": "gauss", "password": PASSWORD})
    assert r.status_code == 429  # Too Many Requests, rendered from AXES_LOCKOUT_TEMPLATE
    assert "Too many failed sign-in attempts" in r.content.decode()


def test_successful_login_resets_the_counter(client):
    get_user_model().objects.create_user("gauss", password=PASSWORD)
    url = reverse("login")
    for i in range(10):
        client.post(url, {"username": "gauss", "password": f"wrong-{i}"})
    assert client.post(url, {"username": "gauss", "password": PASSWORD}).status_code == 302
    from axes.models import AccessAttempt

    assert not AccessAttempt.objects.filter(username="gauss").exists()
