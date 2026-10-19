import pytest
from django.contrib.auth import get_user_model
from django.urls import reverse

User = get_user_model()
pytestmark = pytest.mark.django_db

STRONG = "ellipses have no closed-form perimeter"


def signup(client, password, username="emmy", email="emmy@example.org"):
    return client.post(reverse("signup"), {"username": username, "email": email, "password1": password, "password2": password})


def test_signup_rejects_breached_password_with_reason(client):
    r = signup(client, "correcthorsebatterystaple")
    assert r.status_code == 200
    assert "appeared in a data breach" in r.content.decode()
    assert not User.objects.filter(username="emmy").exists()


def test_signup_rejects_short_and_context_passwords(client):
    assert "at least 15 characters" in signup(client, "fourteen-chars").content.decode()
    assert "too closely tied to this site" in signup(client, "MathVault-2026!").content.decode()  # 15 chars, derivative of the site name


def test_signup_accepts_strong_passphrase_and_logs_in(client):
    r = signup(client, STRONG)
    assert r.status_code == 302
    user = User.objects.get(username="emmy")
    assert user.check_password(STRONG)
    assert client.get(reverse("problems:list")).context["user"].is_authenticated


def test_signup_page_offers_guidance_and_allows_managers(client):
    html = client.get(reverse("signup")).content.decode()
    assert "at least 15 characters" in html  # help text shown before any rejection
    assert "data breaches" in html
    assert 'autocomplete="new-password"' in html  # password managers / autofill allowed
    assert "onpaste" not in html and "paste" not in html.lower().split("script")[0]  # paste never blocked
    assert 'maxlength="256"' in html  # ≥ 64 characters accepted
    assert "password-ui.js" in html  # show-password toggle + strength meter


def test_password_change_runs_validators_and_clears_compromise_flag(client):
    user = User.objects.create_user("emmy", password=STRONG)
    user.mark_password_compromised()
    client.force_login(user)
    url = reverse("password_change")
    bad = client.post(url, {"old_password": STRONG, "new_password1": "P@ssw0rd", "new_password2": "P@ssw0rd"})
    assert bad.status_code == 200 and "data breach" in bad.content.decode()
    new = "banach spaces are complete normed spaces"
    good = client.post(url, {"old_password": STRONG, "new_password1": new, "new_password2": new})
    assert good.status_code == 302
    user.refresh_from_db()
    assert user.check_password(new) and not user.must_change_password


def test_compromised_user_is_forced_to_change_password(client):
    user = User.objects.create_user("emmy", password=STRONG)
    client.force_login(user)
    assert client.get(reverse("problems:list")).status_code == 200
    user.mark_password_compromised()
    r = client.get(reverse("problems:list"))
    assert r.status_code == 302 and r.url == reverse("password_change")
    page = client.get(reverse("password_change"))
    assert page.status_code == 200 and "evidence that your current password was exposed" in page.content.decode()
    assert client.post(reverse("logout")).status_code == 302  # logout stays reachable


def test_no_periodic_expiry_logic_exists():
    import pathlib

    src = "".join(p.read_text() for p in pathlib.Path("accounts").rglob("*.py") if "tests" not in p.parts)
    assert "password_expires" not in src and "max_password_age" not in src.lower()
