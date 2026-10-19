import json

import pytest
from django.urls import reverse

from accounts.pwned.bloom import positions, sha1_digest, sizing

pytestmark = pytest.mark.django_db

PASSWORDS = ["password", "123456", "P@ssw0rd", "Summer2024!"]


def post(client, name, body):
    return client.post(reverse(name), data=json.dumps(body), content_type="application/json")


def test_page_renders_with_defaults(client):
    html = client.get(reverse("simulation")).content.decode()
    assert "Stage 1" in html and "Stage 2" in html and "bloom-sim.js" in html
    assert "correcthorsebatterystaple" in html


def test_build_matches_the_real_formula(client):
    r = post(client, "simulation_build", {"passwords": PASSWORDS, "fp_rate": 0.01})
    assert r.status_code == 200
    data = r.json()
    m, k = sizing(len(PASSWORDS), 0.01)
    assert data["sizing"]["m"] == m and data["sizing"]["k"] == k
    expected_bits = set()
    for item, pw in zip(data["items"], PASSWORDS):
        assert item["sha1"] == sha1_digest(pw).hex().upper()
        assert item["positions"] == list(positions(sha1_digest(pw), m, k))
        expected_bits |= set(item["positions"])
    assert set(data["set_bits"]) == expected_bits
    assert data["header"].startswith("48494250424C4D31")  # "HIBPBLM1"
    assert 0 <= data["estimated_fp"] <= data["measured_fp"] <= 1  # toy filters: measured ≥ formula


def test_check_rejects_listed_password_with_real_validator_message(client):
    r = post(client, "simulation_check", {"passwords": PASSWORDS, "fp_rate": 0.01, "probe": "P@ssw0rd"})
    data = r.json()
    assert data["verdict"] == "reject" and data["kind"] == "true_positive"
    assert all(b["set"] for b in data["bits"]) and data["first_zero"] is None
    assert data["validator"]["code"] == "password_pwned"
    assert "data breach" in data["validator"]["message"]


def test_check_passes_unseen_password_and_stops_at_first_zero(client):
    r = post(client, "simulation_check", {"passwords": PASSWORDS, "fp_rate": 0.01, "probe": "the integral of e to the minus x squared is root pi"})
    data = r.json()
    assert data["verdict"] == "pass" and data["kind"] == "true_negative"
    assert data["bits"][data["first_zero"]]["set"] is False
    assert data["validator"]["message"] is None


def test_hunt_finds_a_false_positive(client):
    r = post(client, "simulation_hunt", {"passwords": PASSWORDS, "fp_rate": 0.1})
    data = r.json()
    assert data["verdict"] == "reject" and data["kind"] == "false_positive"
    assert data["trace"]["password"] not in PASSWORDS
    assert data["tries"] >= 1


@pytest.mark.parametrize(
    "body, msg",
    [
        ({"passwords": [], "fp_rate": 0.01}, "at least one"),
        ({"passwords": ["x"], "fp_rate": 0.9}, "between"),
        ({"passwords": [f"pw{i}" for i in range(301)], "fp_rate": 0.01}, "at most 300"),
        ({"passwords": [f"pw{i}" for i in range(300)], "fp_rate": 0.0001, "probe": "x"}, "fewer passwords"),
        ({"passwords": ["abc"], "fp_rate": 0.01}, "probe"),
    ],
)
def test_bad_input_is_rejected(client, body, msg):
    r = post(client, "simulation_check", body)
    assert r.status_code == 400 and msg in r.content.decode()


def test_endpoints_are_post_only(client):
    assert client.get(reverse("simulation_build")).status_code == 405
