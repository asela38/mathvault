# MathVault — NIST SP 800-63B Rev. 4 password screening in Django

A reference Django 6.1 project that implements the password rules of
**NIST SP 800-63B Rev. 4 §3.1.1.2** properly, end to end, in a small but real
application: a problem-and-proof sharing portal for mathematicians.

It follows the design from *Implementing Common and Compromised Password
Validation in Django* (the source article): keep Django's validators, add an
offline Have I Been Pwned (HIBP) check built as a Bloom filter, add a validator
for context-specific terms — and treat everything around the validator chain
(rate limiting, hashing, Unicode, forced change on compromise, the UI) as part
of the same requirement.

```
                   AUTH_PASSWORD_VALIDATORS (config/settings.py)
                   ┌────────────────────────────────────────────────────────────┐
  signup form ───▶ │ 1 UserAttributeSimilarityValidator   expected (username/email)│
  change form ───▶ │ 2 MinimumLengthValidator(15)         SHALL ≥ 15 chars        │
  admin / CLI ───▶ │ 3 MaximumLengthValidator(256)        SHOULD allow ≥ 64        │
                   │ 4 CommonPasswordValidator            commonly used (Django 20k)│
                   │ 5 BloomPwnedValidator ── mmap ─▶ data/pwned/current.bloom (HIBP, offline)
                   │ 6 HIBPRangeApiValidator ── https ─▶ api.pwnedpasswords.com/range/{5 hex}
                   │ 7 ContextSpecificValidator           expected (site name, maths vocabulary)
                   └────────────────────────────────────────────────────────────┘
                     + django-axes (≤ 100 consecutive failures per account, §3.2.2)
                     + Argon2id hashing, NFC normalisation, forced change on compromise
```

## Quick start

```bash
cd mathvault
make setup          # uv sync, migrate, build a demo Bloom filter, seed demo data
make run            # http://127.0.0.1:8000  (demo login: hypatia / correct-horse-ellipse-perimeter-9)
make test           # 71 tests, ~2 s
make check          # Django system checks + Bloom filter health report
```

Open http://127.0.0.1:8000/accounts/simulation/ to watch a Bloom filter being
built from a password list and then used as a validator, with the real code.

Try signing up with `correcthorsebatterystaple` (rejected by the Bloom layer:
breached but *not* in Django's 20k list), `MathVault-2026!!` (rejected:
derivative of the site name), `riemann-hypothesis-2026` (rejected: expected on
a maths site), `fourteen-chars` (rejected: too short), and then a passphrase
like `the integral of e to the minus x squared is root pi`. Every rejection
names its reason; the help text under the field is shown before and after.

> The demo Bloom filter is built from Django's 20k list plus a few extras so
> the layer is visible in development. Production builds use the full HIBP
> corpus (~1.9 billion SHA-1s → ~4.3 GB filter); see `docs/OPERATIONS.md`.

## Layout

| Path | What it is |
|---|---|
| `config/settings.py` | Everything under **PASSWORD POLICY** and **RATE LIMITING**, each line cross-referenced to the NIST rule it satisfies |
| `accounts/validators.py` | `MaximumLengthValidator`, `BloomPwnedValidator`, `HIBPRangeApiValidator`, `ContextSpecificValidator` |
| `accounts/pwned/bloom.py` | Bloom filter file format, sizing, bit-position formula; builder (pure Python + numpy) and reader (mmap) in one module so they cannot drift |
| `accounts/pwned/hibp.py` | k-anonymity range API client (prefix only, `Add-Padding: true`) |
| `accounts/context_terms.txt` | Context-specific blocklist: service name, derivatives, and the vocabulary a mathematics community shares |
| `accounts/models.py` | Custom `User`: NFC-normalised passwords, `password_compromised_at` |
| `accounts/middleware.py` | Forces a change only on evidence of compromise (never periodically) |
| `accounts/checks.py` | System checks: Bloom file missing/corrupt (W001/E001) or stale (W002) |
| `accounts/management/commands/` | `build_pwned_bloom`, `check_pwned_bloom`, `flag_compromised_passwords` |
| `accounts/forms.py`, `templates/`, `static/password-ui.js` | Help text before and after rejection, show-password toggle, length meter, paste/autofill never blocked, `maxlength=256` |
| `accounts/tests/` | Parity, known-bad/known-good, empirical false-positive rate, fail-open/closed, API mocking, context terms, Unicode, lockout, bypass guard |
| `accounts/simulation.py`, `static/bloom-sim.js` | Interactive page at `/accounts/simulation/`: builds a filter from a password list step by step (sizing, SHA-1, k positions, bit grid), then checks a candidate and shows the real validator's verdict, including a false-positive hunt |
| `problems/` | The mathematics domain: problems, solutions, KaTeX rendering, `seed_demo` |
| `scripts/refresh_pwned.sh` | Monthly refresh job: download → build → checksum → atomic swap |
| `docs/COMPLIANCE.md` | Rule-by-rule checklist with the code and test that covers each |
| `docs/OPERATIONS.md` | Corpus download, sizing, deployment, monitoring, rollback |

## Design decisions (and where they differ from a naive implementation)

* **Whole-password matching everywhere.** NIST: "the entire password SHALL be
  subject to comparison, not substrings". `ContextSpecificValidator`
  canonicalises (NFC, casefold, drop separators, strip edge digits/punctuation,
  undo leetspeak) and then tests *equality*, so `MathVault2026!` and
  `M@th-V4ult` are caught as "derivatives thereof" while
  `mathvault-is-where-i-keep-my-lemmas` passes.
* **Two HIBP modes, same validator list.** The Bloom validator is the
  recommended production path (no network, no false negatives, ~4.3 GB per
  node). The API validator is a no-op when `PWNED_API_ENABLED=0`, so the same
  settings serve online and air-gapped deployments. Running both is fine.
* **Fail-open by default, fail-closed by switch.** With the filter missing the
  Bloom validator logs `pwned_bloom_unavailable` and returns; Django's 20k list
  and the API still screen. `PWNED_FAIL_CLOSED=1` rejects with a clear
  "temporarily unavailable" message instead.
* **No `NumericPasswordValidator`.** It is a composition rule, which Rev. 4
  says verifiers SHALL NOT impose. The 15-character minimum and the breach
  corpus already reject every realistic PIN.
* **Length counted in code points**, as NIST specifies; `len(str)` in Python
  does exactly that. Passwords are NFC-normalised before hashing *and*
  checking, so decomposed input still verifies.
* **Rate limiting is per account** (`AXES_LOCKOUT_PARAMETERS = ["username", "ip_address"]`,
  limit 100) because the NIST cap is "on a single subscriber account".
* **Forced change only on evidence.** `flag_compromised_passwords` or the admin
  action sets `password_compromised_at`; the middleware then allows only the
  change-password and logout routes. There is no expiry logic anywhere (a test
  asserts this).
* **A bypass guard test** greps the tree for `set_password(` / `make_password(`
  / `create_user(` outside an allow-list, because Django only runs validators
  inside its forms and two management commands.

## What is deliberately out of scope

* MFA / phishing-resistant authenticators (AAL2+). The 15-character minimum
  assumes password-only login; drop to 8 only if MFA is enforced for everyone.
* A secret "pepper" (NIST SHOULD: an extra keyed hash). Django has no built-in
  hook; see `docs/COMPLIANCE.md` for the trade-off.
* Password reset by e-mail (Django's built-in views work unchanged and run the
  same validator chain).
