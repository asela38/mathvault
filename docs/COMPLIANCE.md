# NIST SP 800-63B Rev. 4 — compliance checklist

Source: https://pages.nist.gov/800-63-4/sp800-63b.html (§3.1.1.2 Password
Verifiers, §3.2.2 Rate Limiting). Rev. 4 was published in August 2025. Status
is for the code in this repository; "where" points at the implementation and
the test that proves it.

| # | Rule (level) | How MathVault meets it | Where | Status |
|---|---|---|---|---|
| 1 | Minimum 15 characters when the password is the only factor (**SHALL**) | `MinimumLengthValidator(min_length=15)` | `config/settings.py`; `test_minimum_length_is_15_and_counts_code_points` | Covered |
| 2 | Permit at least 64 characters (**SHOULD**) | `MaximumLengthValidator(max_length=256)` refuses to be configured below 64; form fields use `maxlength="256"` | `accounts/validators.py`; `test_maximum_length_allows_at_least_64`, `test_signup_page_offers_guidance_and_allows_managers` | Covered |
| 3 | Accept all printing ASCII, space and Unicode; count each code point as one character (**SHOULD / SHALL**) | Django accepts any `str`; `len()` counts code points; no character is stripped | `test_minimum_length_is_15_and_counts_code_points` (15 maths symbols pass) | Covered |
| 4 | Apply NFC normalisation to Unicode passwords (**SHOULD**) | `User.set_password` / `check_password` normalise with `unicodedata.normalize("NFC", …)` | `accounts/models.py`; `test_nfc_normalisation_on_set_and_check` | Covered |
| 5 | Request the whole password and verify all of it, no truncation (**SHALL**) | Nothing truncates; Django hashers hash the full string (and refuse > 4096 bytes as a DoS guard) | `MaximumLengthValidator` docstring | Covered |
| 6 | No composition rules (**SHALL NOT**) | `NumericPasswordValidator` not configured; no other character-class rule | `test_numeric_password_validator_is_not_configured` | Covered |
| 7 | No periodic change; force a change on evidence of compromise (**SHALL NOT / SHALL**) | No expiry logic; `password_compromised_at` + `CompromisedPasswordMiddleware`; `flag_compromised_passwords` command and admin action record the evidence | `accounts/middleware.py`; `test_compromised_user_is_forced_to_change_password`, `test_no_periodic_expiry_logic_exists` | Covered |
| 8 | Blocklist of commonly used passwords (**SHALL**) | `CommonPasswordValidator` (Django's 20k list) + HIBP Bloom filter | `test_known_bad_rejected_by_chain` | Covered |
| 9 | Blocklist of compromised passwords (**SHALL**) | `BloomPwnedValidator` over the full HIBP corpus (no false negatives) and/or `HIBPRangeApiValidator` | `accounts/validators.py`; `test_breached_but_long_password_is_caught_only_by_bloom`, `test_api_validator_rejects_when_found_and_passes_otherwise` | Covered |
| 10 | Blocklist of context-specific words: service name, username, derivatives (**SHALL**) | `UserAttributeSimilarityValidator` (username, e-mail, names) + `ContextSpecificValidator` (site name, derivatives, mathematics vocabulary) | `accounts/context_terms.txt`; `test_context_specific_rejects_service_and_maths_terms`, `test_user_attribute_similarity_still_covers_username_and_email` | Covered |
| 11 | Whole-password comparison, not substrings (**SHALL**) | Every validator compares the full (canonicalised) password for equality or hash membership | `test_context_specific_does_not_do_substring_matching` | Covered |
| 12 | Blocklist large enough to defeat online guessing (**SHOULD**) | Full HIBP corpus (~1.9 billion); optional `--min-count` threshold if rejection rates prove too high | `docs/OPERATIONS.md` | Covered |
| 13 | On rejection, require a different password and state the reason (**SHALL**) | Each validator raises a distinct `ValidationError` code and message; forms re-render with the message | `test_signup_rejects_breached_password_with_reason` | Covered |
| 14 | Offer guidance for choosing a strong password, e.g. a strength meter (**SHALL**) | Validator help texts shown on signup/change forms before any attempt; length meter and character count in `password-ui.js` | `test_help_texts_mention_every_rule`, `test_signup_page_offers_guidance_and_allows_managers` | Covered |
| 15 | Offer an option to display the password while typing (**SHOULD**) | "Show password" toggle on every password field | `static/password-ui.js` | Covered |
| 16 | Allow password managers and autofill (**SHALL**); permit paste (**SHOULD**) | `autocomplete="new-password"` / `"current-password"`; no `onpaste` handlers anywhere | `test_signup_page_offers_guidance_and_allows_managers` | Covered |
| 17 | No password hints visible to unauthenticated users; no knowledge-based authentication (**SHALL NOT**) | Not implemented anywhere | — | Covered |
| 18 | Salted and hashed with a suitable scheme; salt ≥ 32 bits; cost as high as practical (**SHALL / SHOULD**) | Argon2id first in `PASSWORD_HASHERS` (128-bit salt, memory-hard); PBKDF2 kept for upgrade-on-login | `test_argon2id_is_the_production_hasher` | Covered |
| 19 | Additional keyed hash with a verifier-only secret, i.e. a pepper (**SHOULD**) | Not implemented: Django's hasher API has no pepper hook; adding one means a custom hasher and a key-rotation story | — | **Not implemented (SHOULD)** |
| 20 | Rate limiting: ≤ 100 consecutive failed attempts per account (**SHALL**, §3.2.2) | django-axes, `AXES_FAILURE_LIMIT = 100`, lockout keyed on username (and separately IP), 24 h cool-off or admin reset | `config/settings.py`; `test_account_locks_at_the_nist_cap` | Covered |
| 21 | Every path that sets a password runs the chain | Only Django forms set passwords; guard test fails on any new `set_password(` outside the allow-list | `accounts/tests/test_bypass_guard.py` | Covered |
| 22 | Phishing-resistant MFA for AAL2+ | Out of scope for this reference project | — | Separate work |

## Two caveats, as in the source article

* NIST does not certify blocklists. Using HIBP is a widely accepted way to
  meet rules 8–9 and 12, not an official endorsement.
* SP 800-63B is mandatory for US federal agencies. Elsewhere it is the
  benchmark auditors and customers expect, not a legal requirement.

## Local decisions you may revisit

| Decision | Here | Alternative |
|---|---|---|
| Minimum length | 15 (password-only login) | 8 if MFA is enforced for every account |
| Maximum length | 256 | Anything ≥ 64; Django hard-stops at 4096 bytes |
| Bloom false-positive rate | 1 in 10,000 (~4.3 GB) | 1 in 1,000 (~3.2 GB) or 1 in 1,000,000 (~6.5 GB) |
| Breach-count threshold | none (include everything) | rebuild with `--min-count N` if rejection rates are too high |
| Failure mode | fail-open (+ log + system check) | `PWNED_FAIL_CLOSED=1` |
| Lockout | per username and per IP, 100, 24 h | lower limit, CAPTCHA after N, cache handler for scale |
| Context terms | site name + mathematics vocabulary | add product names, internal project names, local variants |
