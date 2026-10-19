"""
Force a password change only on evidence of compromise (NIST SP 800-63B Rev. 4
§3.1.1.2: "verifiers SHALL force a change if there is evidence that the
authenticator has been compromised" — and SHALL NOT require periodic changes).
"""

from django.shortcuts import redirect
from django.urls import reverse


class CompromisedPasswordMiddleware:
    exempt_url_names = ("password_change", "password_change_done", "logout")

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        user = getattr(request, "user", None)
        if user is not None and user.is_authenticated and getattr(user, "must_change_password", False):
            match = getattr(request, "resolver_match", None) or _resolve(request)
            if match is None or match.url_name not in self.exempt_url_names:
                if not request.path.startswith(("/static/", "/admin/")):
                    return redirect(reverse("password_change"))
        return self.get_response(request)


def _resolve(request):
    from django.urls import Resolver404, resolve

    try:
        return resolve(request.path_info)
    except Resolver404:
        return None
