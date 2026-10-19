"""
Forms are the *only* place passwords are set in this project; each one runs
the full AUTH_PASSWORD_VALIDATORS chain via validate_password(). A guard test
(accounts/tests/test_bypass_guard.py) fails if a new code path calls
set_password or make_password outside the allow-list.
"""

from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import BaseUserCreationForm, PasswordChangeForm

from .models import User

PASSWORD_WIDGET_ATTRS = {
    # NIST: allow password managers/autofill and paste; offer a display option (see JS).
    "autocomplete": "new-password",
    "maxlength": "256",
    "spellcheck": "false",
    "autocapitalize": "off",
    "class": "password-input",
}


class SignupForm(BaseUserCreationForm):
    email = forms.EmailField(required=True)

    class Meta(BaseUserCreationForm.Meta):
        model = User
        fields = ("username", "email")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in ("password1", "password2"):
            self.fields[name].widget.attrs.update(PASSWORD_WIDGET_ATTRS)
        self.fields["password1"].help_text = password_validation.password_validators_help_text_html()
        self.fields["password1"].label = "Password"
        self.fields["password2"].label = "Password (again)"

    def clean_email(self):
        email = self.cleaned_data["email"].strip().lower()
        if User.objects.filter(email__iexact=email).exists():
            raise forms.ValidationError("An account with this e-mail already exists.")
        return email


class NistPasswordChangeForm(PasswordChangeForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in ("new_password1", "new_password2"):
            self.fields[name].widget.attrs.update(PASSWORD_WIDGET_ATTRS)
        self.fields["old_password"].widget.attrs.update({"autocomplete": "current-password", "class": "password-input"})
        self.fields["new_password1"].help_text = password_validation.password_validators_help_text_html()

    def save(self, commit=True):
        user = super().save(commit=False)
        # A changed password resolves the "evidence of compromise" state.
        user.password_compromised_at = None
        if commit:
            user.save()
        return user

