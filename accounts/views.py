from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.urls import reverse_lazy

from .forms import NistPasswordChangeForm, SignupForm


def signup(request):
    if request.user.is_authenticated:
        return redirect("problems:list")
    if request.method == "POST":
        form = SignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            messages.success(request, "Welcome to MathVault. Your account is ready.")
            return redirect("problems:list")
    else:
        form = SignupForm()
    return render(request, "accounts/signup.html", {"form": form})


class PasswordChangeView(auth_views.PasswordChangeView):
    form_class = NistPasswordChangeForm
    template_name = "accounts/password_change.html"
    success_url = reverse_lazy("password_change_done")

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["forced"] = self.request.user.must_change_password
        return ctx


@login_required
def password_change_done(request):
    return render(request, "accounts/password_change_done.html")


class LoginView(auth_views.LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True
