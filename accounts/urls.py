from django.contrib.auth import views as auth_views
from django.urls import path

from . import simulation, views

urlpatterns = [
    path("signup/", views.signup, name="signup"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("password/change/", views.PasswordChangeView.as_view(), name="password_change"),
    path("password/change/done/", views.password_change_done, name="password_change_done"),
    path("simulation/", simulation.simulation_page, name="simulation"),
    path("simulation/api/build/", simulation.api_build, name="simulation_build"),
    path("simulation/api/check/", simulation.api_check, name="simulation_check"),
    path("simulation/api/hunt/", simulation.api_hunt, name="simulation_hunt"),
]
