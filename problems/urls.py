from django.urls import path

from . import views

app_name = "problems"
urlpatterns = [
    path("", views.problem_list, name="list"),
    path("problems/new/", views.problem_create, name="create"),
    path("problems/<int:pk>/", views.problem_detail, name="detail"),
]
