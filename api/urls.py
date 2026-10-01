from django.urls import path
from . import views

urlpatterns = [
    path("", views.login),
    path("auth", views.auth),
    path("hello/", views.hello),
]