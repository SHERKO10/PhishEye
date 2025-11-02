# frontend/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'), # L'URL racine '' appelle la vue 'index'
]