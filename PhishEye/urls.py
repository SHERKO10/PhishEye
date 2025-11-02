# PhishEye/urls.py
from django.urls import path, include

urlpatterns = [
    path('', include('frontend.urls')), # On dit au projet d'inclure les URL de l'app 'frontend'
]