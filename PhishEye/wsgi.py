"""
WSGI config for PhishEye project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

# On dit à Django où trouver le fichier de configuration principal
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PhishEye.settings')

application = get_wsgi_application()