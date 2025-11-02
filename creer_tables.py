import os
import sys
import django

# Ajoute le dossier courant au PYTHONPATH
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Si ton projet s'appelle "PhishEye" à l'intérieur de PhishEye-V3
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PhishEye.settings')

django.setup()

print("Les tables ont été créées avec succès ! ")