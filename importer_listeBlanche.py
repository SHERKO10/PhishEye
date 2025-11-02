# --- On démarre le moteur Django ---
import os
import django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PhishEye.settings')
django.setup()


import csv
from PhishEye.bases_donnees.models import ListeBlanche, URLMalveillants

# Import de la liste blanche
print("Import de la liste blanche...")
ListeBlanche.objects.all().delete()
with open('majestic_million.csv', 'r') as f:
    reader = csv.reader(f)
    next(reader) # sauter la première ligne
    domains = [ListeBlanche(domain=row[2]) for row in reader]
    ListeBlanche.objects.bulk_create(domains)
print(f"{len(domains)} domaines légitimes ajoutés.")

# Import de la liste noire
print("Import de la liste noire...")
URLMalveillants.objects.all().delete()
with open('urlhaus.abuse.txt', 'r') as f:
    urls = [
        URLMalveillants(url=line.strip(), source='URLhaus') 
        for line in f if not line.startswith('#')
    ]
    URLMalveillants.objects.bulk_create(urls)
print(f"{len(urls)} URLs malveillantes ajoutées.")