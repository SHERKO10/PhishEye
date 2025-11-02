# --- On démarre le moteur Django ---
import os
import sys
import django


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PhishEye.settings')
django.setup()


import csv

from PhishEye.bases_donnees.models import ListeBlanche, URLMalveillants


print("\n>>> Importation de la liste blanche (Majestic Million) par paquets...")
try:
    ListeBlanche.objects.all().delete()
    print("   - Anciennes données de la liste blanche supprimées.")

    batch_size = 5000  # On va insérer 5000 domaines à la fois
    domains_to_create = []

    # On s'assure que le chemin vers le fichier est correct
    file_path = os.path.join(BASE_DIR, 'bases_donnees', 'majestic_million.csv')

    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader) # sauter la première ligne

        total_imported = 0
        for i, row in enumerate(reader):
            domains_to_create.append(ListeBlanche(domain=row[2]))
            
            # Si on atteint la taille du paquet, on insère et on vide la liste
            if (i + 1) % batch_size == 0:
                ListeBlanche.objects.bulk_create(domains_to_create)
                total_imported += len(domains_to_create)
                domains_to_create = [] # On réinitialise la liste
                print(f"   - {total_imported} domaines insérés...")

    # Insérer le dernier paquet s'il en reste
    if domains_to_create:
        ListeBlanche.objects.bulk_create(domains_to_create)
        total_imported += len(domains_to_create)
        print("   - Dernier paquet inséré.")
    
    print(f"\n   - SUCCÈS : {total_imported} domaines légitimes ajoutés au total.")

except FileNotFoundError:
    print(f"   - ERREUR : Le fichier {file_path} n'a pas été trouvé.")
except Exception as e:
    print(f"   - ERREUR inattendue lors de l'import de la liste blanche : {e}")



print("\n>>> Importation de la liste noire (URLhaus) par paquets...")
try:
    URLMalveillants.objects.all().delete()
    print("   - Anciennes données de la liste noire supprimées.")

    batch_size = 5000  # On utilise la même taille de paquet
    urls_to_create = []

    file_path = os.path.join(BASE_DIR, 'bases_donnees', 'urlhaus.abuse.txt')

    with open(file_path, 'r', encoding='utf-8') as f:
        total_imported = 0
        lines = f.readlines() # On lit toutes les lignes d'un coup
        for i, line in enumerate(lines):
            if not line.startswith('#') and line.strip(): # Ignorer les commentaires et les lignes vides
                urls_to_create.append(URLMalveillants(url=line.strip(), source='URLhaus'))
                
                # Si on atteint la taille du paquet, on insère et on vide la liste
                if (i + 1) % batch_size == 0:
                    URLMalveillants.objects.bulk_create(urls_to_create)
                    total_imported += len(urls_to_create)
                    urls_to_create = [] # On réinitialise la liste
                    print(f"   - {total_imported} URLs malveillantes insérées...")

    # Insérer le dernier paquet s'il en reste
    if urls_to_create:
        URLMalveillants.objects.bulk_create(urls_to_create)
        total_imported += len(urls_to_create)
        print("   - Dernier paquet inséré.")
        
    print(f"\n   - SUCCÈS : {total_imported} URLs malveillantes ajoutées au total.")

except FileNotFoundError:
    print(f"   - ERREUR : Le fichier {file_path} n'a pas été trouvé.")
except Exception as e:
    print(f"   - ERREUR inattendue lors de l'import de la liste noire : {e}")

print("\n--- SCRIPT D'IMPORTATION TERMINÉ ---")