import requests
from django.conf import settings # On importe les settings de Django
from django.core.management.base import BaseCommand
from PhishEye.bases_donnees.models import URLMalveillants
from decouple import config # On importe config pour lire notre .env

# L'URL de l'API (avec le sous-domaine -api, comme le montre la documentation)
URLHAUS_RECENT_API_URL = 'https://urlhaus-api.abuse.ch/v1/urls/recent/'

class Command(BaseCommand):
    help = 'Met à jour la liste noire en ajoutant les URL récentes depuis l\'API URLhaus.'

    def handle(self, *args, **options):
        # --- ÉTAPE 1 : RÉCUPÉRER LA CLÉ D'API DE MANIÈRE SÉCURISÉE ---
        # config() va la chercher dans le fichier .env ou les variables de Render
        api_key = config('URLHAUS_AUTH_KEY', default=None)

        if not api_key:
            self.stdout.write(self.style.ERROR("ERREUR : La clé d'API URLhaus (URLHAUS_API_KEY) n'est pas configurée."))
            return

        self.stdout.write(self.style.SUCCESS("--- Démarrage de la mise à jour de la liste noire ---"))
        
        # --- ÉTAPE 2 : PRÉPARER L'EN-TÊTE DE LA REQUÊTE ---
        headers = {
            'Auth-Key': api_key
        }

        try:
            self.stdout.write(f"   - Appel de l'API : {URLHAUS_RECENT_API_URL}")
            # On envoie la requête AVEC l'en-tête d'authentification
            response = requests.get(URLHAUS_RECENT_API_URL, headers=headers)
            response.raise_for_status() # Lève une exception pour les erreurs (4xx, 5xx)
            
            data = response.json()
            urls_to_add = data.get('urls', [])

            if not urls_to_add:
                self.stdout.write("   - Aucune nouvelle URL à ajouter.")
                self.stdout.write(self.style.SUCCESS("--- Fin de la mise à jour ---"))
                return

            # Le reste du code ne change pas...
            new_malicious_urls = [
                URLMalveillants(
                    url=item['url'],
                    source='URLhaus API'
                )
                for item in urls_to_add
            ]

            created_objects = URLMalveillants.objects.bulk_create(new_malicious_urls, ignore_conflicts=True)
            
            self.stdout.write(self.style.SUCCESS(f"--- Mise à jour terminée. {len(created_objects)} nouvelles URL ajoutées. ---"))

        except requests.RequestException as e:
            # Gérer les erreurs de manière plus précise
            if e.response is not None:
                self.stdout.write(self.style.ERROR(f"   - ERREUR de l'API : {e.response.status_code} {e.response.reason}"))
                self.stdout.write(self.style.ERROR(f"   - Message : {e.response.text}"))
            else:
                self.stdout.write(self.style.ERROR(f"   - ERREUR de réseau : {e}"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"   - ERREUR inattendue : {e}"))