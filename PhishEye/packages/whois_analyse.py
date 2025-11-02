#Auteur : POZOU Emmanuel, Etudiant en Réseaux, Systèmes et Cybersécurité
#Date : 17/09/2025
#VERSION : 2.0

import whois
import tldextract


def analyse_whois(url):
    """Fonction pour analyser une URL donnée et extraire les informations suivantes:
    - nom du domaine
    - le propriétaire du domaine si possible
    - le registrar
    - date de création
    - date d'expiration
    - dernière mise à jour
    - serveurs DNS associés
    """
    

    try:
        # Extraire le domaine avec tldextract
        ext = tldextract.extract(url)
        domaine = f"{ext.domain}.{ext.suffix}"

        # Vérifier si le domaine est valide
        if not ext.domain:
            return {"erreur": "Nom de domaine inexistant"}

        # Interroger le serveur WHOIS avec le domaine
        infos_whois = whois.whois(domaine)

        # Vérifier si des informations sont disponibles
        if infos_whois.get('domain_name') is None:
            return {"erreur": f"Aucune information trouvée sur le nom de domaine '{domaine}'. Il peut s'agir d'un domaine inconnu ou protégé"}

        # Fonction pour retourner uniquement les premiers éléments si c'est une liste
        def nettoyer_data(data):
            if isinstance(data, list):
                return data[0] if data else None
            return data

        # Résultats au format dictionnaire
        resultats = {
            "nom_domaine": nettoyer_data(infos_whois.domain_name),
            "proprietaire": infos_whois.get('org', 'information masquée/Non disponible'),
            "registrar": nettoyer_data(infos_whois.registrar),
            "date_creation": nettoyer_data(infos_whois.creation_date),
            "date_expiration": nettoyer_data(infos_whois.expiration_date),
            "derniere_maj": nettoyer_data(infos_whois.updated_date),
            "serveur_dns": infos_whois.name_servers
        }

        
        return resultats

    except Exception as e:
        print(f"Erreur : Une erreur est survenue lors de l'analyse WHOIS : {e}")
        return {"erreur": str(e)}

