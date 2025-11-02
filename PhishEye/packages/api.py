#Auteurs : POZOU Emmanuel & ANANIVI Norbert
#Date : 17/09/2025
#VERSION : 2.0

import requests
import time

CLE_API = "9a0a7a2811fc1ecdca34723fdb52c8150396af7fb4f276af2ba6a6aa97348ed9"

def analyse_virus_total(url):
    """
    Cette fonction nous permet d'envoyer directement le lien
    entrée par l'utilisateur vers VirusTotal via une API.
    Cette API a été fournie sur le site Officiel de virusTotal

    Une fois Que le lien est envoyé les moteurs de recherches de
    Virus Total s'en charge et essayent de vérifier si c'est un lien
    légitime et une réponse est renvoyé sur le terminal
    
    
    """




    #Vérification si l'API a été fournie
    if not CLE_API:
        return {"Erreur : Aucune clé API n'a été fournie"}
    


    #Soumissions de l'url à VirusTotal

    url_scan = 'https://www.virustotal.com/api/v3/urls'
    payload = {'url': url}
    en_tetes = {'x-apikey': CLE_API}

    


    try:

        reponse = requests.post(url_scan, headers=en_tetes, data=payload)

        #fonction pour lever les erreurs de type 404, 500
        reponse.raise_for_status()

        #extraction de l'ID du site à analyser
        analyse_id = reponse.json()['data']['id']

        time.sleep(15)



        #URL comportant l'ID de l'analyse
        url_rapport = f'https://www.virustotal.com/api/v3/analyses/{analyse_id}'


        #Requête GET pour récupérer les réponses
        reponse_rapport = requests.get(url_rapport, headers=en_tetes, timeout=10)
        reponse_rapport.raise_for_status()



        #récupération des informations importantes pour un verdict claire

        statistiques = reponse_rapport.json()['data']['attributes']['stats']

        nbre_malveillant = statistiques.get('malicious', 0)
        nbre_suspect = statistiques.get('suspicious', 0)


        if nbre_malveillant > 0:
            verdict = f"Malveillant ({nbre_malveillant} détections)"
        
        elif nbre_suspect > 0:
            verdict = f"Suspect ({nbre_suspect} détections)"
        
        else:
            verdict = f"Légitime"

        return verdict
        


    #Gestion d'erreur HTTP sur L'API
    except requests.exceptions.HTTPError as e:
        return f"Erreur API {e.response.status_code}"
    
    #Gestion d'erreur de connexion à l'API
    except requests.exceptions.RequestException as e:
        return f"Erreur de connexion"
    
    #Gestion d'erreur de la réponse en JSON si elle n'a pas de structure
    except KeyError:
        return f"Erreur : Réponse inattendue de l'API"
    
    
    


