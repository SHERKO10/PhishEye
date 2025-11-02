#Auteur : ANANIVI Norbert, Etudiant en Cybersécurité
#Date : 17/09/2025
#VERSION : 2.0


"""
site_checker_html.py
Vérifie si un site web répond, détecte les redirections
et analyse le HTML pour repérer des éléments suspects.
"""


import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def inspecter_page_web(url):
    """Analyse la réponse HTTP et le contenu HTML et retourne un dictionnaire."""
    resultats = {"erreur": True}
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        domaine_base = urlparse(response.url).netloc
        
        liens_externes = 0
        for a in soup.find_all('a', href=True):
            if a['href'].startswith('http') and domaine_base not in urlparse(a['href']).netloc:
                liens_externes += 1
        
        resultats = {
            "redirection": bool(response.history),
            "iframes_count": len(soup.find_all("iframe")),
            "liens_externes_count": liens_externes,
            "erreur": False
        }
        return resultats
    except requests.exceptions.RequestException:
        return resultats
