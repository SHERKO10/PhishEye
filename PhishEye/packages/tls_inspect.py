#Auteur : ANANIVI Norbert, Etudiant en Cybersécurité
#Date : 17/09/2025
#VERSION : 2.0

import ssl
import socket
from urllib.parse import urlparse
import certifi

def get_certificate_info(hostname, port=443):
    """Obtient les informations du certificat en utilisant un magasin de confiance fiable."""

    context = ssl.create_default_context()

    # On force l'utilisation du magasin de certificats de 'certifi' pour plus de fiabilité
    context.load_verify_locations(certifi.where())

    with socket.create_connection((hostname, port), timeout=5) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert()
        



def analyser_certificat(url):
    """Analyse le certificat et retourne un verdict simple et correct."""
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return "Invalide ou absent"
        
        get_certificate_info(hostname)

        return "Valide"
    
    except Exception as e:
        return "Invalide ou absent"

