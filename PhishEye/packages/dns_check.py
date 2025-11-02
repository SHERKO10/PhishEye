#Auteur : POZOU Emmanuel, Etudiant en Réseaux, Systèmes et Cybersécurité
#Date : 17/09/2025
#VERSION : 2.0

import dns.resolver
import tldextract

def dns_check(url):
    """Fonction pour checker les enregistrements DNS

    type d'enregistrement = A, AAAA, MX, NS, CNAME

    Les résultats sont retournés sous forme de
    dictionnaire.
    """


    try:
        # Extraire le domaine avec tldextract
        ext = tldextract.extract(url)
        domaine = f"{ext.domain}.{ext.suffix}"

        # Vérifier si le domaine est valide
        if not ext.domain:
            return {"erreur": "Domaine introuvable ou invalide"}

        # Création d'un dictionnaire pour contenir les résultats
        resultat_dns = {}

        # Types d'enregistrements à vérifier
        types_enregistrements = ['A', 'AAAA', 'MX', 'NS', 'CNAME']

        # Boucle sur les types d'enregistrements
        for type_rec in types_enregistrements:
            try:
                reponses = dns.resolver.resolve(domaine, type_rec)
                resultat_dns[type_rec] = [reponse.to_text() for reponse in reponses]

            #Gestion d'erreur si aucune réponse n'est envoyée
            except dns.resolver.NoAnswer:
                resultat_dns[type_rec] = "Aucun enregistrement trouvé."

            #Gestion d'erreur au cas ou le domaine n'existerait pas 
            except dns.resolver.NXDOMAIN:
 
                return {"erreur": f"Le domaine '{domaine}' n'existe pas (NXDOMAIN)."}


        return resultat_dns

    except Exception as e:

        return {"erreur": str(e)}




