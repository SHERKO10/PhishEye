"""Programme de détection de phishing basé sur l'analyse d'URL."""




import ipaddress
import urllib.parse
import csv
import tldextract






def normalisation_url(url):
    """Fonction pour normaliser l'URL en supprimant les espaces et en ajoutant le schéma si nécessaire."""
     
    url = url.strip()
    url = url.replace(" ", "")
    url = url.replace("-", "")


    if not url.startswith("http://") and not url.startswith("https://"):
          url = "http://" + url

    
    print("URL normalisée:", url)

    return url


def longueur_url(url):
     """Fonction pour calculer la longueur de l'URL."""
     return len(url)




def nbre_sous_domaines(url):
     """Fonction pour compter le nombre de sous-domaines dans l'URL."""
     ext = tldextract.extract(url)
     return len(ext.subdomain.split('.')) if ext.subdomain else 0



def contient_ip(url):
     """Fonction pour vérifier si l'URL contient une adresse IP."""


     try:
          netloc = urllib.parse.urlparse(url).netloc
          ipaddress.ip_address(netloc)
          return True
     except ValueError:
          return False


def nbre_tirets(url):
    """Fonction pour compter le nombre de tirets dans le domaine de l'URL."""

    ext = tldextract.extract(url)
    domaine = ext.domain
    return domaine.count('-')



def contient_arobase(url):
     """Fonction pour vérifier si l'URL contient un caractère '@'."""
     return '@' in url



def tld(url):
     """Fonction pour extraire l'extension (TLD) de l'URL."""
     ext = tldextract.extract(url)
     return ext.suffix


def mots_suspects(url):
     """Fonction pour détecter la présence de mots suspects dans l'URL."""

     mots = [
     "login", "signin", "verify", "secure", "account", "update", "confirm", "validate",
     "bank", "paypal", "checkout", "payment", "billing", "transaction",
     "apple", "facebook", "google", "microsoft", "amazon", "ebay",
     "free", "bonus", "offer", "prize", "winner", "gift", "promo"]

     url_lower = url.lower()
     trouvés = [mot for mot in mots if mot in url_lower]
     return trouvés


def extraire_features(url):
    """Fonction pour extraire toutes les features de l'URL."""

    features = {
        "longueur_url": longueur_url(url),
        "nbre_sous_domaines": nbre_sous_domaines(url),
        "contient_ip": contient_ip(url),
        "nbre_tirets": nbre_tirets(url),
        "contient_arobase": contient_arobase(url),
        "tld": tld(url),
        "mots_suspects": mots_suspects(url)
    }
    return features



def classer_url(features):
     """Fonction pour classer l'URL en fonction des features extraites."""


     score = 0
     if features["longueur_url"] > 75:
          score += 1
          
     if features["nbre_sous_domaines"] > 3:
          score += 1
     
     if features["contient_ip"]:
          score += 2
     
     if features["nbre_tirets"] > 4:
          score += 1
     
     if features["contient_arobase"]:
          score += 2
     
     if features["tld"] in ['zip', 'review', 'country', 'kim', 'cricket', 'science']:
          score += 2
     
     if features["mots_suspects"]:
          score += 2

     
     if score >= 4:
          return "❌ Potentiellement un lien de Phishing"
     
     elif 2 <= score < 4:
          return "⚠️ Lien Suspect "
     
     else:
          return "✅ Lien Légitime "
     



def enregistrer_dans_csv(url, features, verdict, fichier="resultats_phishing.csv"):
     """Fonction pour enregistrer les résultats dans un fichier CSV."""
     # Définir les en-têtes du CSV

     entetes = [
        "URL", "Verdict", "Longueur URL", "Nbre sous-domaines",
        "Contient une IP", "Nbre de tirets", "Contient @", "Extension (TLD)", "Mots suspects"
     ]

    # Transformer les valeurs techniques en lisibles
     ligne = [
        url,
        verdict,
        features.get("longueur_url", ""),
        features.get("nbre_sous_domaines", ""),
        "Oui" if features.get("contient_ip", False) else "Non",
        features.get("nbre_tirets", ""),
        "Oui" if features.get("contient_arobase", False) else "Non",
        features.get("tld", ""),
        ", ".join(features.get("mots_suspects", [])) if features.get("mots_suspects") else "Aucun"
     ]

     fichier_existe = False

     try:
          with open(fichier, "r", newline='', encoding='utf-8') as f:
               fichier_existe = True
     except FileNotFoundError:
          pass

     with open(fichier, "a", newline='', encoding='utf-8') as f:
          writer = csv.writer(f)
          if not fichier_existe:
               writer.writerow(entetes)
          writer.writerow(ligne)



def afficher_resultats_cli(url, features, verdict):
     """Fonction pour afficher les résultats dans la console de manière lisible."""

     print("\n=== Résultats de l'analyse de l'URL ===")
     print(f"URL analysée     : {url}")
     print(f"Verdict          : {verdict}\n")

     for cle, valeur in features.items():
          # Traduction pour plus de lisibilité
          if isinstance(valeur, bool):
               valeur = "Oui" if valeur else "Non"
          elif isinstance(valeur, list):
               valeur = ", ".join(valeur) if valeur else "Aucun"

          print(f"{cle:20} -> {valeur}")

     print("=======================================\n")






def main():
     print(r"""



 ____    __  __  ____    ____    __  __   _____                 
/\  _`\ /\ \/\ \/\  _`\ /\  _`\ /\ \/\ \ /\  __`\                
\ \,\L\_\ \ \_\ \ \ \L\_\ \ \L\ \ \ \/'/'\ \ \/\ \              
 \/_\__ \\ \  _  \ \  _\L\ \ ,  /\ \ , <  \ \ \ \ \             
   /\ \L\ \ \ \ \ \ \ \L\ \ \ \\ \\ \ \\`\ \ \ \_\ \             
   \ `\____\ \_\ \_\ \____/\ \_\ \_\ \_\ \_\\ \_____\               
    \/_____/\/_/\/_/\/___/  \/_/\/ /\/_/\/_/ \/_____/                
                                                                               
                                                                               


    PHISHING DETECTION TOOL V1.0
    Auteur: SHERKO""")



     url = input("\nEntrez une URL : ")
     url = normalisation_url(url)
     features = extraire_features(url)
     verdict = classer_url(features)
     afficher_resultats_cli(url, features, verdict)
     enregistrer_dans_csv(url, features, verdict)

if __name__ == "__main__":
     main()