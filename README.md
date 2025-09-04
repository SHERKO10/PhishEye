# 🔎 PhishEye👁️ - Détection de Phishing basée sur l'analyse d'URL

PhishEye👁️ est un outil simple permettant de détecter les liens de phishing à partir de leurs caractéristiques.  
Il analyse une URL donnée et extrait plusieurs **features** (longueur, présence de mots suspects, IP dans le domaine, etc.) pour fournir un **verdict** clair :

- ✅ Lien Légitime  
- ⚠️ Lien Suspect  
- ❌ Potentiellement un lien de Phishing  

---

## 🚀 Fonctionnalités

- Normalisation des URLs saisies par l’utilisateur  
- Extraction de plusieurs **indicateurs de risque** :
  - Longueur de l’URL  
  - Nombre de sous-domaines  
  - Présence d’une adresse IP au lieu d’un domaine  
  - Présence de caractères suspects (`@`, tirets `-`, etc.)  
  - Extension de domaine (TLD) utilisée  
  - Recherche de mots suspects liés au phishing (`login`, `bank`, `free`, etc.)  
- Classification finale en **3 catégories** (Légitime, Suspect, Phishing)  
- Enregistrement automatique des résultats dans un fichier CSV (`resultats_phishing.csv`)  
- Affichage technique dans le terminal (clé/valeur)





---

## 🛠️ Installation

### 1. Cloner le projet

git clone https://github.com/SHERKO10/PhishEye
cd PhishEye



### 2. Créer un environnement virtuel (optionnel mais recommandé)

python -m venv venv
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows


### 3. Installer les dépendances

pip install -r requirements.txt


▶️ Utilisation

Lancer le programme :

python PhishEye.py


Exemple :

Entrez une URL : http://secure-login-paypal.com
URL normalisée: http://secure-login-paypal.com

=== Analyse technique ===
longueur_url      : 28
nbre_sous_domaines: 1
contient_ip       : False
nbre_tirets       : 2
contient_arobase  : False
tld               : com
mots_suspects     : ['secure', 'login', 'paypal']

Verdict : ❌ Potentiellement un lien de Phishing

Les résultats sont aussi sauvegardés dans resultats_phishing.csv.



📜 Licence

Projet open-source sous licence MIT.
Vous êtes libre de l’utiliser, le modifier et le partager


👨‍💻 Auteur

Projet développé par SHERKO, étudiant en réseaux et cybersécurité.
N’hésitez pas à contribuer ou proposer des améliorations via des Pull Requests 🚀





