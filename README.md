PhishEye - Outil de Détection de Phishing


PhishEye est un outil d'analyse en ligne de commande développé en Python, conçu pour détecter les tentatives de phishing en inspectant des URLs. Il combine une analyse rapide via des API externes avec une inspection locale approfondie pour fournir un verdict fiable sur la dangerosité d'un lien.

Cet outil est destiné aux étudiants, aux professionnels de la cybersécurité et à toute personne souhaitant un moyen rapide et efficace de vérifier une URL suspecte.




📸 Capture d'écran
![Capture d'écran de PhishEye en action](/home/sherko/PhishEye/demo.png)



🌟 Fonctionnalités Clés

PhishEye utilise une approche multi-couches pour évaluer une URL :

    🌐 Analyse via VirusTotal : Utilise l'API de VirusTotal pour obtenir un verdict immédiat basé sur plus de 70 moteurs de sécurité. Si un lien est unanimement reconnu comme malveillant, l'analyse s'arrête là pour une efficacité maximale.

    👤 Analyse WHOIS Détaillée : Récupère les informations publiques du domaine pour détecter les signaux d'alerte. Un point crucial de l'analyse est la date de création du domaine : les sites de phishing ont très souvent des domaines créés quelques jours ou semaines avant leur utilisation.

    🔒 Validation du Certificat TLS/SSL : Vérifie si le site utilise une connexion HTTPS sécurisée avec un certificat valide et émis par une autorité de confiance. L'absence de certificat ou un certificat invalide est un indicateur de suspicion majeur.

    ↔️ Vérification des Enregistrements DNS : Analyse les enregistrements DNS (A, MX) pour vérifier si l'infrastructure derrière le domaine est cohérente. L'absence d'un enregistrement MX (serveur mail) peut être suspecte pour un site se faisant passer pour une entité officielle.

    📄 Inspection du Contenu Web (HTTP/HTML) : Visite la page de manière sécurisée pour détecter des techniques de phishing courantes comme les redirections (pour masquer la destination finale), l'utilisation d'iframes (pour injecter du contenu malveillant) ou un nombre excessif de liens externes.



⚙️ Méthodologie

L'efficacité de PhishEye repose sur une stratégie d'analyse en deux temps :

    Filtre Rapide : L'URL est d'abord soumise à VirusTotal. Si elle est identifiée comme "Malveillante", le verdict est immédiat et le programme s'arrête. C'est le cas le plus rapide.

    Analyse Approfondie : Si VirusTotal juge l'URL "Légitime", "Suspecte" ou si l'analyse échoue, PhishEye considère que le doute persiste. Il lance alors sa suite complète d'analyses locales (WHOIS, TLS, DNS, Contenu Web) pour collecter des preuves. Un moteur de décision basé sur des règles évalue ces preuves pour fournir un verdict final nuancé.



🚀 Installation

PhishEye est un script Python et ne nécessite que quelques étapes pour être opérationnel.

Prérequis :

    Python 3.8+

    Git


Étapes d'installation :

Clonez le dépôt :

git clone https://github.com/SHERKO10/PhishEye.git

cd PhishEye

  

Créez et activez un environnement virtuel (recommandé) :
    
# Pour Linux/macOS
python3 -m venv MyEnv
source MyEnv/bin/activate

# Pour Windows
python -m venv MyEnv
MyEnv\Scripts\activate




Installez les dépendances :
        
    pip install -r requirements.txt

      

▶️ Utilisation

Pour lancer une analyse, exécutez le script principal phishEye.py :
    
----- python phishEye.py

  

Le programme vous demandera ensuite :

    L'URL à analyser : Entrez le lien que vous souhaitez inspecter.



  

👥 Auteurs et Remerciements

Ce projet est le fruit d'une collaboration et d'une évolution.

    Version 2.0 (Architecture modulaire et analyses avancées) :

        POZOU Ewaba Emmanuel

        ANANIVI Norbert

    Version 1.0 (Analyse initiale basée sur les features de l'URL) :

        POZOU Emmanuel

📜 Licence

Ce projet est distribué sous la Licence MIT. Voir le fichier LICENSE pour plus de détails.


⚠️ Avertissement

Cet outil est fourni à des fins éducatives et de recherche en cybersécurité. Les auteurs ne peuvent être tenus responsables de toute utilisation malveillante ou de tout dommage causé par son utilisation. N'utilisez cet outil que sur des sites et des systèmes pour lesquels vous avez une autorisation explicite. La prudence est de mise lors de l'analyse de liens potentiellement dangereux.
