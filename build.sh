#!/usr/bin/env bash
# Exit on error
set -o errexit

# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Préparer les fichiers statiques (CSS)
# L'option --no-input répond 'yes' automatiquement à la question
python manage.py collectstatic --no-input

# 3. Créer/Mettre à jour les tables de la base de données
python manage.py migrate

# 4. (OPTIONNEL) Lancer l'importation initiale des données
# ATTENTION : Cette commande peut être très longue. Si elle dépasse
# le temps de build autorisé par Render (souvent 15 min), le déploiement échouera.
# On peut la commenter après le premier déploiement réussi.
python importer_listeBlanche.py