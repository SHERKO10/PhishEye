#Création de la base de données de notre application
import os
from django.db import models
from django.utils import timezone

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'PhishEye.settings')


class ListeBlanche(models.Model):
    """Table pour contenir les domaines légitimes"""
    domain = models.CharField(max_length=2040, unique=True, db_index=True)
    date_ajout = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.domain

class URLMalveillants(models.Model):
    """Table chargé de contenir toutes les URLs malveillantes"""
    url = models.CharField(max_length=2040, unique=True, db_index=True)
    date_ajout = models.DateTimeField(default=timezone.now)
    source = models.CharField(max_length=100)


    def __str__(self):
        return self.url


class Cache(models.Model):
    """Table chargé de contenir le cache de chaque analyse déja faite pour optimiser les réponses"""

    class Verdict(models.TextChoices):
        """Table chargé de prédir le verdict selon l'anlyse faite"""
        MALVEILLANT = "Malveillant"
        LEGITIME = "Légitime"
        SUSPECT = "Suspect"
        INCONNU = "Inconnu"


    #Attributs de la classe principale

    url = models.CharField(max_length=2040, unique=True, db_index=True)
    verdict = models.CharField(max_length=20, choices=Verdict.choices)
    details = models.TextField(blank=True, null=True)
    date_analyse = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.url} - {self.verdict}'  
    

class Suggestion(models.Model):
    texte = models.TextField()
    date_creation = models.DateTimeField(auto_now_add=True) # La date est ajoutée automatiquement

    def __str__(self):
        return f"Suggestion du {self.date_creation.strftime('%d/%m/%Y')} : {self.texte[:50]}..."