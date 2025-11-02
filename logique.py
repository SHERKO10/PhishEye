from urllib.parse import urlparse
from datetime import datetime
from PhishEye.bases_donnees.models import ListeBlanche, URLMalveillants, Cache
from PhishEye.packages.dns_check import dns_check
from PhishEye.packages.whois_analyse import analyse_whois
from PhishEye.packages.tls_inspect import analyser_certificat
from PhishEye.packages.web_analyst import inspecter_page_web



def extraire_domain(url):
    """Extrait le nom de domaine principal d'une URL, SANS le port."""

    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        netloc = urlparse(url).netloc

        domain = netloc.split(':')[0]
        return domain
    except Exception:
        return ""
    
    

def calculer_verdict(rapport):

    point_de_suspicion = []

    #Extraire l'âge du domaine dans WHOIS

    infos_whois = rapport.get('infos_whois', {})

    if 'erreur' not in infos_whois and infos_whois.get('date_creation'):
        date_creation = infos_whois['date_creation']


        if isinstance(date_creation, datetime):
            #calcul de l'âge du domaine
            age_domaine = (datetime.now() - date_creation).days

            if age_domaine < 90:
                point_de_suspicion.append(f'Domaine extrêmement récent {age_domaine} jours')
          
        else:
            point_de_suspicion.append("Informations WHOIS masquées ou Indisponible")
          
         
          
     
     #Vérification de la présence du certificat

    if rapport.get('certificat_ssl') == "Invalide ou Abscent":
        point_de_suspicion.append("❌ Certificat SSL invalide ou Abscent")
     
     
     #verification du DNS sur le domaine

    infos_dns = rapport.get('infos_dns', {})

    if "erreur" not in infos_whois:

          #Vérifier si il y a un enregistrement A (présence d'adresse IPV4)

        if not infos_dns.get('A'):
            point_de_suspicion.append("❌Aucun Enregistrement A donc le domaine n'a pas d'adresse IP")
          
          #Vérifier l'enregistrement AAAA (IPV6)

        if not infos_dns.get('AAAA'):
            point_de_suspicion.append("Aucun enregistrement AAAA, pas grave si l'enregistrement A est présent")
          
          #Vérifier l'enregistrement MX pour savoir si un serveur Mail existe
          
        if not infos_dns.get('MX'):
            point_de_suspicion.append("Aucun serveur de messagerie (MX) configuré")
          
          #Vérifier l'existance du serveur principal du domaine

        if not infos_dns.get('NS'):
            point_de_suspicion.append("Aucun serveur principal pour ce domaine")

          #Vérifier la présence d'un alias pour le domaine (CNAME)
          
        if not infos_dns.get('CNAME'):
            point_de_suspicion.append("Aucun alias pour ce domaine")

     

     #Vérification du contenu de la page web du domaine

    inspection_page = rapport.get('inspection_page', {}) # Étape 1: Récupérer le dico de manière sûre

    if not inspection_page.get("erreur"): # Étape 2: Vérifier la clé "erreur" de manière sûre
        if inspection_page.get('redirection'): # On utilise aussi .get() ici par sécurité
            point_de_suspicion.append("❌ Redirection HTTP détecté (ce ci est suspect)")
        
        if inspection_page.get('iframes_count', 0) > 0 : # .get() avec valeur par défaut 0
            point_de_suspicion.append("❌ La page contient des balises iframes (peut masquer du contenu)")
        
        if inspection_page.get('liens_externes_count', 0) > 15 : # .get() avec valeur par défaut 0
            point_de_suspicion.append("❌ Nombre élevés de liens pointant vers d'autres domaine")

     
     #Calcul du nombre de raisons pour le verdict en se basant sur les point de suspicion avec la méthode len()


    nombres_raisons = len(point_de_suspicion)


     #Verdict


    if nombres_raisons >= 3:
         verdict = Cache.Verdict.MALVEILLANT
     
    elif nombres_raisons == 2 or 1:
          verdict = Cache.Verdict.SUSPECT
     
    else:
        verdict = Cache.Verdict.LEGITIME
     

    return verdict, point_de_suspicion




    


def analyse_url(url):

    domain = extraire_domain(url)

    #on vérifie voir si le domaine existe ou pas
    if not domain:
        return {"verdict": Cache.Verdict.INCONNU, "details": "URL invalide ou impossible à analyser !", "source" : "Analyse PhisEye" }

    #ici on vérifie si le domaine est dans la liste blanche
    est_ListeBlanche = any(
        domain.endswith(f".{listeblanche.domain}") or domain == listeblanche.domain
        for listeblanche in ListeBlanche.objects.all()
    )  

    if est_ListeBlanche: 

        verdict = Cache.Verdict.LEGITIME
        details = f"Le domaine {domain} est reconnu comme fiable"
        source = "Base de données PhishEye (Liste Blanche)"

        Cache.objects.get_or_create(
            url=url,
            defaults={'verdict':verdict, 'details':details}
        )
        return {'verdict':verdict, 'details':details, 'source':'Liste Blanche'}
    

    #ici on va vérifier voir si l'analyse sur ce lien n'a pas déja été faite
    cache = Cache.objects.filter(url=url).first()

    if cache:
        return {'verdict':cache.verdict, 'details':cache.details, 'source':'Cache PhisEye'}
    

    #on vérifie maintenant voir si le lien est dans la liste noir

    if URLMalveillants.objects.filter(url=url).exists() or \
        URLMalveillants.objects.filter(url__icontains=domain).exists():
        verdict = Cache.Verdict.MALVEILLANT
        details = f"Le lien {domain} est reconnu comme malveillant par la base de données de PhishEye"
    


        Cache.objects.get_or_create(
            url=url,
            defaults= {'verdict':verdict, 'details':details}
        )
        return {'verdict':verdict, 'details':details, 'source':'Liste Noire'}
    
    
    #Maintenant si le lien n'est ni dans la liste blanche ni dans la liste noir on va faire une analyse approfondie

    print(f"URL '{url}' inconnue. Lancement de l'analyse complète...")

    rapport = {
        'info_whois':analyse_whois(url),
        'certificat_ssl':analyser_certificat(url),
        'info_dns': dns_check(url),
        'inspection_web': inspecter_page_web(url)
    }

    verdict, details = calculer_verdict(rapport)

    Cache.objects.create(url=url, verdict=verdict, details=details)


    
    return {"verdict": verdict, "details": details, "source": "Analyse locale"}






    





