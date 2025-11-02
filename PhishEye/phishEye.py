"""Programme de détection de phishing basé sur l'analyse d'URL."""
#Auteur version 1.0 : POZOU Ewaba Emmanuel, Etudiant en Réseaux, systèmes et Cybersécurité
#Date : 4/09/2025
#Auteur version 2.0 : POZOU Ewaba Emmanuel, ANANIVI Norbert
#Date : 18/09/2025





from packages.api import analyse_virus_total
from packages.dns_check import dns_check
from packages.whois_analyse import analyse_whois
from packages.tls_inspect import analyser_certificat
from packages.web_analyst import inspecter_page_web
from datetime import datetime






def normalisation_url(url):
    """Fonction pour normaliser l'URL en supprimant les espaces et en ajoutant le schéma si nécessaire."""
     
    url = url.strip()
    url = url.replace(" ", "")
    url = url.replace("-", "")


    if not url.startswith("http://") and not url.startswith("https://"):
          url = "http://" + url

    
    print("URL normalisée:", url)

    return url



def calculer_verdict(rapport):

     point_de_suspicion = []

     #Extraire l'âge du domaine dans WHOIS

     infos_whois = rapport['infos_whois']

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

     if rapport['certificat_ssl'] == "Invalide ou Abscent":
          point_de_suspicion.append("❌ Certificat SSL invalide ou Abscent")
     
     
     #verification du DNS sur le domaine

     infos_dns = rapport['infos_dns']


     if "erreur" not in infos_whois:

          #Vérifier si il y a un enregistrement A (présence d'adresse IPV4)

          if not infos_dns.get('A'):
               point_de_suspicion.append("❌Aucun Enregistrement A donc le domaine n'a pas d'adresse IP")
          
          #Vérifier l'enregistrement AAAA (IPV6)

          if not infos_dns.get('AAAA'):
               point_de_suspicion.append("Aucun enregistrement AAAA, pas grave si l'enregistrement A est présent")
          
          #Vérifier l'enregistrement MX pour savoir si un serveur Mail existe
          
          if not infos_dns.get('MX'):
               point_de_suspicion("Aucun serveur de messagerie (MX) configuré")
          
          #Vérifier l'existance du serveur principal du domaine

          if not infos_dns.get('NS'):
               point_de_suspicion.append("Aucun serveur principal pour ce domaine")

          #Vérifier la présence d'un alias pour le domaine (CNAME)
          
          if not infos_dns.get('CNAME'):
               point_de_suspicion.append("Aucun alias pour ce domaine")

     

     #Vérification du contenu de la page web du domaine

     if not rapport['inspection_page']["erreur"]:
          if rapport['inspection_page']['redirection']:
               point_de_suspicion.append("❌ Redirection HTTP détecté (ce ci est suspect)")
          
          if rapport['inspection_page']['iframes_count'] > 0 :
               point_de_suspicion.append("❌ La page contient des balises iframes (peut masquer du contenu)")
          
          if rapport['inspection_page']['liens_externes_count'] > 15 :
               point_de_suspicion.append("❌ Nombre élevés de liens pointant vers d'autres domaine")

     
     #Vérification chez VirusTotal


     if "Suspect" in rapport['verdict_vt']:
          point_de_suspicion.append("❌ Lien signalé comme supect au moins par un moteur de sécurité")

     
     #Calcul du nombre de raisons pour le verdict en se basant sur les point de suspicion avec la méthode len()


     nombres_raisons = len(point_de_suspicion)


     #Verdict


     if nombres_raisons >= 3:
          verdict = "❌ Lien de PHISHING POTENTIEL"
     
     elif nombres_raisons == 2:
          verdict = "⚠️ Lien Suspect surtout ne pas cliquer dessus"
     
     elif nombres_raisons == 1:
          verdict = "🟡 Lien à Surveiller, pas très fiable"
     
     else:
          verdict = "✅ Aucune menace détectée, mais pour des raisons de sécurité ne cliquez pas sans avoir bien vérifié"
     

     return verdict, point_de_suspicion



def afficher_rapport(url, rapport, verdict, raisons):

     print("\n" + "="*70)
     print("RAPPORT DE L'ANALYSE FINALE".center(70))
     print("\n" + "="*70)

     print(f"URL Analysée : {url}")
     print(f"Verdict Final :  {verdict}")



     if not raisons and "Aucune menace détectée" in verdict:
          print("\nAucune activité suspicieuse n'a été détecté sur le domaine")
     
     else:
          print("\n----------INDICATEURS DE SUSPICION DETECTES----------\n")

          for raison in raisons:
               print(f" - {raison}")

     
     print("\n---- Détails de l'analyse ----\n")

     print(f" - Verdict VirusTotal : {rapport['verdict_vt']}")
     print(f" - Certificat SSL : {rapport['certificat_ssl']}")

     #Affichage détails DNS

     infos_dns = rapport['infos_dns']
     print("\n---- AFFICHAGE INFO DNS ----")

     if "erreur" in infos_dns:
          print(f" -> {infos_dns['erreur']}")
     else:
          print(f"  - Enregistrement A : {infos_dns.get('A', 'N/A')}")
          print(f"  - Enregistrement AAAA : {infos_dns.get('AAAA', 'N/A')}")
          print(f"  - Enregistrement MX : {infos_dns.get('MX', 'N/A')}")
          print(f"  - Enregistrement NS : {infos_dns.get('MX', 'N/A')}")
          print(f"  - Enregistrement CNAME : {infos_dns.get('CNAME', 'N/A')}")


     #Afficher détails info_whois

     infos_whois = rapport['infos_whois']
     print("\n---- AFFICHAGE INFO WHOIS ----\n")

     if "erreur" in infos_whois:
          print(f"  -> {infos_whois['erreur']}")
     
     else:
          #Fonction pour formater la date et la retourner
          def formater_date(dt):
               return dt.strftime('%Y-%m-%d') if isinstance(dt, datetime) else "N/A"
          
          print(f"  - Propriétaire du domaine : {infos_whois.get('proprietaire', 'N/A')}") #N/A: Pour signifier que le contenu est nul
          print(f"  - Registrar : {infos_whois.get('registrar', 'N/A')}")
          print(f"  - Date création : {formater_date(infos_whois.get('date_creation'))}")
          print(f"  - Date expiration : {formater_date(infos_whois.get('date_expiration'))}")
          print(f"  - Serveur DNS : {infos_whois.get('serveur_dns', 'N/A')}")
     
     

     #Afficher les détails de l'inspection de la page web du domaine

     inspection = rapport['inspection_page']

     if inspection['erreur']:
          print("   -> Impossible de faire l'analyse de la page web du domaine")
     
     else:

          print("\n  --- Contenu de la Page ---\n")

          print("   - Redirections ({}), Iframes ({}), Liens Externes ({})".format(
            "Oui" if inspection['redirection'] else "Non",
            inspection['iframes_count'],
            inspection['liens_externes_count']
        ))
     print("="*70)








def main():
     print(r"""



 

   ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗███████╗██╗   ██╗███████╗
   ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝╚██╗ ██╔╝██╔════╝
   ██████╔╝███████║██║███████╗███████║█████╗   ╚████╔╝ █████╗  
   ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██╔══╝    ╚██╔╝  ██╔══╝  
   ██║     ██║  ██║██║███████║██║  ██║███████╗   ██║   ███████╗
   ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝


    PHISHING DETECTION TOOL V2.0
    Auteur: SHERKO & Nor ANASCO
    copyright: SHERKO & Anasco""")


     

     url = input("\nEntrez une URL : ")
     url = normalisation_url(url)

     print("\nDébut de l'analyse en profondeur...")

     verdict_vt = analyse_virus_total(url)


     print("\n[1/4] Lancement de l'analyse sur VirusTotal...")
     print("Début de l'analyse chez VirusTotal...")
     verdict_vt = analyse_virus_total(url)
     print("Analyse VirusTotal terminée...")


     print("[2/4] Analyse WHOIS en cours...")
     infos_whois_resultat = analyse_whois(url)


     print("[3/4] Analyse du certificat SSL en cours...")
     certificat_ssl_resultat = analyser_certificat(url)

     print("[4/5] Analyse DNS en cours...")
     dns_resultat = dns_check(url)


     print("[5/5] Analyse du contenu de la page en cours...")
     inspection_page_resultat = inspecter_page_web(url)
    
     rapport_analyses = {
          "verdict_vt": verdict_vt,
          "infos_whois": infos_whois_resultat,
          "certificat_ssl": certificat_ssl_resultat,
          "infos_dns": dns_resultat,
          "inspection_page": inspection_page_resultat
     }


     print("\nToutes les analyses sont terminées. Génération du rapport final...")


     verdict_final, raisons = calculer_verdict(rapport_analyses)


     afficher_rapport(url, rapport_analyses, verdict_final, raisons)

     #Boucle pour permettre à l'utilisateur de continuer ou de stopper 
     while True:
          choix = input("\nVoulez continuer avec un autre lien à tester ? o/n : ")

          if choix == "o":
               main()
          elif choix == "n":
               print("\nMerci d'avoir utilisé PhisEye !\n")
               break
          else:
               print("\nChoix invalide ! \n")




