import customtkinter
import threading
from datetime import datetime


from packages.api import analyse_virus_total
from packages.dns_check import dns_check
from packages.whois_analyse import analyse_whois
from packages.tls_inspect import analyser_certificat
from packages.web_analyst import inspecter_page_web


#apparence de la fenêtre de l'interface, mode système pour qu'il choisisse l'apparence du thème de la machine
customtkinter.set_appearance_mode("system")

#Couleur par défaut du thème : bleue
customtkinter.set_default_color_theme("green")

#Création de la fenêtre principale

app = customtkinter.CTk()

#Titre de l'application

app.title("PhisEye - Détection de lien de Phising") 


#Géometrie de la fenêtre de l'appli

app.geometry("1000x800")


"""Création des Widgets pour l'entrée utilisateur"""

#Création d'une frame pour contenir l'entrée utilisateur


frame_entree = customtkinter.CTkFrame(master=app)
frame_entree.pack(pady=20, padx=60, fill="x", expand=False)


#Champ d'entrée pour l'url

label_url = customtkinter.CTkLabel(master=frame_entree, text="URL à Analyser", font=("Roboto", 16))
label_url.pack(pady=10)

entree_url = customtkinter.CTkEntry(master=frame_entree, placeholder_text="https://exemple.com", width=500, height=35)
entree_url.pack()


#Création du buton de lancement

bouton_lancement = customtkinter.CTkButton(master=app, text="Lancer l'analyse", width=200, height=50, font=("Roboto", 18))
bouton_lancement.pack(pady=20)


#Création d'une zone ou les résultats seront affichés


zone_resultat = customtkinter.CTkTextbox(master=app, width=700, height=300, font=("Courier New", 20))
zone_resultat.pack(pady=10, padx=20, fill="both", expand=True)


zone_resultat.tag_config("titre", justify='center')
zone_resultat.tag_config("danger", foreground="#e63946")  # Rouge pour les menaces
zone_resultat.tag_config("warning", foreground="#ee9b00") # Orange pour les avertissements
zone_resultat.tag_config("success", foreground="#90be6d") # Vert pour ce qui est OK
zone_resultat.tag_config("info", foreground="#4361ee")   # Bleu pour les titres de section



"""Logique métier nous allons mettre en place la logique pour qu'une fois que vous cliquez sur le bouton que l'analyse se fasse"""



def normalisation_url(url):
    """Fonction pour normaliser l'URL en supprimant les espaces et en ajoutant le schéma si nécessaire."""
     
    url = url.strip()
    url = url.replace(" ", "")
    url = url.replace("-", "")


    if not url.startswith("http://") and not url.startswith("https://"):
          url = "http://" + url

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
        verdict = "✅ Aucune menace détectée"
     

    return verdict, point_de_suspicion




def formater_rapport_pour_interface(textbox, url, rapport, verdict, raisons):
    """
    Prend toutes les données de l'analyse et les transforme en une seule
    chaîne de caractères bien formatée, prête à être affichée dans l'interface de l'application.
    """

    textbox.configure(state="normal")
    textbox.delete("1.0", "end")

    textbox.insert("end", "RAPPORT DE L'ANALYSE FINAL\n", "titre")
    textbox.insert("end", "="*78 + "\n\n")
    

    textbox.insert("end", f"URL Analysée : {url}\n")
    textbox.insert("end", "Verdict        : ")
    
    # On choisit la couleur du verdict
    tag_verdict = "info"
    if "PHISHING" in verdict or "Très Suspect" in verdict:
        tag_verdict = "danger"
    elif "surveiller" in verdict:
        tag_verdict = "warning"
    else:
        tag_verdict = "success"
    textbox.insert("end", f"{verdict}\n", tag_verdict)

 
    if raisons:
        textbox.insert("end", "\n--- Indicateurs de suspicion détectés ---\n", "info")
        for raison in raisons:

            textbox.insert("end", f"  - {raison}\n", "warning")
    else:
        textbox.insert("end", "\n--- Aucun indicateur de suspicion majeur n'a été trouvé. ---\n", "success")

    textbox.insert("end", "\n--- Détails des analyses ---\n", "info")
    
    # VirusTotal
    vt_verdict = rapport['verdict_vt']
    textbox.insert("end", "  - Verdict VirusTotal : ")
    tag_vt = "danger" if "Malveillant" in vt_verdict else "warning" if "Suspect" in vt_verdict else "success"
    textbox.insert("end", f"{vt_verdict}\n", tag_vt)
    
    # Certificat SSL
    ssl_verdict = rapport['certificat_ssl']
    textbox.insert("end", "  - Certificat SSL     : ")
    tag_ssl = "success" if "Valide" in ssl_verdict else "danger"
    textbox.insert("end", f"{ssl_verdict}\n", tag_ssl)


    # Rapport DNS 
    infos_dns = rapport['infos_dns']
    textbox.insert("end", "\n  --- Informations DNS ---\n")
    if "erreur" in infos_dns:
        textbox.insert("end", f"    -> {infos_dns['erreur']}\n", "danger")
    else:

        presence_A = "Oui" if infos_dns.get('A') else "Non"
        presence_MX = "Oui" if infos_dns.get('MX') else "Non"
        presence_AAAA = "Oui" if infos_dns.get('AAAA') else "Non"
        presence_NS = "Oui" if infos_dns.get('NS') else "Non"
        presence_CNAME = "Oui" if infos_dns.get('CNAME') else "Non"

        textbox.insert("end", f"    - Enregistrement A (IP)   : {presence_A}\n")
        textbox.insert("end", f"    - Enregistrement AAAA : {presence_AAAA}\n")
        textbox.insert("end", f"    - Enregistrement MX (Mail): {presence_MX}\n")
        textbox.insert("end", f"    - Enregistrement NS : {presence_NS}\n")
        textbox.insert("end", f"    - Enregistrement CNAME : {presence_CNAME}")



    #Informations WHOIS sur le domaine
    infos_whois = rapport['infos_whois']
    textbox.insert("end", "\n  --- Informations WHOIS ---\n", "info")
    if "erreur" in infos_whois:
        textbox.insert("end", f"    -> {infos_whois['erreur']}\n", "danger")
    else:
        def formater_date(dt): return dt.strftime('%Y-%m-%d') if isinstance(dt, datetime) else "N/A"
        textbox.insert("end", f"    - Propriétaire   : {infos_whois.get('proprietaire', 'N/A')}\n")
        textbox.insert("end", f"    - Registrar      : {infos_whois.get('registrar', 'N/A')}\n")
        textbox.insert("end", f"    - Date Création  : {formater_date(infos_whois.get('date_creation'))}\n")
        textbox.insert("end", f"    - Date expiration : {formater_date(infos_whois.get('date_expiration'))}")
        textbox.insert("end", f"    - Serveur DNS : {infos_whois.get('serveur_dns', 'N/A')}")
     


    #Inspection de la page HTML du domaine
    inspection = rapport['inspection_page']
    textbox.insert("end", "\n  --- Contenu de la Page ---\n", "info")
    if inspection["erreur"]:
        textbox.insert("end", "    -> Impossible d'analyser le contenu de la page.\n", "danger")
    else:
        details_page = "    - Redirections ({}), Iframes ({}), Liens Externes ({})\n".format(
            "Oui" if inspection['redirection'] else "Non",
            inspection['iframes_count'],
            inspection['liens_externes_count']
        )
        textbox.insert("end", details_page)

    textbox.insert("end", "="*78 + "\n")
    

    textbox.configure(state="disabled")



def analyse_arriere_plan(url):
    """Fonction qui s'exécuete en arrière plan pour l'anaylse de l'url"""


    rapport_final = ""

 



    url = normalisation_url(url)


    rapport_final += "[1/5] Analyse VirusTotal...\n"
    zone_resultat.insert("end", rapport_final)
    verdict_vt = analyse_virus_total(url)

    if "Malveillant" in verdict_vt:
        rapport_final = f"URL Analysée : {url}\n"
        rapport_final += f"\nVerdict Final  : ❌ PHISHING DÉTECTÉ ❌\n\n"
        rapport_final += f"Raison : {verdict_vt}. Détecté par la communauté de sécurité."
        

        zone_resultat.delete("1.0", "end")
        zone_resultat.insert("1.0", rapport_final)
        bouton_lancement.configure(state="normal", text="Lancer l'Analyse")
        return


    rapport_final += f"Verdict VT : {verdict_vt}\n[2/5] Analyse WHOIS...\n"
    zone_resultat.insert("end", "[2/5] Analyse WHOIS...\n")
    infos_whois_resultat = analyse_whois(url)
    

    zone_resultat.insert("end", "[3/5] Analyse SSL...\n")
    certificat_ssl_resultat = analyser_certificat(url)
    
    zone_resultat.insert("end", "[4/5] Analyse DNS...\n")
    dns_resultat = dns_check(url)
    
    zone_resultat.insert("end", "[5/5] Analyse du contenu web...\n")
    inspection_page_resultat = inspecter_page_web(url)
    


    rapport_analyses = {
        "verdict_vt": verdict_vt,
        "infos_whois": infos_whois_resultat,
        "certificat_ssl": certificat_ssl_resultat,
        "infos_dns": dns_resultat,
        "inspection_page": inspection_page_resultat
    }


    verdict_final, raisons = calculer_verdict(rapport_analyses)
    rapport_final = formater_rapport_pour_interface(zone_resultat, url, rapport_analyses, verdict_final, raisons)


    bouton_lancement.configure(state="normal", text="Lancer l'Analyse")




def lancer_analyse():
    """Fonction pour lancer l'analyse dans un thread séparé une fois cliqué sur le bouton d'analyse"""

    url = entree_url.get()


    #Donc si l'utilisateur ne saisi aucune URL tout à d'abord les anciennes informations sont éffacées et une message d'erreur est affiché
    if not url:
        zone_resultat.delete("1.0", "end")
        zone_resultat.insert("1.0", "Veuillez entrer une URL pour l'analyse")
        return



    zone_resultat.delete("1.0", "end")
    zone_resultat.insert("1.0", "Veuillez patienter, Analyse en cours....\n\n")
    bouton_lancement.configure(state="disabled", text="Analyse en cours...")




    thread_analyse = threading.Thread(target=analyse_arriere_plan, args=(url,))
    thread_analyse.start()


bouton_lancement.configure(command=lancer_analyse)










#Boucle qui va maintenir la fenêtre de l'application

app.mainloop()

