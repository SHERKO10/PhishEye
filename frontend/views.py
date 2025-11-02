
from django.shortcuts import render
from logique import analyse_url  # On importe le cerveau de notre analyse
from PhishEye.bases_donnees.models import URLMalveillants, Suggestion
from django.utils import timezone

def index(request):
    """
    La vue principale qui gère la page d'accueil.
    """
    context = {}

    if request.method == 'POST':
        # --- CORRECTION : On vérifie D'ABORD si c'est une suggestion ---
        if 'suggestion_action' in request.POST:
            suggestion_text = request.POST.get('suggestion_text', '').strip()
            if suggestion_text: # On n'enregistre pas les suggestions vides
                Suggestion.objects.create(texte=suggestion_text)
                context['message'] = "Merci ! Votre suggestion a bien été enregistrée."
            else:
                context['error'] = "Veuillez entrer une suggestion avant d'envoyer."
            # On retourne la page immédiatement et on ne fait rien d'autre.
            return render(request, 'frontend/index.html', context)

        # --- Si ce n'est PAS une suggestion, on continue avec la logique de l'URL ---
        url = request.POST.get('url_input', '').strip()

        if not url:
            context['error'] = "Veuillez entrer une URL."
            return render(request, 'frontend/index.html', context)

        # On vérifie quel bouton de la partie URL a été cliqué
        if 'scan_action' in request.POST:
            print(f"Scan demandé pour : {url}")
            resultat_analyse = analyse_url(url)
            context.update(resultat_analyse)

        elif 'add_action' in request.POST:
            print(f"Ajout demandé pour : {url}")
            obj, created = URLMalveillants.objects.get_or_create(
                url=url,
                defaults={'source': 'Ajout Manuel Utilisateur'}
            )
            if created:
                context['message'] = f"Succès : L'URL '{url}' a été ajoutée à la liste noire."
            else:
                context['message'] = f"Info : L'URL '{url}' était déjà dans la liste noire."

    # C'est ici qu'on arrive soit en visitant la page la première fois (GET),
    # soit après avoir traité une action sur l'URL.
    return render(request, 'frontend/index.html', context)