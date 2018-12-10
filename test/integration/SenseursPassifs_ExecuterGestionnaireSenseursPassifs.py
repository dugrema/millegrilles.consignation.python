from mgdomaines.appareils import GestionnaireSenseursPassifs

gestionnaire = GestionnaireSenseursPassifs()

gestionnaire.initialiser()
gestionnaire.configurer()
gestionnaire.traiter_backlog()
gestionnaire.demarrer_traitement_messages_blocking(gestionnaire.get_nom_queue())