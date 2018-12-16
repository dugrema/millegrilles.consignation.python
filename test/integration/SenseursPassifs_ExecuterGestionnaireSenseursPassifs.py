from mgdomaines.appareils import GestionnaireSenseursPassifs

gestionnaire = GestionnaireSenseursPassifs()

gestionnaire.initialiser()
gestionnaire.configurer()
gestionnaire.traiter_backlog()
gestionnaire.enregistrer_queue(gestionnaire.get_nom_queue())