from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration

configuration = TransactionConfiguration()
configuration.loadEnvironment()

document_dao = MongoDAO(configuration)
document_dao.connecter()

# Creer document processus

id_process_doc = document_dao.sauvegarder_initialisation_processus('MGPProcessus.testsauvegarde.sauvegarde', {"param": "valeur"})

print("Nouveau document cree pour le processus: %s" % id_process_doc)

# Creer etape #1

print("Document a l'etape initiale: %s" % document_dao.charger_processus_par_id(id_process_doc))

etape_1 = {
    "nom-etape": "Etape 1",
    "parametres": {
        "param": "valeur 2",
        "nombre": 23
    }
}

document_dao.sauvegarder_etape_processus(id_process_doc, etape_1)

print("Document a l'etape 1: %s" % document_dao.charger_processus_par_id(id_process_doc))

etape_finale = {
    "nom-etape": "Finale",
    "parametres": {
        "param": "valeur 5",
        "nombre": 122
    }
}

document_dao.sauvegarder_etape_processus(id_process_doc, etape_finale)

print("Document final: %s" % document_dao.charger_processus_par_id(id_process_doc))

document_dao.deconnecter()