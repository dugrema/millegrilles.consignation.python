from millegrilles.dao.InformationGenereeDocumentHelper import InformationGenereeHelper
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles import Constantes
import datetime


def test_executer_recherche1():
    selection = {
        Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'courant'],
        'noeud': 'test'
    }
    projection = {

    }

    cursor = helper.executer_recherche(selection) #, projection)
    #print('Cursor: %s' % str(cursor))

    document_genere = {}
    donnees = []
    document_genere['donnees'] = donnees
    for document in cursor:
        print("Document: %s" % str(document))
        donnees.append(document)

    print("Document genere: %s" % str(document_genere))
    return selection, document_genere

def test_sauvegarder_rapport(selection, document_genere):

    # Ajouter un qualiticatif pour ce rapport - il est fait par noeud
    selection[Constantes.DOCUMENT_INFODOC_CHEMIN].append('noeud')

    helper.sauvegarder_rapport(selection, document_genere)

# --- MAIN ---
configuration = TransactionConfiguration()
configuration.loadEnvironment()
document_dao = MongoDAO(configuration)
document_dao.connecter()
helper = document_dao.information_generee_helper()

def main():
    try:
        selection, document_resultat = test_executer_recherche1()
        test_sauvegarder_rapport(selection, document_resultat)

    finally:
        document_dao.deconnecter()

# executer main
main()