from millegrilles.dao.InformationGenereeDocumentHelper import InformationGenereeHelper
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles import Constantes
import datetime


def test_generer_rapport1():
    selection = {
        Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'courant'],
        'noeud': 'test'
    }
    projection = {

    }

    cursor = helper.generer_rapport(selection) #, projection)
    #print('Cursor: %s' % str(cursor))

    document_genere = {}
    document_genere[Constantes.DOCUMENT_INFODOC_CHEMIN] = ['appareils', 'senseur', 'courant', 'noeud']
    document_genere[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = datetime.datetime.utcnow()
    donnees = []
    document_genere['donnees'] = donnees
    for document in cursor:
        print("Document: %s" % str(document))
        donnees.append(document)

    print("Document genere: %s" % str(document_genere))


# --- MAIN ---
configuration = TransactionConfiguration()
configuration.loadEnvironment()
document_dao = MongoDAO(configuration)
document_dao.connecter()
helper = document_dao.information_generee_helper()

def main():
    try:
        test_generer_rapport1()

    finally:
        document_dao.deconnecter()

# executer main
main()