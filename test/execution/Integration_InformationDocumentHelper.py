from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.InformationDocumentHelper import InformationDocumentHelper

def test_ajouter_document():
    chemin = ['test', 'document']

    nouveau_information_document = {
        'cle': 'valeur'
    }

    resultat = informationHelper.ajouter_document(chemin, nouveau_information_document)
    print('Nouveau document _id:%s' % resultat)

    return resultat

def test_charger_document(id_doc):

    document = informationHelper.charger_par_id(id_doc)
    print("Document charge: %s" % str(document))

    return document


# Wiring initial
configuration = TransactionConfiguration()
configuration.loadEnvironment()
documentDao = MongoDAO(configuration)
documentDao.connecter()
informationHelper = documentDao.information_document_helper()

try:
    doc_id = test_ajouter_document()
    test_charger_document(doc_id)

finally:
    # Fin / deconnecter
    documentDao.deconnecter()

