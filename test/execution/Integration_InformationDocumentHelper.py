from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.InformationDocumentHelper import InformationDocumentHelper
from millegrilles import Constantes

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

def test_touch_document(id_doc):

    informationHelper.touch_document(id_doc)

def test_maj_document_set(id_doc):
    valeurs = {
        'cle': 'le jour',
        'bian': {'le': 'bonjour', 'la': 'nuite', 'les': ['beignes', 'sont', 'bons']}
    }
    informationHelper.maj_document(id_doc, valeurs_a_ajouter=valeurs)

def test_maj_document_unset(id_doc):
    valeurs = ['bian.le']
    informationHelper.maj_document(id_doc, valeurs_a_supprimer=valeurs)

def test_maj_document_contenu(selection):
    valeurs = {'maj': 'Mise a jour via selection: %s' % selection}
    informationHelper.maj_document_selection(selection, valeurs, upsert=True)

# Wiring initial
configuration = TransactionConfiguration()
configuration.loadEnvironment()
documentDao = MongoDAO(configuration)
documentDao.connecter()
informationHelper = documentDao.information_document_helper()

try:
    doc_id = test_ajouter_document()
    test_charger_document(doc_id)

    id_doc_test = '5ba2f236e0940932985ada15'
    test_touch_document(id_doc_test)
    test_maj_document_set(id_doc_test)
    test_maj_document_unset(id_doc_test)
    test_maj_document_contenu({
            Constantes.DOCUMENT_INFODOC_CHEMIN: ['test', 'integration'],
            'cle': 'le soir'
        })

finally:
    # Fin / deconnecter
    documentDao.deconnecter()

