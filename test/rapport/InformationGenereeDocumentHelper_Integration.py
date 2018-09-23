from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles import Constantes
from millegrilles.rapport.GenerateurRapports import GenerateurRapport


def test_executer_groupement_calcul():
    selection = {
        Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'historique'],
        'noeud': 'test',
        'senseur': 15
    }

    regroupement = {
        '_id': {'noeud': '$noeud', 'senseur': '$senseur'},
    }

    operation = [
        {'$match': selection},
        {'$group': regroupement},
        {'$unwind': '$faits'}
    ]

    resultat = helper.executer_regroupement_information_documents(operation)
    print("Document resultats groupement par noeud: %s" % str(resultat))

    return resultat

def test_executer_groupement():
    selection = {
        Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'courant']
    }

    resultat = helper.executer_distinct_information_documents('noeud', selection)

    print("Document resultats groupement par noeud: %s" % str(resultat))

    resultat = helper.executer_distinct_information_documents(['noeud', 'senseur'], selection)
    print("Document resultats groupement par noeud/senseur: %s" % str(resultat))

    return resultat

def test_executer_recherche1():
    selection = {
        Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'courant'],
        'noeud': 'test'
    }

    resultats = []
    with helper.executer_recherche(selection) as cursor:
        for document in cursor:
            print("Document: %s" % str(document))
            resultats.append(document)

    document_genere = {'senseurs': resultats}
    print("Document genere: %s" % str(document_genere))

#    cursor.close()

    return selection, document_genere

def test_sauvegarder_rapport(selection, document_genere):

    # Ajouter un qualiticatif pour ce rapport - il est fait par noeud
    selection[Constantes.DOCUMENT_INFODOC_CHEMIN].append('noeud')

    helper.sauvegarder_rapport(selection, document_genere)

def test_generateur_documents2():

    generateur = GenerateurRapport(document_dao)

    generateur.set_source(
        chemin=['appareils', 'senseur', 'courant'],
        groupe='noeud',
        ligne='senseur'
    )
    generateur.set_chemin_destination(['appareils', 'senseur', 'courant', 'rapport'])

    #groupes = generateur.identifier_groupes_rapport()
    #print('Groupes identifies pour le rapport: %s' % str(groupes))

    generateur.generer()


# --- MAIN ---
configuration = TransactionConfiguration()
configuration.loadEnvironment()
document_dao = MongoDAO(configuration)
document_dao.connecter()
helper = document_dao.information_generee_helper()

def main():
    try:
        #selection, document_resultat = test_executer_recherche1()
        #test_sauvegarder_rapport(selection, document_resultat)
        #test_executer_groupement()
        #test_generateur_documents2()
        test_executer_groupement_calcul()

    finally:
        document_dao.deconnecter()

# executer main
main()