from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles import Constantes
from millegrilles.rapport.GenerateurRapports import GenerateurRapport
import datetime


def test_executer_groupement_calcul():

    # Creer fenetre 24h
    #current_time = datetime.datetime.utcnow()
    current_time = datetime.datetime(2018, 9, 21, 11, 12, 2)
    time_range1 = datetime.datetime(current_time.year, current_time.month, current_time.day, current_time.hour)
    time_range2 = time_range1 - datetime.timedelta(days=1)

    selection = {
        Constantes.DOCUMENT_INFODOC_CHEMIN: ['appareils', 'senseur', 'lecture', 'historique'],
        'noeud': 'test',
        'senseur': 15,
        '_mg-estampille': {'$gte': time_range2, '$lte': time_range1}
    }

    regroupement = {
        '_id': {
            'noeud': '$noeud',
            'senseur': '$senseur',
            'heurejour': {
                '$dateFromParts': {
                    'year': {'$year': '$_mg-estampille'},
                    'month': {'$month': '$_mg-estampille'},
                    'day': {'$dayOfMonth': '$_mg-estampille'},
                    'hour': {'$hour': '$_mg-estampille'}
                }
            }
        },
        'temperature-maximum': {'$max': '$temperature'},
        'temperature-minimum': {'$min': '$temperature'},
        'humidite-maximum': {'$max': '$humidite'},
        'humidite-minimum': {'$min': '$humidite'},
        'pression-maximum': {'$max': '$pression'},
        'pression-minimum': {'$min': '$pression'},
    }

    operation = [
        {'$match': selection},
        {'$group': regroupement}
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