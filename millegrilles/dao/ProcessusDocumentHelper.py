# Classe qui aide a creer et modifier les documents d'information generee.

import datetime

from millegrilles import Constantes
from bson.objectid import ObjectId

'''
Classe avec des methodes pour travailler dans la collection 'transactions'
'''


class ProcessusHelper:

    def __init__(self, mongo_database):
        self._collection_processus = mongo_database[Constantes.DOCUMENT_COLLECTION_PROCESSUS]

    '''
    Sauvegarde un nouveau document dans la collection de processus pour l'initialisation d'un processus.

    :param parametres: Parametres pour l'etape initiale.
    :returns: _id du nouveau document de processus
    '''

    def sauvegarder_initialisation_processus(self, moteur, nom_processus, parametres):
        document = {
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_MOTEUR: moteur,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_PROCESSUS: nom_processus,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: 'initiale',
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES: parametres,
            Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: [
                {
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_NOMETAPE: 'orientation',
                    Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES: parametres
                }
            ]
        }
        doc_id = self._collection_processus.insert_one(document)
        return doc_id.inserted_id

