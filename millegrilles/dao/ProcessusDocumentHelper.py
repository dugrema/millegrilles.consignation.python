# Classe qui aide a creer et modifier les documents d'information generee.

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


    '''
    Modifie un document de processus en ajoutant l'information de l'etape a la suite des autres etapes
    dans la liste du processus.

    :param id_document_processus: _id du document dans la collection processus.
    :param dict_etape: Dictionnaire complet a ajoute a la file des autres etapes.
    '''

    def sauvegarder_etape_processus(self, id_document_processus, dict_etape, etape_suivante=None):
        # Convertir id_document_process en ObjectId
        if isinstance(id_document_processus, ObjectId):
            id_document = {Constantes.MONGO_DOC_ID: id_document_processus}
        else:
            id_document = {Constantes.MONGO_DOC_ID: ObjectId(id_document_processus)}

        # print("$push vers mongo: %s --- %s" % (id_document, str(dict_etape)))
        set_operation = {}
        operation = {
            '$push': {Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPES: dict_etape},
        }
        if etape_suivante is None:
            operation['$unset'] = {Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE: ''}
        else:
            set_operation[Constantes.PROCESSUS_DOCUMENT_LIBELLE_ETAPESUIVANTE] = etape_suivante

        dict_etapes_parametres = dict_etape.get(Constantes.PROCESSUS_DOCUMENT_LIBELLE_PARAMETRES)
        if dict_etapes_parametres is not None:
            for key, value in dict_etapes_parametres.items():
                complete_key = 'parametres.%s' % key
                set_operation[complete_key] = value

        if len(set_operation) > 0:
            operation['$set'] = set_operation

        resultat = self._collection_processus.update_one(id_document, operation)

        if resultat.modified_count != 1:
            raise ErreurMAJProcessus("Erreur MAJ processus: %s" % str(resultat))


class ErreurMAJProcessus(Exception):

    def __init__(self, message=None):
        super().__init__(message=message)

