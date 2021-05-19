import logging
import json

from millegrilles import Constantes
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.Constantes import ConstantesPublication
from millegrilles.dao.DocumentDAO import MongoDAO

document_dao: MongoDAO = None


def init():
    contexte = ContexteRessourcesDocumentsMilleGrilles()
    contexte.initialiser(init_message=False, connecter=False)
    document_dao = MongoDAO(contexte.configuration)
    document_dao.connecter()
    return document_dao


def test1():
    collection_ressources = document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
    curseur = collection_ressources.find()
    for v in curseur:
        print(v)


class TestRapports:

    def __init__(self, document_dao):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.document_dao = document_dao

    def get_etat_publication(self):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        projection = {ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES}
        filtre = {ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'$exists': True}}
        curseur_progres = collection_ressources.find(filtre, projection=projection)

        cdn_sets = set()
        for cp in curseur_progres:
            progres = cp[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES]
            cdn_sets.update(progres.keys())

        en_cours = dict()

        for cdn_id in cdn_sets:
            types_res = dict()
            en_cours[cdn_id] = types_res

            aggregation_pipe = [
                {'$match': {
                    ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id: {
                        '$exists': True,
                        '$ne': dict()
                    }
                }},
                {'$group': {
                    '_id': '$_mg-libelle',
                    'count': {'$sum': 1},
                }}
            ]
            curseur = collection_ressources.aggregate(aggregation_pipe)

            for resultat in curseur:
                self.__logger.debug("Resultat : %s" % str(resultat))
                type_section = resultat['_id']
                count_section = resultat['count']
                types_res[type_section] = count_section

        filtre_erreurs = {
            ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: {'$exists': True}
        }
        projection_erreurs = {
            ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: True,
            Constantes.DOCUMENT_INFODOC_LIBELLE: True,
            ConstantesPublication.CHAMP_SITE_ID: True,
            ConstantesPublication.CHAMP_SECTION_ID: True,
            'uuid': True
        }
        curseur_erreurs = collection_ressources.find(filtre_erreurs, projection=projection_erreurs, limit=1000)
        erreurs = [e for e in curseur_erreurs]

        reponse = {
            'erreurs': erreurs,
            'en_cours': en_cours,
            'cdns': list(cdn_sets),
        }

        return reponse


def main():
    global document_dao
    document_dao = init()

    # test1()
    rapports = TestRapports(document_dao)
    reponse = rapports.get_etat_publication()
    print(json.dumps(reponse, indent=2))


if __name__ == '__main__':
    main()
