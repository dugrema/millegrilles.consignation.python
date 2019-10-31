from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.domaines.SenseursPassifs import SenseursPassifsConstantes

import logging
import datetime


class GenererRapportsFenetresSenseurs:

    def __init__(self):
        self._logger = logging.getLogger('%s' % self.__class__.__name__)
        self._logger.setLevel(logging.INFO)
        self._contexte = ContexteRessourcesMilleGrilles()
        self._contexte.initialiser(init_document=True, init_message=True)

    def rapport_quotidien(self):
        collection_transactions = self._contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)

        # LIBELLE_DOCUMENT_SENSEUR_RAPPORT_HORAIRE
        temps_fin_rapport = datetime.datetime.utcnow()
        temps_fin_rapport.replace(minute=0, second=0)  # Debut de l'heure courante est la fin du rapport
        range_rapport = datetime.timedelta(days=7)  # 7 Jours a calculer pour les heures
        temps_debut_rapport = temps_fin_rapport - range_rapport

        filtre_rapport = {
            SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE: {
                '$gte': temps_debut_rapport.timestamp(),
                '$lt': temps_fin_rapport.timestamp(),
            }
        }

        regroupement_periode = {
            'year': {'$year': '$_evenements._estampille'},
            'month': {'$month': '$_evenements._estampille'},
            'day': {'$dayOfMonth': '$_evenements._estampille'}
        }
        regroupement = {
            '_id': {
                'senseur': '$uuid_senseur',
                'periode': {
                    '$dateFromParts': regroupement_periode
                },
                'appareil_type': '$senseurs.type',
                'appareil_adresse': '$senseurs.adresse',
            },
            'temperature_max': {'$max': '$senseurs.temperature'},
            'temperature_min': {'$min': '$senseurs.temperature'},
            'temperature_avg': {'$avg': '$senseurs.temperature'},
            'humidite_max': {'$max': '$senseurs.humidite'},
            'humidite_min': {'$min': '$senseurs.humidite'},
            'humidite_avg': {'$avg': '$senseurs.humidite'},
            'pression_max': {'$max': '$senseurs.pression'},
            'pression_min': {'$min': '$senseurs.pression'},
            'pression_avg': {'$avg': '$senseurs.pression'},
        }

        # resultat = collection_transactions.find(filter=filtre_rapport)

        operation = [
            {'$match': filtre_rapport},
            {'$unwind': '$senseurs'},
            {'$group': regroupement},
        ]

        resultat = collection_transactions.aggregate(operation)
        self._logger.info("Resultats")
        for transaction in resultat:
            self._logger.info(str(transaction))


def main():
    test = GenererRapportsFenetresSenseurs()
    test.rapport_quotidien()


if __name__ == '__main__':
    main()
