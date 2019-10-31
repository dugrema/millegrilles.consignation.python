from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.domaines.SenseursPassifs import SenseursPassifsConstantes, ProducteurDocumentSenseurPassif
from millegrilles.dao.DocumentDAO import MongoJSONEncoder

import logging
import datetime
import json


class GenererRapportsFenetresSenseurs:

    def __init__(self):
        self._logger = logging.getLogger('%s' % self.__class__.__name__)
        self._logger.setLevel(logging.INFO)
        self._contexte = ContexteRessourcesMilleGrilles()
        self._contexte.initialiser(init_document=True, init_message=True)

        self._producteur_doc_senseurspassifs = ProducteurDocumentSenseurPassif(self._contexte.document_dao)

    def calculer_fenetre_horaire(self):
        self._producteur_doc_senseurspassifs.generer_fenetre_horaire()

    def calculer_fenetre_derniereheure(self):
        self._producteur_doc_senseurspassifs.ajouter_derniereheure_fenetre_horaire()

    # def rapport_senseurs(
    #         self,
    #         uuid_senseur: str = None,
    #         niveau_regroupement: str = 'hour',
    #         temps_fin_rapport: datetime.datetime = datetime.datetime.utcnow(),
    #         range_rapport: datetime.timedelta = datetime.timedelta(days=7)
    # ):
    #     collection_transactions = self._contexte.document_dao.get_collection(SenseursPassifsConstantes.COLLECTION_TRANSACTIONS_NOM)
    #
    #     # LIBELLE_DOCUMENT_SENSEUR_RAPPORT_HORAIRE
    #     temps_fin_rapport.replace(minute=0, second=0)  # Debut de l'heure courante est la fin du rapport
    #     if niveau_regroupement == 'day':
    #         temps_fin_rapport.replace(hour=0)  # Minuit
    #
    #     temps_debut_rapport = temps_fin_rapport - range_rapport
    #
    #     filtre_rapport = {
    #         SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE: {
    #             '$gte': temps_debut_rapport.timestamp(),
    #             '$lt': temps_fin_rapport.timestamp(),
    #         }
    #     }
    #     if uuid_senseur is not None:
    #         filtre_rapport[SenseursPassifsConstantes.TRANSACTION_ID_SENSEUR] = uuid_senseur
    #
    #     regroupement_periode = {
    #         'year': {'$year': '$_evenements._estampille'},
    #         'month': {'$month': '$_evenements._estampille'},
    #     }
    #     if niveau_regroupement == 'day':
    #         regroupement_periode['day'] = {'$dayOfMonth': '$_evenements._estampille'}
    #     elif niveau_regroupement == 'hour':
    #         regroupement_periode['day'] = {'$dayOfMonth': '$_evenements._estampille'}
    #         regroupement_periode['hour'] = {'$hour': '$_evenements._estampille'}
    #
    #     regroupement_elem_numeriques = [
    #         'temperature', 'humidite', 'pression', 'millivolt', 'reserve'
    #     ]
    #     accumulateurs = ['max', 'min', 'avg']
    #
    #     regroupement = {
    #         '_id': {
    #             'uuid_senseur': '$uuid_senseur',
    #             'appareil_type': '$senseurs.type',
    #             'appareil_adresse': '$senseurs.adresse',
    #             'timestamp': {
    #                 '$dateFromParts': regroupement_periode
    #             },
    #         },
    #     }
    #
    #     for elem_regroupement in regroupement_elem_numeriques:
    #         for accumulateur in accumulateurs:
    #             key = '%s_%s' % (elem_regroupement, accumulateur)
    #             regroupement[key] = {'$%s' % accumulateur: '$senseurs.%s' % elem_regroupement}
    #
    #     operation = [
    #         {'$match': filtre_rapport},
    #         {'$unwind': '$senseurs'},
    #         {'$group': regroupement},
    #     ]
    #
    #     resultat = collection_transactions.aggregate(operation)
    #     self._logger.info("Resultats")
    #     # Key=uuid_senseur, Value=[{appareil_type, appareil_adresse, timestamp, accums...}, ...]
    #     resultats_par_senseur = dict()
    #     for ligne_rapport in resultat:
    #         # self._logger.info(str(ligne_rapport))
    #         resultats_appareil = resultats_par_senseur.get(ligne_rapport['_id']['uuid_senseur'])
    #         if resultats_appareil is None:
    #             resultats_appareil = dict()
    #             resultats_par_senseur[ligne_rapport['_id']['uuid_senseur']] = resultats_appareil
    #
    #         # Reorganiser valeurs pour insertion dans document de rapport
    #         cle_appareil = ligne_rapport['_id']['appareil_type']
    #         if cle_appareil == 'onewire/temperature':
    #             adresse = ligne_rapport['_id'].get('appareil_adresse')
    #             cle_appareil = '1W%s' % adresse
    #
    #         liste_valeurs = resultats_appareil.get(cle_appareil)
    #         if liste_valeurs is None:
    #             liste_valeurs = list()
    #             resultats_appareil[cle_appareil] = liste_valeurs
    #
    #         ligne_formattee = dict()
    #         liste_valeurs.append(ligne_formattee)
    #
    #         ligne_formattee['timestamp'] = ligne_rapport['_id']['timestamp']
    #
    #         for elem_regroupement in regroupement_elem_numeriques:
    #             for accumulateur in accumulateurs:
    #                 key = '%s_%s' % (elem_regroupement, accumulateur)
    #                 valeur = ligne_rapport[key]
    #                 if valeur is not None:
    #                     ligne_formattee[key] = valeur
    #
    #     self._logger.info(json.dumps(resultats_par_senseur, indent=2, cls=MongoJSONEncoder))
    #     return resultats_par_senseur
    #
    # def inserer_resultats_rapport(self, resultats: dict, nombre_resultats_limite: int = 175):
    #
    #     for uuid_senseur, appareils in resultats.items():
    #         self._logger.info("Inserer resultats dans document %s" % uuid_senseur)
    #         push_operation = dict()
    #         for appareil, valeurs in appareils.items():
    #             # Ajouter les valeurs en ordre croissant de timestamp.
    #             # Garder les "nombre_resultats_limite" plus recents (~1 semaine)
    #             push_operation['appareils.%s' % appareil] = {
    #                 '$each': valeurs,
    #                 '$sort': {SenseursPassifsConstantes.TRANSACTION_DATE_LECTURE: 1},
    #                 '$slice': -nombre_resultats_limite,
    #             }
    #
    #         self._logger.info('Operation push: %s' % str(push_operation))

def main():
    test = GenererRapportsFenetresSenseurs()
    # test.rapport_senseurs(uuid_senseur='f14951f2f43211e99259b827eb53ee51', niveau_regroupement='hour')
    # resultats = test.rapport_senseurs()
    # test.inserer_resultats_rapport(resultats)

    test.calculer_fenetre_horaire()
    # test.calculer_fenetre_derniereheure()


if __name__ == '__main__':
    main()
