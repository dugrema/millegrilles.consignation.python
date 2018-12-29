# Domaine de l'interface principale
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback

import logging
import datetime


class ConstantesPrincipale:
    """ Constantes pour le domaine de l'interface principale """

    DOMAINE_NOM = 'millegrilles.domaines.Principale'
    COLLECTION_NOM = 'millegrilles_domaines_Principale'
    QUEUE_NOM = 'millegrilles.domaines.Principale'

    LIBVAL_CONFIGURATION = 'configuration'

    # Document par defaut pour la configuration de l'interface principale
    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
        'nom_millegrille': 'Sansnom',
        'adresse_url_base': 'sansnom.millegrilles.com',
        'domaines': {
            'SenseursPassifs': {
                'rang': 1,
                'description': 'SenseursPassifs'
            },
            'Notifications': {
                'rang': 2,
                'description': 'Notifications'
            },
            'WebPoll': {
                'rang': 3,
                'description': 'WebPoll'
            },
            'Rapports': {
                'rang': 4,
                'description': 'Rapports'
            },
            'Principale': {
                'rang': 5,
                'description': 'Principale'
            }
        }
    }


class GestionnairePrincipale(GestionnaireDomaine):

    def __init__(self, configuration=None, message_dao=None, document_dao=None, contexte=None):
        super().__init__(configuration, message_dao, document_dao, contexte)
        self._traitement_message = None

        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessagePrincipale(self)

        nom_queue_domaine = self.get_nom_queue()

        # Configurer la Queue pour les rapports sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_domaine,
            durable=True)

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_domaine,
            routing_key='destinataire.domaine.%s.#' % nom_queue_domaine
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_domaine,
            routing_key='ceduleur.#'
        )

        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.document_dao.get_collection(ConstantesPrincipale.COLLECTION_NOM)

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPrincipale.LIBVAL_CONFIGURATION}
        )
        if document_configuration is None:
            self._logger.info("On insere le document de configuration de reference pour domaine Principale")

            # Preparation document de configuration pour le domaine
            configuration_initiale = ConstantesPrincipale.DOCUMENT_DEFAUT.copy()
            maintenant = datetime.datetime.utcnow()
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant
            configuration_initiale[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant

            collection_domaine.insert(configuration_initiale)
        else:
            self._logger.info("Document de configuration de principale: %s" % str(document_configuration))

    def traiter_cedule(self, evenement):
        pass

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def get_nom_queue(self):
        return ConstantesPrincipale.QUEUE_NOM


class TraitementMessagePrincipale(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.configuration)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get("evenements")

        if evenement == Constantes.EVENEMENT_CEDULEUR:
            # Ceduleur, verifier si action requise
            self._gestionnaire.traiter_cedule(message_dict)
        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % str(evenement))
