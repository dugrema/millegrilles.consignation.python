# Module des rapports et sommaires de documents

from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles import Constantes


class RapportsConstantes:

    DOMAINE_NOM = 'millegrilles.domaines.Rapports'
    COLLECTION_NOM = 'millegrilles_domaines_Rapports'
    QUEUE_NOM = 'millegrilles.domaines.Rapports'


class GestionnaireRapports(GestionnaireDomaine):
    """ Gestionnaire du domaine des rapports"""

    def __init__(self, configuration=None, message_dao=None, document_dao=None, contexte=None):
        super().__init__(configuration, message_dao, document_dao, contexte)
        self._traitement_message = None

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessageRapports(self)

        nom_queue_rapports = self.get_nom_queue()

        # Configurer la Queue pour les rapports sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_rapports,
            durable=True)

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_rapports,
            routing_key='destinataire.domaine.%s.#' % RapportsConstantes.QUEUE_NOM
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_rapports,
            routing_key='ceduleur.#'
        )

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def traiter_cedule(self, evenement):
        pass

    def get_nom_queue(self):
        return RapportsConstantes.QUEUE_NOM


class TraitementMessageRapports(BaseCallback):
    """ Classe helper pour traiter les transactions de la queue de notifications """

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
            raise ValueError("Type d'evenement inconnu: %s" % evenement)
