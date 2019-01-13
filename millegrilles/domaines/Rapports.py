# Module des rapports et sommaires de documents

from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles import Constantes
from millegrilles.MGProcessus import MGProcessusTransaction

import dateutil.parser
import logging


class RapportsConstantes:

    DOMAINE_NOM = 'millegrilles.domaines.Rapports'
    COLLECTION_NOM = 'millegrilles_domaines_Rapports'
    QUEUE_NOM = 'millegrilles.domaines.Rapports'


class GestionnaireRapports(GestionnaireDomaine):
    """ Gestionnaire du domaine des rapports"""

    def __init__(self, configuration=None, message_dao=None, document_dao=None, contexte=None):
        super().__init__(configuration, message_dao, document_dao, contexte)
        self._traitement_message = None

        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

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

        # Creer index _mg-libelle
        collection_domaine = self.document_dao.get_collection(RapportsConstantes.COLLECTION_NOM)
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        # Index _mg-libelle, url
        collection_domaine.create_index([
            ('url', 1),
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def traiter_cedule(self, evenement):
        pass

    def get_nom_queue(self):
        return RapportsConstantes.QUEUE_NOM

    def declencher_processus_persistance(self, routing_key, evenement):
        routing_key_list = routing_key.split('.')

        for nom_cle in TraitementMessageRapports.MAPPING_PROCESSUS:
            if nom_cle in routing_key_list:
                nom_processus = TraitementMessageRapports.MAPPING_PROCESSUS[nom_cle]
                parametres = evenement.copy()
                parametres['type_rapport'] = routing_key_list[-1]
                self.demarrer_processus(nom_processus, parametres)


class TraitementMessageRapports(BaseCallback):
    """ Classe helper pour traiter les transactions de la queue de notifications """

    MAPPING_PROCESSUS = {
        'SommaireRSS': 'millegrilles.domaines.Rapports:ProcessusSommaireRSS'
    }

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.configuration)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if evenement == Constantes.EVENEMENT_CEDULEUR:
            # Ceduleur, verifier si action requise
            self._gestionnaire.traiter_cedule(message_dict)
        elif evenement == Constantes.EVENEMENT_TRANSACTION_PERSISTEE:
            # Verifier quel processus demarrer. On match la valeur dans la routing key.
            routing_key = method.routing_key
            routing_key_sansprefixe = routing_key.replace(
                'destinataire.domaine.',
                ''
            )
            # Trouver le processus a demarrer
            self._gestionnaire.declencher_processus_persistance(routing_key_sansprefixe, message_dict)

        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % str(evenement))


class ProcessusSommaireRSS(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        parametres = self.parametres
        self._logger.debug('Rapport RSS processing, parametres: %s' % parametres)
        doc_transaction = self.charger_transaction()

        # Faire le rapport
        url = doc_transaction['charge-utile']['url']
        contenu_rss = doc_transaction['charge-utile']['rss']
        entries = contenu_rss['entries']

        date_maj = dateutil.parser.parse(contenu_rss['feed']['updated'])
        titre_previsions = contenu_rss['feed']['title']
        watches = entries[0]['summary']
        courant = entries[1]['summary']
        previsions = []
        for prevision in entries[2:3]:
            prevision_texte = prevision['summary']
            previsions.append(prevision_texte)
        for prevision in entries[3:]:
            prevision_texte = prevision['title']
            previsions.append(prevision_texte)

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: str(parametres['type_rapport']),
            'url': url
        }

        operation_set = {
            'titre': titre_previsions,
            'avertissements': watches,
            'previsions_courantes': courant,
            'previsions': previsions,
            'mis_a_jour': date_maj
        }

        operations = {
            '$set': operation_set,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$setOnInsert': filtre
        }

        collection_rapports = self.document_dao().get_collection(RapportsConstantes.COLLECTION_NOM)
        collection_rapports.update_one(filtre, operations, upsert=True)

        self._logger.debug("Previsions: %s" % str(operation_set))

        self.set_etape_suivante()
