# Module du domaine des notifications.

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.processus.MGProcessus import MGProcessus

import datetime


class NotificationsConstantes:

    COLLECTION_NOM = 'mgdomaines_web_WebPoll'
    QUEUE_SUFFIXE = 'millegrilles.domaines.Notifications'

    # Niveaux d'une notification
    INFORMATION = 'information'      # Plus bas niveau
    AVERTISSEMENT = 'avertissement'  # Niveau par defaut
    ALERTE = 'alerte'                # Plus haut niveau


class GestionnaireNotifications(GestionnaireDomaine):

    def __init__(self, configuration, message_dao, document_dao):
        super().__init__(configuration, message_dao, document_dao)
        self._traitement_message = None

    def get_nom_queue(self):
        nom_millegrille = self.configuration.nom_millegrille
        nom_queue = 'mg.%s.%s' % (nom_millegrille, NotificationsConstantes.QUEUE_SUFFIXE)
        return nom_queue

    def traiter_transaction(self, ch, method, properties, body):
        self._traitement_message.callbackAvecAck(ch, method, properties, body)

    def traiter_cedule(self):
        pass

    def traiter_notification(self, notification):
        processus = "millegrilles_domaines_Notifications:ProcessusNotificationRecue"
        self.demarrer_processus(processus, notification)

    def configurer(self):
        super().configurer()
        self._traitement_message = TraitementMessageNotification(self)

        nom_millegrille = self.configuration.nom_millegrille
        nom_queue_notification = self.get_nom_queue()

        # Configurer la Queue pour les notifications sur RabbitMQ
        self.message_dao.channel.queue_declare(
            queue=nom_queue_notification,
            durable=True)

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_notification,
            routing_key='%s.notification.#' % nom_millegrille
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_notification,
            routing_key='%s.destinataire.domaine.%s.#' % (nom_millegrille, NotificationsConstantes.QUEUE_SUFFIXE)
        )

        self.message_dao.channel.queue_bind(
            exchange=self.configuration.exchange_evenements,
            queue=nom_queue_notification,
            routing_key='%s.ceduleur.#' % nom_millegrille
        )


class TraitementMessageNotification(BaseCallback):
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
        elif evenement == Constantes.EVENEMENT_NOTIFICATION:
            # Notification recue
            self._gestionnaire.traiter_notification(message_dict)
        else:
            # Type d'evenement inconnu, on lance une exception
            raise ValueError("Type d'evenement inconnu: %s" % evenement)


class ProcessusNotificationRecue(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        parametres = self.parametres
        self._logger.debug("Traitement notification: %s" % str(parametres))

        # Verifier si on concatene l'information a un document existant ou si on cree un nouveau document
        self.set_etape_suivante(ProcessusNotificationRecue.sauvegarder_notification.__name__)

    def sauvegarder_notification(self):
        self.set_etape_suivante(ProcessusNotificationRecue.avertir_usager.__name__)

    def avertir_usager(self):
        self.set_etape_suivante()  # Termine le processus


class FormatteurEvenementNotification:

    TEMPLATE_NOTIFICATION = {
        "domaine": None,
        Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_NOTIFICATION,
        "source": {
            "_collection": None,
            "_id": None
        },
        "regles": [],
        "valeurs": {}
    }

    def __init__(self, domaine, collection):
        self._domaine = domaine
        self._collection = collection

        self._template = FormatteurEvenementNotification.TEMPLATE_NOTIFICATION.copy()
        self._template['domaine'] = domaine
        self._template['source']['_collection'] = collection

    def formatter_notification(self, id_document, regles, valeurs):
        notification = self._template.copy()
        notification['source']['_id'] = str(id_document)
        notification['valeurs'] = valeurs
        notification['date'] = int(datetime.datetime.utcnow().timestamp())

        if isinstance(regles, list):
            notification['regles'] = regles
        else:
            notification['regles'] = [regles]

        return notification
