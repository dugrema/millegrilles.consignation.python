import logging

from threading import Event

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesHebergementTransactions
from millegrilles.dao.MessageDAO import JSONHelper, BaseCallback, CertificatInconnu


class TraitementMessage(BaseCallback):

    def __init__(self, gestionnaire, contexte):
        super().__init__(contexte)
        self.__gestionnaire = gestionnaire
        self.__channel = None
        self.queue_name = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        exchange = method.exchange

        if correlation_id == ConstantesHebergementTransactions.CORRELATION_MILLEGRILLES_ACTIVES:
            self.__logger.debug("Message recu : %s" % message_dict)
            self.__gestionnaire.entretien_millegrilles_actives(message_dict['resultats'])
        else:
            raise ValueError("Type message inconnu", correlation_id, routing_key)

    def on_channel_open(self, channel):
        self.__channel = channel
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=1)

        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        self.__channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.__gestionnaire.queue_prete.set()

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.queue_name = None

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed


class Hebergement(ModeleConfiguration):
    """
    Supporte la creation de Contexte pour une ou plusieurs MilleGrilles hebergees.
    """

    def __init__(self):
        super().__init__()
        self.__millegrilles = None
        self.__fermeture_event = Event()
        self.__traitement_messages = None
        self.queue_prete = Event()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        super().initialiser(init_document, init_message, connecter)
        self.__traitement_messages = TraitementMessage(self, self.contexte)
        self.contexte.message_dao.register_channel_listener(self.__traitement_messages)

    def deconnecter(self):
        self.__fermeture_event.set()

    def executer(self):
        self.__logger.info("Demarrage hebergement")

        self.queue_prete.wait(10)
        if self.queue_prete.is_set():
            self.__logger.info("Queue hebergement prete")

        while not self.__fermeture_event.is_set():
            self.verifier_millegrilles_actives()
            self.__fermeture_event.wait(10)

        self.__logger.info("Arret hebergement")

    def verifier_millegrilles_actives(self):
        """
        Transmet une requete pour demander la liste des MilleGrilles actives.
        :return:
        """
        domaine_requete = Constantes.ConstantesHebergement.REQUETE_MILLEGRILLES_ACTIVES
        queue_name = self.__traitement_messages.queue_name
        if not queue_name:
            raise ValueError("Queue reception non initialisee")

        self.contexte.generateur_transactions.transmettre_requete(
            {},
            domaine_requete,
            correlation_id=ConstantesHebergementTransactions.CORRELATION_MILLEGRILLES_ACTIVES,
            reply_to=self.__traitement_messages.queue_name
        )

    def entretien_millegrilles_actives(self, liste_millegrilles: list):

        for info in liste_millegrilles:
            self.__logger.debug("Entretien idmg %s", info['idmg'])


class HebergementTransactions(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)


class HebergementDomaines(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)


class HebergementMaitreDesCles(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)
