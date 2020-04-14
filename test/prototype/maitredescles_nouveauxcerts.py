# Sert a tester, developper domaine Hebergement
import logging

from threading import Event

from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.domaines.MaitreDesCles import GestionnaireMaitreDesCles
from millegrilles.dao.MessageDAO import BaseCallback


logging.basicConfig()
logging.getLogger('millegrilles.Domaines.TestGestionnaireMaitredescles_NouveauxCertificats').setLevel(logging.DEBUG)

contexte = ContexteRessourcesDocumentsMilleGrilles()
contexte.initialiser()


class TestGestionnaireMaitredescles_NouveauxCertificats(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger.setLevel(logging.DEBUG)

        self.channel = None
        self.event_recu = Event()
        self.queue_name = None

        self.contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.executer()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        self.__logger.debug('Reponse recue : %s' % str(body))
        self.event_recu.set()  # Termine

    def executer(self):
        self.__logger.info("*** DEBUT executer prototype ***")
        gestionnaire = GestionnaireMaitreDesCles(contexte)

        try:
            pass
        finally:
            pass
            self.event_recu.set()  # Termine
        self.__logger.info("*** FIN executer prototype ***")


# -------
sample = TestGestionnaireMaitredescles_NouveauxCertificats()

# FIN TEST
sample.event_recu.wait(200)
sample.deconnecter()
