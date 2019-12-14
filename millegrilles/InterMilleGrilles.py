# Module Inter-MilleGrilles
# Ce module sert a etablir et maintenir des connexions entre MilleGrilles via RabbitMQ
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import TraitementMessageCallback

from threading import Event, Thread, Lock

import logging
import datetime

class ConstantesInterMilleGrilles:

    COMMANDE_CONNECTER = 'commande.inter.connecter'


class ConnecteurInterMilleGrilles(ModeleConfiguration):
    """
    Gestionnaire pour toutes les connexions inter-MilleGrilles
    """

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        # Mot de passe utilise pour toutes les cles
        self.__mot_de_passe_cle = None
        self.__connexions = dict()  # Connexions, cle=IDMG, valeur=ConnexionInterMilleGrilles

        self.__attendre_q_prete = Event()
        self.__callback_q_locale = None
        self.__ctag_local = None
        self.__q_locale = None

        self._stop_event = Event()

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        """
        L'initialisation connecte RabbitMQ local et lance la configuration
        """
        super().initialiser(False, True, True)
        self.__logger.info("On enregistre la queue de commandes")

        self.__callback_q_locale = TraitementMessageQueueLocale(self.contexte.message_dao, self.contexte.configuration)
        self.__logger.info("Attente Q et routes prets")

        self.__attendre_q_prete.wait(10)

        if not self.__attendre_q_prete.is_set():
            self.__logger.warning('wait_Q_read pas set, on va forcer error state sur la connexion pour recuperer')
            self.contexte.message_dao.enter_error_state()
        else:
            self.__logger.info("Q et routes prets")

    def executer(self):
        while not self._stop_event.is_set():
            self._stop_event.wait(60)

        self.__logger.info("Fin execution InterMilleGrilles")

    def exit_gracefully(self, signum=None, frame=None):
        self.__logger.warning("Arret de ConnecteurInterMilleGrilles")
        self._stop_event.set()
        super().exit_gracefully(signum, frame)

    def on_channel_open(self, channel):
        """
        Appelle lors de la connexion a MQ local
        """
        super().on_channel_open(channel)
        self.creer_q_commandes_locales()

    def creer_q_commandes_locales(self):
        """
        Prepare une Q exclusive locale pour recevoir les commandes de connexions, etc.
        """

        # Creer la Q sur la connexion en aval
        self.channel.queue_declare(
            queue='',  # Va generer un nom aleatoire
            durable=False,
            exclusive=True,
            callback=self.creer_bindings_local,
        )

        self.__attendre_q_prete.set()

    def creer_bindings_local(self, queue):
        self.__q_locale = queue.method.queue

        routing_keys = [
            ConstantesInterMilleGrilles.COMMANDE_CONNECTER,
        ]

        for routing in routing_keys:
            self.channel.queue_bind(
                exchange=self.contexte.configuration.exchange_prive,
                queue=self.__q_locale,
                routing_key=routing,
                callback=self.__compter_route
            )

        self.__ctag_local = self.channel.basic_consume(
            self.__callback_q_locale.callbackAvecAck,
            queue=self.__q_locale,
            no_ack=False
        )

    def __compter_route(self, frame):
        self.__logger.debug("Frame route: %s" % str(frame))


class TraitementMessageQueueLocale(TraitementMessageCallback):

    def __init__(self, message_dao, configuration):
        super().__init__(message_dao, configuration)
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        """
        S'occupe de l'execution d'une commande.
        """
        routing_key = method.routing_key
        exchange = method.exchange

        self.__logger.debug("Commande inter-millegrilles recue sur echange %s: %s, contenu %s" % (exchange, routing_key, body.decode('utf-8')))


class ConnexionInterMilleGrilles:
    """
    Represente une connexion avec une instance de RabbitMQ.
    """

    def __init__(self):
        self.__idmg = None  # IDMG de la connexion (millegrille distante)
        self.__certificat = None  # Certificat client utilise pour se connecter
        self.__cle_privee = None
        self.__dernierer_activite = datetime.datetime.utcnow()

        # Temps d'inactivite apres lequel on ferme la connexion
        self.__temps_inactivite_secs = datetime.timedelta(seconds=300)

    def definir_q_locale(self):
        """
        Tente d'ouvrir une Q exclusive locale au nom de la MilleGrille distante.
        """
        pass

    def connecter_mq_distant(self):
        """
        Se connecte a la MilleGrille distante avec le certificat approprie
        """
        pass

    def connexion_distante_ouverte(self):
        """
        Callback sur ouverture de connexion distante pour ouvrir un channel
        """
        pass

    def channel_distant_ouvert(self):
        """
        Callback sur ouverture
        """

    def connexion_distante_fermee(self):
        """
        Callback sur fermeture de la connexion distante
        """

    def demander_maj_certificat(self):
        """
        Demander a la millegrille distante une mise a jour du certificat
        """
        pass

    def demander_bindings_requis(self):
        """
        Demande a la MilleGrille distante une liste de bindings desires avec la MilleGrille locale
        """
        pass

