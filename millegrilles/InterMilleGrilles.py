# Module Inter-MilleGrilles
# Ce module sert a etablir et maintenir des connexions entre MilleGrilles via RabbitMQ
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import TraitementMessageCallback, JSONHelper

from threading import Event, Thread, Lock

import logging
import datetime
import json


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

        self.__callback_q_locale = TraitementMessageQueueLocale(
            self, self.contexte.message_dao, self.contexte.configuration)
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

        for connexion in self.__connexions.values():
            try:
                connexion.arreter()
            except:
                pass

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

    def connecter_millegrille(self, commande):
        """
        Tente de se connecter a une MilleGrille distante
        """
        idmg = commande[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        connexion_existante = self.__connexions.get(idmg)
        if connexion_existante is None:
            # Creer une nouvelle connexion. La classe va s'occuper d'etablir une connexion si c'est possible.
            connexion = ConnexionInterMilleGrilles(self, idmg)
            self.__connexions[idmg] = connexion
            connexion.demarrer()
        else:
            self.__logger.warning("Demande de connexion a %s mais une thread de connexion est deja en cours")
            connexion_existante.poke()


class TraitementMessageQueueLocale(TraitementMessageCallback):

    def __init__(self, connecteur, message_dao, configuration):
        super().__init__(message_dao, configuration)
        self.__connecteur = connecteur
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        """
        S'occupe de l'execution d'une commande.
        """
        routing_key = method.routing_key
        exchange = method.exchange
        dict_message = json.loads(body)

        if exchange == Constantes.DEFAUT_MQ_EXCHANGE_PRIVE:
            if routing_key == ConstantesInterMilleGrilles.COMMANDE_CONNECTER:
                self.__connecteur.connecter_millegrille(dict_message)

        self.__logger.debug("Commande inter-millegrilles recue sur echange %s: %s, contenu %s" % (exchange, routing_key, body.decode('utf-8')))


class TraitementMessageLocalVersTiers(TraitementMessageCallback):

    def __init__(self, connecteur, message_dao, configuration):
        super().__init__(message_dao, configuration)
        self.__connecteur = connecteur
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        """
        S'occupe de la reception d'un message en amont a transferer vers la millegrille designee.
        """
        routing_key = method.routing_key
        exchange = method.exchange
        dict_message = json.loads(body)

        self.__logger.debug("Commande inter-millegrilles recue sur echange %s: %s, contenu %s" % (exchange, routing_key, body.decode('utf-8')))

        if exchange == Constantes.DEFAUT_MQ_EXCHANGE_PRIVE:
            self.__logger.debug("Message en amont sur exchange prive local, on le passe a la millegrille distante")
        elif exchange == '':  # Echange direct
            self.__logger.debug("Message sur exchange direct")
        else:
            raise Exception("Message non traitable")


class ConnexionInterMilleGrilles:
    """
    Represente une connexion avec une instance de RabbitMQ.
    """

    def __init__(self, connecteur: ConnecteurInterMilleGrilles, idmg: str):
        self.__connecteur = connecteur
        self.__idmg = idmg  # IDMG de la connexion (millegrille distante)
        self.__thread = Thread(name="CX-" + idmg, target=self.executer, daemon=True)

        self.__traitement_local_vers_tiers = TraitementMessageLocalVersTiers(
            connecteur, connecteur.contexte.message_dao, connecteur.contexte.configuration)
        self.__ctag_local = None

        self.__nom_q = 'inter.' + idmg

        self.__connexion_mq_distante = None
        self.__channel_distant = None

        self.__certificat = None  # Certificat client utilise pour se connecter
        self.__cle_privee = None
        self.__derniere_activite = datetime.datetime.utcnow()

        # Temps d'inactivite apres lequel on ferme la connexion
        self.__temps_inactivite_secs = datetime.timedelta(seconds=300)

        self.__wait_event = Event()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def faker(self):
        self.__certificat = self.__connecteur.contexte.configuration.mq_certfile
        self.__cle_privee = self.__connecteur.contexte.configuration.mq_keyfile

    def poke(self):
        self.__logger.warning("On vient de se faire poker (idmg: %s)" % self.__idmg)

    def demarrer(self):
        self.__logger.info("Demarrage thread connexion a " + self.__idmg)
        self.__thread.start()

    def executer(self):
        self.__logger.info("Execution thread connexion a " + self.__idmg)

        self.definir_q_locale()

        while not self.__wait_event.is_set():
            self.__wait_event.wait(10)

        self.__logger.info("Fin execution thread connexion a " + self.__idmg)

    def arreter(self):
        self.__wait_event.set()

    def definir_q_locale(self):
        """
        Tente d'ouvrir une Q exclusive locale au nom de la MilleGrille distante.
        """
        # Creer la Q sur la connexion en aval
        self.__connecteur.channel.queue_declare(
            queue=self.__nom_q,
            durable=False,
            exclusive=True,
            callback=self.creer_bindings_local,
        )

    def creer_bindings_local(self, queue):
        self.__logger.info("Ouverture Q locale pour %s: %s" % (self.__idmg, str(queue)))
        self.__ctag_local = self.__connecteur.channel.basic_consume(
            self.__traitement_local_vers_tiers.callbackAvecAck,
            queue=self.__nom_q,
            no_ack=False
        )

    def preparer_certificat(self):
        """
        S'assure d'avoir le certificat requis et la cle pour se connecter a la MilleGrille distante.
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

