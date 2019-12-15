# Module Inter-MilleGrilles
# Ce module sert a etablir et maintenir des connexions entre MilleGrilles via RabbitMQ
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import TraitementMessageCallback, ConnexionWrapper, JSONHelper
from millegrilles.domaines.Annuaire import ConstantesAnnuaire
from millegrilles.util.X509Certificate import EnveloppeCleCert

from threading import Event, Thread, Lock, Barrier
from pika.channel import Channel

import logging
import datetime
import json
import tempfile
import os
import shutil


class ConstantesInterMilleGrilles:

    COMMANDE_CONNECTER = 'commande.inter.connecter'

    REPERTOIRE_INTER = '/opt/millegrilles/dist/inter'
    REPERTOIRE_FICHES = os.path.join(REPERTOIRE_INTER, "fiches")
    REPERTOIRE_CERTS = os.path.join(REPERTOIRE_INTER, "certs")
    REPERTOIRE_SECRETS = os.path.join(REPERTOIRE_INTER, "secrets")


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

        # Repertoire temporaire pour conserver les fichiers de certificats
        self.interca_dir = tempfile.mkdtemp(prefix='interca_')

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

        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(60)

        finally:
            self.__logger.info("Fin execution InterMilleGrilles")
            self.__fermeture()

    def exit_gracefully(self, signum=None, frame=None):
        self.__logger.warning("Arret de ConnecteurInterMilleGrilles")
        self._stop_event.set()

        super().exit_gracefully(signum, frame)

    def __fermeture(self):
        self.enlever_toutes_connexions()
        try:
            shutil.rmtree(self.interca_dir)
        except Exception:
            self.__logger.exception("Erreur suppression repertoire certificats")

    def on_channel_open(self, channel):
        """
        Appelle lors de la connexion a MQ local
        """
        super().on_channel_open(channel)
        channel.add_on_return_callback(self._on_return)
        self.creer_q_commandes_locales()

    def on_channel_close(self, channel=None, code=None, reason=None):
        self._logger.warning("MQ Channel local ferme - enlever toutes les connexions")
        self.enlever_toutes_connexions()
        super().on_channel_close(channel, code, reason)

    def _on_return(self, channel, method, properties, body):
        self.__logger.warning("Return value: %s\n%s" % (str(method), str(body)))

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

    def enlever_toutes_connexions(self):
        liste_idmg = list()
        liste_idmg.extend(self.__connexions.keys())
        for idmg in liste_idmg:
            self.enlever_connexion(idmg)

    def enlever_connexion(self, idmg):
        connexion = self.__connexions.get(idmg)
        if connexion is not None:
            del self.__connexions[idmg]
            try:
                connexion.arreter()
            except:
                pass


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


class ConfigurationInterMilleGrilles:
    """
    Configuration a utiliser pour se connecter a une MilleGrille distante
    """

    def __init__(self, fiche_privee, repertoire_interca, heartbeat=30):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._fiche_privee = fiche_privee
        self._repertoire_interca = repertoire_interca
        self._heartbeat = heartbeat

        self._idmg = fiche_privee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        self._host = None
        self._port = None
        self._cafile = None

        self._keyfile = os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_SECRETS, self.idmg+'.key.pem')
        self._certfile = os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_CERTS, self.idmg+'.cert.pem')

        self._parse_host()
        self._extraire_cafile()

    def _parse_host(self):
        """
        Separer les entree de host prives amqps en hostname,
        """
        hosts = self._fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_LIENS_PRIVES_MQ]
        host = hosts[0]
        hostname_port = host.split('/')[2].split(':')
        self._host = hostname_port[0]
        self._port = hostname_port[1]

    def _extraire_cafile(self):
        """
        Extraire le CA file pour la millegrille distante (et valide le IDMG).
        """
        cert_ca_pem = self._fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_RACINE]

        # Valider le certificat, il faut s'assurer que le fingerprint=IDMG
        clecert_ca = EnveloppeCleCert()
        clecert_ca.cert_from_pem_bytes(cert_bytes=cert_ca_pem.encode('utf-8'))
        fingerprint = clecert_ca.fingerprint_base58

        # if fingerprint != self._idmg:
        #     raise Exception("Fingerprint %s du certificat CA ne correspond pas a IDMG %s" % (fingerprint, self._idmg))

        # Sauvegarder le ca localement
        tmp_file_ca = os.path.join(self._repertoire_interca, self._idmg + '.cert.pem')
        self._cafile = tmp_file_ca
        try:
            with open(tmp_file_ca, 'w') as fichier:
                fichier.write(cert_ca_pem)
        except Exception:
            self.__logger.exception("Erreur excriture cert CA pour idmg=%s" % self._idmg)

    @property
    def idmg(self):
        return self._idmg

    @property
    def mq_host(self):
        return self._host

    @property
    def mq_port(self):
        return self._port

    @property
    def mq_heartbeat(self):
        return self._heartbeat

    @property
    def mq_keyfile(self):
        return self._keyfile

    @property
    def mq_certfile(self):
        return self._certfile

    @property
    def mq_cafile(self):
        return self._cafile

    @property
    def mq_ssl(self):
        return "on"

    @property
    def mq_auth_cert(self):
        return "on"


class ConnexionInterMilleGrilles:
    """
    Represente une connexion avec une instance de RabbitMQ.
    """

    def __init__(self, connecteur: ConnecteurInterMilleGrilles, idmg: str):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__connecteur = connecteur
        self.__idmg = idmg  # IDMG de la connexion (millegrille distante)
        self.__thread = Thread(name="CX-" + idmg, target=self.executer, daemon=True)

        self.__traitement_local_vers_tiers = TraitementMessageLocalVersTiers(
            self, connecteur.contexte.message_dao, connecteur.contexte.configuration)

        # Ouvrir un nouveau canal en amont local
        # Necessaire en partie parce que la verification de Q exclusive ferme le canal si la
        # Q existe deja (e.g. ouverte par MG tierce)
        self.__channel_amont_local = None
        self.__ctag_amont_local = None

        self.__nom_q = 'inter.' + idmg

        # Information de connexion
        self.__fiche_privee_tiers = None
        self.__configuration_connexion = None

        # Connexions distantes en amont et aval
        self.__connexion_mq_amont_distante = None
        self.__connexion_mq_aval_distante = None

        self.__derniere_activite = datetime.datetime.utcnow()

        # Temps d'inactivite apres lequel on ferme la connexion
        self.__temps_inactivite_secs = datetime.timedelta(seconds=300)

        self.__connexion_event = Event()
        self.__stop_event = Event()

    def poke(self):
        self.__logger.warning("On vient de se faire poker (idmg: %s)" % self.__idmg)

    def demarrer(self):
        self.__logger.info("Demarrage thread connexion a " + self.__idmg)
        self.__thread.start()

    def executer(self):
        self.__logger.info("Execution thread connexion a " + self.__idmg)

        try:
            self.charger_configuration_tiers()

            self.ouvrir_canal_amont_local()
            self.__connexion_event.wait(10)
            if not self.__connexion_event.is_set():
                raise Exception('Erreur connexion idmg=%s, channel local pas pret' % self.__idmg)
            self.__connexion_event.clear()

            self.__logger.info("Connexion amont locale %s prete, demarrage connexions distantes" % self.__idmg)

            self.connecter_mq_distant()  # Methode blocking (barrier)

            while not self.__stop_event.is_set():
                self.__stop_event.wait(10)

        finally:
            self._fermeture()

        self.__logger.info("Fin execution thread connexion a " + self.__idmg)

    def arreter(self):
        self.__stop_event.set()
        self.__connexion_event.set()

    def _fermeture(self):
        self.__logger.info("Fermeture connexion idmg %s" % self.idmg)
        self.__connecteur.enlever_connexion(self.__idmg)
        self.__connecteur.contexte.message_dao.enlever_channel_listener(self)
        try:
            self.__channel_amont_local.close()
        except:
            pass

        try:
            self.__connexion_mq_aval_distante.deconnecter()
        except:
            pass

        try:
            self.__connexion_mq_amont_distante.deconnecter()
        except:
            pass

    def charger_configuration_tiers(self):
        with open(os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_FICHES, self.idmg+'.json')) as fichier:
            self.__fiche_privee_tiers = json.load(fichier)
        self.__configuration_connexion = ConfigurationInterMilleGrilles(
            self.__fiche_privee_tiers, self.connecteur.interca_dir)

    def ouvrir_canal_amont_local(self):
        # Enregistrer nouveau canal via DAO (managed pour les exceptions de connexions)
        self.__connecteur.contexte.message_dao.enregistrer_channel_listener(self)

    def on_channel_open(self, channel):
        """
        Canal en amont local ouvert.
        """
        self.__channel_amont_local = channel
        channel.add_on_return_callback(self._on_return_amont_local)
        channel.add_on_close_callback(self._on_channel_amont_local_close)
        self.definir_q_locale()

    def _on_channel_amont_local_close(self, channel=None, code=None, reason=None):
        self.__channel_amont_local = None
        self.__logger.debug("MQ Channel idmg=%s ferme, code=%s" % (self.__idmg, str(code)))

        # Verifier la raison de la fermeture
        if code == 405:
            self.__logger.info(
                "Fermeture pour cause de lock sur Q existante. La connexion inter-millegrilles %s existe deja, on ferme",
                self.__idmg
            )
            self.arreter()

    def _on_return_amont_local(self, channel, method, properties, body):
        self.__logger.warning("MQ Return idmg=%s, %s " % (self.__idmg, str(method)))

    def is_channel_open(self):
        return self.__channel_amont_local is not None

    def definir_q_locale(self):
        """
        Tente d'ouvrir une Q exclusive locale au nom de la MilleGrille distante.
        """
        # Creer la Q sur la connexion en aval
        self.__channel_amont_local.queue_declare(
            queue=self.__nom_q,
            durable=False,
            exclusive=True,
            callback=self.creer_bindings_local,
        )

        # La connexion est prete
        self.__connexion_event.set()

    def creer_bindings_local(self, queue):
        self.__logger.info("Ouverture Q locale pour %s: %s" % (self.__idmg, str(queue)))
        self.__ctag_amont_local = self.__channel_amont_local.basic_consume(
            self.__traitement_local_vers_tiers.callbackAvecAck,
            queue=self.__nom_q,
            no_ack=False
        )

    def connecter_mq_distant(self):
        """
        Se connecte a la MilleGrille distante avec le certificat approprie
        """
        self.__connexion_mq_aval_distante = ConnexionWrapper(self.__configuration_connexion, self.__stop_event)
        self.__connexion_mq_amont_distante = ConnexionWrapper(self.__configuration_connexion, self.__stop_event)

        # Ouvrir les connexions, donner 20 secondes max avant d'abandonner
        barrier = Barrier(3)
        self.__connexion_mq_aval_distante.connecter(barrier)
        self.__connexion_mq_amont_distante.connecter(barrier)
        barrier.wait(20)
        if barrier.broken:
            raise Exception("Erreur connexion a MQ distant")

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

    @property
    def idmg(self):
        return self.__idmg

    @property
    def connecteur(self):
        return self.__connecteur


class TraitementMessageLocalVersTiers(TraitementMessageCallback):

    def __init__(self, connexion: ConnexionInterMilleGrilles, message_dao, configuration):
        super().__init__(message_dao, configuration)
        self.__connexion = connexion
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        """
        S'occupe de la reception d'un message en amont a transferer vers la millegrille designee.
        """
        routing_key = method.routing_key
        exchange = method.exchange
        dict_message = json.loads(body)

        self.__logger.debug("%s: Commande inter-millegrilles recue sur echange %s: %s, contenu %s" % (
            self.__connexion.idmg, exchange, routing_key, body.decode('utf-8')))

        if exchange == Constantes.DEFAUT_MQ_EXCHANGE_PRIVE:
            self.__logger.debug("Message en amont sur exchange prive local, on le passe a la millegrille distante")
        elif exchange == '':  # Echange direct
            self.__logger.debug("Message sur exchange direct")
        else:
            raise Exception("Message non traitable")