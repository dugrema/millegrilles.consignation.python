# Module Inter-MilleGrilles
# Ce module sert a etablir et maintenir des connexions entre MilleGrilles via RabbitMQ
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles import Constantes
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import TraitementMessageCallback, ConnexionWrapper, JSONHelper, CertificatInconnu
from millegrilles.domaines.Annuaire import ConstantesAnnuaire
from millegrilles.util.X509Certificate import EnveloppeCleCert, GenerateurCertificat

from threading import Event, Thread, Lock, Barrier
from pika.channel import Channel

import logging
import datetime
import json
import tempfile
import os
import shutil
import traceback
import pika
import uuid
import base64


class ConstantesInterMilleGrilles:

    COMMANDE_CONNECTER = 'commande.inter.connecter'
    REQUETE_GENERER_CSR = 'inter.genererCsr'

    REPERTOIRE_INTER = '/opt/millegrilles/dist/inter'
    REPERTOIRE_FICHES = os.path.join(REPERTOIRE_INTER, "fiches")
    REPERTOIRE_CERTS = os.path.join(REPERTOIRE_INTER, "certs")
    REPERTOIRE_SECRETS = os.path.join(REPERTOIRE_INTER, "secrets")

    CERTIFICAT_LOCAL = 'certificat_local'
    CLE_LOCALE = 'cle_locale'

    ENV_PATH_MOTDEPASSE_CLE = 'MG_MOTDEPASSECLE_PATH'

    ROUTING_KEY_NOTICES_INTER = 'inter.notices'

    LIBELLE_CSR = 'csr'
    LIBELLE_CORRELATION = 'correlation'


class ConnecteurInterMilleGrilles(ModeleConfiguration):
    """
    Gestionnaire pour toutes les connexions inter-MilleGrilles
    """

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        # Mot de passe utilise pour toutes les cles
        self.__mot_de_passe_cle = None

        # Sites de relais avec paires de connexions
        # Cle = idmg du relai, Valeur = ConnexionRelaiMilleGrilles
        self.__relais = dict()

        # Paire de Q locale/Echange relai pour une MilleGrille tierce
        # Cle=IDMG, Valeur=RouteMilleGrilleTiers
        self.__route_tiers = dict()

        self.__attendre_q_prete = Event()
        self.__callback_q_locale = None
        self.__ctag_local = None
        self.__q_locale = None

        # Repertoire temporaire pour conserver les fichiers de certificats
        self.interca_dir = tempfile.mkdtemp(prefix='interca_')

        self._stop_event = Event()
        self.json_helper = JSONHelper()

    def initialiser(self, init_document=False, init_message=True, connecter=True):
        """
        L'initialisation connecte RabbitMQ local et lance la configuration
        """
        super().initialiser(False, True, True)
        self.__logger.info("On enregistre la queue de commandes")

        ficher_motdepasse_cle = os.environ.get(ConstantesInterMilleGrilles.ENV_PATH_MOTDEPASSE_CLE)
        with open(ficher_motdepasse_cle, 'r') as fichier:
            self.__mot_de_passe_cle = fichier.read().strip()

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

        routing_keys_prive = [
            ConstantesInterMilleGrilles.COMMANDE_CONNECTER,
        ]

        for routing in routing_keys_prive:
            self.channel.queue_bind(
                exchange=self.contexte.configuration.exchange_prive,
                queue=self.__q_locale,
                routing_key=routing,
                callback=self.__compter_route
            )

        routing_keys_protege = [
            'requete.' + ConstantesInterMilleGrilles.REQUETE_GENERER_CSR,
        ]

        for routing in routing_keys_protege:
            self.channel.queue_bind(
                exchange=self.contexte.configuration.exchange_noeuds,
                queue=self.__q_locale,
                routing_key=routing,
                callback=self.__compter_route
            )

        self.__ctag_local = self.channel.basic_consume(
            self.__callback_q_locale.callbackAvecAck,
            queue=self.__q_locale,
            no_ack=False
        )

        # Lancer une connexion avec l'echange prive local
        self.connecter_relai_local()

    def __compter_route(self, frame):
        self.__logger.debug("Frame route: %s" % str(frame))

    def connecter_relai_local(self):
        """
        Simule une fiche locale pour se connecter au relai local. Utilise meme config que pour MQ local.
        """
        idmg = self.contexte.idmg
        url_prive_local = 'amqps://%s:%d/prive' % (self.contexte.configuration.mq_host, self.contexte.configuration.mq_port)

        with open(self.contexte.configuration.pki_cafile, 'r') as fichier:
            ca_pem = fichier.read()

        configuration_mq_local = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: idmg,
            ConstantesAnnuaire.LIBELLE_DOC_LIENS_PRIVES_MQ: [url_prive_local],
            ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_RACINE: ca_pem,

            Constantes.CONFIG_MQ_HOST: self.contexte.configuration.mq_host,
            Constantes.CONFIG_MQ_PORT: self.contexte.configuration.mq_port,

            # Ajout information complementaire pour relai local
            Constantes.CONFIG_MQ_CERTFILE: self.contexte.configuration.pki_certfile,
            Constantes.CONFIG_MQ_KEYFILE: self.contexte.configuration.pki_keyfile,
        }
        self.connecter_relai(configuration_mq_local)

    def connecter_relai(self, fiche_millegrille):
        """
        Tente de se connecter a un relai
        :param fiche_millegrille: Utiliser les informations de connexion MQ de cette fiche et certificats associes pour se connecter
        """
        idmg = fiche_millegrille[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        relai = self.__relais.get(idmg)

        if relai is None:
            # Creer une nouvelle instance de relai avec cette MilleGrille
            configuration_relai = ConfigurationRelai(fiche_millegrille, self.interca_dir)
            relai = ConnexionRelaiMilleGrilles(self, configuration_relai)
            relai.demarrer()

        return relai

    def ouvrir_route_millegrille(self, commande):
        """
        Tente de trouver une route vers une MilleGrille distante
        Utilise les relais deja connectes si applicable, sinon tente d'ouvrir une connexion vers de nouveaux relais
        """
        idmg = commande[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]
        route_existante = self.__route_tiers.get(idmg)
        if route_existante is None:
            # Creer une nouvelle connexion. La classe va s'occuper d'etablir une connexion si c'est possible.
            connexion = ConnexionRelaiMilleGrilles(self, idmg)
            self.__route_tiers[idmg] = connexion
            connexion.demarrer()
        else:
            self.__logger.warning("Demande de connexion a %s mais une thread de connexion est deja en cours")
            route_existante.poke()

    def enlever_toutes_connexions(self):
        liste_idmg = list()
        liste_idmg.extend(self.__route_tiers.keys())
        for idmg in liste_idmg:
            self.enlever_connexion(idmg)

    def enlever_connexion(self, idmg):
        connexion = self.__route_tiers.get(idmg)
        if connexion is not None:
            del self.__route_tiers[idmg]
            try:
                connexion.arreter()
            except:
                pass

    def generer_csr(self, properties):
        """
        Generer une cle privee et un csr pour une demande d'inscription
        """
        generateur = GenerateurCertificat(self.contexte.idmg)
        clecert = generateur.preparer_request('Connecteur')

        correlation_cle = str(uuid.uuid4())

        clecert.password = self.__mot_de_passe_cle.encode('utf-8')

        private_file = os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_SECRETS, 'new.' + correlation_cle + '.key.pem')
        with open(private_file, 'wb') as fichier:
            fichier.write(clecert.private_key_bytes)

        csr_string = clecert.csr_bytes.decode('utf-8')

        reponse = {
            ConstantesInterMilleGrilles.LIBELLE_CSR: csr_string,
            ConstantesInterMilleGrilles.LIBELLE_CORRELATION: correlation_cle,
        }

        reply_q = properties.reply_to
        correlation_id = properties.correlation_id
        self.contexte.generateur_transactions.transmettre_reponse(reponse, reply_q, correlation_id)


class TraitementMessageQueueLocale(TraitementMessageCallback):

    def __init__(self, connecteur: ConnecteurInterMilleGrilles, message_dao, configuration):
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

        elif exchange == Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS:
            if routing_key == 'requete.' + ConstantesInterMilleGrilles.REQUETE_GENERER_CSR:
                self.__connecteur.generer_csr(properties)


class ConfigurationRelai:
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
        self._vhost = None
        self._cafile = None

        self._keyfile = os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_SECRETS, self.idmg+'.key.pem')
        self._certfile = os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_CERTS, self.idmg+'.cert.pem')

        self._parse_host()
        self._extraire_cafile()
        self.__identifier_certs()

    def _parse_host(self):
        """
        Separer les entree de host prives amqps en hostname,
        """
        hosts = self._fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_LIENS_PRIVES_MQ]
        host = hosts[0]
        url_split = host.split('/')
        hostname_port = url_split[2].split(':')
        self._host = hostname_port[0]
        self._port = hostname_port[1]
        if len(url_split) > 3:
            self._vhost = url_split[3]

    def _extraire_cafile(self):
        """
        Extraire le CA file pour la millegrille distante (et valide le IDMG).
        """
        cert_ca_pem = self._fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_RACINE]

        # Valider le certificat, il faut s'assurer que le fingerprint=IDMG
        clecert_ca = EnveloppeCleCert()
        clecert_ca.cert_from_pem_bytes(cert_bytes=cert_ca_pem.encode('utf-8'))
        fingerprint = clecert_ca.fingerprint_base58

        if fingerprint != self._idmg:
            self.__logger.error("Fingerprint %s du certificat CA ne correspond pas a IDMG %s" % (fingerprint, self._idmg))
        #     raise Exception("Fingerprint %s du certificat CA ne correspond pas a IDMG %s" % (fingerprint, self._idmg))

        # Sauvegarder le ca localement
        tmp_file_ca = os.path.join(self._repertoire_interca, self._idmg + '.cert.pem')
        self._cafile = tmp_file_ca
        try:
            with open(tmp_file_ca, 'w') as fichier:
                fichier.write(cert_ca_pem)
        except Exception:
            self.__logger.exception("Erreur excriture cert CA pour idmg=%s" % self._idmg)

    def __identifier_certs(self):
        self._keyfile = self._fiche_privee.get(Constantes.CONFIG_MQ_KEYFILE)
        if self._keyfile is None:
            self._keyfile = os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_SECRETS, self.idmg+'.key.pem')

        self._certfile = self._fiche_privee.get(Constantes.CONFIG_MQ_CERTFILE)
        if self.mq_certfile is None:
            self._certfile = os.path.join(ConstantesInterMilleGrilles.REPERTOIRE_CERTS, self.idmg+'.cert.pem')

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
    def mq_virtual_host(self):
        return self._vhost

    @property
    def mq_cafile(self):
        return self._cafile

    @property
    def mq_ssl(self):
        return "on"

    @property
    def mq_auth_cert(self):
        return "on"


class ConnexionRelaiMilleGrilles:
    """
    Represente une connexion avec un relai prive.
    """

    def __init__(self, connecteur: ConnecteurInterMilleGrilles, configuration):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__connecteur = connecteur
        self.__configuration_relai = configuration
        self.__idmg = configuration.idmg

        # self.__idmg = idmg  # IDMG de la connexion (millegrille distante)
        self.__thread = Thread(name="Relai-" + self.__idmg, target=self.executer, daemon=True)

        # Connexions MQ au relai dans les 2 directions
        self.__connexion_mq_amont_distante = None
        self.__connexion_mq_aval_distante = None
        self.__ctag_amont_distant = None
        self.__traitement_tiers_vers_local = None

        # Temps d'inactivite apres lequel on ferme la connexion
        self.__temps_inactivite_secs = datetime.timedelta(seconds=300)
        self.__derniere_activite = datetime.datetime.utcnow()

        self.__connexion_event = Event()
        self.__stop_event = Event()

        self.__fiche_privee_relai = None
        self.__nom_q_distante = 'inter.' + self.connecteur.contexte.idmg  # Q pour MilleGrille locale

    def demarrer(self):
        self.__logger.info("Demarrage thread connexion a relai " + self.__idmg)
        self.__thread.start()

    def executer(self):
        self.__logger.info("Execution thread connexion a relai " + self.__idmg)

        try:
            # self.charger_configuration_tiers()

            self.__logger.info("Connexion amont locale %s prete, demarrage connexions distantes" % self.__idmg)

            self.connecter_mq_distant()  # Methode blocking (barrier)
            self.__connexion_event.wait(10)  # Attendre que la Q en amont distante soit prete
            if not self.__connexion_event.is_set():
                raise Exception('Erreur connexion relai %s, q en amont distante pas prete' % self.__idmg)

            while not self.__stop_event.is_set():
                self.__stop_event.wait(10)

        finally:
            self._fermeture()

        self.__logger.info("Fin execution thread connexion a " + self.__idmg)

    def arreter(self):
        self.__stop_event.set()
        self.__connexion_event.set()

    def _fermeture(self):
        self.__logger.info("Fermeture connexion idmg %s" % self.__idmg)
        self.__connecteur.enlever_connexion(self.__idmg)
        self.__connecteur.contexte.message_dao.enlever_channel_listener(self)

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
            self.__fiche_privee_relai = json.load(fichier)
        self.__configuration_relai = ConfigurationRelai(
            self.__fiche_privee_relai, self.connecteur.interca_dir)

    def connecter_mq_distant(self):
        """
        Se connecte a la MilleGrille distante avec le certificat approprie
        """
        self.__connexion_mq_aval_distante = ConnexionWrapper(self.__configuration_relai, self.__stop_event)
        self.__connexion_mq_amont_distante = ConnexionWrapper(self.__configuration_relai, self.__stop_event)

        # Ouvrir les connexions, donner 20 secondes max avant d'abandonner
        barrier = Barrier(3)
        self.__connexion_mq_aval_distante.connecter(barrier)
        self.__connexion_mq_amont_distante.connecter(barrier)
        barrier.wait(20)
        if barrier.broken:
            raise Exception("Erreur connexion a MQ distant")

        self.__traitement_tiers_vers_local = TraitementMessageTiersVersLocal(self)

        # Creer et enregistrer un listener d'evenements en amont - sert a ouvrir un Q pour la millegrille locale
        listener_distant = ListenerDistant()
        listener_distant.on_channel_open = self.on_channel_amont_distant_open
        listener_distant.on_channel_close = self.on_channel_amont_distant_close
        self.__connexion_mq_amont_distante.register_channel_listener(listener_distant)

    def on_channel_amont_distant_open(self, channel):
        self.__logger.info("MQ Channel distant ouvert pour %s" % self.idmg)
        self.__channel_amont_distant = channel
        self.definir_q_distante()

    def definir_q_distante(self):
        """
        Tente d'ouvrir une Q exclusive locale au nom de la MilleGrille distante.
        """
        # Creer la Q sur la connexion en aval
        self.__channel_amont_distant.queue_declare(
            queue=self.__nom_q_distante,
            durable=False,
            exclusive=True,
            callback=self.creer_bindings_distant,
        )

    def on_channel_amont_distant_close(self, channel=None, code=None, reason=None):
        self.__logger.info("MQ Channel distant ferme pour %s" % self.idmg)

    def transmettre_message_vers_local(self, dict_message, routing_key, reply_to=None, correlation_id=None):
        self.__connecteur.contexte.message_dao.recevoir_message_intermillegrilles(
            dict_message, routing_key, idmg_origine=self.__idmg, reply_to=reply_to, correlation_id=correlation_id)

    def transmettre_message_exchdefault_vers_local(self, dict_message, method, properties):
        """
        Recevoir une reponse inter-millegrilles.
        Le correlation id contient la reply_q et le correlation_id local.
        """
        reply_q = properties.reply_to
        correlation_id = properties.correlation_id

        if correlation_id.startswith('inter:'):
            # On a une reponse
            params_reponse = correlation_id.split(':')[1].split('/')
            replying_to = params_reponse[0]
            correlation_id_local = params_reponse[1]

            self.__connecteur.contexte.message_dao.transmettre_reponse(
                dict_message, replying_to, correlation_id_local,
            )
        elif reply_q is not None:
            # On a une requete, on passe combine reply_q/correlation_id et on passe sur l'echange prive local
            routing_key = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
            correlation_id_distant = 'inter:' + reply_q + '/' + correlation_id
            self.__connecteur.contexte.message_dao.recevoir_message_intermillegrilles(
                dict_message, routing_key, idmg_origine=self.__idmg, reply_to=self.__nom_q_distante, correlation_id=correlation_id_distant)
        else:
            raise Exception("Un a un message sur exchange defaut non routable via inter-MilleGrilles")

    def creer_bindings_distant(self, queue):
        """
        Prepare les bindings sur la MilleGrille distante (e.g. les abonnements)
        """
        self.__logger.info("Ouverture Q distante avec %s: %s" % (self.__idmg, str(queue)))

        self.__channel_amont_distant.queue_bind(
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_PRIVE,
            queue=self.__nom_q_distante,
            routing_key=ConstantesInterMilleGrilles.ROUTING_KEY_NOTICES_INTER,
            callback=None
        )

        self.__ctag_amont_distant = self.__channel_amont_distant.basic_consume(
            self.__traitement_tiers_vers_local.callbackAvecAck,
            queue=self.__nom_q_distante,
            no_ack=False
        )

        # La connexion est prete
        self.__connexion_event.set()

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


class ListenerDistant:
    """
    Helper pour messages callbacks RabbitMQ
    """

    def __init__(self):
        self.on_channel_open = None
        self.on_channel_close = None


class RouteMilleGrilleTiers:
    """
    Lien entre la MilleGrille locale (Q locale) et une MilleGrilles distante (tiers, Q sur relai)
    """

    def __init__(self, connecteur: ConnecteurInterMilleGrilles, idmg: str):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.connecteur = connecteur
        self.__idmg = idmg

        self.__traitement_local_vers_tiers = TraitementMessageLocalVersTiers(
            self, connecteur.contexte.message_dao, connecteur.contexte.configuration)

        self.__traitement_tiers_vers_local = None

        # Ouvrir un nouveau canal en amont local
        # Necessaire en partie parce que la verification de Q exclusive ferme le canal si la
        # Q existe deja (e.g. ouverte par MG tierce)
        self.__nom_q_locale = 'inter.' + idmg  # IDMG distant sur MQ local
        self.__channel_amont_local = None
        self.__ctag_amont_local = None

        # Information de connexion
        self.__fiche_privee_tiers = None
        self.__configuration_connexion = None

        # Connexions distantes en amont et aval
        self.__nom_q_distante = 'inter.' + self.connecteur.contexte.idmg  # IDMG local sur MQ distant
        self.__channel_amont_distant = None
        self.__ctag_amont_distant = None

    def poke(self):
        self.__logger.warning("On vient de se faire poker (idmg: %s)" % self.__idmg)

    def transmettre_message_prive_vers_distant(self, dict_message, routing_key=None, reply_q=None, correlation_id=None):
        properties = pika.BasicProperties(delivery_mode=1)

        properties.reply_to = 'inter.' + self.connecteur.contexte.idmg  # Q de reponse inter pour local

        if reply_q is not None:
            self.__logger.debug("On modifie le message de requete pour permettre une reponse inter-millegrilles")
            properties.correlation_id = reply_q + '/' + correlation_id
        else:
            properties.correlation_id = correlation_id

        properties.headers = {
            'inter': 'true',
            'origine': self.connecteur.contexte.idmg,
        }

        message_utf8 = self.connecteur.json_helper.dict_vers_json(dict_message, encoding=json.JSONEncoder)
        channel_publisher = self.__connexion_mq_aval_distante.channel
        channel_publisher.basic_publish(
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_PRIVE,  # Exchange prive pour message inter
            routing_key=routing_key,
            body=message_utf8,
            properties=properties,
            mandatory=True)

        # Utiliser pubdog pour la connexion publishing par defaut
        self.__connexion_mq_aval_distante.publish_watch()

    def transmettre_message_exchdefault_vers_distant(self, dict_message, reply_q=None, correlation_id=None):
        properties = pika.BasicProperties(delivery_mode=1)

        # Q de reponse inter pour MilleGrille local
        properties.reply_to = 'inter.' + self.connecteur.contexte.idmg

        properties.headers = {
            'inter': 'true',
            'origine': self.connecteur.contexte.idmg,
        }

        message_utf8 = self.connecteur.json_helper.dict_vers_json(dict_message, encoding=json.JSONEncoder)
        channel_publisher = self.__connexion_mq_aval_distante.channel

        if correlation_id.startswith('inter:'):
            self.__logger.debug("Message default transmis vers distant, correlation a splitter: %s" % correlation_id)
            exchange = ''  # Exchange par defaut
            correlation_id_path = correlation_id.split(':')[1].split('/')
            routing_key = correlation_id_path[0]
            properties.correlation_id = correlation_id_path[1]
        elif reply_q is not None:
            # On a une requete, on combine reply_q/correlation_id
            exchange = Constantes.DEFAUT_MQ_EXCHANGE_PRIVE
            properties.correlation_id = 'inter:' + reply_q + '/' + correlation_id
            routing_key = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        else:
            raise Exception("Message sur exchange par defaut non routable par inter-MilleGrilles")

        self.__logger.debug("Message inter-millegrilles, correlation: %s, routing: %s" % (properties.correlation_id, routing_key))

        channel_publisher.basic_publish(
            exchange=exchange,
            routing_key=routing_key,
            body=message_utf8,
            properties=properties,
            mandatory=True)

        # Utiliser pubdog pour la connexion publishing par defaut
        self.__connexion_mq_aval_distante.publish_watch()


class TraitementMessageLocalVersTiers(TraitementMessageCallback):

    def __init__(self, route: RouteMilleGrilleTiers, message_dao, configuration):
        super().__init__(message_dao, configuration)
        self.__route = route
        self.__logger = logging.getLogger(__name__+'.'+self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        """
        S'occupe de la reception d'un message en amont a transferer vers la millegrille designee.
        """
        routing_key = method.routing_key
        exchange = method.exchange
        dict_message = json.loads(body)

        self.__logger.debug("%s: Message inter-millegrilles recue sur echange '%s' : %s, contenu %s" % (
            self.__route.idmg, exchange, routing_key, body.decode('utf-8')))

        if exchange == Constantes.DEFAUT_MQ_EXCHANGE_PRIVE:
            if properties.headers is None or properties.headers.get('inter') != 'true':
                self.__logger.debug("Message en amont sur exchange prive local, on le passe a la millegrille distante")
                self.transferer_message_echange_prive(dict_message, method, properties)
            else:
                self.__logger.debug("Message inter deja transmis, on l'ignore (pour eviter boucles")
        elif exchange == '':  # Echange direct
            self.__logger.debug("Message sur exchange direct local")
            self.transferer_message_direct(dict_message, method, properties)
        else:
            raise Exception("Message non traitable")

    def transferer_message_direct(self, dict_message, method, properties):
        self.__connexion.transmettre_message_exchdefault_vers_distant(dict_message, properties.reply_to,
                                                                      properties.correlation_id)

    def transferer_message_echange_prive(self, dict_message, method, properties):
        self.__logger.debug("Message echange prive local. Method: %s, properties: %s" % (str(method), str(properties)))
        if properties.headers is None or properties.headers.get('inter') != 'true':
            self.__connexion.transmettre_message_prive_vers_distant(dict_message, method.routing_key, properties.reply_to, properties.correlation_id)
        else:
            self.__logger.debug("Message inter deja transmis, on l'ignore (pour eviter boucles")


class TraitementMessageTiersVersLocal:

    def __init__(self, connexion: ConnexionRelaiMilleGrilles):
        self.__connexion = connexion
        self.__json_helper = JSONHelper()
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def callbackAvecAck(self, ch, method, properties, body):
        try:
            self.traiter_message(ch, method, properties, body)
        except CertificatInconnu as ci:
            fingerprint = ci.fingerprint
            self.__logger.warning("Certificat inconnu, on fait la demande %s" % fingerprint)
            pass  # A FAIRE
        except Exception as e:
            self.__logger.exception("Erreur dans TraitementMessageTiersVersLocal, exception: %s" % str(e))
            self.transmettre_erreur(ch, method, body, e)
        finally:
            self.transmettre_ack(ch, method)

    def transmettre_ack(self, ch, method):
        try:
            ch.basic_ack(delivery_tag=method.delivery_tag)
        except AttributeError:
            self.__logger.exception("Erreur transmission ACK")

    def transmettre_erreur(self, ch, method, body, erreur):
        message = {
            "message_original": str(body)
        }
        if erreur is not None:
            message["erreur"] = str(erreur)
            message["stacktrace"] = traceback.format_exception(etype=type(erreur), value=erreur,
                                                               tb=erreur.__traceback__)

        message_utf8 = self.__json_helper.dict_vers_json(message)

        ch.basic_publish(exchange=method.exchange,
                         routing_key='processus.erreur',
                         body=message_utf8)

    def decoder_message_json(self, body):
        return self.__json_helper.bin_utf8_json_vers_dict(body)

    @property
    def json_helper(self):
        return self.__json_helper

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
            # Verifier si le message a deja ete transfere
            if properties.headers is None or properties.headers.get('inter') != 'true':
                self.__logger.debug("Message en amont sur exchange prive distant, on le passe a la millegrille locale")
                self.__connexion.transmettre_message_vers_local(
                    dict_message, routing_key, reply_to=properties.reply_to, correlation_id=properties.correlation_id)
            else:
                self.__logger.debug("Message inter deja transmis, on l'ignore (pour eviter boucles")
        elif exchange == '':  # Echange direct
            self.__logger.debug("Message sur exchange distant")
            self.__connexion.transmettre_message_exchdefault_vers_local(dict_message, method, properties)
        else:
            raise Exception("Message non traitable")
