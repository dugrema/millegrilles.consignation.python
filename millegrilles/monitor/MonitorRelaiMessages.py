import datetime
import json
import logging
import os
import tempfile
from base64 import b64decode
from os import path
from threading import Thread, Event
from typing import cast

import docker
from pymongo.errors import ServerSelectionTimeoutError, DuplicateKeyError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.SecuritePKI import GestionnaireEvenementsCertificat
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles, TransactionConfiguration
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificats
from millegrilles.monitor.MonitorComptes import GestionnaireComptesMongo, GestionnaireComptesMQ
# from millegrilles.monitor.ServiceMonitor import ServiceMonitorDependant, GestionnaireModulesDocker
from millegrilles.monitor.MonitorCommandes import CommandeMonitor, GestionnaireCommandes
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat, PemHelpers, EnveloppeCleCert
from millegrilles.monitor import MonitorConstantes


class TraitementMessagesMiddleware(BaseCallback):

    def __init__(self, noeud_id: str, gestionnaire_commandes, contexte):
        super().__init__(contexte)
        self._noeud_id = noeud_id
        self.__gestionnaire_commandes = gestionnaire_commandes
        self.__channel = None
        self.queue_name = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.__logger_verbose = logging.getLogger('trace.%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        exchange = method.exchange

        self.__logger_verbose.debug("Message recu : %s" % message_dict)

        if routing_key.startswith('commande.'):
            action = routing_key.split('.')[-1]
            contenu = {
                'commande': action,
                'exchange': exchange,
                'properties': properties,
            }
            contenu.update(message_dict)
            commande = CommandeMonitor(contenu=contenu, mq_properties=properties, message=message_dict)
            self.__gestionnaire_commandes.ajouter_commande(commande)
        elif routing_key == Constantes.EVENEMENT_ROUTING_PRESENCE_DOMAINES:
            self.traiter_presence_domaine(message_dict)
        elif correlation_id == ConstantesServiceMonitor.CORRELATION_HEBERGEMENT_LISTE:
            self.__gestionnaire_commandes.traiter_reponse_hebergement(message_dict)
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

        routing_keys = [
            'commande.servicemonitor.%s.#' % self._noeud_id,
            'evenement.presence.domaine',
            'commande.servicemonitor.' + ConstantesServiceMonitor.COMMANDE_AJOUTER_COMPTE,
            'commande.servicemonitor.' + ConstantesServiceMonitor.COMMANDE_TRANSMETTRE_CATALOGUES,
            'commande.servicemonitor.' + ConstantesServiceMonitor.COMMANDE_SIGNER_NAVIGATEUR,
            'commande.servicemonitor.' + ConstantesServiceMonitor.COMMANDE_SIGNER_NOEUD,

            # Backup
            Constantes.ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_SNAPSHOT.replace('_DOMAINE_', 'global'),
            Constantes.ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL,
            'commande.servicemonitor.' + ConstantesServiceMonitor.COMMANDE_BACKUP_APPLICATION,
        ]

        # Ajouter les routing keys
        for routing_key in routing_keys:
            self.__channel.queue_bind(
                exchange=self.configuration.exchange_defaut,
                queue=self.queue_name,
                routing_key=routing_key,
                callback=None
            )

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.queue_name = None

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed

    def traiter_presence_domaine(self, message_dict):
        domaine = message_dict['domaine']
        exchanges_routing = message_dict['exchanges_routing']
        self.__logger_verbose.debug("Presence domaine %s detectee : %s", domaine, str(message_dict))
        self.__gestionnaire_commandes.inscrire_domaine(domaine, exchanges_routing)


class TransfertMessages(BaseCallback):
    """
    Recoit des messages sur une Q source et les transfere vers une Q destination (semblable a shovel MQ)
    Met un header sur le message transmis pour permettre d'empecher un retour
    """

    LOCAL_Q_PLACEHOLDER = '**local**'

    def __init__(self, contexte, fonction_relai, nom_noeud):
        super().__init__(contexte)
        self.__fonction_relai = fonction_relai
        self.__nom_noeud = nom_noeud

        self.__channel = None
        self.queue_name = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        reply_to = properties.reply_to
        exchange = method.exchange

        # S'assurer que le message ne vient pas de ce noeud (si on est l'emetteur)
        if properties.headers:
            headers = properties.headers
            if headers['noeud_source'] == self.__nom_noeud:
                # Ne pas traiter le message, il a ete emis par ce noeud
                return

        # Determiner si on a un message route ou une reponse
        if routing_key == self.queue_name:
            # C'est une reponse, on depile la reply_to queue de correlation
            corr_split = correlation_id.split(':')
            routing_key = corr_split[0]
            correlation_id = ':'.join(corr_split[1:])
            reply_to = None
        elif reply_to:
            # C'est un message route, on empile la reply_to queue sur correlation
            # et on indique de repondre a notre Q distante
            correlation_id = reply_to + ':' + correlation_id
            reply_to = TransfertMessages.LOCAL_Q_PLACEHOLDER

        self.__logger.debug("Relayer message %s : %s" % (routing_key, message_dict))
        self.__fonction_relai(message_dict, routing_key, exchange, reply_to, correlation_id)

    def on_channel_open(self, channel):
        self.__channel = channel
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=50)

        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        self.__channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.queue_name = None

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed

    def ajouter_domaine(self, nom_domaine: str, exchanges_routing: dict):
        if not self.__channel:
            self.__logger.warning("ServiceMonitor transfert non pret, domaine %s pas ajoute", nom_domaine)
            return

        routing_a_exclure = [
            'erreur',
        ]

        for exchange, routing_keys in exchanges_routing.items():
            for routing_key in routing_keys:
                if routing_key not in routing_a_exclure:
                    self.__channel.queue_bind(
                        exchange=exchange,
                        queue=self.queue_name,
                        routing_key=routing_key,
                        callback=None
                    )


class ConnexionPrincipal:
    """
    Connexion au noeud protege principal
    """

    # def __init__(self, client_docker: docker.DockerClient, service_monitor: ServiceMonitorDependant):
    def __init__(self, client_docker: docker.DockerClient, service_monitor):
        self.__docker = client_docker
        self.__service_monitor = service_monitor

        self.__contexte: ContexteRessourcesMilleGrilles = cast(ContexteRessourcesMilleGrilles, None)
        self.__traitement_messages_principal: TraitementMessagesConnexionPrincipale = cast(TraitementMessagesConnexionPrincipale, None)
        self.__transfert_messages_principal: TransfertMessages = cast(TransfertMessages, None)

    def connecter(self):
        gestionnaire_docker = self.__service_monitor.gestionnaire_docker
        config_connexion_docker = gestionnaire_docker.charger_config_recente('millegrille.connexion')['config']
        config_connexion = json.loads(b64decode(config_connexion_docker.attrs['Spec']['Data']))
        # clecert_monitor = self.__service_monitor.clc

        gestionnaire_certificats = self.__service_monitor.gestionnaire_certificats
        certificats = gestionnaire_certificats.certificats
        path_secrets = gestionnaire_certificats.secret_path
        ca_certs_file = certificats['pki.millegrille.cert']
        monitor_cert_file = certificats['pki.%s.cert' % ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT]
        monitor_key_file = path.join(path_secrets, ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_DEPENDANT_KEY + '.pem')

        node_name = config_connexion['principal_mq_url']

        additionnals = [{
            'MG_MQ_HOST': node_name,
            'MG_MQ_PORT': 5673,
            'MG_MQ_CA_CERTS': ca_certs_file,
            'MG_MQ_CERTFILE': monitor_cert_file,
            'MG_MQ_KEYFILE': monitor_key_file,
            'MG_MQ_SSL': 'on',
            'MG_MQ_AUTH_CERT': 'on',
        }]

        configuration = TransactionConfiguration()
        self.__contexte = ContexteRessourcesMilleGrilles(configuration=configuration, additionals=additionnals)

        # Connecter a MQ du noeud principal
        self.__contexte.initialiser(init_message=True, connecter=True)

        self.__traitement_messages_principal = TraitementMessagesConnexionPrincipale(self.__service_monitor, self.__contexte)
        self.__contexte.message_dao.register_channel_listener(self.__traitement_messages_principal)

    def initialiser_relai_messages(self, fonction_relai):
        self.__transfert_messages_principal = TransfertMessages(
            self.__contexte, fonction_relai, self.__service_monitor.nodename)
        self.__contexte.message_dao.register_channel_listener(self.__transfert_messages_principal)

    def relayer_message(self, message_dict, routing_key, exchange, reply_to=None, correlation_id=None):
        """
        Relai un message recu vers le noeud principal

        :param message_dict:
        :param routing_key:
        :param exchange:
        :param reply_to:
        :param correlation_id:
        :return:
        """
        headers = {'noeud_source': self.__service_monitor.nodename}
        if reply_to == TransfertMessages.LOCAL_Q_PLACEHOLDER:
            # Mettre la queue de relai cote principal pour recevoir la reponse
            reply_to = self.__transfert_messages_principal.queue_name
        self.generateur_transactions.emettre_message(message_dict, routing_key, [exchange], reply_to, correlation_id, headers)

    @property
    def reply_q(self):
        return self.__traitement_messages_principal.queue_name

    @property
    def generateur_transactions(self):
        return self.__contexte.generateur_transactions

    def enregistrer_domaine(self, nom_domaine: str, exchanges_routing: dict):
        self.__transfert_messages_principal.ajouter_domaine(nom_domaine, exchanges_routing)


class TraitementMessagesConnexionPrincipale(BaseCallback):
    """
    Traitement des messages vus sur une connexion principale pour un noeud dependant, prive, etc.
    """

    # def __init__(self, service_monitor: ServiceMonitorDependant, contexte: ContexteRessourcesMilleGrilles):
    def __init__(self, service_monitor, contexte: ContexteRessourcesMilleGrilles):
        super().__init__(contexte)
        self._service_monitor = service_monitor
        self.__channel = None
        self.queue_name = None

        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.__logger_verbose = logging.getLogger('trace.%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key
        correlation_id = properties.correlation_id
        exchange = method.exchange

        # self.__logger.debug("Message recu : %s" % message_dict)

        if routing_key == Constantes.EVENEMENT_ROUTING_PRESENCE_DOMAINES:
            self.traiter_presence_domaine(message_dict)
        elif correlation_id == ConstantesServiceMonitor.CORRELATION_CERTIFICAT_SIGNE:
            self._service_monitor.gestionnaire_certificats.recevoir_certificat(message_dict)
        else:
            raise ValueError("Type message inconnu", correlation_id, routing_key)

    def on_channel_open(self, channel):
        self.__channel = channel
        channel.add_on_close_callback(self.__on_channel_close)
        channel.basic_qos(prefetch_count=1)

        queue_name = 'dependant.' + self._service_monitor.nodename + '.monitor'

        channel.queue_declare(queue=queue_name, durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        self.__channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)

        # Ajouter les routing keys
        routing_keys = [
            Constantes.EVENEMENT_ROUTING_PRESENCE_DOMAINES,
            'commande.servicemonitordependant.#',
            'commande.servicemonitor.activerHebergement',
            'commande.servicemonitor.desactiverHebergement',
            'commande.servicemonitor.' + ConstantesServiceMonitor.COMMANDE_TRANSMETTRE_CATALOGUES,
        ]

        for key in routing_keys:
            self.__channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=self.queue_name,
                routing_key=key,
                callback=None
            )

    def __on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.queue_name = None

    def is_channel_open(self):
        return self.__channel is not None and not self.__channel.is_closed

    def traiter_presence_domaine(self, message_dict):
        domaine = message_dict['domaine']
        exchanges_routing = message_dict['exchanges_routing']
        self.__logger_verbose.debug("Presence domaine %s detectee : %s", domaine, str(message_dict))
        self._service_monitor.inscrire_domaine(domaine, exchanges_routing)

    # def enregistrer_domaine(self, nom_domaine: str, exchanges_routing: dict):
    #     routing_a_exclure = [
    #         'erreur',
    #     ]
    #
    #     for exchange, routing_keys in exchanges_routing.items():
    #         for routing_key in routing_keys:
    #             if routing_key not in routing_a_exclure:
    #                 self.__channel.queue_bind(
    #                     exchange=exchange,
    #                     queue=self.queue_name,
    #                     routing_key=routing_key,
    #                     callback=None
    #                 )


class ConnexionMiddleware:
    """
    Connexion au middleware de la MilleGrille en service.
    """

    def __init__(self, configuration: TransactionConfiguration, client_docker: docker.DockerClient,
                 service_monitor, certificats: dict, **kwargs):
        self._configuration = configuration
        self._docker = client_docker
        self._service_monitor = service_monitor
        self._certificats = certificats

        self._path_secrets: str = kwargs.get('secrets') or '/run/secrets'
        self._monitor_keycert_file: str

        self._connexion_relai: ConnexionPrincipal = cast(ConnexionPrincipal, None)

        self._contexte: ContexteRessourcesDocumentsMilleGrilles = cast(ContexteRessourcesDocumentsMilleGrilles, None)
        self._thread: Thread = cast(Thread, None)
        self._channel = None

        self._fermeture_event = Event()

        self._certificat_event_handler: GestionnaireEvenementsCertificat
        self.__commandes_handler: TraitementMessagesMiddleware = cast(TraitementMessagesMiddleware, None)
        self.__transfert_local_handler: TransfertMessages = cast(TransfertMessages, None)

        self.__monitor_cert_file: str

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self._comptes_middleware_ok = False
        self._comptes_mq_ok = False
        self._prochaine_verification_comptes_noeuds = datetime.datetime.utcnow().timestamp()
        self._gestionnaire_mdns = kwargs.get('gestionnaire_mdns')

    def start(self):
        self.__logger.info("Demarrage ConnexionMiddleware")
        # Connecter

        # Demarrer thread
        self._thread = Thread(target=self.run, name="mw", daemon=True)
        self._thread.start()

    def stop(self):
        self._fermeture_event.set()

        try:
            self._contexte.message_dao.deconnecter()
            self._contexte.document_dao.deconnecter()
        except Exception:
            pass

    def initialiser(self, init_document=True):
        additionnals = self._contexte_additionnals()
        self._contexte = ContexteRessourcesDocumentsMilleGrilles(
            configuration=self._configuration, additionals=additionnals)

        try:
            self._contexte.initialiser(
                init_document=init_document,
                init_message=True,
                connecter=True,
            )
        except ServerSelectionTimeoutError:
            self.__logger.warning("Erreur connexion mongo, ServerSelectionTimeoutError")
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Detail error connexion Mongo")

        self._certificat_event_handler = GestionnaireEvenementsCertificat(self._contexte)
        self.__commandes_handler = TraitementMessagesMiddleware(self._service_monitor.noeud_id, self._service_monitor.gestionnaire_commandes, self._contexte)

        self._contexte.message_dao.register_channel_listener(self)
        self._contexte.message_dao.register_channel_listener(self.__commandes_handler)

    def _contexte_additionnals(self) -> list:
        ca_certs_file = self._certificats['pki.millegrille.cert']
        monitor_cert_file = self._certificats[GestionnaireCertificats.MONITOR_CERT_PATH]
        monitor_key_file = path.join(self._path_secrets, self._certificats[GestionnaireCertificats.MONITOR_KEY_FILE])

        mq_info = self.get_mq_info()
        self.__logger.info("Information de connexion MQ : %s" % str(mq_info))

        additionnals = [{
            'MG_MQ_HOST': mq_info['host'],
            'MG_MQ_PORT': mq_info['port'],
            'MG_MQ_CA_CERTS': ca_certs_file,
            'MG_MQ_CERTFILE': monitor_cert_file,
            'MG_MQ_KEYFILE': monitor_key_file,
            'MG_MQ_SSL': 'on',
            'MG_MQ_AUTH_CERT': 'on',
        }]

        return additionnals

    def get_mq_info(self):
        self.__logger.debug("Demande services mdns pour idmg %s" % self._service_monitor.idmg)

        try:
            services = self._service_monitor.gestionnaire_commandes.requete_mdns_acteur(self._service_monitor.idmg)
        except Exception:
            self.__logger.warning("Erreur acces MDNS pour host MQ, tentative utilisation host/port env")
            host = self.configuration.mq_host
            port = self.configuration.mq_port
        else:
            self.__logger.debug("Services MDNS detectes : %d" % len(services))
            for service in services:
                self.__logger.debug("Service %s port %d, addresses : %s" % (service['type'], service['port'], str(service['addresses'])))

            services_mq = [s for s in services if s.get('type') == '_mgamqps._tcp.local.']
            self.__logger.debug("Services MDNS MQ detectes : %d" % len(services))
            for service_mq in services_mq:
                self.__logger.debug("Service %s port %d, addresses : %s" % (service_mq['type'], service_mq['port'], str(service_mq['addresses'])))

            try:
                service_retenu = services_mq[0]
                host = service_retenu['addresses'][0]
                port = service_retenu['port']
            except IndexError:
                # Utiliser configuration fourni
                self.__logger.info("Information MDNS non disponible, fallback sur configuration environnement")
                host = self.configuration.mq_host
                port = self.configuration.mq_port

        info_mq = {'host': host, 'port': port}
        self.__logger.info("Service MDNS MQ detecte : %s" % str(info_mq))

        return info_mq

    def set_relai(self, connexion_relai: ConnexionPrincipal):
        if not self.__transfert_local_handler:
            self.__transfert_local_handler = TransfertMessages(
                self._contexte, connexion_relai.relayer_message, self._service_monitor.nodename)
            self._contexte.message_dao.register_channel_listener(self.__transfert_local_handler)

    def relayer_message(self, message_dict, routing_key, exchange, reply_to=None, correlation_id=None):
        """
        Relai un message recu sur le noeud principal vers le noeud dependant.

        :param message_dict:
        :param routing_key:
        :param exchange:
        :param reply_to:
        :param correlation_id:
        :return:
        """
        headers = {'noeud_source': self._service_monitor.nodename}

        if reply_to == TransfertMessages.LOCAL_Q_PLACEHOLDER:
            # Ajouter la Q de transfert locale pour recevoir la reponse a relayer
            reply_to = self.__transfert_local_handler.queue_name

        self.generateur_transactions.emettre_message(message_dict, routing_key, [exchange], reply_to, correlation_id, headers)

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self._channel = channel
        self._certificat_event_handler.initialiser()

    def on_channel_close(self, channel=None, code=None, reason=None):
        self._channel = None
        self.__logger.warning("MQ Channel ferme")
        if not self._fermeture_event.is_set():
            try:
                self._contexte.message_dao.enter_error_state()
            except Exception:
                # Erreur d'activation du error state, la connexion ne peut pas etre reactivee
                self.__logger.exception("Erreur fermeture channel")
                self._fermeture_event.set()  # S'assurer que la fermeture est en cours

    def __on_return(self, channel, method, properties, body):
        pass

    def run(self):
        self.__logger.info("Thread middleware demarree")

        while not self._fermeture_event.is_set():
            try:
                self.__entretien_comptes()
                self._entretien()
            except Exception:
                self.__logger.exception("Exception generique")
            finally:
                self._fermeture_event.wait(30)

        self.__logger.info("Fin thread middleware")

    def __entretien_comptes(self):

        if not self._comptes_middleware_ok or not self._comptes_mq_ok:
            comptes_mq_ok = True  # Va etre mis a false si un compte n'esp pas ajoute correctement
            try:
                idmg = self._configuration.idmg
                igmd_tronque = idmg[0:12]
                roles_comptes = [info['role'] for info in MonitorConstantes.DICT_MODULES_PROTEGES.values() if info.get('role')]
                roles_comptes = ['%s.pki.%s.cert' % (igmd_tronque, role) for role in roles_comptes]

                roles_mongo = [
                    ConstantesGenerateurCertificat.ROLE_TRANSACTIONS,
                    ConstantesGenerateurCertificat.ROLE_DOMAINES,
                    ConstantesGenerateurCertificat.ROLE_MAITREDESCLES,
                ]
                for role in roles_comptes:
                    filtre = {'name': role}
                    configs = self._docker.configs.list(filters=filtre)

                    if len(configs) > 0:
                        dict_configs = dict()
                        for config in configs:
                            dict_configs[config.name] = config

                        # Choisir plus recent certificat
                        liste_configs_str = list(dict_configs.keys())
                        liste_configs_str.sort()
                        nom_config = liste_configs_str[-1]
                        config_cert = dict_configs[nom_config]

                        # Extraire certificat
                        cert_pem = b64decode(config_cert.attrs['Spec']['Data'])
                        clecert = EnveloppeCleCert()
                        clecert.cert_from_pem_bytes(cert_pem)

                        # Creer compte
                        roles_cert = clecert.get_roles
                        if any([role in roles_mongo for role in roles_cert]):
                            try:
                                self.__mongo.creer_compte(clecert)
                            except DuplicateKeyError:
                                self.__logger.debug("Compte mongo (deja) cree : %s", nom_config)

                        try:
                            gestionnaire_mq: GestionnaireComptesMQ = self._service_monitor.gestionnaire_mq
                            gestionnaire_mq.ajouter_compte(clecert)
                        except ValueError:
                            comptes_mq_ok = False

                self._comptes_middleware_ok = True

            except Exception:
                self.__logger.exception("Erreur enregistrement comptes")

            self._comptes_mq_ok = comptes_mq_ok

    def _entretien(self):
        ts_courant = datetime.datetime.utcnow().timestamp()

        exchange = self.exchange

        # Emettre message de presence du monitor
        self.emettre_presence()

        # Transmettre requete pour avoir l'etat de l'hebergement
        self.generateur_transactions.transmettre_requete(
            dict(), Constantes.ConstantesHebergement.REQUETE_MILLEGRILLES_ACTIVES,
            reply_to=self.__commandes_handler.queue_name,
            correlation_id=ConstantesServiceMonitor.CORRELATION_HEBERGEMENT_LISTE,
            securite=exchange
        )

    def emettre_presence(self):
        info_monitor = dict(self._service_monitor.get_info_monitor(inclure_services=True))
        info_monitor['noeud_id'] = self._service_monitor.noeud_id
        info_monitor['securite'] = self._service_monitor.securite
        domaine_action = Constantes.ConstantesTopologie.EVENEMENT_PRESENCE_MONITOR

        self.generateur_transactions.emettre_message(info_monitor, domaine_action, ajouter_certificats=True)

    def ajouter_commande(self, commande):
        gestionnaire_commandes: GestionnaireCommandes = self._service_monitor.gestionnaire_commandes
        gestionnaire_commandes.ajouter_commande(commande)

    def rediriger_messages_domaine(self, nom_domaine: str, exchanges_routing: dict):
        self.__transfert_local_handler.ajouter_domaine(nom_domaine, exchanges_routing)

    def enregistrer_listener(self, methode_initialisation):
        """
        Initialise un objet/methode avec le contexte et enregistre le listener retourne
        :param methode_initialisation: Methode qui va recevoir contexte, doit retourner l'instance du listener
        :return:
        """
        listener = methode_initialisation(self._contexte)
        self._contexte.message_dao.register_channel_listener(listener)

    @property
    def document_dao(self) -> MongoDAO:
        return self._contexte.document_dao

    @property
    def configuration(self) -> TransactionConfiguration:
        return self._configuration

    @property
    def generateur_transactions(self):
        return self._contexte.generateur_transactions

    @property
    def exchange(self):
        return self._service_monitor.securite

    @property
    def verificateur_transactions(self):
        return self._contexte.verificateur_transaction


class ConnexionMiddlewarePublic(ConnexionMiddleware):
    """
    Connexion au middleware de la MilleGrille en service pour un noeud public
    """

    def __init__(self, configuration: TransactionConfiguration, client_docker: docker.DockerClient,
                 service_monitor, certificats: dict, **kwargs):
        super().__init__(configuration, client_docker, service_monitor, certificats, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initialiser(self, init_document=False):
        super().initialiser(init_document=init_document)

    def _contexte_additionnals(self) -> list:
        additionnals = super()._contexte_additionnals()

        additionnals.append({
            'MG_' + Constantes.CONFIG_MQ_EXCHANGE_DEFAUT.upper(): Constantes.SECURITE_PUBLIC,
        })

        return additionnals


class ConnexionMiddlewarePrive(ConnexionMiddleware):
    """
    Connexion au middleware de la MilleGrille en service pour un noeud prive
    """

    def __init__(self, configuration: TransactionConfiguration, client_docker: docker.DockerClient,
                 service_monitor, certificats: dict, **kwargs):
        super().__init__(configuration, client_docker, service_monitor, certificats, **kwargs)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initialiser(self, init_document=False):
        super().initialiser(init_document=init_document)

    def _contexte_additionnals(self) -> list:
        additionnals = super()._contexte_additionnals()

        additionnals.append({
            'MG_' + Constantes.CONFIG_MQ_EXCHANGE_DEFAUT.upper(): Constantes.SECURITE_PRIVE,
        })

        return additionnals


class ConnexionMiddlewareProtege(ConnexionMiddleware):
    """
    Connexion au middleware de la MilleGrille en service, incluant Mongo (noeud protege)
    """

    def __init__(self, configuration: TransactionConfiguration, client_docker: docker.DockerClient,
                 service_monitor, certificats: dict, **kwargs):
        super().__init__(configuration, client_docker, service_monitor, certificats, **kwargs)

        self.__path_secrets: str = kwargs.get('secrets') or '/run/secrets'
        self.__file_mongo_passwd: str = kwargs.get('mongo_passwd_file') or ConstantesServiceMonitor.FICHIER_MONGO_MOTDEPASSE

        self.__contexte: ContexteRessourcesDocumentsMilleGrilles = cast(ContexteRessourcesDocumentsMilleGrilles, None)

        self.__fermeture_event = Event()

        self.__mongo = GestionnaireComptesMongo(connexion_middleware=self)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__prochaine_verification_comptes_noeuds = datetime.datetime.utcnow().timestamp()

    def initialiser(self, init_document=True):
        super().initialiser(init_document=init_document)

    def _entretien(self):
        self.__mongo.entretien()
        super()._entretien()

    def get_mq_info(self):
        """
        Connexion MQ pour noeud protege - necessairement locale
        :return:
        """
        node_name = self.configuration.mq_host or 'mq'
        return {'host': node_name, 'port': 5673}

    def _contexte_additionnals(self) -> list:
        additionnals = super()._contexte_additionnals()

        ca_certs_file = self._certificats['pki.millegrille.cert']
        monitor_cert_file = self._certificats[GestionnaireCertificats.MONITOR_CERT_PATH]
        monitor_key_file = path.join(self._path_secrets, self._certificats[GestionnaireCertificats.MONITOR_KEY_FILE])

        # Preparer fichier keycert pour mongo
        keycert, monitor_keycert_file = tempfile.mkstemp(dir='/tmp')
        with open(monitor_key_file, 'rb') as fichier:
            os.write(keycert, fichier.read())
        with open(monitor_cert_file, 'rb') as fichier:
            cert_content = fichier.read()
            os.write(keycert, cert_content)
            split_cert = PemHelpers.split_certificats(str(cert_content, 'utf-8'))
        self._monitor_keycert_file = monitor_keycert_file
        os.close(keycert)

        # Creer chaine de certs CA a partir du certificat de monitor (doit inclure cert millegrille)
        ca_certs_content = '\n'.join(split_cert[1:])
        fp, ca_file_mq = tempfile.mkstemp(dir='/tmp')
        os.write(fp, ca_certs_content.encode('utf-8'))
        os.close(fp)

        mongo_passwd_file = path.join(self.__path_secrets, self.__file_mongo_passwd)
        with open(mongo_passwd_file, 'r') as fichier:
            mongo_passwd = fichier.read()

        node_name = self._docker.info()['Name']

        additionnals.append({
            'MG_MONGO_HOST': node_name,
            'MG_MONGO_USERNAME': 'admin',
            'MG_MONGO_PASSWORD': mongo_passwd,
            'MG_MONGO_AUTHSOURCE': 'admin',
            'MG_MONGO_SSL': 'on',
            'MG_MONGO_SSL_CA_CERTS': ca_certs_file,
            'MG_MONGO_SSL_CERTFILE': monitor_keycert_file,
        })

        return additionnals

    @property
    def get_gestionnaire_comptes_mongo(self):
        return self.__mongo

    @property
    def certificat(self):
        return self.__contexte.verificateur_certificats.certificat
