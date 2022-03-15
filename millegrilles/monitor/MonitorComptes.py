import logging
from os import path, environ
from threading import Event
from typing import cast, Union

from cryptography import x509
from pymongo.errors import OperationFailure
from requests.exceptions import ConnectionError, HTTPError, SSLError
from urllib3.exceptions import MaxRetryError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
# from millegrilles.monitor.MonitorRelaiMessages import ConnexionMiddleware
from millegrilles.util.RabbitMQManagement import RabbitMQAPI
from millegrilles.util.X509Certificate import EnveloppeCleCert
from millegrilles.SecuritePKI import EnveloppeCertificat


class GestionnaireComptesMQ:
    """
    Permet de gerer les comptes RabbitMQ via connexion https a la management console.
    """

    def __init__(self, idmg, clecert_monitor: EnveloppeCleCert, certificats: dict, **kwargs):
        self.__idmg = idmg
        self.__clecert_monitor = clecert_monitor
        self.__certificats = certificats

        self.__host: str = environ.get('MG_MQ_HOST') or kwargs.get('host') or 'mq'
        self.__path_secrets: str = kwargs.get('secrets') or '/run/secrets'
        self.__file_passwd: str = kwargs.get('passwd_file') or ConstantesServiceMonitor.FICHIER_MQ_MOTDEPASSE
        self.__file_ca: str = kwargs.get('cert_ca') or ConstantesServiceMonitor.DOCKER_CONFIG_MILLEGRILLE_CERT + '.pem'
        self.__insecure_mode: bool = kwargs.get('insecure') or False

        self.__wait_event = Event()
        self.__password_mq: str = cast(str, None)

        self.__path_ca = certificats['pki.millegrille.cert']

        self.__millegrille_prete = False

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.charger_api()

    def charger_api(self):
        with open(path.join(self.__path_secrets, self.__file_passwd), 'r') as fichier:
            motdepasse = fichier.read()
        self._admin_api = RabbitMQAPI(self.__host, motdepasse, self.__path_ca)

    def fermer(self):
        self.__wait_event.set()

    def initialiser_motdepasse_admin(self):
        fichier_motdepasse = path.join(self.__path_secrets, self.__file_passwd)
        with open(fichier_motdepasse, 'r') as fichiers:
            nouveau_motdepasse = fichiers.read()

        admin_api = RabbitMQAPI(self.__host, '', self.__path_ca, guest=True)
        admin_api.create_admin('admin', nouveau_motdepasse)

        # Recharger api avec nouveau mot de passe
        self.charger_api()

        # Supprimer le user guest
        self._admin_api.delete_user('guest')

        return True

    def attendre_mq(self, attente_sec=300):
        """
        Attendre que le container et rabbitmq soit disponible. Effectue un ping a rabbitmq pour confirmer.
        :param attente_sec:
        :return:
        """
        mq_pret = False
        periode_attente = 5  # Secondes entre essais de connexion
        nb_essais_max = int(attente_sec / periode_attente) + 1
        for essai in range(1, nb_essais_max):
            try:
                resultat_healthcheck = self._admin_api.healthchecks()
                if resultat_healthcheck.get('status') == 'ok':
                    self.__logger.debug("MQ est pret")
                    try:
                        self.initialiser_motdepasse_admin()
                        mq_pret = True
                    except HTTPError as httpe:
                        if httpe.response.status_code in [401, 403]:
                            # OK, on a deja un mot de passe configure
                            mq_pret = True
                    break
            except MaxRetryError:
                self.__logger.warning("MQ Max Retry error, on va reessayer plus tard")
            except ConnectionError:
                self.__logger.warning("MQ Connection error, on va reessayer plus tard")
                if self.__logger.isEnabledFor(logging.DEBUG):
                    self.__logger.exception("MQ Connection Error")
            except HTTPError as httpe:
                if httpe.response.status_code in [401]:
                    self.__logger.error("Erreur connexion MQ code 401, on tente de configurer compte admin")
                    # Erreur authentification, tenter d'initialiser avec compte guest
                    self.initialiser_motdepasse_admin()
                    self.__entretien_comptes_mq()
                else:
                    if self.__logger.isEnabledFor(logging.DEBUG):
                        self.__logger.exception("MQ HTTPError, code : %d" % httpe.response.status_code)

            self.__logger.debug("Attente MQ (%s/%s)" % (essai, nb_essais_max))
            self.__wait_event.wait(periode_attente)

        return mq_pret

    def get_user_permissions(self, enveloppe: EnveloppeCleCert):

        read_permissions = ''
        write_permissions = ''
        configure_permissions = ''

        if Constantes.SECURITE_SECURE in enveloppe.get_exchanges:
            # Permission secure, on donne tous les acces
            read_permissions = '.*'
            write_permissions = '.*'
            configure_permissions = '.*'
        else:
            exchanges = '|'.join([e.replace('.', '\\.') for e in enveloppe.get_exchanges])

            roles = enveloppe.get_roles
            if 'media' in roles or 'fichiers' in roles:
                role_configs = '|'.join([r + '/.*' for r in roles])
                configure_permissions = '|'.join([role_configs, 'amq.*'])
                read_permissions = '|'.join([role_configs, exchanges, 'amq.*'])
                write_permissions = '|'.join([role_configs, exchanges, 'amq.*'])
            else:
                # TODO Corriger, permissions pour tous les roles
                read_permissions = '.*'
                write_permissions = '.*'
                configure_permissions = '.*'

        return configure_permissions, read_permissions, write_permissions

    def get_topic_permissions(self):
        raise NotImplementedError()
        # Exemple pour media
        # TOPICS (1.public, 2.prive, 3.protege)
        # write, exchanges 2.prive, 3.protege:
        # requete\..*|evenement\.fichiers.*|evenement\.media.*|\..*|commande\..*|transaction\.GrosFichiers\..*|amq\..*
        # read
        # requete\.certificat\..*|evenement\.certificat\..*|requete\.media\..*|evenement\.media\..*|commande\.media\..*|commande\.fichiers\..*|amq.*

    def ajouter_compte(self, enveloppe: EnveloppeCleCert):
        issuer = enveloppe.formatter_issuer()
        idmg = issuer['organizationName']

        subject = enveloppe.subject_rfc4514_string_mq()
        self.__logger.info("Creation compte MQ pour %s" % subject)

        try:
            self.ajouter_exchanges(idmg)

            # Charger exchanges immediatement - un certificat sans exchanges ne peut pas acceder a mongo/mq
            exchanges = enveloppe.get_exchanges

            responses = list()
            responses.append(self._admin_api.create_user(subject))

            configure_permissions, read_permissions, write_permissions = self.get_user_permissions(enveloppe)
            responses.append(self._admin_api.create_user_permission(
                subject, idmg, configure=configure_permissions, write=write_permissions, read=read_permissions
            ))

            liste_inclure = {Constantes.SECURITE_PUBLIC}  # PUblic toujours inclus
            if Constantes.SECURITE_PROTEGE in exchanges:
                # pour l'echange protege, on inclus aussi l'echange prive (et public)
                liste_inclure.add(Constantes.SECURITE_PRIVE)
            if Constantes.SECURITE_SECURE in exchanges:
                # pour l'echange secure, on inclus aussi tous les autres echanges
                liste_inclure.add(Constantes.SECURITE_PRIVE)
                liste_inclure.add(Constantes.SECURITE_PROTEGE)
            liste_inclure.update(exchanges)

            liste_exchanges_exclure = [
                Constantes.SECURITE_PUBLIC,
                Constantes.SECURITE_PRIVE,
                Constantes.SECURITE_PROTEGE,
                Constantes.SECURITE_SECURE
            ]

            for exchange in liste_inclure:
                liste_exchanges_exclure.remove(exchange)  # Retire de la liste d'exchanges a exclure
                responses.append(self._admin_api.create_user_topic(subject, idmg, exchange))

            # Bloquer les exchanges a exclure
            for exchange in liste_exchanges_exclure:
                responses.append(self._admin_api.create_user_topic(subject, idmg, exchange, write='', read=''))

            if any([response.status_code not in [201, 204] for response in responses]):
                raise ValueError("Erreur ajout compte", subject)

        except x509.extensions.ExtensionNotFound:
            self.__logger.info("Aucun access a MQ pour certificat %s", subject)

    def ajouter_exchanges(self, idmg: str = None):
        if idmg is None:
            idmg = self.__idmg

        self._admin_api.create_vhost(idmg)

        params_exchange = {
            "type": "topic",
            "auto_delete": False,
            "durable": True,
            "internal": False
        }
        self._admin_api.create_exchange_for_vhost(Constantes.SECURITE_SECURE, idmg, params_exchange)
        self._admin_api.create_exchange_for_vhost(Constantes.SECURITE_PROTEGE, idmg, params_exchange)
        self._admin_api.create_exchange_for_vhost(Constantes.SECURITE_PRIVE, idmg, params_exchange)
        self._admin_api.create_exchange_for_vhost(Constantes.SECURITE_PUBLIC, idmg, params_exchange)

    def entretien(self):
        try:
            mq_pret = self.attendre_mq(10)  # Healthcheck, attendre 10 secondes
            if mq_pret:
                # Verifier vhost, compte admin
                self.__entretien_comptes_mq()
        except SSLError:
            self.__logger.exception("SSL Erreur sur MQ, initialisation incorrecte")
        except HTTPError as httpe:
            if httpe.response.status_code in [401, 403]:
                # Erreur authentification, tenter d'initialiser avec compte guest
                self.initialiser_motdepasse_admin()
                self.__entretien_comptes_mq()

    def __entretien_comptes_mq(self):
        response = self._admin_api.create_vhost(self.__idmg)
        if self.__millegrille_prete and response.status_code == 204:
            # Host existant, on fait entretien de base
            pass
        else:
            # Vhost cree, on continue l'initialisation
            self.ajouter_exchanges()

            # Ajouter compte du monitor
            self.ajouter_compte(self.__clecert_monitor)

        self.__millegrille_prete = True


class GestionnaireComptesMongo:
    """
    Permet de gerer les comptes MongoDB.
    """

    def __init__(self, connexion_middleware):
        self.__connexion = connexion_middleware

        self.__rs_init_ok = False
        # self.__compte_monitor_ok = False

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def entretien(self):
        pass
        # 2022-01-13 Retrait de la replication
        #if not self.__rs_init_ok:
        #    self.init_replication()

        # if not self.__compte_monitor_ok:
        #     with open(self.__connexion.monitor_cert_file, 'rb') as fichier:
        #         cert_monitor = EnveloppeCleCert()
        #         cert_monitor.cert_from_pem_bytes(fichier.read())
        #
        #     try:
        #         self.creer_compte(cert_monitor)
        #         self.__compte_monitor_ok = True
        #     except DuplicateKeyError:
        #         self.__compte_monitor_ok = True

    def init_replication(self):
        document_dao = self.__connexion.document_dao
        try:
            document_dao.commande('replSetInitiate')
            self.__rs_init_ok = True
        except OperationFailure:
            self.__rs_init_ok = True

    def creer_compte(self, cert: Union[EnveloppeCertificat, EnveloppeCleCert]):
        try:
            issuer = cert.formatter_issuer()
        except AttributeError:
            pem = cert.certificat_pem
            certificat_clecert = EnveloppeCleCert()
            certificat_clecert.cert_from_pem_bytes(pem)
            cert = certificat_clecert
            issuer = certificat_clecert.formatter_issuer()

        idmg = issuer['organizationName']
        nom_compte = cert.subject_rfc4514_string_mq()
        commande = {
            'createUser': nom_compte,
            'roles': [{
                'role': 'readWrite',
                'db': idmg,
            }]
        }

        self.__logger.debug("Creation compte Mongo : %s", commande)

        document_dao = self.__connexion.document_dao
        external_db = document_dao.get_database('$external')
        external_db.command(commande)
