import argparse
import signal
import logging
import sys
import docker
import json
import datetime
import secrets
import os

from threading import Event, Thread
from docker.errors import APIError
from docker.types import Resources, RestartPolicy, ServiceMode, NetworkAttachmentConfig, ConfigReference, \
    SecretReference, EndpointSpec
from base64 import b64encode, b64decode
from requests.exceptions import HTTPError
from os import path

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.SecuritePKI import GestionnaireEvenementsCertificat
from millegrilles.util.X509Certificate import GenerateurInitial, RenouvelleurCertificat, EnveloppeCleCert, \
    ConstantesGenerateurCertificat

SERVICEMONITOR_LOGGING_FORMAT = '%(threadName)s:%(levelname)s:%(message)s'


class ServiceMonitor:
    """
    Service deploye dans un swarm docker en mode global qui s'occupe du deploiement des autres modules de la
    MilleGrille et du renouvellement des certificats. S'occupe de configurer les comptes RabbitMQ et MongoDB.

    Supporte aussi les MilleGrilles hebergees par l'hote.
    """

    def __init__(self):
        self.__logger = logging.getLogger('%s' % self.__class__.__name__)

        self.__securite: str                # Niveau de securite de la swarm docker
        self.__args = None                  # Arguments de la ligne de commande
        self.__connexion_middleware = None  # Connexion a MQ, MongoDB
        self.__docker: docker.DockerClient  # Client docker
        self.__nodename: str                # Node name de la connexion locale dans Docker
        self.__idmg: str = None             # IDMG de la MilleGrille hote

        self.__fermeture_event = Event()

        self.__gestionnaire_certificats: GestionnaireCertificats
        self.__gestionnaire_docker: GestionnaireModulesDocker

        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.fermer)
        signal.signal(signal.SIGTERM, self.fermer)

    def parse(self):
        parser = argparse.ArgumentParser(description="Service Monitor de MilleGrilles")

        parser.add_argument(
            '--debug', action="store_true", required=False,
            help="Active le debugging (tres verbose)"
        )

        parser.add_argument(
            '--info', action="store_true", required=False,
            help="Afficher davantage de messages (verbose)"
        )

        parser.add_argument(
            '--dev', action="store_true", required=False,
            help="Active des options de developpement (insecure)"
        )

        parser.add_argument(
            '--secrets', type=str, required=False, default="/run/secrets",
            help="Repertoire de secrets"
        )

        parser.add_argument(
            '--configs', type=str, required=False, default="/etc/opt/millegrille",
            help="Repertoire de configuration"
        )

        parser.add_argument(
            '--securite', type=str, required=False, default='protege',
            choices=['prive', 'protege', 'secure'],
            help="Niveau de securite du noeud. Defaut = protege"
        )

        parser.add_argument(
            '--docker', type=str, required=False, default='/run/docker.sock',
            help="Path du pipe docker"
        )

        parser.add_argument(
            '--pipe', type=str, required=False, default='/run/millegrille.sock',
            help="Path du pipe de controle du ServiceMonitor"
        )

        parser.add_argument(
            '--config', type=str, required=False, default='/etc/opt/millegrilles/servicemonitor.json',
            help="Path du fichier de configuration de l'hote MilleGrilles"
        )

        parser.add_argument(
            '--data', type=str, required=False, default='/var/opt/millegrilles',
            help="Path du repertoire data de toutes les MilleGrilles"
        )

        self.__args = parser.parse_args()

        # Appliquer args
        if self.__args.debug:
            logging.getLogger('__main__').setLevel(logging.DEBUG)
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
            self.__logger.setLevel(logging.DEBUG)
        elif self.__args.info:
            logging.getLogger('__main__').setLevel(logging.INFO)
            logging.getLogger('millegrilles').setLevel(logging.INFO)

        self.__securite = self.__args.securite

        self.__logger.info("Arguments: %s", self.__args)

    def fermer(self, signum=None, frame=None):
        if signum:
            self.__logger.warning("Fermeture ServiceMonitor, signum=%d", signum)
        if not self.__fermeture_event.is_set():
            self.__fermeture_event.set()

        try:
            self.__docker.close()
        except Exception:
            pass

        try:
            self.__gestionnaire_docker.fermer()
        except Exception:
            pass

    def verifier_etat_courant(self):
        """
        :return: Etat courant detecte sur le systeme.
        """
        pass

    def generer_certificats_CA_initiaux(self):
        """
        Generer un certificat de millegrille, intermediaire et leurs cles/mots de passe.
        Insere les fichiers dans docker config/secret.
        :return:
        """
        pass

    def connecter_middleware(self):
        """
        Genere un contexte et se connecte a MQ et MongoDB.
        Lance une thread distincte pour s'occuper des messages.
        :return:
        """
        pass

    def __connecter_docker(self):
        self.__docker = docker.DockerClient('unix://' + self.__args.docker)
        # self.__logger.debug("Docker info: %s", str(self.__docker.info()))

        self.__nodename = self.__docker.info()['Name']
        self.__logger.debug("Docker node name: %s", self.__nodename)

        self.__logger.debug("--------------")
        self.__logger.debug("Docker configs")
        self.__logger.debug("--------------")
        for config in self.__docker.configs.list():
            self.__logger.debug("  %s", str(config.name))

        self.__logger.debug("--------------")
        self.__logger.debug("Docker secrets")
        self.__logger.debug("--------------")
        for secret in self.__docker.secrets.list():
            self.__logger.debug("  %s", str(secret.name))

        self.__logger.debug("--------------")
        self.__logger.debug("Docker services")
        self.__logger.debug("--------------")
        for service in self.__docker.services.list():
            self.__logger.debug("  %s", str(service.name))

        self.__logger.debug("--------------")

    def __charger_configuration(self):
        try:
            configuration_docker = self.__docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG)
            data = b64decode(configuration_docker.attrs['Spec']['Data'])
            configuration_json = json.loads(data)
            self.__idmg = configuration_json[Constantes.CONFIG_IDMG]
            self.__securite = configuration_json[Constantes.DOCUMENT_INFODOC_SECURITE]

            self.__gestionnaire_certificats = GestionnaireCertificats(
                self.__docker, idmg=self.__idmg, millegrille_cert_pem=configuration_json['pem'], secrets=self.__args.secrets)
            self.__gestionnaire_certificats.charger_cas()

            self.__logger.debug("Configuration noeud, idmg: %s, securite: %s", self.__idmg, self.__securite)
        except HTTPError as he:
            if he.status_code == 404:
                # La configuration n'existe pas
                self.__gestionnaire_certificats = GestionnaireCertificats(self.__docker, secrets=self.__args.secrets)
            else:
                raise he

    def __entretien_certificats(self):
        """
        Effectue l'entretien des certificats : genere certificats manquants ou expires avec leur cle
        :return:
        """
        # MAJ date pour creation de certificats
        self.__gestionnaire_certificats.maj_date()

        prefixe_certificats = self.idmg_tronque + '.pki.'
        filtre = {'name': prefixe_certificats}
        roles = {
            ConstantesGenerateurCertificat.ROLE_MONGO: dict(),
            ConstantesGenerateurCertificat.ROLE_MQ: dict(),
            ConstantesGenerateurCertificat.ROLE_TRANSACTIONS: dict(),
            ConstantesGenerateurCertificat.ROLE_MAITREDESCLES: dict(),
            ConstantesGenerateurCertificat.ROLE_CEDULEUR: dict(),
            ConstantesGenerateurCertificat.ROLE_FICHIERS: dict(),
            ConstantesGenerateurCertificat.ROLE_COUPDOEIL: dict(),
            ConstantesGenerateurCertificat.ROLE_DOMAINES: dict(),
        }

        # Charger la configuration existante
        date_renouvellement = datetime.datetime.utcnow() + datetime.timedelta(days=21)
        for config in self.__docker.configs.list(filters=filtre):
            self.__logger.debug("Config : %s", str(config))
            nom_config = config.name.split('.')
            nom_role = nom_config[2]
            if nom_config[3] == 'cert' and nom_role in roles.keys():
                role_info = roles[nom_role]
                self.__logger.debug("Verification cert %s date %s", nom_role, nom_config[4])
                pem = b64decode(config.attrs['Spec']['Data'])
                clecert = EnveloppeCleCert()
                clecert.cert_from_pem_bytes(pem)
                date_expiration = clecert.not_valid_after

                expiration_existante = role_info.get('expiration')
                if not expiration_existante or expiration_existante < date_expiration:
                    role_info['expiration'] = date_expiration
                    if date_expiration < date_renouvellement:
                        role_info['est_expire'] = True
                    else:
                        role_info['est_expire'] = False

        # Generer certificats expires et manquants
        for nom_role, info_role in roles.items():
            if not info_role.get('expiration') or info_role.get('est_expire'):
                self.__logger.debug("Generer nouveau certificat role %s", nom_role)
                self.__gestionnaire_certificats.generer_clecert_module(nom_role, self.__nodename)

    def configurer_millegrille(self):
        besoin_initialiser = not self.__idmg

        if besoin_initialiser:
            # Generer certificat de MilleGrille
            self.__idmg = self.__gestionnaire_certificats.generer_nouveau_idmg()

            if self.__args.dev:
                self.__gestionnaire_certificats.sauvegarder_cas()

        self.__gestionnaire_docker = GestionnaireModulesDocker(self.__idmg, self.__docker, self.__fermeture_event)
        self.__gestionnaire_docker.start_events()

        if besoin_initialiser:
            self.__gestionnaire_docker.initialiser_millegrille()

        # Generer certificats de module manquants ou expires, avec leur cle
        self.__entretien_certificats()

    def __entretien_modules(self):
        # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
        self.__gestionnaire_docker.entretien_services()

    def run(self):
        self.__logger.info("Demarrage du ServiceMonitor")

        try:
            self.parse()
            self.__connecter_docker()
            self.__charger_configuration()
            self.configurer_millegrille()

            while not self.__fermeture_event.is_set():
                try:
                    self.__logger.debug("Cycle entretien ServiceMonitor")

                    self.__entretien_modules()

                    self.__logger.debug("Fin cycle entretien ServiceMonitor")
                except Exception:
                    self.__logger.exception("ServiceMonitor: erreur generique")
                finally:
                    self.__fermeture_event.wait(30)

        except Exception:
            self.__logger.exception("Erreur demarrage ServiceMonitor, on abandonne l'execution")

        self.__logger.info("Fermeture du ServiceMonitor")

    @property
    def idmg_tronque(self):
        return self.__idmg[0:12]


class GestionnaireCertificats:

    def __init__(self, docker_client: docker.DockerClient, **kwargs):
        self.__docker = docker_client
        self.__date: datetime.datetime = None
        self.idmg = kwargs.get('idmg')
        self.clecert_millegrille: EnveloppeCleCert
        self.clecert_intermediaire: EnveloppeCleCert
        self.renouvelleur: RenouvelleurCertificat = None
        self.secret_path = kwargs.get('secrets')

        self.maj_date()

        cert_pem = kwargs.get('millegrille_cert_pem')
        if cert_pem:
            self.clecert_millegrille = EnveloppeCleCert()
            self.clecert_millegrille.cert_from_pem_bytes(cert_pem.encode('utf-8'))

    def maj_date(self):
        self.__date = str(datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S'))

    def generer_nouveau_idmg(self):
        generateur_initial = GenerateurInitial(None)
        clecert_intermediaire = generateur_initial.generer()
        clecert_millegrille = generateur_initial.autorite

        self.clecert_millegrille = clecert_millegrille
        self.clecert_intermediaire = clecert_intermediaire
        self.idmg = clecert_millegrille.idmg

        # Sauvegarder certificats, cles et mots de passe dans docker
        self.ajouter_secret('pki.millegrille.key', clecert_millegrille.private_key_bytes)
        self.ajouter_secret('pki.millegrille.passwd', clecert_millegrille.password)
        self.ajouter_config('pki.millegrille.cert', clecert_millegrille.cert_bytes)

        self.ajouter_secret('pki.intermediaire.key', clecert_intermediaire.private_key_bytes)
        self.ajouter_secret('pki.intermediaire.passwd', clecert_intermediaire.password)
        self.ajouter_config('pki.intermediaire.cert', clecert_intermediaire.cert_bytes)

        # Conserver la configuration de base pour ServiceMonitor
        configuration = {
            'idmg': self.idmg,
            'pem': str(clecert_millegrille.cert_bytes, 'utf-8'),
            'securite': '3.protege',
        }
        configuration_bytes = json.dumps(configuration).encode('utf-8')
        self.__docker.configs.create(name='millegrille.configuration', data=configuration_bytes, labels={'idmg': self.idmg})

        # Generer mots de passes
        self.generer_motsdepasse()

        self.preparer_repertoires()

        return self.idmg

    def generer_motsdepasse(self):
        passwd_mongo = b64encode(secrets.token_bytes(32))
        label_passwd_mongo = self.idmg_tronque + '.passwd.mongo.' + self.__date
        self.__docker.secrets.create(name=label_passwd_mongo, data=passwd_mongo, labels={'millegrille': self.idmg})

    def preparer_repertoires(self):
        mounts = path.join('/var/opt/millegrilles', self.idmg, 'mounts')
        os.makedirs(mounts, mode=0o770)

        mongo_data = path.join(mounts, 'mongo/data')
        os.makedirs(mongo_data, mode=0o700)

        mongo_scripts = path.join(mounts, 'mongo/scripts')
        os.makedirs(mongo_scripts, mode=0o700)


    def generer_clecert_module(self, role: str, common_name: str):
        clecert = self.renouvelleur.renouveller_par_role(role, common_name)
        chaine_certs = '\n'.join(clecert.chaine)

        secret = clecert.private_key_bytes

        # Verifier si on doit combiner le cert et la cle (requis pour Mongo)
        if role in [ConstantesGenerateurCertificat.ROLE_MONGO, ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS]:
            secret_str = [str(secret, 'utf-8')]
            secret_str.extend(clecert.chaine)
            secret = '\n'.join(secret_str).encode('utf-8')

        self.ajouter_secret('pki.%s.key' % role, secret)
        self.ajouter_config('pki.%s.cert' % role, chaine_certs.encode('utf-8'))

    def sauvegarder_cas(self):
        """
        Sauvegarder le certificat de millegrille sous 'args.secrets' - surtout utilise pour dev (insecure)
        :return:
        """
        secret_path = path.abspath(self.secret_path)
        with open(path.join(secret_path, 'pki.intermediaire.key.pem'), 'wb') as fichiers:
            fichiers.write(self.clecert_intermediaire.private_key_bytes)
        with open(path.join(secret_path, 'pki.intermediaire.cert.pem'), 'wb') as fichiers:
            fichiers.write(self.clecert_intermediaire.cert_bytes)
        with open(path.join(secret_path, 'pki.intermediaire.passwd.pem'), 'wb') as fichiers:
            fichiers.write(self.clecert_intermediaire.password)

        self.__charger_renouvelleur()

    def charger_cas(self):
        secret_path = path.abspath(self.secret_path)
        with open(path.join(secret_path, 'pki.intermediaire.key.pem'), 'rb') as fichiers:
            key_pem = fichiers.read()
        with open(path.join(secret_path, 'pki.intermediaire.cert.pem'), 'rb') as fichiers:
            cert_pem = fichiers.read()
        with open(path.join(secret_path, 'pki.intermediaire.passwd.pem'), 'rb') as fichiers:
            passwd_bytes = fichiers.read()

        clecert_intermediaire = EnveloppeCleCert()
        clecert_intermediaire.from_pem_bytes(key_pem, cert_pem, passwd_bytes)
        clecert_intermediaire.password = None  # Effacer mot de passe
        self.clecert_intermediaire = clecert_intermediaire

        self.__charger_renouvelleur()

    def __charger_renouvelleur(self):
        dict_ca = {
            self.clecert_intermediaire.skid: self.clecert_intermediaire.cert,
            self.clecert_millegrille.skid: self.clecert_millegrille.cert,
        }

        self.renouvelleur = RenouvelleurCertificat(self.idmg, dict_ca, self.clecert_intermediaire, generer_password=False)

    def __preparer_label(self, name):
        params = {
            'idmg_tronque': self.idmg[0:12],
            'name': name,
            'date': self.__date,
        }
        name_docker = '%(idmg_tronque)s.%(name)s.%(date)s' % params
        return name_docker[0:64]  # Max 64 chars pour name docker

    def ajouter_config(self, name: str, data: bytes):
        name_tronque = self.__preparer_label(name)
        self.__docker.configs.create(name=name_tronque, data=data, labels={'idmg': self.idmg})

    def ajouter_secret(self, name: str, data: bytes):
        name_tronque = self.__preparer_label(name)
        self.__docker.secrets.create(name=name_tronque, data=data, labels={'idmg': self.idmg})

    @property
    def idmg_tronque(self):
        return self.idmg[0:12]


class ConnexionMiddleware:
    """
    Connexion au middleware de la MilleGrille en service.
    """

    def __init__(self):
        self.__contexte = None
        self.__thread = None
        self.__channel = None

        self.__fermeture_event = Event()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__certificat_event_handler = GestionnaireEvenementsCertificat(self.__contexte)

    def start(self):
        self.__logger.info("Demarrage ConnexionMiddleware")
        # Generer contexte

        # Connecter

        # Demarrer thread
        self.__thread = Thread(target=self.run, name="mw")
        self.__thread.start()

    def stop(self):
        self.__fermeture_event.set()

        # try:
        #     self.__contexte.deconnecter()
        # except Exception:
        #     pass

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        self.__contexte.initialiser(
            init_document=init_document,
            init_message=init_message,
            connecter=connecter
        )

        if init_message:
            self.__contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel
        self.__certificat_event_handler.initialiser()

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__channel = None
        self.__logger.warning("MQ Channel ferme")
        if not self.__fermeture_event.is_set():
            try:
                self.__contexte.message_dao.enter_error_state()
            except Exception:
                # Erreur d'activation du error state, la connexion ne peut pas etre reactivee
                self.__logger.exception("Erreur fermeture channel")
                self.__fermeture_event.set()  # S'assurer que la fermeture est en cours

    def __on_return(self, channel, method, properties, body):
        pass

    def run(self):
        self.__logger.info("Thread middleware demarree")

        self.__logger.info("Fin thread middleware")


class GestionnaireModulesDocker:

    def __init__(self, idmg: str, docker_client: docker.DockerClient, fermeture_event: Event):
        self.__idmg = idmg
        self.__docker = docker_client
        self.__fermeture_event = fermeture_event
        self.__thread_events: Thread = None
        self.__event_stream = None

        # Liste de modules requis. L'ordre est important, les dependances sont implicites.
        self.__modules_requis = [
            ConstantesServiceMonitor.MODULE_MQ,
            ConstantesServiceMonitor.MODULE_MONGO,
            # ConstantesServiceMonitor.MODULE_TRANSACTION,
            # ConstantesServiceMonitor.MODULE_MAITREDESCLES,
            # ConstantesServiceMonitor.MODULE_CEDULEUR,
            # ConstantesServiceMonitor.MODULE_CONSIGNATIONFICHIERS,
            # ConstantesServiceMonitor.MODULE_COUPDOEIL,
            # ConstantesServiceMonitor.MODULE_TRANSMISSION,
            # ConstantesServiceMonitor.MODULE_DOMAINES,
        ]

        self.__mappings = {
            'IDMG': self.__idmg,
            'IDMGLOWER': self.__idmg.lower(),
            'IDMGTRUNCLOWER': self.idmg_tronque,
            'MONGO_INITDB_ROOT_USERNAME': 'admin',
            'MOUNTS': '/var/opt/millegrilles/%s/mounts' % self.__idmg,
        }

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def start_events(self):
        self.__thread_events = Thread(target=self.ecouter_events, name='events')
        self.__thread_events.start()

    def fermer(self):
        try:
            self.__event_stream.close()
        except Exception:
            pass

    def ecouter_events(self):
        self.__logger.info("Debut ecouter events docker")
        self.__event_stream = self.__docker.events()
        for event in self.__event_stream:
            self.__logger.debug("Event : %s", str(event))
            if self.__fermeture_event.is_set():
                break
        self.__logger.info("Fin ecouter events docker")

    def initialiser_millegrille(self):
        # Creer reseau pour cette millegrille
        network_name = 'mg_' + self.__idmg + '_net'
        labels = {'millegrille': self.__idmg}
        self.__docker.networks.create(name=network_name, labels=labels, scope="swarm", driver="overlay")

    def entretien_services(self):
        """
        Verifie si les services sont actifs, les demarre au besoin.
        :return:
        """
        filtre = {'name': self.idmg_tronque + '_'}
        liste_services = self.__docker.services.list(filters=filtre)
        dict_services = dict()
        for service in liste_services:
            service_name = service.name.split('_')[1]
            dict_services[service_name] = service

        for service_name in self.__modules_requis:
            service = dict_services.get(service_name)
            if not service:
                self.demarrer_service(service_name)
                break  # On demarre un seul service a la fois, on attend qu'il soit pret
            else:
                # Verifier etat service
                self.verifier_etat_service(service)

    def demarrer_service(self, service_name: str):
        self.__logger.info("Demarrage service %s", service_name)

        gestionnaire_images = GestionnaireImagesDocker(self.__idmg, self.__docker)
        image = gestionnaire_images.telecharger_image_docker(service_name)

        # Prendre un tag au hasard
        image_tag = image.tags[0]

        configuration = self.__formatter_configuration_service(service_name)

        constraints = configuration.get('constraints')
        if constraints:
            self.__add_node_labels(constraints)

        self.__docker.services.create(image_tag, **configuration)

    def verifier_etat_service(self, service):
        pass

    def charger_config(self, config_name):
        filtre = {'name': config_name}
        return b64decode(self.__docker.configs.list(filters=filtre)[0].attrs['Spec']['Data'])

    def __trouver_config(self, config_name):
        config_names = config_name.split(';')
        for config_name_val in config_names:
            filtre = {'name': self.idmg_tronque + '.' + config_name_val}
            configs = self.__docker.configs.list(filters=filtre)
            if len(configs) > 0:
                break

        # Trouver la configuration la plus recente (par date). La meme date va etre utilise pour un secret, au besoin
        date_config: int = None
        config_retenue = None
        for config in configs:
            nom_config = config.name
            split_config = nom_config.split('.')
            date_config_str = split_config[-1]
            date_config_int = int(date_config_str)
            if not date_config or date_config_int > date_config:
                date_config = date_config_int
                config_retenue = config

        pass

        return {
            'config_reference': {
                'config_id': config_retenue.attrs['ID'],
                'config_name': config_retenue.name,
            },
            'date': str(date_config),
        }

    def __trouver_secret(self, secret_name):
        secret_names = secret_name.split(';')
        for secret_name_val in secret_names:
            filtre = {'name': self.idmg_tronque + '.' + secret_name_val}
            secrets = self.__docker.secrets.list(filters=filtre)
            if len(secrets) > 0:
                break

        # Trouver la configuration la plus recente (par date). La meme date va etre utilise pour un secret, au besoin
        date_secret: int = None
        secret_retenue = None
        for secret in secrets:
            nom_secret = secret.name
            split_secret = nom_secret.split('.')
            date_secret_str = split_secret[-1]
            date_secret_int = int(date_secret_str)
            if not date_secret or date_secret_int > date_secret:
                date_secret = date_secret_int
                secret_retenue = secret

        return {
            'secret_id': secret_retenue.attrs['ID'],
            'secret_name': secret_retenue.name,
        }

    def __trouver_secret_matchdate(self, secret_names, date_secrets: dict):
        for secret_name in secret_names.split(';'):
            secret_name_split = secret_name.split('.')[0:2]
            secret_name_split.append('cert')
            config_name = '.'.join(secret_name_split)
            try:
                date_secret = date_secrets[config_name]

                nom_filtre = self.idmg_tronque + '.' + secret_name + '.' + date_secret
                filtre = {'name': nom_filtre}
                secrets = self.__docker.secrets.list(filters=filtre)

                if len(secrets) != 1:
                    raise ValueError("Le secret_name ne correspond pas a un secret : %s", nom_filtre)

                secret = secrets[0]

                return {
                    'secret_id': secret.attrs['ID'],
                    'secret_name': secret.name,
                }

            except KeyError:
                continue

    def __mapping(self, valeur: str):
        for cle, valeur_mappee in self.__mappings.items():
            cle = cle.upper()
            valeur = valeur.replace('${%s}' % cle, valeur_mappee)

        return valeur

    def __formatter_configuration_service(self, service_name):
        config_service = json.loads(self.charger_config('docker.cfg.' + service_name))
        self.__logger.debug("Configuration service %s : %s", service_name, str(config_service))

        dict_config_docker = self.__remplacer_variables(service_name, config_service)

        return dict_config_docker

    def __remplacer_variables(self, nom_service, config_service):
        self.__logger.debug("Remplacer variables %s" % nom_service)
        dict_config_docker = dict()

        try:
            # Name
            dict_config_docker['name'] = self.idmg_tronque + '_' + config_service['name']

            # Resources
            config_resources = config_service.get('resources')
            if config_resources:
                dict_config_docker['resources'] = Resources(**config_resources)

            # Restart Policy
            config_restart_policy = config_service.get('restart_policy')
            if config_restart_policy:
                dict_config_docker['restart_policy'] = RestartPolicy(**config_restart_policy)

            # Service Mode
            config_service_mode = config_service.get('mode')
            if config_service_mode:
                dict_config_docker['mode'] = ServiceMode(**config_service_mode)

            # Variables d'environnement, inclus mapping
            config_env = config_service.get('env')
            if config_env:
                # Mapping des variables
                config_env = [self.__mapping(valeur) for valeur in config_env]
                dict_config_docker['env'] = config_env

            # Constraints
            config_constraints = config_service.get('constraints')
            if config_constraints:
                dict_config_docker['constraints'] = config_constraints

            # Service labels
            config_labels = config_service.get('labels')
            if config_labels:
                updated_labels = dict()
                for key, value in config_labels.items():
                    value = self.__mapping(value)
                    updated_labels[key] = value
                dict_config_docker['labels'] = updated_labels

            # Container labels
            config_container_labels = config_service.get('container_labels')
            if config_container_labels:
                updated_labels = dict()
                for key, value in config_container_labels.items():
                    value = self.__mapping(value)
                    updated_labels[key] = value
                dict_config_docker['container_labels'] = updated_labels

            # Networks
            config_networks = config_service.get('networks')
            if config_networks:
                networks = list()
                for network in config_networks:
                    network['target'] = self.__mapping(network['target'])
                    networks.append(NetworkAttachmentConfig(**network))

                dict_config_docker['networks'] = networks

            # Configs
            config_configs = config_service.get('configs')
            dates_configs = dict()
            if config_configs:
                liste_configs = list()
                for config in config_configs:
                    self.__logger.debug("Mapping configs %s" % config)
                    config_name = config['name']
                    config_dict = self.__trouver_config(config_name)

                    config_reference = config_dict['config_reference']
                    config_reference['filename'] = config['filename']
                    config_reference['uid'] = config.get('uid') or 0
                    config_reference['gid'] = config.get('gid') or 0
                    config_reference['mode'] = config.get('mode') or 0o444
                    liste_configs.append(ConfigReference(**config_reference))

                    dates_configs[config_name] = config_dict['date']

                dict_config_docker['configs'] = liste_configs

            # Secrets
            config_secrets = config_service.get('secrets')
            if config_secrets:
                liste_secrets = list()
                for secret in config_secrets:
                    self.__logger.debug("Mapping secret %s" % secret)
                    secret_name = secret['name']
                    if secret.get('match_config'):
                        secret_reference = self.__trouver_secret_matchdate(secret_name, dates_configs)
                    else:
                        secret_reference = self.__trouver_secret(secret_name)
                    secret_reference['filename'] = secret['filename']
                    secret_reference['uid'] = secret.get('uid') or 0
                    secret_reference['gid'] = secret.get('gid') or 0
                    secret_reference['mode'] = secret.get('mode') or 0o444
                    liste_secrets.append(SecretReference(**secret_reference))

                dict_config_docker['secrets'] = liste_secrets

            # Ports
            config_endpoint_spec = config_service.get('endpoint_spec')
            if config_endpoint_spec:
                ports = dict()
                mode = config_endpoint_spec.get('mode') or 'vip'
                for port in config_endpoint_spec.get('ports'):
                    published_port = port['published_port']
                    target_port = port['target_port']
                    protocol = port.get('protocol') or 'tcp'
                    publish_mode = port.get('publish_mode')

                    if protocol or publish_mode:
                        ports[published_port] = (target_port, protocol, publish_mode)
                    else:
                        ports[published_port] = target_port

                dict_config_docker['endpoint_spec'] = EndpointSpec(mode=mode, ports=ports)

            # Mounts
            config_mounts = config_service.get('mounts')
            if config_mounts:
                dict_config_docker['mounts'] = [self.__mapping(mount) for mount in config_mounts]

        except TypeError as te:
            self.__logger.error("Erreur mapping %s", nom_service)
            raise te

        return dict_config_docker

    def __add_node_labels(self, constraints: list):
        labels_ajoutes = dict()
        for constraint in constraints:
            if '== true' in constraint:
                valeurs = constraint.split('==')
                labels_ajoutes[valeurs[0].strip().replace('node.labels.', '')] = valeurs[1].strip()

        if len(labels_ajoutes) > 0:
            nodename = self.__docker.info()['Name']
            node_info = self.__docker.nodes.get(nodename)
            node_spec = node_info.attrs['Spec']
            labels = node_spec['Labels']
            labels.update(labels_ajoutes)
            node_info.update(node_spec)

    @property
    def idmg_tronque(self):
        return self.__idmg[0:12]


class GestionnaireComptesMQ:
    """
    Permet de gerer les comptes RabbitMQ via connexion https a la management console.
    """

    def __init__(self, connexion_middleware: ConnexionMiddleware):
        self.__connexion = connexion_middleware


class GestionnaireComptesMqMongo(GestionnaireComptesMQ):
    """
    Permet de gerer les comptes RabbitMQ et MongoDB.
    """

    def __init__(self, connexion_middleware: ConnexionMiddleware):
        super().__init__(connexion_middleware)


class GestionnaireImagesDocker:

    def __init__(self, idmg: str, docker_client: docker.DockerClient):
        self.__idmg = idmg
        self.__docker = docker_client
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self.__versions_images: dict = None

    @property
    def tronquer_idmg(self):
        return self.__idmg[0:12]

    def charger_versions(self):
        filtre = {'name': 'docker.versions'}
        self.__versions_images = json.loads(b64decode(self.__docker.configs.list(filters=filtre)[0].attrs['Spec']['Data']))

    def telecharger_images_docker(self):
        """
        S'assure d'avoir une version locale de chaque image - telecharge au besoin
        :return:
        """
        images_non_trouvees = list()

        self.charger_versions()

        for service in self.__versions_images['images'].keys():
            # Il est possible de definir des registre specifiquement pour un service
            self.pull_image(service, images_non_trouvees)

        if len(images_non_trouvees) > 0:
            message = "Images non trouvees: %s" % str(images_non_trouvees)
            raise Exception(message)

    def telecharger_image_docker(self, nom_service):
        """
        S'assure d'avoir une version locale de chaque image - telecharge au besoin
        :return:
        """
        images_non_trouvees = list()

        self.charger_versions()

        # Il est possible de definir des registre specifiquement pour un service
        image = self.pull_image(nom_service, images_non_trouvees)

        if len(images_non_trouvees) > 0:
            message = "Images non trouvees: %s" % str(images_non_trouvees)
            raise Exception(message)

        return image
        
    def pull_image(self, service, images_non_trouvees):
        registries = self.__versions_images['registries']
        config = self.__versions_images['images'][service]
        nom_image = config['image']
        tag = config['version']

        service_registries = config.get('registries')
        if service_registries is None:
            service_registries = registries
        image_locale = self.get_image_locale(nom_image, tag)
        if image_locale is None:
            image = None
            for registry in service_registries:
                if registry != '':
                    nom_image_reg = '%s/%s' % (registry, nom_image)
                else:
                    # Le registre '' represente une image docker officielle
                    nom_image_reg = nom_image

                self.__logger.info("Telecharger image %s:%s" % (nom_image, tag))
                image = self.pull(nom_image_reg, tag)
                if image is not None:
                    self.__logger.info("Image %s:%s sauvegardee avec succes" % (nom_image, tag))
                    return image  # On prend un tag au hasard

            if image is None:
                images_non_trouvees.append('%s:%s' % (nom_image, tag))

        return image_locale

    def pull(self, image_name, tag):
        """
        Effectue le telechargement d'une image.
        Cherche dans tous les registres configures.
        """

        image = None
        try:
            self.__logger.info("Telechargement image %s" % image_name)
            image = self.__docker.images.pull(image_name, tag)
            self.__logger.debug("Image telechargee : %s" % str(image))
        except APIError as e:
            if e.status_code == 404:
                self.__logger.debug("Image inconnue: %s" % e.explanation)
            else:
                self.__logger.warning("Erreur api, %s" % str(e))

        return image

    def get_image_locale(self, image_name, tag, custom_registries: list = tuple()):
        """
        Verifie si une image existe deja localement. Cherche dans tous les registres.
        :param image_name:
        :param tag:
        :param custom_registries:
        :return:
        """
        self.__logger.debug("Get image locale %s:%s" % (image_name, tag))

        registries = self.__versions_images['registries'].copy()
        registries.extend(custom_registries)
        registries.append('')
        for registry in registries:
            if registry != '':
                nom_image_reg = '%s/%s:%s' % (registry, image_name, tag)
            else:
                # Verifier nom de l'image sans registre (e.g. docker.io)
                nom_image_reg = '%s:%s' % (image_name, tag)

            try:
                image = self.__docker.images.get(nom_image_reg)
                self.__logger.info("Image locale %s:%s trouvee" % (image_name, tag))
                return image
            except APIError:
                self.__logger.debug("Image non trouvee: %s" % nom_image_reg)

        return None

    def get_image_parconfig(self, config_key: str):
        config_values = self.__versions_images['images'].get(config_key)
        self.__logger.debug("Config values pour %s: %s" % (config_key, str(config_values)))
        custom_registries = list()
        if config_values.get('registries') is not None:
            custom_registries = config_values['registries']
        image = self.get_image_locale(config_values['image'], config_values['version'], custom_registries)
        if image is not None:
            self.__logger.debug("Tags pour image %s : %s" % (config_key, str(image.tags)))
            nom_image = image.tags[0]  # On prend un tag au hasard
        else:
            self.__logger.warning("Image locale non trouvee pour config_key: %s " % config_key)
            raise ImageNonTrouvee(config_key)

        return nom_image


class ImageNonTrouvee(Exception):

    def __init__(self, image, t=None, obj=None):
        super().__init__(t, obj)
        self.image = image


# Section main
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format=SERVICEMONITOR_LOGGING_FORMAT)
    logging.getLogger(ServiceMonitor.__name__).setLevel(logging.INFO)

    ServiceMonitor().run()
