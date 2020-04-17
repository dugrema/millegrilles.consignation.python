import argparse
import signal
import logging
import sys
import docker
import json
import datetime

from threading import Event, Thread
from docker.errors import APIError
from base64 import b64decode
from requests.exceptions import HTTPError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.util import UtilScriptLigneCommande
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
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
            self.__logger.setLevel(logging.DEBUG)
        elif self.__args.info:
            logging.getLogger('millegrilles').setLevel(logging.INFO)

        self.__securite = self.__args.securite

        self.__logger.info("Arguments: %s", self.__args)

    def fermer(self, signum=None, frame=None):
        if signum:
            self.__logger.warning("Fermeture ServiceMonitor, signum=%d", signum)
        if not self.__fermeture_event.is_set():
            self.__fermeture_event.set()

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

            self.__gestionnaire_certificats = GestionnaireCertificats(self.__docker, self.__idmg, configuration_json['pem'])
            self.__gestionnaire_certificats.charger_cas()

            self.__logger.debug("Configuration noeud, idmg: %s, securite: %s", self.__idmg, self.__securite)
        except HTTPError:
            # La configuration n'existe pas
            self.__gestionnaire_certificats = GestionnaireCertificats(self.__docker)

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
        if not self.__idmg:
            # Generer certificat de MilleGrille
            self.__idmg = self.__gestionnaire_certificats.generer_nouveau_idmg()

            if self.__args.dev:
                self.__gestionnaire_certificats.sauvegarder_cas()

        # Generer certificats de module manquants ou expires, avec leur cle
        self.__entretien_certificats()

    def run(self):
        self.__logger.info("Demarrage du ServiceMonitor")
        self.parse()

        try:
            self.__connecter_docker()
            self.__charger_configuration()
            self.configurer_millegrille()

            self.__logger.debug("Cycle entretien ServiceMonitor")

            self.__logger.debug("Fin cycle entretien ServiceMonitor")
        except Exception:
            self.__logger.exception("Erreur generique")
        finally:
            self.__fermeture_event.wait(30)

        self.__logger.info("Fermeture du ServiceMonitor")

    @property
    def idmg_tronque(self):
        return self.__idmg[0:12]


class GestionnaireCertificats:

    def __init__(self, docker_client: docker.DockerClient, idmg: str = None, millegrille_cert_pem: str = None):
        self.__docker = docker_client
        self.__date: datetime.datetime = None
        self.idmg = idmg
        self.clecert_millegrille: EnveloppeCleCert
        self.clecert_intermediaire: EnveloppeCleCert
        self.renouvelleur: RenouvelleurCertificat = None

        self.maj_date()

        if millegrille_cert_pem:
            self.clecert_millegrille = EnveloppeCleCert()
            self.clecert_millegrille.cert_from_pem_bytes(millegrille_cert_pem.encode('utf-8'))

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

        return self.idmg

    def generer_clecert_module(self, role: str, common_name: str):
        clecert = self.renouvelleur.renouveller_par_role(role, common_name)
        chaine_certs = '\n'.join(clecert.chaine)
        self.ajouter_secret('pki.%s.key' % role, clecert.private_key_bytes)
        self.ajouter_config('pki.%s.cert' % role, chaine_certs.encode('utf-8'))

    def sauvegarder_cas(self):
        """
        Sauvegarder le certificat de millegrille sous /run/secrets - surtout utilise pour dev (insecure)
        :return:
        """
        with open('/run/secrets/pki.intermediaire.key.pem', 'wb') as fichiers:
            fichiers.write(self.clecert_intermediaire.private_key_bytes)
        with open('/run/secrets/pki.intermediaire.cert.pem', 'wb') as fichiers:
            fichiers.write(self.clecert_intermediaire.cert_bytes)
        with open('/run/secrets/pki.intermediaire.passwd.pem', 'wb') as fichiers:
            fichiers.write(self.clecert_intermediaire.password)

        self.__charger_renouvelleur()

    def charger_cas(self):
        with open('/run/secrets/pki.intermediaire.key.pem', 'rb') as fichiers:
            key_pem = fichiers.read()
        with open('/run/secrets/pki.intermediaire.cert.pem', 'rb') as fichiers:
            cert_pem = fichiers.read()
        with open('/run/secrets/pki.intermediaire.passwd.pem', 'rb') as fichiers:
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

        self.renouvelleur = RenouvelleurCertificat(self.idmg, dict_ca, self.clecert_intermediaire)

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


# Section main
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format=SERVICEMONITOR_LOGGING_FORMAT)
    logging.getLogger(ServiceMonitor.__name__).setLevel(logging.INFO)

    ServiceMonitor().run()
