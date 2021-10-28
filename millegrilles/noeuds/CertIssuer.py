# Programme de signature de certificats
# Expose une interface web sur https://certissuer:8443/certificats
import argparse
import datetime
import json
import logging
import signal
import time
import pytz

from http import HTTPStatus
from cryptography import x509
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from json.decoder import JSONDecodeError
from http.server import SimpleHTTPRequestHandler, HTTPServer
from os import environ, makedirs, path, chmod, rename, remove
from threading import Event, Thread
from typing import Optional

from millegrilles import Constantes
from millegrilles.util.X509Certificate import EnveloppeCleCert, RenouvelleurCertificat
from millegrilles.util.ValidateursPki import ValidateurCertificat


# Variables globales
logger = logging.getLogger('certissuer')
stop_event = Event()
host_name = '0.0.0.0'
server_port = 80
thread_entretien = None
web_server: Optional[HTTPServer] = None


class Config:

    def __init__(self):
        self.args_parse = None
        self.idmg: Optional[str] = None
        self.path_data = '/var/opt/millegrilles/issuer'
        self.noeud_id: Optional[str] = None
        # self.clecert: Optional[EnveloppeCleCert] = None
        # self.cert_ca: Optional[str] = None
        # self.renouvelleur: Optional[RenouvelleurCertificat] = None


class HandlerCertificats:

    def __init__(self, config: Config):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.config = config
        self.cert_ca: Optional[str] = None
        self.__clecert: Optional[EnveloppeCleCert] = None
        self.__renouvelleur: Optional[RenouvelleurCertificat] = None
        self.__validateur: Optional[ValidateurCertificat] = None

    def set_intermediaire(self, clecert: EnveloppeCleCert):
        """
        Changer la cle intermediaire. Valide le certificat intermediaire.
        :param clecert: Cle intermediaire courante
        :raises PathValidationError: Certificat intermediaire invalide
        """
        self.__clecert = clecert
        cert_ca = clecert.chaine[-1]
        self.cert_ca = cert_ca

        # Charger cert CA (millegrille), calculer idmg
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(cert_ca.encode('utf-8'))
        idmg = clecert_millegrille.idmg

        # Creer instance de validateur de certificats, valider chaine intermediaire
        self.__validateur = ValidateurCertificat(idmg, cert_ca)
        self.__validateur.valider(clecert.chaine, usages={'key_cert_sign'})

        # Creer instance de renouvelleur de certificats
        dict_ca = {
            clecert.skid: clecert.cert,
            clecert_millegrille.skid: clecert_millegrille.cert,
        }

        self.__renouvelleur = RenouvelleurCertificat(idmg, dict_ca, clecert, clecert_millegrille)


# Creer objet config global, permet de le passer plus facilement au serveur
config = Config()
handler = HandlerCertificats(config)


def main():
    # Parse args en premier, si -h/--help va sortir immediatement
    global config, handler
    parse(config, handler)
    setup(config, handler)

    # Demarrer thread d'entretien
    global thread_entretien
    thread_entretien = Thread(name="entretien", target=entretien, daemon=True)
    thread_entretien.start()

    executer()


def executer():
    global stop_event
    logger.info("Demarrage certissuer sur port http %d" % server_port)

    thread_server = Thread(name="web_server", target=executer_serveur, daemon=True)
    thread_server.start()

    # Conserver la thread main active (sert a recevoir les 'signal')
    while not stop_event.is_set():
        stop_event.wait(1)

    logger.info("Fermeture certissuer")


def setup(config_in: Config, handler: HandlerCertificats):
    logger.info("Utilisation path_data = %s", config_in.path_data)
    path_data = config_in.path_data
    makedirs(path_data, exist_ok=True)

    # Preparer sub-folders
    path_secrets = path.join(path_data, 'secrets')
    path_certs = path.join(path_data, 'certs')
    path_config = path.join(path_data, 'config')

    makedirs(path_secrets, exist_ok=True)
    chmod(path_secrets, 0o700)
    makedirs(path_certs, exist_ok=True)
    chmod(path_certs, 0o750)
    makedirs(path_config, exist_ok=True)
    chmod(path_config, 0o750)


def executer_serveur():
    global web_server, config, stop_event, handler
    web_server = HTTPServer((host_name, server_port), ServeurHttp)
    web_server.config = config
    web_server.handler = handler
    web_server.serve_forever()

    if not stop_event.is_set():
        logger.warning("Serveur HTTP a cesse son execution")

    # S'assurer que le serveur va fermer
    stop_event.set()


def exit_gracefully(signum=None, frame=None):
    global web_server
    logger.info("Fermer sur signal: %d" % signum)
    stop_event.set()
    logger.info("Stop event set - fermeture en cours")
    # web_server.shutdown()
    logger.info("Shutdown web serveur complete")


def entretien():
    stop_event.wait(15)  # Attente initiale
    while not stop_event.is_set():
        logger.debug("Cycle entretien")
        stop_event.wait(30)

    logger.info("Fin thread entretien")


def parse(config_in: Config, handler_in: HandlerCertificats):
    # Variables d'environnement
    global host_name, server_port
    host_name = environ.get("HOST") or host_name
    port = environ.get('PORT') or str(server_port)
    server_port = int(port)
    config_in.idmg = environ.get("IDMG")
    config_in.path_data = environ.get("PATH_DATA") or config_in.path_data
    config_in.noeud_id = environ.get("MG_NOEUD_ID") or 'certissuer'

    # Charger cle courante
    try:
        clecert = charger_clecert()
        handler_in.set_intermediaire(clecert)

        # Charger cert millegrille (dernier dans la chaine), recalculer le IDMG
        idmg = calculer_idmg(clecert)

        # Override du IDMG env, on utilise celui de la cle courante
        config.idmg = idmg

    except FileNotFoundError:
        logger.info("Certificat intermediare n'est pas encore charge")

    # Ligne de commande
    parser = argparse.ArgumentParser(description="""
Demarre le certissuer de MilleGrilles, gere le certificat intermediare d'une instance protegee
    """)

    parser.add_argument(
        '--verbose', action="store_true", required=False,
        help="Active le logging maximal"
    )

    config_in.args_parse = parser.parse_args()

    if config_in.args_parse.verbose:
        logging.getLogger('certissuer').setLevel(logging.DEBUG)
        logging.getLogger('millegrilles').setLevel(logging.DEBUG)


def calculer_idmg(clecert: EnveloppeCleCert):
    cert_ca = clecert.chaine[-1]
    clecert_millegrille = EnveloppeCleCert()
    clecert_millegrille.cert_from_pem_bytes(cert_ca.encode('utf-8'))
    idmg = clecert_millegrille.idmg

    return idmg


class ServeurHttp(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        super().__init__(*args, **kwargs)
        self.config: Optional[Config] = None

    def do_GET(self):
        path_request = self.path.split('/')
        try:
            if path_request[1] == 'certissuer':
                self.traiter_get_communs(path_request)
            elif path_request[1] == 'certissuerInterne':
                # Path uniquement accessible de l'interne (network docker)
                self.traiter_get_communs(path_request, interne=True)
            else:
                self.send_error(404)

        except IndexError:
            self.send_error(404)
        except:
            logger.exception("Erreur traitement")
            self.send_error(500)

    def do_POST(self):
        path_request = self.path.split('/')
        try:
            if path_request[1] == 'certissuer':
                self.traiter_post_communs(path_request)
            elif path_request[1] == 'certissuerInterne':
                # Path uniquement accessible de l'interne (network docker)
                self.traiter_post_communs(path_request, interne=True)
            else:
                self.send_error(404)

        except IndexError:
            self.send_error(404)
        except:
            self.send_error(500)

    def traiter_get_communs(self, path_request: list, interne=False):
        requete = path_request[2]
        try:
            if requete == 'csr':
                send_csr(self)
            else:
                self.send_error(404)
        except:
            self.send_error(500)

    def traiter_post_communs(self, path_request: list, interne=False):
        commande = path_request[2]

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)
        try:
            request_data = json.loads(post_body)
        except JSONDecodeError:
            request_data = None

        try:
            if commande == 'issuer':
                set_intermediaire(self, request_data, interne)
            else:
                self.send_error(404)
        except:
            self.__logger.exception("Erreur traitement http")
            self.send_error(500)


def send_csr(http_instance: ServeurHttp):

    try:
        server = http_instance.server
        config = server.config
        csr = charger_csr(config)
        http_instance.send_response(200)
        http_instance.send_header("Content-type", "text/ascii")
        http_instance.send_header("Access-Control-Allow-Origin", "*")
        http_instance.end_headers()
        http_instance.wfile.write(csr)
    except:
        http_instance.send_response(410)
        http_instance.send_header("Content-type", "text/ascii")
        http_instance.send_header("Access-Control-Allow-Origin", "*")
        http_instance.end_headers()
        http_instance.finish()


def set_intermediaire(http_instance: ServeurHttp, request_data: dict, interne=False):
    config = http_instance.server.config

    # Charger le certificat recu, verifier correspondence avec csr
    path_data = config.path_data
    try:
        clecert = charger_clecert(csr=True)
    except FileNotFoundError:
        http_instance.send_error(404)
        return

    chaine_pem: list = request_data['chainePem']
    clecert.cert_from_pem_bytes(''.join(chaine_pem).encode('utf-8'))

    clecert_millegrille = EnveloppeCleCert()
    clecert_millegrille.cert_from_pem_bytes(chaine_pem[-1].encode('utf-8'))
    idmg_recu = clecert_millegrille.idmg
    if config.idmg is not None:
        if config.idmg != idmg_recu:
            # Mauvais idmg, on refuse la cle
            http_instance.send_error(403)
            return

    # Verifier si la cle correspond au certificat
    if clecert.cle_correspondent():

        # Ok, sauvegarder le nouveau certificat, mettre nouvelle cle/password effectifs
        sauvegarder_certificat(config, chaine_pem)
        handler = http_instance.server.handler
        handler.set_intermediaire(clecert)  # Activer cle immediatement

        if interne:
            try:
                csr_monitor = request_data['csr_monitor']
                signer_monitor(handler, csr_monitor)
            except KeyError:
                pass  # Aucun certificat monitor a generer

        http_instance.send_response(200)
    else:
        logger.error("Mismatch cle et cert (csr)")
        http_instance.send_error(400)


def signer_monitor(handler: HandlerCertificats, csr_monitor: str):
    pass


def sauvegarder_certificat(config: Config, chaine: list):
    # Marquer fichiers courantes comme .old
    rotation_courant(config)
    path_data = config.path_data

    path_csr = path.join(path_data, 'config/csr.pem')
    path_csr_key = path.join(path_data, 'secrets/csr.key.pem')
    path_csr_pwd = path.join(path_data, 'secrets/csr.passwd.pem')

    path_current_cert = path.join(path_data, 'config/current.cert.pem')
    path_current_key = path.join(path_data, 'secrets/current.key.pem')
    path_current_pwd = path.join(path_data, 'secrets/current.passwd.pem')

    # Sauvegarder cert, deplacer cle/password csr comme courant
    with open(path_current_cert, 'w') as fichier:
        fichier.write(''.join(chaine))

    rename(path_csr_key, path_current_key)
    rename(path_csr_pwd, path_current_pwd)
    remove(path_csr)


def rotation_courant(config: Config):
    """
    Effectue une rotation des cles, passwd et cert courants (marquer .old)
    :return:
    """
    path_data = config.path_data
    path_current_cert = path.join(path_data, 'config/current.cert.pem')
    path_current_key = path.join(path_data, 'secrets/current.key.pem')
    path_current_pwd = path.join(path_data, 'secrets/current.passwd.pem')

    path_old_cert = path.join(path_data, 'config/old.cert.pem')
    path_old_key = path.join(path_data, 'secrets/old.key.pem')
    path_old_pwd = path.join(path_data, 'secrets/old.passwd.pem')

    for old in [path_old_cert, path_old_key, path_old_pwd]:
        try:
            remove(old)
        except FileNotFoundError:
            pass

    for (current, old) in [(path_current_cert, path_old_cert), (path_current_key, path_old_key), (path_current_pwd, path_old_pwd)]:
        try:
            rename(current, old)
        except FileNotFoundError:
            pass


def charger_clecert(csr=False):
    clecert = EnveloppeCleCert()

    path_data = config.path_data
    path_cert = path.join(path_data, 'config/current.cert.pem')
    if csr is True:
        path_key = path.join(path_data, 'secrets/csr.key.pem')
        path_pwd = path.join(path_data, 'secrets/csr.passwd.pem')
    else:
        path_key = path.join(path_data, 'secrets/current.key.pem')
        path_pwd = path.join(path_data, 'secrets/current.passwd.pem')

    with open(path_key, 'rb') as fichier:
        cle_pem = fichier.read()
    with open(path_pwd, 'rb') as fichier:
        passwd = fichier.read()

    if csr:
        clecert.key_from_pem_bytes(cle_pem, passwd)
    else:
        with open(path_cert, 'rb') as fichier:
            cert_pem = fichier.read()
        clecert.from_pem_bytes(cle_pem, cert_pem, passwd)
        if not clecert.cle_correspondent():
            raise Exception("Mismatch cle/cert")

    return clecert


def charger_csr(config: Config):
    path_data = config.path_data
    path_csr = path.join(path_data, 'config/csr.pem')
    try:
        ctime_csr = path.getctime(path_csr)
        time_courant = time.time()
        if ctime_csr < time_courant - float(24 * 60 * 60):
            csr = generer_csr(config)
        else:
            with open(path_csr, 'rb') as fichier:
                csr = fichier.read()
    except FileNotFoundError:
        # Le fichier CSR n'existe pas. On genere une nouvelle cle/mot de passe et CSR associe
        csr = generer_csr(config)

    return csr


def generer_csr(config: Config):
    path_data = config.path_data
    path_csr = path.join(path_data, 'config/csr.pem')
    path_key = path.join(path_data, 'secrets/csr.key.pem')
    path_pwd = path.join(path_data, 'secrets/csr.passwd.pem')

    # Generer cle, password
    clecert = EnveloppeCleCert()
    clecert.generer_private_key(generer_password=True)

    # Generer CSR
    builder = x509.CertificateSigningRequestBuilder()
    name_list = list()
    name_list.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, u'intermediaire'))
    name_list.append(x509.NameAttribute(x509.name.NameOID.COMMON_NAME, config.noeud_id))

    if config.idmg:
        name_list.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, config.idmg))
    name = x509.Name(name_list)
    builder = builder.subject_name(name)

    request = builder.sign(clecert.private_key, hashes.SHA256(), default_backend())
    csr = request.public_bytes(primitives.serialization.Encoding.PEM)

    with open(path_key, 'wb') as fichier:
        fichier.write(clecert.private_key_bytes)
    with open(path_pwd, 'wb') as fichier:
        fichier.write(clecert.password)
    with open(path_csr, 'wb') as fichier:
        fichier.write(csr)

    return csr


def verifier_eligibilite_renouvellement(clecert: EnveloppeCleCert):
    not_valid_after = clecert.not_valid_after
    not_valid_before = clecert.not_valid_before

    # Calculer 2/3 de la duree du certificat
    delta_2tiers = not_valid_after - not_valid_before
    delta_2tiers = delta_2tiers * 0.67
    date_eligible = not_valid_before + delta_2tiers
    if date_eligible < pytz.utc.localize(datetime.datetime.utcnow()):
        return True

    return False


# class GestionnaireCertificatsNoeudProtegePrincipal(GestionnaireCertificatsNoeudProtegeDependant):
#
#     def __init__(self, docker_client: docker.DockerClient, service_monitor, **kwargs):
#         super().__init__(docker_client, service_monitor, **kwargs)
#         self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
#         self.__renouvelleur: RenouvelleurCertificat = cast(RenouvelleurCertificat, None)
#         self._clecert_intermediaire: EnveloppeCleCert = cast(EnveloppeCleCert, None)
#
#     def generer_clecert_module(self, role: str, common_name: str, nomcle: str = None, liste_dns: list = None, combiner_keycert=False) -> EnveloppeCleCert:
#         if nomcle is None:
#             nomcle = role
#
#         duree_certs = environ.get('CERT_DUREE') or '3'  # Default 3 jours
#         duree_certs = int(duree_certs)
#
#         duree_certs_heures = environ.get('CERT_DUREE_HEURES') or '0'  # Default 0 heures de plus
#         duree_certs_heures = int(duree_certs_heures)
#
#         clecert = self.__renouvelleur.renouveller_par_role(role, common_name, liste_dns, duree_certs, duree_certs_heures)
#         chaine = list(clecert.chaine)
#         chaine_certs = '\n'.join(chaine)
#
#         secret = clecert.private_key_bytes
#
#         # Verifier si on doit combiner le cert et la cle (requis pour Mongo)
#         if combiner_keycert or role in [ConstantesGenerateurCertificat.ROLE_MONGO, ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS]:
#             secret_str = [str(secret, 'utf-8')]
#             secret_str.extend(clecert.chaine)
#             secret = '\n'.join(secret_str).encode('utf-8')
#
#         labels = {'mg_type': 'pki', 'role': role, 'common_name': common_name}
#
#         self.ajouter_secret('pki.%s.key' % nomcle, secret, labels=labels)
#         self.ajouter_config('pki.%s.cert' % nomcle, chaine_certs.encode('utf-8'), labels=labels)
#
#         return clecert
#
#     def charger_certificats(self):
#         secret_path = path.abspath(self.secret_path)
#         os.makedirs(secret_path, exist_ok=True)  # Creer path secret, au besoin
#
#         # Charger information certificat intermediaire
#         config_cert = self._service_monitor.gestionnaire_docker.trouver_config('pki.intermediaire.cert')
#         cert_pem = self._charger_certificat_docker('pki.intermediaire.cert')
#
#         if self._service_monitor.is_dev_mode:
#             path_key = os.path.join(self._service_monitor.path_secrets, 'pki.intermediaire.key.%s' % config_cert['date'])
#             path_passwd = os.path.join(self._service_monitor.path_secrets, 'pki.intermediaire.passwd.%s' % config_cert['date'])
#         else:
#             path_key = os.path.join(self._service_monitor.path_secrets, 'pki.intermediaire.key.pem')
#             path_passwd = os.path.join(self._service_monitor.path_secrets, 'pki.intermediaire.passwd.txt')
#
#         with open(path_key, 'rb') as fichier:
#             key_pem = fichier.read()
#         with open(path_passwd, 'rb') as fichier:
#             passwd_bytes = fichier.read()
#
#         clecert_intermediaire = EnveloppeCleCert()
#         clecert_intermediaire.from_pem_bytes(key_pem, cert_pem, passwd_bytes)
#         clecert_intermediaire.password = None  # Effacer mot de passe
#
#         if not clecert_intermediaire.cle_correspondent():
#             self.__logger.fatal("Certificat et cle intermediaire ne correspondent pas")
#             self._service_monitor.gestionnaire_docker.configurer_monitor()  #  reconfigurer_clecert('pki.intermediaire.cert', True)
#             raise ForcerRedemarrage("Certificat et cle intermediaire mismatch")
#
#         self._clecert_intermediaire = clecert_intermediaire
#
#         # Valider existence des certificats/chaines de base
#         self._charger_certificat_docker('pki.millegrille.cert')
#         self._charger_certificat_docker('pki.intermediaire.cert')
#
#         self.__charger_renouvelleur()
#
#         try:
#             # Charger information certificat monitor
#             config_cert_monitor = self._service_monitor.gestionnaire_docker.trouver_config('pki.monitor.cert')
#             cert_pem = self._charger_certificat_docker('pki.monitor.cert')
#             if self._service_monitor.is_dev_mode:
#                 path_key = os.path.join(self._service_monitor.path_secrets,
#                                         'pki.monitor.key.%s' % config_cert_monitor['date'])
#             else:
#                 path_key = os.path.join(self._service_monitor.path_secrets, 'pki.monitor.key.pem')
#             with open(path_key, 'rb') as fichiers:
#                 key_pem = fichiers.read()
#             clecert_monitor = EnveloppeCleCert()
#             clecert_monitor.from_pem_bytes(key_pem, cert_pem)
#             self.clecert_monitor: EnveloppeCleCert = clecert_monitor
#
#             # Conserver reference au cert monitor pour middleware
#             self.certificats[GestionnaireCertificats.MONITOR_CERT_PATH] = self.certificats['pki.monitor.cert']
#             self.certificats[GestionnaireCertificats.MONITOR_KEY_FILE] = GestionnaireCertificats.MONITOR_KEY_FILENAME + '.pem'
#
#             # with open(path.join(secret_path, ConstantesServiceMonitor.FICHIER_MONGO_MOTDEPASSE), 'r') as fichiers:
#             #     self._passwd_mongo = fichiers.read()
#             # with open(path.join(secret_path, ConstantesServiceMonitor.FICHIER_MQ_MOTDEPASSE), 'r') as fichiers:
#             #     self._passwd_mq = fichiers.read()
#         except Exception:
#             self.__logger.exception("Erreur chargement certificat monitor, il va etre regenere")
#
#     def __charger_renouvelleur(self):
#         dict_ca = {
#             self._clecert_intermediaire.skid: self._clecert_intermediaire.cert,
#             self._clecert_millegrille.skid: self._clecert_millegrille.cert,
#         }
#
#         self.__renouvelleur = RenouvelleurCertificat(self.idmg, dict_ca, self._clecert_intermediaire, generer_password=False)
#
#     def preparer_repertoires(self):
#         mounts = path.join('/var/opt/millegrilles', self.idmg, 'mounts')
#         os.makedirs(mounts, mode=0o770)
#
#     # def generer_nouveau_idmg(self) -> str:
#     #     """
#     #     Generer nouveau trousseau de MilleGrille, incluant cle/cert de MilleGrille, intermediaire et monitor.
#     #     Insere les entrees de configs et secrets dans docker.
#     #     :return: idmg
#     #     """
#     #     generateur_initial = GenerateurInitial(None)
#     #     clecert_intermediaire = generateur_initial.generer()
#     #     clecert_millegrille = generateur_initial.autorite
#     #
#     #     self._clecert_millegrille = clecert_millegrille
#     #     self._clecert_intermediaire = clecert_intermediaire
#     #     self.idmg = clecert_millegrille.idmg
#     #
#     #     # Preparer repertoires locaux pour le noeud
#     #     self.preparer_repertoires()
#     #
#     #     # Conserver la configuration de base pour ServiceMonitor
#     #     configuration = {
#     #         Constantes.CONFIG_IDMG: self.idmg,
#     #         'pem': str(clecert_millegrille.cert_bytes, 'utf-8'),
#     #         Constantes.DOCUMENT_INFODOC_SECURITE: '3.protege',
#     #     }
#     #     configuration_bytes = json.dumps(configuration).encode('utf-8')
#     #     self._docker.configs.create(name='millegrille.configuration', data=configuration_bytes, labels={'idmg': self.idmg})
#     #
#     #     # Sauvegarder certificats, cles et mots de passe dans docker
#     #     self.ajouter_secret(ConstantesServiceMonitor.DOCKER_CONFIG_MILLEGRILLE_KEY, clecert_millegrille.private_key_bytes)
#     #     self.ajouter_secret(ConstantesServiceMonitor.DOCKER_CONFIG_MILLEGRILLE_PASSWD, clecert_millegrille.password)
#     #     self.ajouter_config(ConstantesServiceMonitor.DOCKER_CONFIG_MILLEGRILLE_CERT, clecert_millegrille.cert_bytes)
#     #
#     #     chaine_certs = '\n'.join(clecert_intermediaire.chaine).encode('utf-8')
#     #     self.ajouter_secret(ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY, clecert_intermediaire.private_key_bytes)
#     #     self.ajouter_secret(ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD, clecert_intermediaire.password)
#     #     self.ajouter_config(ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_CERT, clecert_intermediaire.cert_bytes)
#     #     self.ajouter_config(ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_CHAIN, chaine_certs)
#     #
#     #     # Initialiser le renouvelleur de certificats avec le nouveau trousseau
#     #     self.__charger_renouvelleur()
#     #
#     #     # Generer certificat pour monitor
#     #     self.clecert_monitor = self.generer_clecert_module(ConstantesGenerateurCertificat.ROLE_MONITOR, self._nodename)
#     #
#     #     if self._mode_insecure:
#     #         self.sauvegarder_secrets()
#     #
#     #     # Generer mots de passes
#     #     self.generer_motsdepasse()
#     #
#     #     return self.idmg
#
#     # def sauvegarder_secrets(self):
#     #     """
#     #     Sauvegarder le certificat de millegrille sous 'args.secrets' - surtout utilise pour dev (insecure)
#     #     :return:
#     #     """
#     #     secret_path = path.abspath(self.secret_path)
#     #     os.makedirs(secret_path, exist_ok=True)  # Creer path secret, au besoin
#     #
#     #     # Sauvegarder information certificat intermediaire
#     #     with open(path.join(secret_path, ConstantesServiceMonitor.DOCKER_CONFIG_MILLEGRILLE_KEY + '.pem'), 'wb') as fichiers:
#     #         fichiers.write(self._clecert_millegrille.private_key_bytes)
#     #     with open(path.join(secret_path, ConstantesServiceMonitor.DOCKER_CONFIG_MILLEGRILLE_PASSWD + '.txt'), 'wb') as fichiers:
#     #         fichiers.write(self._clecert_millegrille.password)
#     #
#     #     # Sauvegarder information certificat intermediaire
#     #     with open(path.join(secret_path, ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_KEY + '.pem'), 'wb') as fichiers:
#     #         fichiers.write(self._clecert_intermediaire.private_key_bytes)
#     #     with open(path.join(secret_path, ConstantesServiceMonitor.DOCKER_CONFIG_INTERMEDIAIRE_PASSWD + '.txt'), 'wb') as fichiers:
#     #         fichiers.write(self._clecert_intermediaire.password)
#     #
#     #     # Sauvegarder information certificat monitor
#     #     with open(path.join(secret_path, ConstantesServiceMonitor.DOCKER_CONFIG_MONITOR_KEY + '.pem'), 'wb') as fichiers:
#     #         fichiers.write(self.clecert_monitor.private_key_bytes)
#
#     def commande_signer_navigateur(self, commande):
#         """
#         Signe la demande de certificat d'un navigateur
#         :param commande:
#         :return:
#         """
#         self.__logger.debug("Commande signature certificat : %s" % str(commande))
#
#         # Verifier signature du message - doit venir d'un service secure
#         message = commande.message
#         compte = message['compte']
#         enveloppe_certificat = self._service_monitor.validateur_message.verifier(message)
#         securite_commande = enveloppe_certificat.get_exchanges
#         if Constantes.SECURITE_SECURE not in securite_commande:
#             return {'err': 'Permission refusee', 'code': 5}
#
#         duree_certs = environ.get('CERT_DUREE') or '3'  # Defaut 3 jours
#         duree_certs = int(duree_certs)
#         duree_certs_heures = environ.get('CERT_DUREE_HEURES') or '0'  # Default 0 heures de plus
#         duree_certs_heures = int(duree_certs_heures)
#         duree_delta = datetime.timedelta(days=duree_certs, hours=duree_certs_heures)
#
#         # Valider la signature, s'assurer que le certificat permet de faire une demande de signature de certificat
#         contenu = commande.contenu
#         message_commande = commande.message
#         # enveloppe_cert = self._service_monitor.verificateur_transactions.verifier(message_commande)
#         enveloppe_cert = self._service_monitor.validateur_message.verifier(message_commande)
#         idmg = self._service_monitor.idmg
#         # roles_cert = enveloppe_cert.get_roles
#
#         # roles_permis = [
#         #     ConstantesGenerateurCertificat.ROLE_WEB_PROTEGE,
#         #     ConstantesGenerateurCertificat.ROLE_DOMAINES,
#         # ]
#         # est_protege = enveloppe_cert.est_acces_protege(roles_permis)
#
#         try:
#             exchanges = enveloppe_cert.get_exchanges
#         except ExtensionNotFound:
#             exchanges = None
#
#         if enveloppe_cert.subject_organization_name != idmg or Constantes.SECURITE_SECURE not in exchanges:
#             return {
#                 'autorise': False,
#                 'ok': False,
#                 'description': "La signature de la commande de certificat n'est pas faite avec un niveau d'acces approprie"
#             }
#
#         # if enveloppe_cert.subject_organization_name == idmg and est_protege:
#         #     pass
#         # else:
#         #     return {
#         #         'autorise': False,
#         #         'description': 'demandeur non autorise a demander la signateur de ce certificat',
#         #         'roles_demandeur': roles_cert
#         #     }
#
#         csr = contenu['csr'].encode('utf-8')
#         # est_proprietaire = contenu.get('estProprietaire')
#         nom_usager = compte['nomUsager']
#         user_id = compte['userId']
#
#         delegation_globale = compte.get('delegation_globale')
#         delegations_domaines = compte.get('delegations_domaines')
#         if delegations_domaines is not None:
#             delegations_domaines = ','.join(delegations_domaines)
#         delegations_sousdomaines = compte.get('delegations_sousdomaines')
#         if delegations_sousdomaines is not None:
#             delegations_sousdomaines = ','.join(delegations_sousdomaines)
#
#         compte_prive = compte.get(Constantes.ConstantesMaitreDesComptes.CHAMP_COMPTE_PRIVE) or False
#
#         if compte_prive is True:
#             securite = Constantes.SECURITE_PRIVE
#         else:
#             securite = Constantes.SECURITE_PUBLIC
#
#         clecert = self.__renouvelleur.signer_navigateur(
#             csr,
#             securite,
#             duree=duree_delta,
#             nom_usager=nom_usager,
#             user_id=user_id,
#             compte_prive=compte_prive,
#             delegation_globale=delegation_globale,
#             delegations_domaines=delegations_domaines,
#             delegations_sousdomaines=delegations_sousdomaines
#         )
#
#         # Emettre le nouveau certificat pour conserver sous PKI
#         self._service_monitor.generateur_transactions.emettre_certificat(clecert.chaine)
#
#         # Emettre commande activation_tierce si parametre present
#         if contenu.get('activationTierce') is True:
#             # Calculer le fingerprint_pk du certificat
#             fingerprint_pk = clecert.fingerprint_cle_publique
#             # domaine_activation = 'commande.MaitreDesComptes.activationTierce'
#             domaine = 'CoreMaitreDesComptes'
#             action = 'activationTierce'
#             commande_activation = {
#                 'nomUsager': nom_usager,
#                 'userId': user_id,
#                 'fingerprint_pk': fingerprint_pk,
#                 'certificat_pem': clecert.chaine
#             }
#             self._service_monitor.generateur_transactions.transmettre_commande(commande_activation, domaine, action=action)
#
#         return {
#             'cert': clecert.cert_bytes.decode('utf-8'),
#             'fullchain': clecert.chaine,
#         }
#
#     def commande_signer_noeud(self, commande):
#         """
#         Signe la demande de certificat d'un noeud 2.prive ou 1.public
#         :param commande:
#         :return:
#         """
#         self.__logger.debug("Commande signature certificat : %s" % str(commande))
#
#         duree_certs = environ.get('CERT_DUREE') or '3'  # Default 3 jours
#         duree_certs = int(duree_certs)
#         duree_certs_heures = environ.get('CERT_DUREE_HEURES') or '0'  # Default 0 heures de plus
#         duree_certs_heures = int(duree_certs_heures)
#         duree_delta = datetime.timedelta(days=duree_certs, hours=duree_certs_heures)
#
#         # Valider la signature, s'assurer que le certificat permet de faire une demande de signature de certificat
#         contenu = commande.contenu
#         message_commande = commande.message
#         # enveloppe_cert = self._service_monitor.verificateur_transactions.verifier(message_commande)
#
#         try:
#             enveloppe_cert = self._service_monitor.validateur_message.verifier(message_commande)
#         except PathValidationError as pve:
#             self.__logger.error("Refuser signature certificat noeud, erreur de validation de la commande : %s" % pve)
#             raise pve  # Va transmettre un message d'erreur comme reponse
#         except CertificatInconnu as ce:
#             self.__logger.error("commande_signer_noeud Certificat inconnu : %s" % str(ce))
#             return {
#                 'autorise': False,
#                 'description': 'certificat du demande inconnu'
#             }
#
#         idmg = self._service_monitor.idmg
#         roles_cert = enveloppe_cert.get_roles
#
#         roles_permis = [
#             ConstantesGenerateurCertificat.ROLE_WEB_PROTEGE,
#             ConstantesGenerateurCertificat.ROLE_DOMAINES,
#             ConstantesGenerateurCertificat.ROLE_CORE,
#         ]
#         est_protege = enveloppe_cert.est_acces_protege(roles_permis)
#
#         csr_bytes = contenu['csr'].encode('utf-8')
#         # csr = x509.load_pem_x509_csr(csr_bytes, backend=default_backend())
#
#         if enveloppe_cert.subject_organization_name == idmg and est_protege:
#             # On utilise le niveau de securite demande
#             role_noeud = contenu['securite'].split('.')[1]
#         elif ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE in roles_cert:
#             # On utilise le niveau de securite dans le certificat signateur (prive)
#             role_noeud = ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE
#         elif ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC in roles_cert:
#             # On utilise le niveau de securite dans le certificat signateur (public)
#             role_noeud = ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC
#         else:
#             return {
#                 'autorise': False,
#                 'description': 'demandeur non autorise a demander la signateur de ce certificat',
#                 'roles_demandeur': roles_cert
#             }
#
#         try:
#             clecert = self.__renouvelleur.signer_noeud(csr_bytes, role_in=role_noeud, duree=duree_delta)
#         except ValueError as ve:
#             self.__logger.error("Erreur renouvellement noeud, contenu commande : %s" % str(contenu))
#             raise ve
#         else:
#             return {
#                 'cert': clecert.cert_bytes.decode('utf-8'),
#                 'fullchain': clecert.chaine,
#             }
#
#     def renouveller_intermediaire(self, commande):
#         # Valider certificat intermediaire
#         contenu = commande.contenu
#         pem_intermediaire = contenu['pem']
#
#         # Concatener cert millegrille local et nouveau cert intermediaire
#         chaine = self.clecert_monitor.chaine
#         pems = '\n'.join([pem_intermediaire, chaine[-1]]).encode('utf-8')
#
#         # Valider le certificat
#         clecert = EnveloppeCleCert()
#         clecert.cert_from_pem_bytes(pems)
#         validateur_pki = self._service_monitor.validateur_pki
#         try:
#             validateur_pki.valider(pems, usages=set())
#         except Exception as e:
#             self.__logger.exception("Erreur validation nouveau certificat intermediaire")
#             raise e
#
#         # Trouver cle correspondante (date)
#         label_role_cert = 'pki.intermediaire.cert'
#         label_role_key = 'pki.intermediaire.key'
#         info_role_key = self._service_monitor.gestionnaire_docker.trouver_secret(label_role_key)
#         date_key = str(info_role_key['date'])
#
#         # Inserer la chaine de certificat
#         self._service_monitor.gestionnaire_certificats.ajouter_config(label_role_cert, pem_intermediaire.encode('utf-8'), date_key)
#
#         # Supprimer le csr precedent
#         try:
#             self._service_monitor.gestionnaire_docker.supprimer_config('pki.intermediaire.csr.%s' % date_key)
#         except Exception:
#             self.__logger.exception("Erreur suppression CSR du certificat intermediaire")
#
#         # Reconfigurer monitor avec le nouveau certificat intermediaire
#         self._service_monitor.gestionnaire_docker.configurer_monitor()


if __name__ == '__main__':
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    # Init logging
    logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.DEBUG)
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('certissuer').setLevel(logging.INFO)
    logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

    main()
