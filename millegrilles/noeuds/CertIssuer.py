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
from cryptography.x509.extensions import ExtensionNotFound
from json.decoder import JSONDecodeError
from http.server import SimpleHTTPRequestHandler, HTTPServer
from os import environ, makedirs, path, chmod, rename, remove
from threading import Event, Thread
from typing import Optional, Union


from millegrilles import Constantes
from millegrilles.SecuritePKI import EnveloppeCertificat
from millegrilles.util.X509Certificate import EnveloppeCleCert, RenouvelleurCertificat, ConstantesGenerateurCertificat
from millegrilles.util.ValidateursPki import ValidateurCertificat
from millegrilles.util.ValidateursMessages import ValidateurMessage


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
        self.__chaine_certs: Optional[list] = None
        self.__validateur_messages: Optional[ValidateurMessage] = None

    def set_intermediaire(self, clecert: EnveloppeCleCert):
        """
        Changer la cle intermediaire. Valide le certificat intermediaire.
        :param clecert: Cle intermediaire courante
        :raises PathValidationError: Certificat intermediaire invalide
        """
        self.__clecert = clecert
        chaine = clecert.chaine
        cert_ca = chaine.pop()  # retirer le dernier cert (CA) de la chaine
        self.cert_ca = cert_ca

        # Charger cert CA (millegrille), calculer idmg
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(cert_ca.encode('utf-8'))
        idmg = clecert_millegrille.idmg

        self.__chaine_certs = [clecert.cert_bytes.decode('utf-8'), self.cert_ca]

        # Creer instance de validateur de certificats, valider chaine intermediaire
        self.__validateur = ValidateurCertificat(idmg, cert_ca)
        self.__validateur.valider(clecert.chaine, usages={'key_cert_sign'})

        self.__validateur_messages = ValidateurMessage(idmg=idmg, certificat_millegrille=cert_ca)

        # Creer instance de renouvelleur de certificats
        dict_ca = {
            clecert.skid: clecert.cert,
            clecert_millegrille.skid: clecert_millegrille.cert,
        }

        self.__renouvelleur = RenouvelleurCertificat(idmg, dict_ca, clecert, clecert_millegrille)

    def generer_clecert_module(self, role: str, csr: str, liste_dns: list = None) -> EnveloppeCleCert:
        duree_certs = environ.get('CERT_DUREE_MODULE') or environ.get('CERT_DUREE') or '3'  # Default 3 jours
        duree_certs = int(duree_certs)
        duree_certs_heures = environ.get('CERT_DUREE_HEURES') or '0'  # Default 0 heures de plus
        duree_certs_heures = int(duree_certs_heures)

        duree = datetime.timedelta(days=duree_certs, hours=duree_certs_heures)

        noeud_id = self.config.noeud_id
        clecert = self.__renouvelleur.renouveller_avec_csr(role, noeud_id, csr.encode('utf-8'), duree, liste_dns=liste_dns)

        return clecert

    def signer_usager(self, nom_usager: str, user_id: str, csr: str, request_data: dict = None) -> EnveloppeCleCert:
        duree_certs = environ.get('CERT_DUREE_USAGER') or environ.get('CERT_DUREE') or '31'  # Default 31 jours
        duree_certs = int(duree_certs)
        duree_certs_heures = environ.get('CERT_DUREE_HEURES') or '0'  # Default 0 heures de plus
        duree_certs_heures = int(duree_certs_heures)
        duree = datetime.timedelta(days=duree_certs, hours=duree_certs_heures)

        # Parse request data au besoin
        compte_prive = request_data.get('compte_prive')
        delegation_globale = request_data.get('delegation_globale')

        clecert = self.__renouvelleur.signer_usager(
            csr.encode('utf-8'), nom_usager, user_id,
            compte_prive=compte_prive,
            delegation_globale=delegation_globale,
            duree=duree
        )

        return clecert

    def signer_csr(self, csr: str, request_data: dict = None) -> EnveloppeCleCert:
        duree_certs = environ.get('CERT_DUREE_CSR') or environ.get('CERT_DUREE') or '21'  # Default 21 jours
        duree_certs = int(duree_certs)
        duree_certs_heures = environ.get('CERT_DUREE_HEURES') or '0'  # Default 0 heures de plus
        duree_certs_heures = int(duree_certs_heures)
        duree = datetime.timedelta(days=duree_certs, hours=duree_certs_heures)

        # Parse request data au besoin
        try:
            role = request_data.get('role')
        except KeyError:
            role = None
        clecert = self.__renouvelleur.signer_csr(csr.encode('utf-8'), role=role, duree=duree)

        return clecert

    @property
    def chaine_certs(self):
        return self.__chaine_certs

    def verifier_message(self, message: Union[bytes, str, dict]) -> EnveloppeCertificat:
        return self.__validateur_messages.verifier(message)


# Creer objet config global, permet de le passer plus facilement au serveur
config = Config()
handler = HandlerCertificats(config)


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
                self.traiter_post_internes(path_request)
            else:
                self.send_error(404)

        except IndexError:
            self.send_error(404)
        except:
            self.send_error(500)

    def traiter_get_communs(self, path_request: list):
        requete = path_request[2]
        try:
            if requete == 'csr':
                send_csr(self)
            else:
                self.send_error(404)
        except:
            self.send_error(500)

    def traiter_post_communs(self, path_request: list, request_data: dict = None):
        commande = path_request[2]

        if request_data is None:
            content_len = int(self.headers.get('content-length', 0))
            post_body = self.rfile.read(content_len)
            if content_len > 0:
                try:
                    self.__logger.info("traiter_post_communs Contenu recu : %s", post_body)
                    request_data = json.loads(post_body)
                except JSONDecodeError as jde:
                    self.__logger.exception("Erreur decodage request %s (len: %d)" % (path_request, content_len))
                    raise jde
            else:
                request_data = None

        try:
            if commande == 'issuer':
                set_intermediaire(self, request_data, False)
            else:
                self.send_error(404)
        except:
            self.__logger.exception("Erreur traitement http")
            self.send_error(500)

    def traiter_post_internes(self, path_request: list):
        commande = path_request[2]

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)
        if content_len > 0:
            try:
                request_data = json.loads(post_body)
            except JSONDecodeError as jde:
                self.__logger.exception("Erreur decodage request %s (len: %d)" % (path_request, content_len))
                raise jde
        else:
            request_data = None

        try:
            if commande == 'issuer':
                set_intermediaire(self, request_data, True)
            elif commande == 'signerModule':
                signer_module(self, request_data, True)
            elif commande == 'signerUsager':
                signer_usager(self, request_data, True)
            elif commande == 'signerCsr':
                signer_csr(self, request_data, True)
            else:
                self.traiter_post_communs(path_request, request_data=request_data)
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
    except Exception as e:
        logger.exception("Erreur traitement CSR")
        http_instance.send_response(410)
        http_instance.send_header("Content-type", "text/ascii")
        http_instance.send_header("Access-Control-Allow-Origin", "*")
        http_instance.end_headers()
        http_instance.finish()


def set_intermediaire(http_instance: ServeurHttp, request_data: dict, interne=False):
    logger.debug("Set certificat intermediaire (interne: %s): %s" % (interne, request_data))
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

        reponse = {'ok': True}
        if interne:
            try:
                csr_monitor = request_data['csr_monitor']
                clecert_monitor = handler.generer_clecert_module(ConstantesGenerateurCertificat.ROLE_MONITOR, csr_monitor)
                certificat = [clecert_monitor.cert_bytes.decode('utf-8')]
                certificat.extend(handler.chaine_certs)
                certificat.pop()  # Retirer le dernier certificat (root self-signed)
                reponse['certificat_monitor'] = certificat
                reponse['ca'] = handler.cert_ca
            except KeyError:
                pass  # Aucun certificat monitor a generer

        reponse_bytes = json.dumps(reponse).encode('utf-8')

        http_instance.send_response(200)
        http_instance.send_header("Content-type", "application/json")
        http_instance.end_headers()
        http_instance.wfile.write(reponse_bytes)

        # http_instance.send_response(200, json.dumps(reponse))
    else:
        logger.error("Mismatch cle et cert (csr)")
        http_instance.send_error(400)


def signer_module(http_instance: ServeurHttp, request_data: dict, interne=False):

    if interne is False:
        logger.warning("Erreur - signer_module demande externe - REFUSE")
        http_instance.send_error(403)
        return

    handler = http_instance.server.handler

    # Verifier signature de la requete
    enveloppe_certificat: EnveloppeCertificat = handler.verifier_message(request_data)

    # Aucune exception, la signature est valide
    if 'monitor' not in enveloppe_certificat.get_roles:
        logger.warning("Erreur - signer_module demande avec certificat autre que monitor - REFUSE")
        http_instance.send_error(403)
        return

    csr = request_data['csr']
    role = request_data['role']
    liste_dns = request_data['liste_dns']

    logger.info("Signer nouveau certificat %s" % role)

    clecert_module = handler.generer_clecert_module(role, csr, liste_dns)
    certificat = [clecert_module.cert_bytes.decode('utf-8')]
    certificat.extend(handler.chaine_certs)
    certificat.pop()  # Retirer le dernier certificat (root self-signed)
    reponse = {
        'ok': True,
        'certificat': certificat,
        'ca': handler.cert_ca
    }
    reponse_bytes = json.dumps(reponse).encode('utf-8')

    http_instance.send_response(200)
    http_instance.send_header("Content-type", "application/json")
    http_instance.end_headers()
    http_instance.wfile.write(reponse_bytes)


def signer_usager(http_instance: ServeurHttp, request_data: dict, interne=False):

    if interne is False:
        logger.warning("Erreur - signer_usager demande externe - REFUSE")
        http_instance.send_error(403)
        return

    handler: HandlerCertificats = http_instance.server.handler

    # Verifier signature de la requete
    enveloppe_certificat: EnveloppeCertificat = handler.verifier_message(request_data)

    # Aucune exception, la signature est valide
    if 'core' not in enveloppe_certificat.get_roles:
        logger.warning("Erreur - signer_usager demande avec certificat autre que core - REFUSE")
        http_instance.send_error(403)
        return

    csr = request_data['csr']
    nom_usager = request_data['nom_usager']
    user_id = request_data['user_id']

    logger.info("Signer nouveau certificat usager %s (user_id: %s)" % (nom_usager, user_id))

    clecert_module = handler.signer_usager(nom_usager, user_id, csr, request_data)
    certificat = [clecert_module.cert_bytes.decode('utf-8')]
    certificat.extend(handler.chaine_certs)
    reponse = {
        'ok': True,
        'certificat': certificat,
        'ca': handler.cert_ca,
    }
    reponse_bytes = json.dumps(reponse).encode('utf-8')

    http_instance.send_response(200)
    http_instance.send_header("Content-type", "application/json")
    http_instance.end_headers()
    http_instance.wfile.write(reponse_bytes)


def signer_csr(http_instance: ServeurHttp, request_data: dict, interne=False):

    if interne is False:
        logger.warning("Erreur - signer_csr demande externe - REFUSE")
        http_instance.send_error(403)
        return

    handler: HandlerCertificats = http_instance.server.handler

    # Verifier signature de la requete
    enveloppe_certificat: EnveloppeCertificat = handler.verifier_message(request_data)

    # Aucune exception, la signature est valide. Verifier autorisation.
    try:
        delegation_globale = enveloppe_certificat.get_delegation_globale
    except ExtensionNotFound:
        delegation_globale = None
    try:
        roles = enveloppe_certificat.get_roles
    except ExtensionNotFound:
        roles = None

    if 'proprietaire' == delegation_globale:
        pass  # Delegation globale, signature est autorisee
    else:
        # On doit s'assurer que c'est un renouvellement - e.g. prive peut renouveller prive, public => public, etc.
        role = request_data['role']
        if role not in roles:
            logger.warning("Erreur - signer_module demande avec certificat autre que core - REFUSE")
            http_instance.send_error(403)
            return

    csr = request_data['csr']

    logger.info("Signer nouveau certificat via CSR")

    clecert_module = handler.signer_csr(csr, request_data)
    certificat = [clecert_module.cert_bytes.decode('utf-8')]
    certificat.extend(handler.chaine_certs)
    reponse = {
        'ok': True,
        'certificat': certificat,
        'ca': handler.cert_ca,
    }
    reponse_bytes = json.dumps(reponse).encode('utf-8')

    http_instance.send_response(200)
    http_instance.send_header("Content-type", "application/json")
    http_instance.end_headers()
    http_instance.wfile.write(reponse_bytes)


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

    request = builder.sign(clecert.private_key, None, default_backend())
    # request = builder.sign(clecert.private_key, hashes.SHA256(), default_backend())
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


PROFIL_PAR_ROLE = {
    ConstantesGenerateurCertificat.ROLE_MQ: {},
    ConstantesGenerateurCertificat.ROLE_MONGO: {},
    ConstantesGenerateurCertificat.ROLE_MAITREDESCLES: {},
    ConstantesGenerateurCertificat.ROLE_CORE: {},
    ConstantesGenerateurCertificat.ROLE_COLLECTIONS: {},
    ConstantesGenerateurCertificat.ROLE_FICHIERS: {},
    ConstantesGenerateurCertificat.ROLE_GROS_FICHIERS: {},
    ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS: {},
    ConstantesGenerateurCertificat.ROLE_NAVIGATEUR: {},
    ConstantesGenerateurCertificat.ROLE_WEB_PROTEGE: {},
    ConstantesGenerateurCertificat.ROLE_AGENT_BACKUP: {},
    ConstantesGenerateurCertificat.ROLE_NGINX: {},
    ConstantesGenerateurCertificat.ROLE_VITRINE: {},
    ConstantesGenerateurCertificat.ROLE_MONITOR: {},
    ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE: {},
    ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC: {},
    ConstantesGenerateurCertificat.ROLE_SENSEURSPASSIFS: {},
    ConstantesGenerateurCertificat.ROLE_MEDIA: {},
}


def main():
    # Parse args en premier, si -h/--help va sortir immediatement
    global config, handler

    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    # Init logging
    logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.DEBUG)
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('certissuer').setLevel(logging.INFO)
    logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

    parse(config, handler)
    setup(config, handler)

    # Demarrer thread d'entretien
    global thread_entretien
    thread_entretien = Thread(name="entretien", target=entretien, daemon=True)
    thread_entretien.start()

    executer()


if __name__ == '__main__':
    main()
