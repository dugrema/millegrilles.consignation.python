# Programme de signature de certificats
# Expose une interface web sur https://certissuer:8443/certificats
import argparse
import json
import logging
import signal
import time

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
from millegrilles.util.X509Certificate import EnveloppeCleCert


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
        self.clecert: Optional[EnveloppeCleCert] = None


# Creer objet config global, permet de le passer plus facilement au serveur
config = Config()


def main():
    # Parse args en premier, si -h/--help va sortir immediatement
    global config
    parse(config)

    setup(config)

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


def setup(config_in: Config):
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
    global web_server, config, stop_event
    web_server = HTTPServer((host_name, server_port), ServeurHttp)
    web_server.config = config
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


def parse(config_in: Config):
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
        clecert = charger_clecert(config_in)
        config_in.clecert = clecert
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
                set_intermediaire(self, request_data)
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


def set_intermediaire(http_instance: ServeurHttp, request_data: dict):
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

    # Verifier si la cle correspond au certificat
    if clecert.cle_correspondent():
        # Ok, sauvegarder le nouveau certificat, mettre nouvelle cle/password effectifs
        sauvegarder_certificat(config, chaine_pem)
        config.clecert = clecert  # Activer cle immediatement
        http_instance.send_response(200)
    else:
        logger.error("Mismatch cle et cert (csr)")
        http_instance.send_error(400)


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
    path_cert = path.join(path_data, 'config/cert.pem')
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


if __name__ == '__main__':
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    # Init logging
    logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.DEBUG)
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('certissuer').setLevel(logging.INFO)
    logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

    main()
