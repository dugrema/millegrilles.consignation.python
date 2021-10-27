# Programme de signature de certificats
# Expose une interface web sur https://certissuer:8443/certificats
import argparse
import logging
import signal
import time

from http import HTTPStatus
from cryptography import x509
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from http.server import SimpleHTTPRequestHandler, HTTPServer
from os import environ, makedirs, path, chmod
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
    logger.info("Demarrage certissuer sur port http %d" % server_port)

    thread_server = Thread(name="web_server", target=executer_serveur)
    thread_server.start()

    # Conserver la thread main active (sert a recevoir les 'signal')
    while not stop_event.is_set():
        stop_event.wait(300)

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
    global web_server, config
    web_server = HTTPServer((host_name, server_port), ServeurHttp)
    web_server.config = config
    web_server.serve_forever()

    if not stop_event.is_set():
        logger.warning("Serveur HTTP a cesse son execution")

    # S'assurer que le serveur va fermer
    stop_event.set()


def exit_gracefully(signum=None, frame=None):
    logger.info("Fermer sur signal: %d" % signum)
    stop_event.set()
    global web_server
    web_server.shutdown()


def entretien():
    stop_event.wait(15)  # Attente initiale
    while not stop_event.is_set():
        logger.debug("Cycle entretien")
        stop_event.wait(30)


def parse(config_in: Config):
    # Variables d'environnement
    global host_name, server_port
    host_name = environ.get("HOST") or host_name
    port = environ.get('PORT') or str(server_port)
    server_port = int(port)
    config_in.idmg = environ.get("IDMG")
    config_in.path_data = environ.get("PATH_DATA") or config_in.path_data

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
        self.config: Optional[dict] = None

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
