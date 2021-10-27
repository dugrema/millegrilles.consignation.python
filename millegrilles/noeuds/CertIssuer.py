# Programme de signature de certificats
# Expose une interface web sur https://certissuer:8443/certificats
import argparse
import logging
import signal

from http.server import SimpleHTTPRequestHandler, HTTPServer
from os import environ
from threading import Event, Thread
from typing import Optional

from millegrilles import Constantes


# Variables globales
logger = logging.getLogger('certissuer')

args_parse = None
thread_entretien = None
web_server: Optional[HTTPServer] = None
stop_event = Event()
host_name = "0.0.0.0"
server_port = 80


def main():
    # Parse args en premier, si -h/--help va sortir immediatement
    global args_parse
    args_parse = parse()

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


def executer_serveur():
    global web_server
    web_server = HTTPServer((host_name, server_port), ServeurHttp)
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


def parse():
    # Variables d'environnement
    global host_name, server_port
    host_name = environ.get("HOST") or host_name
    port = environ.get('PORT') or str(server_port)
    server_port = int(port)

    # Ligne de commande
    parser = argparse.ArgumentParser(description="""
Demarre le certissuer de MilleGrilles, gere le certificat intermediare d'une instance protegee
    """)

    parser.add_argument(
        '--verbose', action="store_true", required=False,
        help="Active le logging maximal"
    )

    args_in = parser.parse_args()

    if args_in.verbose:
        logging.getLogger('certissuer').setLevel(logging.DEBUG)
        logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    return args_in


class ServeurHttp(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        super().__init__(*args, **kwargs)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    # Init logging
    logging.basicConfig(format=Constantes.LOGGING_FORMAT, level=logging.DEBUG)
    logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('certissuer').setLevel(logging.INFO)
    logging.getLogger('millegrilles.noeuds').setLevel(logging.INFO)

    main()
