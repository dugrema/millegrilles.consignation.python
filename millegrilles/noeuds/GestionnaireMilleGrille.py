# Gestionnaire de MilleGrille
# Responsable de l'installation, mise a jour et health check
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles.util.Daemon import Daemon

import json
import requests_unixsocket


class GestionnaireMilleGrille(Daemon, ModeleConfiguration):
    """
    Noeud gestionnaire d'une MilleGrille. Responsable de l'installation initiale, deploiement, entretient et healthcheck
    """

    def __init__(self):
        self.__pidfile = '/var/run/mg-manager.pid'
        self.__stdout = '/var/logs/mg-manager.log'
        self.__stderr = '/var/logs/mg-manager.err'

        Daemon.__init__(self, self.__pidfile, self.__stdout, self.__stderr)
        ModeleConfiguration.__init__(self)

        self.__docker_socket_path = GestionnaireMilleGrille.__format_url_docker('/var/run/docker.sock')

    def initialiser(self, init_document=False, init_message=False, connecter=False):
        # Initialiser mais ne pas connecter a MQ
        super().initialiser(init_document=init_document, init_message=init_message, connecter=connecter)

    def get_docker_version(self):
        session = requests_unixsocket.Session()
        r = session.get('http+unix://%s/info' % self.__docker_socket_path)
        registry_config = r.json()['RegistryConfig']
        print(json.dumps(registry_config, indent=4))

    @staticmethod
    def __format_url_docker(url):
        return url.replace('/', '%2F')


GestionnaireMilleGrille().get_docker_version()