# Serveur web / API pour le monitor
import logging
import json

from http.server import SimpleHTTPRequestHandler, HTTPServer
from threading import Thread

from millegrilles.monitor.MonitorConstantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorConstantes import CommandeMonitor

hostName = "0.0.0.0"
serverPort = 8080


class ServerMonitorHttp(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='/tmp', **kwargs)
        self.__service_monitor = None

    @property
    def service_monitor(self):
        return self.server.service_monitor

    def do_GET(self):
        path_request = self.path.split('/')
        try:
            if path_request[2] == 'static':
                super().do_GET()
            elif path_request[2] == 'api':
                self._traiter_get_api()
            else:
                self.error_404()
        except IndexError:
            self.error_404()

    def do_POST(self):
        path_fichier = self.path.split('/')

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)
        request_data = json.loads(post_body)

        if path_fichier[2] == 'api':
            self._traiter_post_api(request_data)
        else:
            self.error_404()

    def error_404(self):
        self.send_error(404)

    def _traiter_get_api(self):
        path_fichier = self.path
        path_split = path_fichier.split('/')
        if path_split[3] == 'infoMonitor':
            self.return_info_monitor()
        elif path_split[3] == 'csr':
            self.return_csr()
        else:
            self.error_404()

    def _traiter_post_api(self, request_data):
        path_fichier = self.path
        path_split = path_fichier.split('/')
        if path_split[3] == 'initialisation':
            self.post_initialiser(request_data)
        else:
            self.error_404()

    def return_info_monitor(self):
        dict_infomillegrille = dict()
        dict_infomillegrille['idmg'] = None
        dict_infomillegrille['url_prive'] = 'https://maple.maceroc.com'
        self.repondre_json(dict_infomillegrille)

    def post_initialiser(self, request_data):
        logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        logger.debug("POST recu\n%s", json.dumps(request_data, indent=2))

        request_data['commande'] = ConstantesServiceMonitor.COMMANDE_INITIALISER_NOEUD
        commande = CommandeMonitor(request_data)
        self.service_monitor.gestionnaire_commandes.ajouter_commande(commande)

        self.repondre_json(dict(), status_code=200)

    def return_csr(self):
        csr_intermediaire = self.service_monitor.csr_intermediaire
        if csr_intermediaire:
            self.send_response(200)
            self.send_header("Content-type", "text/ascii")
            self.end_headers()
            self.wfile.write(csr_intermediaire)
        else:
            self.send_error(410)

    def repondre_json(self, dict_message: dict, status_code=200):
        info_bytes = json.dumps(dict_message).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(info_bytes)


class ServerWebAPI:

    def __init__(self, service_monitor):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__thread = Thread(name="WebApi", target=self.run)
        self.__service_monitor = service_monitor
        self.webServer = None

    def start(self):
        self.__thread.start()

    def run(self):
        self.webServer = HTTPServer((hostName, serverPort), ServerMonitorHttp)
        self.webServer.service_monitor = self.__service_monitor
        self.__logger.info("Web API Server started http://%s:%s" % (hostName, serverPort))

        try:
            self.webServer.serve_forever()
        except Exception:
            pass

        self.__logger.info("Web API Server stopped.")

    def server_close(self):
        self.__logger.info("Demande fermeture Web API")
        self.webServer.shutdown()
