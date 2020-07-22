# Serveur web / API pour le monitor
import logging
import json
import socket

from http.server import SimpleHTTPRequestHandler, HTTPServer
from threading import Thread

from millegrilles.monitor.MonitorConstantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorConstantes import CommandeMonitor

hostName = "0.0.0.0"
serverPort = 8080


class ServerMonitorHttp(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        server = args[2]
        super().__init__(*args, directory=server.webroot, **kwargs)

    @property
    def service_monitor(self):
        return self.server.service_monitor

    def do_GET(self):
        path_request = self.path.split('/')
        try:
            if path_request[2] == 'api':
                self._traiter_get_api()
            else:
                self.path = '/' + '/'.join(path_request[2:])
                super().do_GET()
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
        elif path_split[3] == 'services':
            self.return_services_installes()
        elif path_split[3] == 'etatCertificatWeb':
            self.return_etat_certificat_web()
        else:
            self.error_404()

    def _traiter_post_api(self, request_data):
        path_fichier = self.path
        path_split = path_fichier.split('/')
        if path_split[3] == 'configurerDomaine':
            self.post_configurer_domaine(request_data)
        elif path_split[3] == 'initialisation':
            self.post_initialiser(request_data)
        else:
            self.error_404()

    def return_info_monitor(self):
        dict_infomillegrille = dict()

        nodename = self.service_monitor.nodename
        ip_address = get_ip(nodename)
        dict_infomillegrille['fqdn_detecte'] = nodename
        dict_infomillegrille['ip_detectee'] = ip_address

        idmg = self.service_monitor.idmg
        if idmg:
            dict_infomillegrille['idmg'] = idmg

        gestionnaire_docker = self.service_monitor.gestionnaire_docker

        try:
            configuration_acme = json.loads(gestionnaire_docker.charger_config('acme.configuration'))
            dict_infomillegrille['domaine'] = configuration_acme['domain']
        except IndexError:
            pass

        try:
            configuration_millegrille = json.loads(gestionnaire_docker.charger_config('millegrille.configuration'))
            dict_infomillegrille['securite'] = configuration_millegrille['securite']
        except IndexError:
            pass

        self.repondre_json(dict_infomillegrille)

    def return_services_installes(self):
        gestionnaire_docker = self.service_monitor.gestionnaire_docker
        self.repondre_json(gestionnaire_docker.get_liste_services())

    def post_initialiser(self, request_data):
        logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        logger.debug("POST recu\n%s", json.dumps(request_data, indent=2))

        request_data['commande'] = ConstantesServiceMonitor.COMMANDE_INITIALISER_NOEUD
        commande = CommandeMonitor(request_data)
        self.service_monitor.gestionnaire_commandes.ajouter_commande(commande)

        self.repondre_json(dict(), status_code=200)

    def post_configurer_domaine(self, request_data):
        logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        logger.debug("POST recu\n%s", json.dumps(request_data, indent=2))

        request_data['commande'] = ConstantesServiceMonitor.COMMANDE_CONFIGURER_DOMAINE
        commande = CommandeMonitor(request_data)
        self.service_monitor.gestionnaire_commandes.ajouter_commande(commande)

        reponse = {
            'domaine': request_data['domaine'],
        }
        self.repondre_json(reponse, status_code=200)

    def return_csr(self):
        csr_intermediaire = self.service_monitor.csr_intermediaire
        if csr_intermediaire:
            self.send_response(200)
            self.send_header("Content-type", "text/ascii")
            self.end_headers()
            self.wfile.write(csr_intermediaire)
        else:
            self.send_error(410)

    def return_etat_certificat_web(self):
        gestionnaire_docker = self.service_monitor.gestionnaire_docker
        try:
            config_cert = gestionnaire_docker.charger_config_recente('pki.web.cert')
            etat_cert = {
                'pret': True,
            }
        except AttributeError:
            etat_cert = {
                'pret': False,
            }
        self.repondre_json(etat_cert)

    def repondre_json(self, dict_message: dict, status_code=200):
        info_bytes = json.dumps(dict_message).encode('utf-8')
        self.send_response(status_code)
        self.send_header("Content-type", "application/json")
        self.end_headers()
        self.wfile.write(info_bytes)


class ServerWebAPI:

    def __init__(self, service_monitor, webroot='/var/opt/millegrilles/installeur'):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__thread = Thread(name="WebApi", target=self.run)
        self.__service_monitor = service_monitor
        self.__webroot = webroot
        self.webServer = None

    def start(self):
        self.__thread.start()

    def run(self):
        self.webServer = HTTPServer((hostName, serverPort), ServerMonitorHttp)
        self.webServer.service_monitor = self.__service_monitor
        self.webServer.webroot = self.__webroot
        self.__logger.info("Web API Server started http://%s:%s" % (hostName, serverPort))

        try:
            self.webServer.serve_forever()
        except Exception:
            pass

        self.__logger.info("Web API Server stopped.")

    def server_close(self):
        self.__logger.info("Demande fermeture Web API")
        self.webServer.shutdown()


def get_ip(hostname):

    IP = socket.gethostbyname(hostname)
    if IP.startswith('127.') or IP.startswith('172.'):
        # On n'a pas trouve l'adresse, essayer d'ouvrir un socket pour laisser
        # la table de routage trouver la destination.

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Si on est sur le meme hote (hostname == localhost == 127.0.0.1), essayer de connecter a "l'exterieur"
            # Noter que l'adresse est dummy
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]

            if IP.startswith('127') or IP.startswith('172'):
                # On n'a toujours pas l'adresse, pas bon signe. Derniere chance, revient presque au meme que le 1er test.
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect((hostname, 1))
                IP = s.getsockname()[0]

        except Exception:
            IP = 'ND'
        finally:
            s.close()
    return IP

