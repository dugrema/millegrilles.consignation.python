# Serveur web / API pour le monitor
import logging
import json
import socket

from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, HTTPServer
from threading import Thread
from json.decoder import JSONDecodeError

from millegrilles.monitor.MonitorConstantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorConstantes import CommandeMonitor

from millegrilles.util.IpUtils import get_ip

hostName = "0.0.0.0"
serverPort = 8080


class ServerMonitorHttp(SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        server = args[2]
        super().__init__(*args, directory=server.webroot, **kwargs)

    @property
    def service_monitor(self):
        return self.server.service_monitor

    def do_OPTIONS(self):
        path_supportes = [
            '/installation/api/installer',
            '/installation/api/configurerMQ',
            '/installation/api/configurerDomaine',
        ]
        if self.path in path_supportes:
            self.send_response(HTTPStatus.OK)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Headers", "*")
            self.send_header("Accept", "application/json, text/plain")
            self.end_headers()

    def do_GET(self):
        path_request = self.path.split('/')
        try:
            if self.path == '/installation':
                self.send_response(HTTPStatus.TEMPORARY_REDIRECT)
                self.send_header("Location", '/installation/')
                self.end_headers()
            elif path_request[1] == 'installation':
                if path_request[2] == 'api':
                    self._traiter_get_api()
                else:
                    self.path = '/' + '/'.join(path_request[2:])
                    super().do_GET()
            elif path_request[1] == 'administration':
                # Path qui requiert un certificat client SSL
                self._traiter_administration_GET()
        except IndexError:
            self.error_404()

    def do_POST(self):
        path_fichier = self.path.split('/')

        content_len = int(self.headers.get('content-length', 0))
        post_body = self.rfile.read(content_len)
        try:
            request_data = json.loads(post_body)
        except JSONDecodeError:
            request_data = None

        if path_fichier[1] == 'installation':
            if path_fichier[2] == 'api':
                self._traiter_post_api(request_data)
            else:
                self.error_404()
        elif path_fichier[1] == 'administration':
            self._traiter_administration_POST()

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

        if path_split[3] == 'installer':
            self.post_installer(request_data)
            return

        try:
            service_monitor = self.service_monitor
            if service_monitor.est_verouille:
                # S'assurer que la commande est correctement signee
                try:
                    connexion_middleware = service_monitor.connexion_middleware
                    verificateur_transactions = connexion_middleware.verificateur_transactions
                except AttributeError:
                    verificateur_transactions = service_monitor.verificateur_transactions

                cert = verificateur_transactions.verifier(request_data)

                # S'assurer que le certificat est au moins de niveau protege ou de type navigateur
                if 'navigateur' not in cert.get_roles and not any([s in ['3.protege', '4.secure'] for s in cert.get_exchanges]):
                    return self.repondre_json({'ok': False, 'message': 'Certificat non autorise'}, 401)

        except (AttributeError, KeyError):
            # Non autorise, erreur dans la validation de la commande/signature
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Erreur traitement commande")
            self.repondre_json({'ok': False}, 401)
        else:
            if path_split[3] == 'configurerDomaine':
                self.post_configurer_domaine(request_data)
            elif path_split[3] == 'configurerIdmg':
                self.post_configurer_idmg(request_data)
            elif path_split[3] == 'configurerMQ':
                self.post_configurer_mq(request_data)
            else:
                self.error_404()

    def return_info_monitor(self):
        dict_infomillegrille = self.service_monitor.get_info_monitor()
        self.repondre_json(dict_infomillegrille)

    def return_services_installes(self):
        gestionnaire_docker = self.service_monitor.gestionnaire_docker
        self.repondre_json(gestionnaire_docker.get_liste_services())

    def post_installer(self, request_data):
        logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        logger.debug("post_installer : recu\n%s", json.dumps(request_data, indent=2))

        request_data['commande'] = ConstantesServiceMonitor.COMMANDE_INSTALLER_NOEUD
        commande = CommandeMonitor(request_data)
        self.service_monitor.gestionnaire_commandes.ajouter_commande(commande)

        self.repondre_json(dict(), status_code=200)

    def post_configurer_domaine(self, request_data):
        logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        logger.debug("POST recu configuration domaine\n%s", json.dumps(request_data, indent=2))

        request_data['commande'] = ConstantesServiceMonitor.COMMANDE_CONFIGURER_DOMAINE
        commande = CommandeMonitor(request_data)
        self.service_monitor.gestionnaire_commandes.ajouter_commande(commande)

        reponse = {
            'domaine': request_data['domaine'],
        }
        self.repondre_json(reponse, status_code=200)

    def post_configurer_idmg(self, request_data):
        logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("post_configurer_idmg: POST recu\n%s", json.dumps(request_data, indent=2))

        # S'assurer que le IDMG n'est pas deja configure
        if self.service_monitor.idmg is not None and self.service_monitor.securite is not None:
            logger.error("IDMG et securite deja configure, retourner erreur 403")
            return self.repondre_json({'ok': False, 'idmg': self.service_monitor.idmg}, status_code=403)

        try:
            # Valider input
            reponse = {
                'idmg': request_data['idmg'],
                'securite': request_data['securite'],
            }

            request_data['commande'] = ConstantesServiceMonitor.COMMANDE_CONFIGURER_IDMG
            commande = CommandeMonitor(request_data)
            self.service_monitor.gestionnaire_commandes.ajouter_commande(commande)

            self.repondre_json(reponse, status_code=200)
        except Exception as e:
            self.__logger.exception("post_configurer_idmg: Erreur traitement")
            reponse = {'err': str(e)}
            self.repondre_json(reponse, status_code=500)

    def post_configurer_mq(self, request_data):
        logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("post_configurer_mq: POST recu\n%s", json.dumps(request_data, indent=2))

        try:
            # Valider input
            if request_data.get('host') and request_data.get('port') or request_data.get('supprimer_params_mq'):
                request_data['commande'] = ConstantesServiceMonitor.COMMANDE_CONFIGURER_MQ
                commande = CommandeMonitor(request_data)
                self.service_monitor.gestionnaire_commandes.ajouter_commande(commande)

                self.repondre_json({'ok': True}, status_code=200)
            else:
                self.repondre_json({'ok': False, 'message': 'Params incomplets'}, status_code=500)

        except Exception as e:
            self.__logger.exception("post_configurer_mq: Erreur traitement")
            reponse = {'err': str(e)}
            self.repondre_json(reponse, status_code=500)

    def return_csr(self):
        csr_intermediaire = self.service_monitor.csr_intermediaire
        if csr_intermediaire:
            self.send_response(200)
            self.send_header("Content-type", "text/ascii")
            self.send_header("Access-Control-Allow-Origin", "*")
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
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(info_bytes)

    def _traiter_administration_GET(self):
        if not self.headers.get('VERIFIED') == 'SUCCESS':
            self.__logger.debug("/administration Access refuse, SSL invalide")
            self.send_error(401)
            return

        self.send_response(200)
        self.send_header("Content-type", "text/ascii")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"GET ADMINISTRATION, pas implemente")

    def _traiter_administration_POST(self):
        if not self.headers.get('VERIFIED') == 'SUCCESS':
            self.__logger.debug("/administration Access refuse, SSL invalide")
            self.send_error(401)
            return

        path_fichier = self.path
        path_split = path_fichier.split('/')

        # S'assurer que la verification du certificat client est OK
        if path_split[2] == 'ajouterCompte':
            self.ajouter_compte()
        else:
            self.send_error(404)

    def ajouter_compte(self):
        issuer_dn = self.headers.get('X-Client-Issuer-DN')
        issuer_info = dict()
        for elem in issuer_dn.split(','):
            key, value = elem.split('=')
            issuer_info[key] = value
        idmg_issuer = issuer_info['O']
        headers = self.headers
        try:
            if idmg_issuer == self.service_monitor.idmg:
                cert_pem = self.headers.get('X-Client-Cert')
                cert_pem = cert_pem.replace('\t', '')
                # cert_payload = self.headers.get_payload()
                # cert_pem = cert_pem + '\n' + cert_payload
                self.service_monitor.ajouter_compte(cert_pem)
                self.send_response(200)
            else:
                self.send_response(403)
        except:
            self.send_response(503)

        self.end_headers()
        self.wfile.write(b"")


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

