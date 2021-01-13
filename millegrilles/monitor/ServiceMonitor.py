import argparse
import signal
import logging
import sys
import docker
import json
import datetime
import os
import psutil
import tarfile
import io
import lzma

from typing import cast, Optional
from threading import Event, BrokenBarrierError
from docker.errors import APIError
from base64 import b64decode

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificats, \
    GestionnaireCertificatsNoeudProtegeDependant, GestionnaireCertificatsNoeudProtegePrincipal, \
    GestionnaireCertificatsInstallation, GestionnaireCertificatsNoeudPrive, GestionnaireCertificatsNoeudPublic
from millegrilles.monitor.MonitorCommandes import GestionnaireCommandes, GestionnaireCommandesNoeudProtegeDependant
from millegrilles.monitor.MonitorComptes import GestionnaireComptesMQ
from millegrilles.monitor.MonitorConstantes import ForcerRedemarrage
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker
from millegrilles.monitor.MonitorRelaiMessages import ConnexionPrincipal, ConnexionMiddleware, \
    ConnexionMiddlewarePrive, ConnexionMiddlewareProtege, ConnexionMiddlewarePublic
from millegrilles.monitor.MonitorNetworking import GestionnaireWeb
from millegrilles.util.X509Certificate import EnveloppeCleCert, \
    ConstantesGenerateurCertificat
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorApplications import GestionnaireApplications
from millegrilles.monitor.MonitorWebAPI import ServerWebAPI
from millegrilles.monitor.MonitorConstantes import CommandeMonitor, PkiCleNonTrouvee
from millegrilles.util.IpUtils import get_ip
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.ValidateursPki import ValidateurCertificat

class InitialiserServiceMonitor:

    def __init__(self):
        self.__docker: docker.DockerClient = cast(docker.DockerClient, None)  # Client docker
        self.__args = None
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._configuration_json = None

    def __parse(self):
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
            '--secrets', type=str, required=False, default="/run/secrets",
            help="Repertoire de secrets"
        )

        parser.add_argument(
            '--configs', type=str, required=False, default="/etc/opt/millegrille",
            help="Repertoire de configuration"
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
            '--pipe', type=str, required=False, default=MonitorConstantes.PATH_FIFO,
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

        parser.add_argument(
            '--webroot', type=str, required=False, default='/var/opt/millegrilles/installation',
            help="Path du webroot de l'installeur"
        )

        self.__args = parser.parse_args()

        # Appliquer args
        if self.__args.debug:
            logging.getLogger('__main__').setLevel(logging.DEBUG)
            logging.getLogger('millegrilles').setLevel(logging.DEBUG)
            self.__logger.setLevel(logging.DEBUG)
        elif self.__args.info:
            logging.getLogger('__main__').setLevel(logging.INFO)
            logging.getLogger('millegrilles').setLevel(logging.INFO)

        self.__logger.info("Arguments: %s", self.__args)

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

    def detecter_type_noeud(self):
        self.__parse()
        self.__connecter_docker()

        try:
            config_securite = self.__docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_SECURITE)
            securite = b64decode(config_securite.attrs['Spec']['Data']).decode('utf-8').strip()
            self.__logger.debug("Niveau de securite millegrille : %s" % securite)

            # Verifier si on a le cert de monitor - indique que noeud est configure et completement installe
            # Lance une exception si aucune configuration ne commence par pki.monitor.cert
            # monitor_cert = self.__docker.configs.list(filters={'name': 'pki.monitor.cert'})[0]

            if securite == '1.public':
                self.__logger.info("Noeud public")
                service_monitor_classe = ServiceMonitorPublic
            elif securite == Constantes.SECURITE_PRIVE:
                self.__logger.info("Noeud prive")
                service_monitor_classe = ServiceMonitorPrive
            elif securite == Constantes.SECURITE_PROTEGE:
                service_monitor_classe = ServiceMonitorPrincipal
            else:
                raise ValueError("Noeud de type non reconnu")
        except (docker.errors.NotFound, IndexError):
            self.__logger.info("Config millegrille.configuration n'existe pas, le noeud est demarre en mode d'installation")
            service_monitor_classe = ServiceMonitorInstalleur

        return service_monitor_classe

    def demarrer(self):
        class_noeud = self.detecter_type_noeud()
        self.__logger.info("Chargement d'un monitor type %s", class_noeud.__name__)

        service_monitor = class_noeud(self.__args, self.__docker, self._configuration_json)
        service_monitor.run()


class ServiceMonitor:
    """
    Service deploye dans un swarm docker en mode global qui s'occupe du deploiement des autres modules de la
    MilleGrille et du renouvellement des certificats. S'occupe de configurer les comptes RabbitMQ et MongoDB.

    Supporte aussi les MilleGrilles hebergees par l'hote.
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self._args = args                                       # Arguments de la ligne de commande
        self._docker: docker.DockerClient = docker_client       # Client docker
        self._configuration_json = configuration_json           # millegrille.configuration dans docker

        # self._securite: Optional[str] = None                    # Niveau de securite de la swarm docker
        # self._role: Optional[str] = None                        # Role pour les certificats (e.g. prive, public)
        self._connexion_middleware: Optional[ConnexionMiddleware] = None  # Connexion a MQ, MongoDB
        self._noeud_id: Optional[str] = None                    # UUID du noeud
        self._idmg: Optional[str] = None                        # IDMG de la MilleGrille hote

        self._socket_fifo = None  # Socket FIFO pour les commandes

        self._fermeture_event = Event()
        self._attente_event = Event()

        self._gestionnaire_certificats: Optional[GestionnaireCertificats] = None
        self._gestionnaire_docker: Optional[GestionnaireModulesDocker] = None
        self._gestionnaire_mq: Optional[GestionnaireComptesMQ] = None
        self._gestionnaire_commandes: Optional[GestionnaireCommandes] = None
        self._gestionnaire_web: Optional[GestionnaireWeb] = None
        self._gestionnaire_applications: Optional[GestionnaireApplications] = None

        self._web_api: ServerWebAPI = cast(ServerWebAPI, None)

        self.limiter_entretien = True

        self._nodename = self._docker.info()['Name']            # Node name de la connexion locale dans Docker

        # Delais entretien pour differents modules et services
        self._certificats_entretien_date = None
        # self._certificats_entretien_frequence = datetime.timedelta(minutes=5)
        self._certificats_entretien_frequence = datetime.timedelta(seconds=30)
        self._web_entretien_date = None
        self._web_entretien_frequence = datetime.timedelta(minutes=2)

        # self._verificateur_transactions: Optional[VerificateurTransaction] = None
        self.__validateur_message: Optional[ValidateurMessage] = None

        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.fermer)
        signal.signal(signal.SIGTERM, self.fermer)

        self.exit_code = 0

    def fermer(self, signum=None, frame=None):
        if signum:
            self.__logger.warning("Fermeture ServiceMonitor, signum=%d", signum)
        if not self._fermeture_event.is_set():
            self._fermeture_event.set()
            self._attente_event.set()
            try:
                self._web_api.server_close()
            except Exception:
                self.__logger.debug("Erreur fermeture web_api")
                if self.__logger.isEnabledFor(logging.DEBUG):
                    self.__logger.exception('Erreur fermeture Web API')

            try:
                self._connexion_middleware.stop()
            except Exception:
                pass

            try:
                self._docker.close()
            except Exception:
                pass

            try:
                self._gestionnaire_docker.fermer()
            except Exception:
                pass

            # Cleanup fichiers temporaires de certificats/cles
            try:
                for fichier in self._gestionnaire_certificats.certificats.values():
                    os.remove(fichier)
            except Exception:
                pass

            try:
                if self._gestionnaire_commandes:
                    self._gestionnaire_commandes.stop()
            except Exception:
                self.__logger.exception("Erreur fermeture gestionnaire commandes")

            try:
                os.remove(MonitorConstantes.PATH_FIFO)
            except Exception:
                pass

    def connecter_middleware(self):
        """
        Genere un contexte et se connecte a MQ et MongoDB.
        Lance une thread distincte pour s'occuper des messages.
        :return:
        """
        raise NotImplementedError()

    def preparer_gestionnaire_certificats(self):
        raise NotImplementedError()

    def preparer_gestionnaire_comptesmq(self):
        mode_insecure = self._args.dev
        path_secrets = self._args.secrets
        self._gestionnaire_mq = GestionnaireComptesMQ(
            self._idmg, self._gestionnaire_certificats.clecert_monitor, self._gestionnaire_certificats.certificats,
            host=self._nodename, secrets=path_secrets, insecure=mode_insecure
        )

    def preparer_gestionnaire_commandes(self):
        try:
            os.mkfifo(self._args.pipe)
        except FileExistsError:
            self.__logger.debug("Pipe %s deja cree", self._args.pipe)

        os.chmod(MonitorConstantes.PATH_FIFO, 0o620)

        # Verifier si on doit creer une instance (utilise pour override dans sous-classe)
        if self._gestionnaire_commandes is None:
            self._gestionnaire_commandes = GestionnaireCommandes(self._fermeture_event, self)

        self._gestionnaire_commandes.start()

    def preparer_gestionnaire_applications(self):
        if not self._gestionnaire_applications:
            self._gestionnaire_applications = GestionnaireApplications(
                self,
                self._gestionnaire_docker
            )

    def preparer_web_api(self):
        self._web_api = ServerWebAPI(self, webroot=self._args.webroot)
        self._web_api.start()

    def get_info_monitor(self, inclure_services=False):
        dict_infomillegrille = dict()

        nodename = self.nodename
        ip_address = get_ip(nodename)
        dict_infomillegrille['fqdn_detecte'] = nodename
        dict_infomillegrille['ip_detectee'] = ip_address
        dict_infomillegrille['noeud_id'] = self.noeud_id

        gestionnaire_docker = self.gestionnaire_docker

        idmg = self.idmg
        if idmg:
            dict_infomillegrille['idmg'] = idmg
        else:
            try:
                idmg = gestionnaire_docker.charger_config(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_IDMG).decode(
                    'utf-8').strip()
                dict_infomillegrille['idmg'] = idmg
            except IndexError:
                pass

        try:
            configuration_acme = json.loads(gestionnaire_docker.charger_config('acme.configuration'))
            dict_infomillegrille['domaine'] = configuration_acme['domain']
        except IndexError:
            pass

        try:
            securite = gestionnaire_docker.charger_config(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_SECURITE).decode('utf-8').strip()
            dict_infomillegrille['securite'] = securite
        except IndexError:
            pass

        # Verifier si on a le certificat de monitor - indique que le noeud est installe
        try:
            monitor_cert = gestionnaire_docker.charger_config_recente('pki.monitor.cert')
            monitor_cert = b64decode(monitor_cert['config'].attrs['Spec']['Data']).decode('utf-8')
            dict_infomillegrille['certificat'] = monitor_cert
        except (IndexError, AttributeError):
            self.__logger.info("Certificat de monitor n'existe pas")

        if inclure_services:
            dict_infomillegrille['services'] = gestionnaire_docker.get_liste_services()
            dict_infomillegrille['containers'] = gestionnaire_docker.get_liste_containers()

        # Charger la liste des applications configurees (config app.cfg.*)
        apps = gestionnaire_docker.charger_configs('app.cfg.')
        config_apps = list()
        for app in apps:
            app_config = json.loads(app['configuration'].decode('utf-8'))
            config_apps.append({'nom': app_config['nom'], 'version': app_config['version']})

        dict_infomillegrille['applications_configurees'] = config_apps

        return dict_infomillegrille

    def _charger_configuration(self):
        # classe_configuration = self._classe_configuration()
        try:
            # Charger l'identificateur de noeud
            configuration_docker = self._docker.configs.get(ConstantesServiceMonitor.DOCKER_CONFIG_NOEUD_ID)
            data = b64decode(configuration_docker.attrs['Spec']['Data'])
            self._noeud_id = data.decode('utf-8')
        except docker.errors.NotFound as he:
            self.__logger.info("configuration: Noeud Id n'existe pas")

        try:
            idmg_config = self._docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_IDMG)
            self._idmg = b64decode(idmg_config.attrs['Spec']['Data']).decode('utf-8').strip()
        except docker.errors.NotFound:
            self.__logger.info("configuration: IDMG n'est pas encore configure")

        try:
            securite_config = self._docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_SECURITE)
            securite = b64decode(securite_config.attrs['Spec']['Data']).decode('utf-8').strip()
            self.__logger.debug("Configuration noeud, idmg: %s, securite: %s", self._idmg, securite)
        except docker.errors.NotFound:
            self.__logger.info("configuration: Niveau de securite n'est pas encore configure")

    def _classe_configuration(self):
        """
        Retourne la classe de gestion de certificat
        :return: Sous-classe de GestionnaireCertificats
        """
        raise NotImplementedError()

    def _entretien_certificats(self):
        """
        Effectue l'entretien des certificats : genere certificats manquants ou expires avec leur cle
        :return:
        """
        # MAJ date pour creation de certificats
        self._gestionnaire_certificats.maj_date()

        info_monitor = self.get_info_monitor()
        fqdn_noeud = info_monitor['fqdn_detecte']
        try:
            domaine_noeud = info_monitor['domaine']
        except KeyError:
            domaine_noeud = fqdn_noeud

        # prefixe_certificats = 'pki.'
        # filtre = {'name': prefixe_certificats}
        #
        # # Generer tous les certificas qui peuvent etre utilises
        # roles = dict()
        # for role in [info['role'] for info in MonitorConstantes.DICT_MODULES_PROTEGES.values() if info.get('role')]:
        #     roles[role] = dict()
        #
        # date_courante = datetime.datetime.utcnow()
        #
        # for config in self._docker.configs.list(filters=filtre):
        #     self.__logger.debug("Config : %s", str(config))
        #     nom_config = config.name.split('.')
        #     nom_role = nom_config[1]
        #     if nom_config[2] == 'cert' and nom_role in roles.keys():
        #         role_info = roles[nom_role]
        #         self.__logger.debug("Verification cert %s date %s", nom_role, nom_config[3])
        #         pem = b64decode(config.attrs['Spec']['Data'])
        #         clecert = EnveloppeCleCert()
        #         clecert.cert_from_pem_bytes(pem)
        #         date_expiration = clecert.not_valid_after
        #
        #         if date_expiration:
        #             role_info['expiration'] = date_expiration
        #
        #             # Calculer 2/3 de la duree du certificat
        #             not_valid_before = clecert.not_valid_before
        #             delta_fin_debut = date_expiration.timestamp() - not_valid_before.timestamp()
        #             epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
        #             date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers)
        #
        #             # Verifier si on renouvelle
        #             if date_renouvellement < date_courante:
        #                 role_info['est_expire'] = True
        #             else:
        #                 role_info['est_expire'] = False
        #
        #             # Verifier si on supprime
        #             if date_expiration < date_courante:
        #                 # Le certificat n'est plus valide, on le supprime immediatement
        #                 try:
        #                     config.remove()
        #                     self.__logger.info("Certificat expire (%s) a ete supprime : %s" % (date_expiration, config.name))
        #                 except Exception:
        #                     self.__logger.exception("Erreur suppression certificat expire (%s) de config : %s" % (date_expiration, config.name))

        # Entretien des certificats services
        roles = [info['role'] for info in MonitorConstantes.DICT_MODULES_PROTEGES.values() if info.get('role')]
        resultat_entretien_certificats = self._supprimer_certificats_expires(roles)

        # Generer certificats expires et manquants
        for nom_role, info_role in resultat_entretien_certificats.items():
            if not info_role.get('expiration') or info_role.get('est_expire'):
                self.__logger.debug("Generer nouveau certificat role %s", nom_role)
                self._gestionnaire_certificats.generer_clecert_module(
                    nom_role, self._nodename, liste_dns=[fqdn_noeud, domaine_noeud])

                # Reconfigurer tous les services qui utilisent le nouveau certificat
                self._gestionnaire_docker.maj_services_avec_certificat(nom_role)

        # Nettoyer certificats monitor
        self._supprimer_certificats_expires(['monitor'])

        # Entretien certificats applications
        self._entretien_certificats_applications()

    def _entretien_certificats_applications(self):
        prefixe_certificats = 'pki.'
        filtre = {
            'name': prefixe_certificats,
            'label': ['mg_type=pki', 'role=application']
        }
        nom_applications = dict()
        for config in self._docker.configs.list(filters=filtre):
            labels = config.attrs['Spec']['Labels']
            app_name = labels['common_name']
            nom_applications[app_name] = labels

        # Supprimer les certificats expires, renouveller si possible (ok si echec)
        liste_apps = list(nom_applications.keys())
        resultat_suppression = self._supprimer_certificats_expires(liste_apps)

        info_monitor = self.get_info_monitor()
        fqdn_noeud = info_monitor['fqdn_detecte']
        try:
            domaine_noeud = info_monitor['domaine']
        except KeyError:
            domaine_noeud = fqdn_noeud

        # Renouveller certificats expires
        # Generer certificats expires et manquants
        for nom_role, info_role in resultat_suppression.items():
            if not info_role.get('expiration') or info_role.get('est_expire'):
            # if True:
                self.__logger.debug("Generer nouveau certificat role %s", nom_role)
                self._gestionnaire_certificats.generer_clecert_module(
                    ConstantesGenerateurCertificat.ROLE_APPLICATION_PRIVEE,
                    nom_role,
                    nom_role,
                    liste_dns=[fqdn_noeud, domaine_noeud, nom_role + '.' + domaine_noeud]
                )

                # Reconfigurer tous les services qui utilisent le nouveau certificat
                self._gestionnaire_docker.maj_services_avec_certificat(nom_role)

    def _supprimer_certificats_expires(self, roles_entretien: list):
        prefixe_certificats = 'pki.'
        filtre = {'name': prefixe_certificats}

        # Generer tous les certificas qui peuvent etre utilises
        roles = dict()
        for role in roles_entretien:
            roles[role] = {
                'est_expire': True,
            }

        date_courante = datetime.datetime.utcnow()

        for config in self._docker.configs.list(filters=filtre):
            self.__logger.debug("Config : %s", str(config))
            nom_config = config.name.split('.')
            nom_role = nom_config[1]
            if nom_config[2] == 'cert' and nom_role in roles_entretien:
                role_info = roles[nom_role]
                self.__logger.debug("Verification cert %s date %s", nom_role, nom_config[3])
                pem = b64decode(config.attrs['Spec']['Data'])
                clecert = EnveloppeCleCert()
                clecert.cert_from_pem_bytes(pem)
                date_expiration = clecert.not_valid_after

                if date_expiration is not None:
                    role_info['expiration'] = date_expiration

                    # Calculer 2/3 de la duree du certificat
                    not_valid_before = clecert.not_valid_before
                    delta_fin_debut = date_expiration.timestamp() - not_valid_before.timestamp()
                    epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
                    date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers)

                    # Verifier si on renouvelle
                    if date_renouvellement < date_courante:
                        role_info['est_expire'] = True
                    else:
                        role_info['est_expire'] = False

                    # Verifier si on supprime
                    if date_expiration < date_courante:
                        # Le certificat n'est plus valide, on le supprime immediatement
                        try:
                            config.remove()
                            self.__logger.info(
                                "Certificat expire (%s) a ete supprime : %s" % (date_expiration, config.name))
                        except Exception:
                            self.__logger.exception("Erreur suppression certificat expire (%s) de config : %s" % (
                            date_expiration, config.name))
                else:
                    # Le certificat n'a pas de date d'expiration (invalide)
                    role_info['est_expire'] = True

        return roles

    def _entretien_secrets_pki(self, prefixe_filtre='pki.'):
        """
        Supprime les secrets qui ne sont plus associes a une config pki.MODULE.cert.DATE (ou csr)
        :return:
        """
        filtre = {'name': prefixe_filtre}
        for secret in self._docker.secrets.list(filters=filtre):
            name_secret = secret.name
            name_split = name_secret.split('.')
            nom_module = name_split[1]
            date_secret = name_split[3]

            nom_config = '.'.join(['pki', nom_module, 'cert', date_secret])
            try:
                self._docker.configs.get(nom_config)
            except docker.errors.NotFound:
                nom_config = '.'.join(['pki', nom_module, 'csr', date_secret])
                try:
                    self._docker.configs.get(nom_config)
                    self.__logger.debug("Secret non associe a config, supprimer : %s" % name_secret)
                except docker.errors.NotFound:
                    try:
                        secret.remove()
                    except APIError as apie:
                        if apie.status_code == 400:
                            # Ok, le secret est toujours en utilisation
                            pass
                        else:
                            raise apie
                except Exception:
                    self.__logger.exception("Erreur suppression secret non associe a config : %s" % name_secret)

    def configurer_millegrille(self):
        besoin_initialiser = not self._idmg

        if besoin_initialiser:
            # Generer certificat de MilleGrille
            self._idmg = self._gestionnaire_certificats.generer_nouveau_idmg()

        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_PRIMAIRE.copy(),
            self,
            insecure=self._args.dev,
            secrets=self._args.secrets
        )
        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)

        if besoin_initialiser:
            self._gestionnaire_docker.initialiser_millegrille()

            # Modifier service docker du service monitor pour ajouter secrets
            self._gestionnaire_docker.configurer_monitor()
            self.fermer()  # Fermer le monitor, va forcer un redemarrage du service
            raise ForcerRedemarrage("Redemarrage")

        # Initialiser gestionnaire web
        self._gestionnaire_web = GestionnaireWeb(self, mode_dev=self._args.dev)

    def _entretien_modules(self):
        if not self.limiter_entretien:
            # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
            self._gestionnaire_docker.entretien_services()

            # Entretien du middleware
            self._gestionnaire_mq.entretien()

            # Entretien web
            if self._web_entretien_date is None or \
                    self._web_entretien_date + self._web_entretien_frequence < datetime.datetime.utcnow():
                self._web_entretien_date = datetime.datetime.utcnow()
                self._gestionnaire_web.entretien()

            # Entretien des certificats du monitor, services
            if self._certificats_entretien_date is None or \
                    self._certificats_entretien_date + self._certificats_entretien_frequence < datetime.datetime.utcnow():

                self._certificats_entretien_date = datetime.datetime.utcnow()
                self._entretien_certificats()
                self._entretien_secrets_pki()

    def run(self):
        raise NotImplementedError()

    def verifier_load(self):
        cpu_load, cpu_load5, cpu_load10 = psutil.getloadavg()
        if cpu_load > 3.0 or cpu_load5 > 4.0:
            self.limiter_entretien = True
            self.__logger.warning("Charge de travail elevee %s / %s, entretien limite" % (cpu_load, cpu_load5))
        else:
            self.limiter_entretien = False

    def ajouter_compte(self, certificat: str):
        raise NotImplementedError()

    def regenerer_certificat(self, role: str, common_name: str, nomcle: str = None):
        """
        Verifie si le certificat existe et est valide - le regenere au besoin
        :param role:
        :param common_name:
        :return:
        """
        if nomcle is None:
            nomcle = role

        certificat_courant = None
        try:
            certificat_courant = self.gestionnaire_docker.charger_config_recente('pki.%s.cert' % nomcle)
        except AttributeError:
            pass
        if certificat_courant is None:
            # Le certificat n'existe pas, on va le creer
            clecert = self._gestionnaire_certificats.generer_clecert_module(role, common_name, nomcle)

    @property
    def noeud_id(self) -> str:
        return self._noeud_id

    @property
    def idmg(self):
        return self._idmg

    @property
    def idmg_tronque(self):
        return self._idmg[0:12]

    @property
    def nodename(self):
        return self._nodename

    @property
    def identificateur(self):
        return self._nodename

    def event(self, event):
        event_json = json.loads(event)
        if event_json.get('Type') == 'container':
            if event_json.get('Action') == 'start' and event_json.get('status') == 'start':
                self.__logger.debug("Container demarre: %s", event_json)
                self._attente_event.set()

    def _preparer_csr(self):
        date_courante = datetime.datetime.utcnow().strftime(MonitorConstantes.DOCKER_LABEL_TIME)
        # Sauvegarder information pour cert, cle
        label_cert_millegrille = self.idmg_tronque + '.pki.millegrille.cert.' + date_courante
        self._docker.configs.create(name=label_cert_millegrille, data=json.dumps(self._configuration_json['pem']))

    def transmettre_info_acteur(self, commande):
        """
        Transmet les information du noeud vers l'acteur
        :param commande:
        :return:
        """
        information_systeme = self._get_info_noeud()
        information_systeme['commande'] = 'set_info'
        self._gestionnaire_commandes.transmettre_vers_acteur(information_systeme)

    def get_configuration_application(self, commande: CommandeMonitor):
        nom_app = commande.contenu['nom_application']
        nom_config_app = 'app.cfg.' + nom_app
        configuration_bytes = self._gestionnaire_docker.charger_config(nom_config_app)
        configuration_dict = json.loads(configuration_bytes.decode('utf-8'))
        return {'nom_application': nom_app, 'configuration': configuration_dict}

    def _get_info_noeud(self):
        information_systeme = {
            'noeud_id': self.noeud_id
        }

        try:
            securite = self.securite
            if securite:
                information_systeme['securite'] = securite
                if securite == Constantes.SECURITE_PROTEGE:
                    information_systeme['mq_port'] = self._connexion_middleware.configuration.mq_port
        except NotImplementedError:
            information_systeme['securite'] = Constantes.SECURITE_OUVERT

        if self._idmg:
            information_systeme['idmg'] = self._idmg

        return information_systeme

    def get_info_connexion_mq(self, nowait=False):
        info_mq = dict()
        try:
            info_mq['MQ_HOST'] = self._connexion_middleware.configuration.mq_host
            info_mq['MQ_PORT'] = self._connexion_middleware.configuration.mq_port
        except:
            # Connexion middleware pas chargee, on tente d'utiliser mdns
            if not nowait:
                self._attente_event.wait(2)
                # services = self._gestionnaire_mdns.get_service(self.idmg, '_mgamqps._tcp')
                services = self._gestionnaire_commandes.requete_mdns_acteur(self.idmg)
                services_mq = [s for s in services if s.get('type') is not None and s['type'].startswith('_mgamqps._tcp')]
                try:
                    service = services_mq[0]
                    info_mq['MQ_HOST'] = service['addresses'][0]
                    info_mq['MQ_PORT'] = service['port']
                except IndexError:
                    pass  # Aucun service disponible

        return info_mq

    def preparer_secrets(self):
        """
        Expose les certs/cle prive dans le volume secrets pour les containers
        :return:
        """
        pass

    def transmettre_catalogue_local(self):
        """
        Charger tous les fichiers de catalogue locaux et transmettre sur MQ.
        :return:
        """
        webroot = self._args.webroot
        path_catalogues = os.path.join(webroot, 'catalogues')

        with lzma.open(os.path.join(path_catalogues, 'catalogue.domaines.json.xz'), 'rt') as fichier:
            catalogue_domaines = json.load(fichier)
        domaine_action = 'transaction.' + catalogue_domaines[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        self._connexion_middleware.generateur_transactions.emettre_message(catalogue_domaines, domaine_action)

        path_applications = os.path.join(webroot, 'catalogues', 'applications')
        liste_fichiers_apps = os.listdir(path_applications)
        info_apps = [os.path.join(path_applications, f) for f in liste_fichiers_apps if f.endswith('.json.xz')]
        for app_path in info_apps:
            with lzma.open(app_path, 'rt') as fichier:
                app_transaction = json.load(fichier)
            domaine_action = 'transaction.' + app_transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
            self._connexion_middleware.generateur_transactions.emettre_message(app_transaction, domaine_action)

    def emettre_presence(self):
        """
        Emet la presence du monitor avec information docker (containers, services) a jour.
        :return:
        """
        self._connexion_middleware.emettre_presence()

    def emettre_evenement(self, action: str, info: dict = None):
        """
        Emet un evenement de monitor. Insere le noeudId dans le routing
        :return:
        """
        routing = 'evenement.servicemonitor.%s.%s' % (self.noeud_id, action)
        if info is None:
            info = dict()
        try:
            self._connexion_middleware.generateur_transactions.emettre_message(info, routing)
        except Exception:
            self.__logger.exception("Erreur transmission evenement monitor")

    @property
    def connexion_middleware(self) -> ConnexionMiddleware:
        return self._connexion_middleware

    @property
    def validateur_message(self) -> ValidateurMessage:
        try:
            if self._connexion_middleware is not None:
                validateur = self._connexion_middleware.validateur_message
                if validateur is not None:
                    return validateur
        except Exception:
            self.__logger.exception("Erreur chargement validateur messages, on utilise une version offline")
        else:
            self.__logger.warning("Erreur chargement validateur messages, on utilise une version offline")

        if self.__validateur_message is None:
            self.__validateur_message = ValidateurMessage(idmg=self.idmg)

        return self.__validateur_message

    @property
    def gestionnaire_mq(self):
        return self._gestionnaire_mq

    @property
    def gestionnaire_docker(self) -> GestionnaireModulesDocker:
        return self._gestionnaire_docker

    @property
    def gestionnaire_commandes(self):
        return self._gestionnaire_commandes

    @property
    def gestionnaire_certificats(self):
        return self._gestionnaire_certificats

    @property
    def generateur_transactions(self):
        return self._connexion_middleware.generateur_transactions

    @property
    def verificateur_transactions(self):
        raise NotImplementedError("Deprecated - remplace par validateur_message()")
        # return self._connexion_middleware.verificateur_transactions

    @property
    def validateur_pki(self) -> ValidateurCertificat:
        return self._connexion_middleware.validateur_message.validateur_pki

    @property
    def gestionnaire_applications(self):
        return self._gestionnaire_applications

    @property
    def docker(self):
        return self._docker

    def set_noeud_id(self, noeud_id: str):
        self._noeud_id = noeud_id

    def rediriger_messages_downstream(self, nom_domaine: str, exchanges_routing: dict):
        raise NotImplementedError()

    @property
    def securite(self):
        raise NotImplementedError()
        # return self._securite  # or Constantes.SECURITE_PRIVE

    @property
    def role(self):
        raise NotImplementedError()
        # return self._role  # e.g. ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE

    @property
    def path_secrets(self):
        return self._args.secrets

    @property
    def is_dev_mode(self):
        return self._args.dev

    @property
    def est_verrouille(self):
        """
        Un noeud verrouille est un noeud qui ne repond qu'a des commandes signees.
        Le noeud est deverouille durant l'installation si le type (securite) et l'IDMG ne sont pas fournis.
        :return:
        """
        try:
            self.securite
        except NotImplementedError:
            return False
        else:
            return self._idmg is not None and self._idmg != ''

    def initialiser_domaine(self, commande):
        params = commande.contenu
        gestionnaire_docker = self.gestionnaire_docker

        # Aller chercher le certificat SSL de LetsEncrypt
        domaine_noeud = params['domaine']  # 'mg-dev4.maple.maceroc.com'
        mode_test = self._args.dev or params.get('modeTest')

        params_environnement = list()
        params_secrets = list()
        mode_dns = False
        if params.get('modeCreation') == 'dns_cloudns':
            # Utiliser dnssleep, la detection de presence du record TXT marche rarement
            dnssleep = params.get('dnssleep') or 240
            methode_validation = '--dns dns_cloudns --dnssleep %s' % str(dnssleep)
            params_environnement.append("CLOUDNS_SUB_AUTH_ID=" + params['cloudnsSubid'])
            params_secrets.append("CLOUDNS_AUTH_PASSWORD=" + params['cloudnsPassword'])
            mode_dns = True
        else:
            methode_validation = '--webroot /usr/share/nginx/html'

        configuration_acme = {
            'domain': domaine_noeud,
            'methode': {
                'commande': methode_validation,
                'mode_test': mode_test,
                'params_environnement': params_environnement,
            }
        }

        commande_acme = methode_validation
        if mode_test:
            commande_acme = '--test ' + methode_validation

        params_combines = list(params_environnement)
        params_combines.extend(params_secrets)

        acme_container_id = gestionnaire_docker.trouver_container_pour_service('acme')
        commande_acme = "acme.sh --issue %s -d %s" % (commande_acme, domaine_noeud)
        if mode_dns:
            self.__logger.info("Mode DNS, on ajoute wildcard *.%s" % domaine_noeud)
            commande_acme = commande_acme + " -d '*.%s'" % domaine_noeud
        resultat_acme, output_acme = gestionnaire_docker.executer_script_blind(
            acme_container_id,
            commande_acme,
            environment=params_combines
        )
        if resultat_acme != 0:
            self.__logger.error("Erreur ACME, code : %d\n%s", resultat_acme, output_acme.decode('utf-8'))
            #raise Exception("Erreur creation certificat avec ACME")
        cert_bytes = gestionnaire_docker.get_archive_bytes(acme_container_id, '/acme.sh/%s' % domaine_noeud)
        io_buffer = io.BytesIO(cert_bytes)
        with tarfile.open(fileobj=io_buffer) as tar_content:
            member_key = tar_content.getmember('%s/%s.key' % (domaine_noeud, domaine_noeud))
            key_bytes = tar_content.extractfile(member_key).read()
            member_fullchain = tar_content.getmember('%s/fullchain.cer' % domaine_noeud)
            fullchain_bytes = tar_content.extractfile(member_fullchain).read()

        # Inserer certificat, cle dans docker
        secret_name, date_secret = gestionnaire_docker.sauvegarder_secret(
            'pki.web.key', key_bytes, ajouter_date=True)

        gestionnaire_docker.sauvegarder_config('acme.configuration', json.dumps(configuration_acme).encode('utf-8'))
        gestionnaire_docker.sauvegarder_config('pki.web.cert.' + date_secret, fullchain_bytes)

        # Forcer reconfiguration nginx
        gestionnaire_docker.maj_service('nginx')

    def configurer_mq(self, commande: CommandeMonitor):
        """
        Modifie la configuration de MQ, permet d'ajouter le host/port manuellement
        :param commande:
        :return:
        """
        params = commande.contenu
        inst_service = self._gestionnaire_docker.get_service('monitor')

        try:
            if params['supprimer_params_mq']:
                self.__logger.info("Suppression manual override pour MQ")
                liste_valeurs = list()
                inst_service.update(env=liste_valeurs)
        except KeyError:
            host = params['host']
            port = params['port']
            liste_valeurs = [
                'MG_MQ_HOST=' + host,
                'MG_MQ_PORT=' + port,
            ]
            self.__logger.info("MAJ connexion MQ avec %s" + str(liste_valeurs))
            inst_service.update(env=liste_valeurs)

    def get_certificat_acme(self, domaine_noeud: str = None):

        if domaine_noeud is None:
            info_monitor = self.get_info_monitor()
            domaine_noeud = info_monitor['domaine']

        gestionnaire_docker = self._gestionnaire_docker
        acme_container_id = gestionnaire_docker.trouver_container_pour_service('acme')
        cert_bytes = gestionnaire_docker.get_archive_bytes(acme_container_id, '/acme.sh/%s' % domaine_noeud)
        io_buffer = io.BytesIO(cert_bytes)
        with tarfile.open(fileobj=io_buffer) as tar_content:
            member_key = tar_content.getmember('%s/%s.key' % (domaine_noeud, domaine_noeud))
            key_bytes = tar_content.extractfile(member_key).read()
            member_fullchain = tar_content.getmember('%s/fullchain.cer' % domaine_noeud)
            fullchain_bytes = tar_content.extractfile(member_fullchain).read()

        return {
            'cle': key_bytes,
            'chain': fullchain_bytes,
        }

    def sauvegarder_config_millegrille(self, idmg, securite):
        """
        Sauvegarde la config docker millegrille.confuration
        :param idmg:
        :param securite:
        :return:
        """
        # Sauvegarder niveau securite
        try:
            securite_config = self._docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_SECURITE)
            securite_existant = b64decode(securite_config.attrs['Spec']['Data']).decode('utf-8').strip()
            # On ne change pas le idmg
            if securite is not None and securite != securite_existant:
                self.__logger.warning("Securite existant (%s) ne correspond pas au IDMG fourni (%s) - on conserve le niveau existant" % (securite_existant, securite))
        except docker.errors.NotFound:
            self.__logger.info("Sauvegarder securite sous %s : %s" % (ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_SECURITE, idmg))
            self.gestionnaire_docker.sauvegarder_config(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_SECURITE,
                                                        securite)
            self._securite = securite

        try:
            idmg_config = self._docker.configs.get(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_IDMG)
            idmg_existant = b64decode(idmg_config.attrs['Spec']['Data']).decode('utf-8').strip()
            # On ne change pas le idmg
            if idmg is not None and idmg != idmg_existant:
                self.__logger.warning("IDMG existant (%s) ne correspond pas au IDMG fourni (%s) - on conserve le IDMG existant" % (idmg_existant, idmg))
        except docker.errors.NotFound:
            self.__logger.info("Sauvegarder IDMG sous %s : %s" % (ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_IDMG, idmg))
            self.gestionnaire_docker.sauvegarder_config(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_IDMG, idmg)
            self._idmg = idmg

    def _renouveller_certificat_monitor(self, commande: CommandeMonitor):
        """
        Initialise un noeud protege avec un certificat
        :param commande:
        :return:
        """

        params = commande.contenu
        gestionnaire_docker = self.gestionnaire_docker

        # gestionnaire_certs = GestionnaireCertificatsNoeudPrive(
        #     self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
        role = self.role

        # Faire correspondre et sauvegarder certificat de noeud
        # secret_intermediaire = gestionnaire_docker.trouver_secret('pki.monitor.key')
        # secret_date = secret_intermediaire['date']

        certificat_pem = params.get('certificatPem') or params['cert']
        chaine = params.get('chainePem') or params['fullchain']
        certificat_millegrille = chaine[-1]

        try:
            config_csr = self.gestionnaire_docker.charger_config_recente('pki.monitor.csr')
            date_csr = config_csr['date']

            if not self._args.dev:
                with open(os.path.join(self._args.secrets, 'pki.monitor.key.pem'), 'rb') as fichier:
                    monitor_key_pem = fichier.read()
            else:
                with open(os.path.join(self._args.secrets, 'pki.monitor.key.%s' % date_csr), 'rb') as fichier:
                    monitor_key_pem = fichier.read()

            clecert_recu = EnveloppeCleCert()
            clecert_recu.from_pem_bytes(monitor_key_pem, certificat_pem.encode('utf-8'))
            if not clecert_recu.cle_correspondent():
                raise ValueError('MODE DEV : Cle et Certificat monitor (mode insecure) ne correspondent pas')
        except Exception as e:
            self.__logger.exception("Erreur ouverture CSR")
            raise e

        # if not self._args.dev:
        #     nom_fichier_key = 'pki.monitor.key.pem'
        # else:
        #     nom_fichier_key = 'pki.monitor.key.%s' % secret_date
        #
        # with open(os.path.join(self._args.secrets, nom_fichier_key), 'rb') as fichier:
        #     intermediaire_key_pem = fichier.read()
        # with open(os.path.join(self._args.secrets, nom_fichier_passwd), 'rb') as fichier:
        #     intermediaire_passwd_pem = fichier.read()
        # certificat_pem = params['certificatPem']
        # certificat_millegrille = params['chainePem'][-1]
        # chaine = params['chainePem']

        # Extraire IDMG
        self.__logger.debug("Certificat de la MilleGrille :\n%s" % certificat_millegrille)
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(certificat_millegrille.encode('utf-8'))
        idmg = clecert_millegrille.idmg

        if self.idmg != idmg:
            raise ValueError("Le IDMG du certificat (%s) ne correspond pas a celui du noeud (%s)", (idmg, self.idmg))

        # clecert_recu = EnveloppeCleCert()
        # clecert_recu.from_pem_bytes(intermediaire_key_pem, certificat_pem.encode('utf-8'))
        # if not clecert_recu.cle_correspondent():
        #         raise ValueError('Cle et Certificat intermediaire ne correspondent pas')

        # Verifier si on doit generer un certificat web SSL
        # domaine_web = params.get('domaine')
        # if domaine_web is not None:
        #     self.__logger.info("Generer certificat web SSL pour %s" % domaine_web)
        #     self.initialiser_domaine(commande)

        cert_subject = clecert_recu.formatter_subject()

        # Verifier le type de certificat - il determine le type de noeud:
        # intermediaire = noeud protege, prive = noeud prive, public = noeud public
        self.__logger.debug("Certificat recu : %s", str(cert_subject))
        subject_clecert_recu = clecert_recu.formatter_subject()
        if subject_clecert_recu['organizationName'] != idmg:
            raise Exception("IDMG %s ne correspond pas au certificat de monitor" % idmg)

        type_certificat_recu = subject_clecert_recu['organizationalUnitName']
        if type_certificat_recu != role:
            raise Exception("Type de certificat inconnu : %s" % type_certificat_recu)

        # Comencer sauvegarde
        # try:
        #     gestionnaire_docker.sauvegarder_config('pki.millegrille.cert', certificat_millegrille)
        # except APIError as apie:
        #     if apie.status_code == 400:
        #         self.__logger.info("pki.millegrille.cert deja present, on ne le change pas : " + str(apie))
        #     else:
        #         raise apie

        self.__logger.debug("Sauvegarde certificat recu et cle comme cert/cle de monitor %s" % self.role)
        clecert_recu.password = None
        cle_monitor = clecert_recu.private_key_bytes
        secret_name, date_key = gestionnaire_docker.sauvegarder_secret(
            ConstantesServiceMonitor.PKI_MONITOR_KEY, cle_monitor, ajouter_date=True)

        # if self._args.dev:
        #     nom_key = ConstantesServiceMonitor.PKI_MONITOR_KEY + date_key
        #     with open(os.path.join(self._args.secrets, nom_key), 'w') as fichier:
        #         fichier.write(cle_monitor)

        gestionnaire_docker.sauvegarder_config(
            'pki.monitor.cert.' + date_key,
            '\n'.join(chaine)
        )

        # Supprimer le CSR
        try:
            gestionnaire_docker.supprimer_config('pki.monitor.csr.%s' % date_csr)
        except docker.errors.NotFound:
            pass
        # try:
        #     gestionnaire_docker.supprimer_config('pki.intermediaire.csr.' + str(secret_intermediaire['date']))
        # except docker.errors.NotFound:
        #     pass

        # Terminer configuration swarm docker
        # gestionnaire_docker.initialiser_noeud(idmg=idmg)

        # self.sauvegarder_config_millegrille(idmg, securite)

        # Regenerer la configuraiton de NGINX (change defaut de /installation vers /vitrine)
        # Redemarrage est implicite (fait a la fin de la prep)
        self._gestionnaire_web.regenerer_configuration(mode_installe=True)

        # Forcer reconfiguration nginx (ajout certificat de millegrille pour validation client ssl)
        try:
            gestionnaire_docker.maj_service('nginx')
        except docker.errors.APIError as apie:
            if apie.status_code == 500:
                self.__logger.warning(
                    "Erreur mise a jour, probablement update concurrentes. On attend 15 secondes puis on reessaie")
                Event().wait(15)
                gestionnaire_docker.maj_service('nginx')
            else:
                raise apie

        # Redemarrer / reconfigurer le monitor
        self.__logger.info("Configuration completee, redemarrer le monitor")
        gestionnaire_docker.configurer_monitor()

        raise ForcerRedemarrage("Redemarrage")


class ServiceMonitorPrincipal(ServiceMonitor):
    """
    ServiceMonitor pour noeud protege principal
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)

    def run(self):
        self.__logger.info("Demarrage du ServiceMonitor")

        try:
            self._charger_configuration()
            self.preparer_gestionnaire_certificats()
            self.configurer_millegrille()
            self.preparer_gestionnaire_comptesmq()
            self.preparer_gestionnaire_commandes()
            self.preparer_gestionnaire_applications()
            self.preparer_web_api()

            # S'assurer d'utiliser les certificats les plus recents avec NGINX
            self._gestionnaire_web.redeployer_nginx()

            while not self._fermeture_event.is_set():
                self._attente_event.clear()

                try:
                    self.__logger_verbose.debug("Cycle entretien ServiceMonitor")

                    self.verifier_load()

                    self._entretien_modules()

                    if not self._connexion_middleware:
                        try:
                            self.connecter_middleware()
                            # self.preparer_secrets()  # Pour noeud protege, ne pas extrait la cle
                        except BrokenBarrierError:
                            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")

                    self.__logger_verbose.debug("Fin cycle entretien ServiceMonitor")
                except ForcerRedemarrage as e:
                    self.__logger.exception("ServiceMonitor: Redemarrer : " + str(e))
                    self.fermer()
                except Exception as e:
                    self.__logger.exception("ServiceMonitor: erreur generique : " + str(e))
                finally:
                    self._attente_event.wait(30)

        except ForcerRedemarrage:
            self.__logger.info("Configuration initiale terminee, fermeture pour redemarrage")
            self.exit_code = ConstantesServiceMonitor.EXIT_REDEMARRAGE

        except Exception:
            self.__logger.exception("Erreur demarrage ServiceMonitor, on abandonne l'execution")

        self.__logger.info("Fermeture du ServiceMonitor")
        self.fermer()

        # Fermer le service monitor, retourne exit code pour shell script
        sys.exit(self.exit_code)

    def configurer_millegrille(self):
        super().configurer_millegrille()

        # Generer certificats de module manquants ou expires, avec leur cle
        try:
            self._gestionnaire_certificats.charger_certificats()  # Charger certs sur disque
        except FileNotFoundError:
            self.__logger.exception("Erreur chargement certificats/cles pour monitor")
        self._entretien_certificats()

    def connecter_middleware(self):
        """
        Genere un contexte et se connecte a MQ et MongoDB.
        Lance une thread distincte pour s'occuper des messages.
        :return:
        """
        configuration = TransactionConfiguration()

        self._connexion_middleware = ConnexionMiddlewareProtege(
            configuration, self._docker, self, self._gestionnaire_certificats.certificats,
            secrets=self._args.secrets)

        try:
            self._connexion_middleware.initialiser()
            self._connexion_middleware.start()

            # Ajouter les listeners au besoin
            self._connexion_middleware.enregistrer_listener(self.gestionnaire_commandes.initialiser_handler_mq)
            self._connexion_middleware.enregistrer_listener(self.gestionnaire_applications.initialiser_handler_mq)

        except TypeError as te:
            self.__logger.exception("Erreur fatale configuration MQ, abandonner")
            self.fermer()
            raise te
        except BrokenBarrierError:
            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")
            self._connexion_middleware.stop()
            self._connexion_middleware = None

    def preparer_gestionnaire_certificats(self):
        params = dict()
        if self._args.dev:
            params['insecure'] = True
        if self._args.secrets:
            params['secrets'] = self._args.secrets
        self._gestionnaire_certificats = GestionnaireCertificatsNoeudProtegePrincipal(self._docker, self, **params)

    def preparer_gestionnaire_commandes(self):
        self._gestionnaire_commandes = GestionnaireCommandes(self._fermeture_event, self)

        super().preparer_gestionnaire_commandes()  # Creer pipe et demarrer

    def rediriger_messages_downstream(self, nom_domaine: str, exchanges_routing: dict):
        pass  # Rien a faire pour le monitor principal

    def ajouter_compte(self, certificat: str):
        commande_dict = {
            'commande': Constantes.ConstantesServiceMonitor.COMMANDE_AJOUTER_COMPTE,
            'contenu': {
                Constantes.ConstantesPki.LIBELLE_CERTIFICAT_PEM: certificat,
            }
        }
        commande = CommandeMonitor(commande_dict)
        self.gestionnaire_commandes.ajouter_commande(commande)

    def _entretien_certificats(self):
        """
        Entretien certificats des services/modules et du monitor
        :return:
        """
        clecert_monitor = self._gestionnaire_certificats.clecert_monitor

        not_valid_before = clecert_monitor.not_valid_before
        not_valid_after = clecert_monitor.not_valid_after
        self.__logger.debug("Verification validite certificat du monitor : valide jusqu'a %s" % str(clecert_monitor.not_valid_after))

        # Calculer 2/3 de la duree du certificat
        delta_fin_debut = not_valid_after.timestamp() - not_valid_before.timestamp()
        epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
        date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers)

        if date_renouvellement is None or date_renouvellement < datetime.datetime.utcnow():
            self.__logger.warning("Certificat monitor expire, on genere un nouveau et redemarre immediatement")

            # MAJ date pour creation de certificats
            self._gestionnaire_certificats.maj_date()

            self._gestionnaire_certificats.generer_clecert_module('monitor', self.noeud_id)
            self._gestionnaire_docker.configurer_monitor()
            raise ForcerRedemarrage("Redemarrage apres configuration service monitor")

        super()._entretien_certificats()

    @property
    def gestionnaire_mongo(self):
        return self._connexion_middleware.get_gestionnaire_comptes_mongo

    @property
    def securite(self):
        return Constantes.SECURITE_PROTEGE

    @property
    def role(self):
        return ConstantesGenerateurCertificat.ROLE_MONITOR


class ServiceMonitorDependant(ServiceMonitor):
    """
    ServiceMonitor pour noeud protege dependant
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)
        self.__event_attente = Event()

        self.__connexion_principal: ConnexionPrincipal = cast(ConnexionPrincipal, None)

    def fermer(self, signum=None, frame=None):
        super().fermer(signum, frame)
        self.__event_attente.set()

    def trigger_event_attente(self):
        self.__event_attente.set()

    def run(self):
        self.__logger.debug("Execution noeud dependant")
        self._charger_configuration()
        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_DEPENDANT.copy(),
            self, insecure=self._args.dev, secrets=self._args.secrets)
        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)
        self.preparer_gestionnaire_certificats()

        methode_run = self.__determiner_type_run()
        methode_run()  # Excuter run

    def __determiner_type_run(self):
        # Verifier si le certificat de millegrille a ete charge
        try:
            info_cert_millegrille = MonitorConstantes.trouver_config(
                'pki.millegrille.cert', self._docker)
            self.__logger.debug("Cert millegrille deja charge, date %s" % info_cert_millegrille['date'])
        except AttributeError:
            self.__logger.info("Run initialisation noeud dependant")
            return self.run_configuration_initiale

        # Le certificat de millegrille est charge, s'assurer que la cle de monitor est generee
        # Il est anormal que le cert millegrille soit charge et la cle de monitor absente, mais c'est supporte
        try:
            label_key = 'pki.' + ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT + '.key'
            info_cle_monitor = self.gestionnaire_docker.trouver_secret(label_key)
            self.__logger.debug("Cle monitor deja chargee, date %s" % info_cle_monitor['date'])
        except AttributeError:
            self.__logger.warning("Cle secrete monitor manquante, run initialisation noeud dependant")
            return self.run_configuration_initiale

        # Verifier si le certificat de monitor correspondant a la cle est charge

        return self.run_monitor

    def run_configuration_initiale(self):
        """
        Sert a initialiser le noeud protege dependant.
        Termine son execution immediatement apres creation du CSR.
        :return:
        """

        self.__logger.info("Run configuration initiale, (mode insecure: %s)" % self._args.dev)

        # Creer CSR pour le service monitor
        self._gestionnaire_certificats.generer_csr(
            ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT, insecure=self._args.dev)

        # Generer mots de passe
        self._gestionnaire_certificats.generer_motsdepasse()

        # Sauvegarder information pour CSR, cle
        cert_millegrille = self._configuration_json['pem'].encode('utf-8')
        self._gestionnaire_certificats.ajouter_config(
            name='pki.millegrille.cert', data=cert_millegrille)

        self._gestionnaire_docker.initialiser_millegrille()

        print("Preparation CSR du noeud dependant terminee")
        print("Redemarrer le service monitor")

    def run_monitor(self):
        """
        Execution du monitor.
        :return:
        """
        self.__logger.info("Run monitor noeud protege dependant")

        # Activer ecoute des commandes
        self.preparer_gestionnaire_commandes()

        # Initialiser cles, certificats disponibles
        self._gestionnaire_certificats.charger_certificats()  # Charger certs sur disque

        self._attendre_certificat_monitor()  # S'assurer que le certificat du monitor est correct, l'attendre au besoin
        self._initialiser_middleware()       # S'assurer que les certificats du middleware sont corrects
        self._run_entretien()                # Mode d'operation de base, lorsque le noeud est bien configure

    def _attendre_certificat_monitor(self):
        """
        Mode d'attente de la commande avec le certificat signe du monitor.
        :return:
        """
        self.__logger.info("Verifier et attendre certificat du service monitor")

        clecert_monitor = self._gestionnaire_certificats.clecert_monitor
        if not clecert_monitor.cert:
            while not self.__event_attente.is_set():
                self.__logger.info("Attente du certificat de monitor dependant")
                self.__event_attente.wait(120)

        self.__logger.debug("Certificat monitor valide jusqu'a : %s" % clecert_monitor.not_valid_after)

        self.__logger.info("Certificat du service monitor pret")

    def _initialiser_middleware(self):
        """
        Mode de creation des certificats du middleware (MQ, Mongo, MongoExpress)
        :return:
        """
        self.__logger.info("Verifier et attendre certificats du middleware")

        # Charger certificats - copie les certs sous /tmp pour connecter a MQ
        self._gestionnaire_certificats.charger_certificats()

        # Connecter au MQ principal
        self.__connexion_principal = ConnexionPrincipal(self._docker, self)
        self.__connexion_principal.connecter()

        # Confirmer que les cles mq, mongo, mongoxp ont ete crees
        liste_csr = list()
        for role in MonitorConstantes.CERTIFICATS_REQUIS_DEPENDANT:
            label_cert = 'pki.%s.cert' % role
            try:
                MonitorConstantes.trouver_config(label_cert, self._docker)
            except AttributeError:
                label_key = 'pki.%s.key' % role
                fichier_csr = 'pki.%s.csr.pem' % role
                try:
                    self._gestionnaire_docker.trouver_secret(label_key)
                    path_fichier = os.path.join(MonitorConstantes.PATH_PKI, fichier_csr)
                    with open(path_fichier, 'r') as fichier:
                        csr = fichier.read()
                except AttributeError:
                    # Creer la cle, CSR correspondant
                    inserer_cle = role not in ['mongo']
                    info_csr = self._gestionnaire_certificats.generer_csr(role, insecure=self._args.dev, inserer_cle=inserer_cle)
                    csr = str(info_csr['request'], 'utf-8')
                    if role == 'mongo':
                        self._gestionnaire_certificats.memoriser_cle(role, info_csr['cle_pem'])
                liste_csr.append(csr)

        if len(liste_csr) > 0:
            self.__event_attente.clear()
            commande = {
                'liste_csr': liste_csr,
            }
            # Transmettre commande de signature de certificats, attendre reponse
            while not self.__event_attente.is_set():
                self.__connexion_principal.generateur_transactions.transmettre_commande(
                    commande,
                    'commande.MaitreDesCles.%s' % Constantes.ConstantesMaitreDesCles.COMMANDE_SIGNER_CSR,
                    correlation_id=ConstantesServiceMonitor.CORRELATION_CERTIFICAT_SIGNE,
                    reply_to=self.__connexion_principal.reply_q
                )
                self.__logger.info("Attente certificats signes du middleware")
                self.__event_attente.wait(120)

        self.preparer_gestionnaire_comptesmq()
        self.__logger.info("Certificats du middleware prets")

    def _run_entretien(self):
        """
        Mode d'operation de base du monitor, lorsque toute la configuration est completee.
        :return:
        """
        self.__logger.info("Debut boucle d'entretien du service monitor")

        while not self._fermeture_event.is_set():
            self._attente_event.clear()

            try:
                self.__logger.debug("Cycle entretien ServiceMonitor")

                self.verifier_load()

                if not self._connexion_middleware:
                    try:
                        self.connecter_middleware()
                        self._connexion_middleware.set_relai(self.__connexion_principal)
                        self.__connexion_principal.initialiser_relai_messages(self._connexion_middleware.relayer_message)
                    except BrokenBarrierError:
                        self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")

                self._entretien_modules()

                self.__logger_verbose.debug("Fin cycle entretien ServiceMonitor")
            except Exception as e:
                self.__logger.exception("ServiceMonitor: erreur generique : " + str(e))
            finally:
                self._attente_event.wait(30)

        self.__logger.info("Fin execution de la boucle d'entretien du service monitor")

    def connecter_middleware(self):
        super().connecter_middleware()

    def __charger_cle(self):
        if self._args.dev:
            path_cle = '/var/opt/millegrilles/pki/servicemonitor.key.pem'
        else:
            path_cle = '/run/secrets/pki.monitor.key.pem'

        with open(path_cle, 'rb') as fichier:
            cle_bytes = fichier.read()

    def preparer_gestionnaire_certificats(self):
        params = dict()
        if self._args.dev:
            params['insecure'] = True
        if self._args.secrets:
            params['secrets'] = self._args.secrets
        self._gestionnaire_certificats = GestionnaireCertificatsNoeudProtegeDependant(self._docker, self, **params)

    def preparer_gestionnaire_commandes(self):
        self._gestionnaire_commandes = GestionnaireCommandesNoeudProtegeDependant(self._fermeture_event, self)

        super().preparer_gestionnaire_commandes()  # Creer pipe et demarrer

    def inscrire_domaine(self, nom_domaine: str, exchanges_routing: dict):
        self._connexion_middleware.rediriger_messages_domaine(nom_domaine, exchanges_routing)

    def rediriger_messages_downstream(self, nom_domaine: str, exchanges_routing: dict):
        self.__connexion_principal.enregistrer_domaine(nom_domaine, exchanges_routing)


class ServiceMonitorPrive(ServiceMonitor):
    """
    ServiceMonitor pour noeud prive
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)

        self._configuration = TransactionConfiguration()
        self._configuration.loadEnvironment()

    def _entretien_modules(self):
        if not self.limiter_entretien:
            # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
            self._gestionnaire_docker.entretien_services()

            # Entretien web
            if self._web_entretien_date is None or \
                    self._web_entretien_date + self._web_entretien_frequence < datetime.datetime.utcnow():
                self._web_entretien_date = datetime.datetime.utcnow()
                self._gestionnaire_web.entretien()

            # Entretien des certificats du monitor, services
            if self._certificats_entretien_date is None or \
                    self._certificats_entretien_date + self._certificats_entretien_frequence < datetime.datetime.utcnow():

                self._certificats_entretien_date = datetime.datetime.utcnow()
                self._entretien_certificats()
                self._entretien_secrets_pki()

    def connecter_middleware(self):
        """
        Genere un contexte et se connecte a MQ et MongoDB.
        Lance une thread distincte pour s'occuper des messages.
        :return:
        """
        self._connexion_middleware = ConnexionMiddlewarePrive(
            self._configuration, self._docker, self, self._gestionnaire_certificats.certificats,
            secrets=self._args.secrets)

        try:
            self._connexion_middleware.initialiser()
            self._connexion_middleware.start()
        except TypeError as te:
            self.__logger.exception("Erreur fatale configuration MQ, abandonner")
            self.fermer()
            raise te
        except BrokenBarrierError:
            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")
            self._connexion_middleware.stop()
            self._connexion_middleware = None

    def run(self):
        self.__logger.info("Demarrage du ServiceMonitor")

        try:
            self._charger_configuration()
            self.configurer_millegrille()
            self.preparer_gestionnaire_certificats()
            self.preparer_gestionnaire_commandes()
            self.preparer_gestionnaire_applications()
            self.preparer_web_api()

            while not self._fermeture_event.is_set():
                self._attente_event.clear()

                try:
                    self.__logger.debug("Cycle entretien ServiceMonitor")

                    self.verifier_load()

                    self._entretien_modules()

                    if not self._connexion_middleware:
                        try:
                            self.connecter_middleware()
                            self.preparer_secrets()
                        except BrokenBarrierError:
                            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")

                    self.__logger_verbose.debug("Fin cycle entretien ServiceMonitor")
                except Exception as e:
                    self.__logger.exception("ServiceMonitor: erreur generique : " + str(e))
                finally:
                    self._attente_event.wait(30)

        except ForcerRedemarrage:
            self.__logger.info("Configuration initiale terminee, fermeture pour redemarrage")
            self.exit_code = ConstantesServiceMonitor.EXIT_REDEMARRAGE

        except Exception:
            self.__logger.exception("Erreur demarrage ServiceMonitor, on abandonne l'execution")

        self.__logger.info("Fermeture du ServiceMonitor")
        self.fermer()

        # Fermer le service monitor, retourne exit code pour shell script
        sys.exit(self.exit_code)

    def configurer_millegrille(self):
        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_INSTALLATION.copy(),
            self,
            configuration_services=MonitorConstantes.DICT_MODULES_PRIVES,
            insecure=self._args.dev,
            secrets=self._args.secrets
        )

        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)

        # Initialiser gestionnaire web
        self._gestionnaire_web = GestionnaireWeb(self, mode_dev=self._args.dev)

    def preparer_gestionnaire_commandes(self):
        self._gestionnaire_commandes = GestionnaireCommandes(self._fermeture_event, self)
        super().preparer_gestionnaire_commandes()  # Creer pipe et demarrer

    def preparer_gestionnaire_certificats(self):
        params = dict()
        if self._args.dev:
            params['insecure'] = True
        if self._args.secrets:
            params['secrets'] = self._args.secrets
        self._gestionnaire_certificats = GestionnaireCertificatsNoeudPrive(self._docker, self, **params)
        self._gestionnaire_certificats.charger_certificats()

    def preparer_secrets(self):
        """
        Expose les certs/cle prive dans le volume secrets pour les containers
        :return:
        """

        if self.path_secrets == MonitorConstantes.PATH_SECRET_DEFAUT:
            # Le monitor est deploye sous forme de service, on copie les secrets vers le repertoire partage
            path_secret_prives = '/var/opt/millegrilles_secrets'
            self.__logger.info("Preparer clecert pour les containers a partir de " + path_secret_prives)

            if os.path.exists(path_secret_prives):
                volume_secrets = '/var/opt/millegrilles_secrets'
                self.__logger.debug("Copie cle/certs vers %s" % volume_secrets)
                fichiers = [
                    # (os.path.join(volume_secrets, 'key.pem'), self._configuration.mq_keyfile),
                    (os.path.join(volume_secrets, 'key.pem'), self._configuration.mq_keyfile),
                    (os.path.join(volume_secrets, 'cert.pem'), self._configuration.mq_certfile),
                    (os.path.join(volume_secrets, 'millegrille.cert.pem'), self._configuration.mq_cafile)
                ]

                for fichier in fichiers:
                    with open(fichier[0], 'w') as cle_out:
                        with open(fichier[1], 'r') as cle_in:
                            cle_out.write(cle_in.read())

    def _entretien_certificats(self):
        """
        Entretien certificats des services/modules et du monitor
        :return:
        """
        clecert_monitor = self._gestionnaire_certificats.clecert_monitor

        try:
            not_valid_before = clecert_monitor.not_valid_before
            not_valid_after = clecert_monitor.not_valid_after
            self.__logger.debug("Verification validite certificat du monitor : valide jusqu'a %s" % str(clecert_monitor.not_valid_after))
        except AttributeError:
            self.__logger.exception("Certificat monitor absent")
            date_renouvellement = None
        else:
            # Calculer 2/3 de la duree du certificat
            delta_fin_debut = not_valid_after.timestamp() - not_valid_before.timestamp()
            epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
            date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers)

        if date_renouvellement is None or date_renouvellement < datetime.datetime.utcnow():
        # if True:
            # MAJ date pour creation de certificats
            self._gestionnaire_certificats.maj_date()

            # Generer un nouveau CSR
            # Verifier si le CSR a deja ete genere, sinon le generer
            try:
                csr_docker = self._gestionnaire_docker.charger_config_recente('pki.%s.csr' % ConstantesGenerateurCertificat.ROLE_MONITOR)
                csr_intermediaire = b64decode(csr_docker['config'].attrs['Spec']['Data']).decode('utf-8')
            except AttributeError:
                self.__logger.warning("Certificat monitor expire, on genere un nouveau CSR")

                # Creer CSR pour le service monitor
                csr_info = self._gestionnaire_certificats.generer_csr(
                    ConstantesGenerateurCertificat.ROLE_MONITOR,
                    insecure=self._args.dev,
                    generer_password=False
                )
                csr_intermediaire = csr_info['request']

            # Generer message a transmettre au monitor pour renouvellement
            commande = {
                'csr': csr_intermediaire,
                'securite': self.securite
            }

            try:
                self.connexion_middleware.generateur_transactions.transmettre_commande(
                    commande,
                    'commande.servicemonitor.%s' % Constantes.ConstantesServiceMonitor.COMMANDE_SIGNER_NOEUD,
                    exchange=self.securite,
                    correlation_id=ConstantesServiceMonitor.CORRELATION_RENOUVELLEMENT_CERTIFICAT,
                    reply_to=self.connexion_middleware.reply_q
                )
            except AttributeError:
                self.__logger.warning("Connexion MQ pas prete, on ne peut pas renouveller le certificat de monitor")
                if self.__logger.isEnabledFor(logging.DEBUG):
                    self.__logger.exception("Connexion MQ pas prete")

            # self._gestionnaire_certificats.generer_clecert_module('monitor', self.noeud_id)
            # self._gestionnaire_docker.configurer_monitor()
            # raise ForcerRedemarrage("Redemarrage apres configuration service monitor")

        # Nettoyer certificats monitor
        self._supprimer_certificats_expires(['monitor'])

    def initialiser_noeud(self, commande: CommandeMonitor):
        if self.__logger.isEnabledFor(logging.DEBUG):
            try:
                self.__logger.debug("Commande initialiser noeud : %s", json.dumps(commande.contenu, indent=2))
            except Exception:
                self.__logger.debug("Commande initialiser noeud : %s", commande.contenu)

        params = commande.contenu
        self._renouveller_certificat_monitor(commande)

    def ajouter_compte(self, certificat: str):
        raise Exception("Ajouter compte PEM (**non implemente pour prive**): %s" % certificat)

    @property
    def securite(self):
        return Constantes.SECURITE_PRIVE

    @property
    def role(self):
        return ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE


class ServiceMonitorPublic(ServiceMonitor):
    """
    ServiceMonitor pour noeud public
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)

        self._configuration = TransactionConfiguration()
        self._configuration.loadEnvironment()

    def _entretien_modules(self):
        if not self.limiter_entretien:
            # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
            self._gestionnaire_docker.entretien_services()

            # Entretien web
            self._gestionnaire_web.entretien()

    def connecter_middleware(self):
        """
        Genere un contexte et se connecte a MQ et MongoDB.
        Lance une thread distincte pour s'occuper des messages.
        :return:
        """
        self._connexion_middleware = ConnexionMiddlewarePublic(
            self._configuration, self._docker, self, self._gestionnaire_certificats.certificats,
            secrets=self._args.secrets)

        try:
            self._connexion_middleware.initialiser()
            self._connexion_middleware.start()
        except TypeError as te:
            self.__logger.exception("Erreur fatale configuration MQ, abandonner")
            self.fermer()
            raise te
        except BrokenBarrierError:
            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")
            self._connexion_middleware.stop()
            self._connexion_middleware = None

    def run(self):
        self.__logger.info("Demarrage du ServiceMonitor")

        try:
            self._charger_configuration()
            self.configurer_millegrille()
            self.preparer_gestionnaire_certificats()
            self.preparer_gestionnaire_commandes()
            self.preparer_gestionnaire_applications()
            self.preparer_web_api()

            while not self._fermeture_event.is_set():
                self._attente_event.clear()

                try:
                    self.__logger.debug("Cycle entretien ServiceMonitor")

                    self.verifier_load()

                    self._entretien_modules()

                    if not self._connexion_middleware:
                        try:
                            self.connecter_middleware()
                            self.preparer_secrets()
                        except BrokenBarrierError:
                            self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")

                    self.__logger_verbose.debug("Fin cycle entretien ServiceMonitor")
                except Exception as e:
                    self.__logger.exception("ServiceMonitor: erreur generique : " + str(e))
                finally:
                    self._attente_event.wait(30)

        except ForcerRedemarrage:
            self.__logger.info("Configuration initiale terminee, fermeture pour redemarrage")
            self.exit_code = ConstantesServiceMonitor.EXIT_REDEMARRAGE

        except Exception:
            self.__logger.exception("Erreur demarrage ServiceMonitor, on abandonne l'execution")

        self.__logger.info("Fermeture du ServiceMonitor")
        self.fermer()

        # Fermer le service monitor, retourne exit code pour shell script
        sys.exit(self.exit_code)

    def configurer_millegrille(self):
        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_INSTALLATION.copy(),
            self,
            configuration_services=MonitorConstantes.DICT_MODULES_PUBLICS,
            insecure=self._args.dev,
            secrets=self._args.secrets
        )

        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)

        # Initialiser gestionnaire web
        self._gestionnaire_web = GestionnaireWeb(self, mode_dev=self._args.dev)

    def preparer_gestionnaire_commandes(self):
        self._gestionnaire_commandes = GestionnaireCommandes(self._fermeture_event, self)
        super().preparer_gestionnaire_commandes()  # Creer pipe et demarrer

    def preparer_gestionnaire_certificats(self):
        params = dict()
        if self._args.dev:
            params['insecure'] = True
        if self._args.secrets:
            params['secrets'] = self._args.secrets
        self._gestionnaire_certificats = GestionnaireCertificatsNoeudPublic(self._docker, self, **params)
        self._gestionnaire_certificats.charger_certificats()

    def preparer_secrets(self):
        """
        Expose les certs/cle prive dans le volume secrets pour les containers
        :return:
        """

        if self.path_secrets == MonitorConstantes.PATH_SECRET_DEFAUT:
            # Le monitor est deploye sous forme de service, on copie les secrets vers le repertoire partage
            path_secret_prives = '/var/opt/millegrilles_secrets'
            self.__logger.info("Preparer clecert pour les containers a partir de " + path_secret_prives)

            if os.path.exists(path_secret_prives):
                volume_secrets = '/var/opt/millegrilles_secrets'
                self.__logger.debug("Copie cle/certs vers %s" % volume_secrets)
                fichiers = [
                    (os.path.join(volume_secrets, 'key.pem'), self._configuration.mq_keyfile),
                    (os.path.join(volume_secrets, 'cert.pem'), self._configuration.mq_certfile),
                    (os.path.join(volume_secrets, 'millegrille.cert.pem'), self._configuration.mq_cafile)
                ]

                for fichier in fichiers:
                    with open(fichier[0], 'w') as cle_out:
                        with open(fichier[1], 'r') as cle_in:
                            cle_out.write(cle_in.read())

    def ajouter_compte(self, certificat: str):
        raise NotImplementedError("Ajouter compte PEM (**non implemente pour public**): %s" % certificat)

    @property
    def securite(self):
        return Constantes.SECURITE_PUBLIC

    @property
    def role(self):
        return ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC


class ServiceMonitorInstalleur(ServiceMonitor):

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)
        self.__event_attente = Event()

        self.__connexion_principal: ConnexionPrincipal = cast(ConnexionPrincipal, None)

        self.csr_intermediaire = None

    def fermer(self, signum=None, frame=None):
        super().fermer(signum, frame)
        self.__event_attente.set()

    def trigger_event_attente(self):
        self.__event_attente.set()

    def _charger_configuration(self):
        super()._charger_configuration()
        self._idmg = ''

    def run(self):
        self.__logger.debug("Execution installation du noeud")
        self.__logger.info("Run configuration initiale, (mode insecure: %s)" % self._args.dev)
        self._charger_configuration()

        self._gestionnaire_docker = GestionnaireModulesDocker(
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_INSTALLATION.copy(), self,
            configuration_services=MonitorConstantes.DICT_MODULES_PRIVES,
            insecure=self._args.dev,
            secrets=self._args.secrets
        )

        try:
            self._gestionnaire_docker.initialiser_noeud()
        except APIError:
            self.__logger.info("Docker.initialiser_noeud: Noeud deja initialise")

        try:
            self._idmg = self._gestionnaire_docker.charger_config(ConstantesServiceMonitor.DOCKER_LIBVAL_CONFIG_IDMG).decode('utf-8').strip()
        except (IndexError, docker.errors.NotFound):
            self.__logger.info("IDMG non initialise")

        # Initialiser gestionnaire web
        self._gestionnaire_web = GestionnaireWeb(self, mode_dev=self._args.dev)
        self._gestionnaire_web.entretien()

        self._gestionnaire_docker.start_events()
        self._gestionnaire_docker.add_event_listener(self)

        self.__logger.info("Preparation CSR du noeud dependant terminee")
        self.preparer_gestionnaire_certificats()

        self.preparer_gestionnaire_commandes()

        # Entretien initial pour s'assurer d'avoir les services de base
        try:
            self._gestionnaire_docker.entretien_services()
        except AttributeError as ae:
            self.__logger.exception("Erreur creation services, docker config non chargee")
            raise ae

        self.__logger.info("Web API - attence connexion sur port 8444")
        self.preparer_web_api()

        while not self.__event_attente.is_set():
            self._run_entretien()
            self.__event_attente.wait(10)

    def _run_entretien(self):
        """
        Mode d'operation de base du monitor, lorsque toute la configuration est completee.
        :return:
        """
        self.__logger.info("Debut boucle d'entretien du service monitor")

        while not self._fermeture_event.is_set():
            self._attente_event.clear()

            try:
                self.__logger.debug("Cycle entretien ServiceMonitor")
                self.verifier_load()

                if not self.limiter_entretien:
                    # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
                    self._gestionnaire_docker.entretien_services()

                self.__logger_verbose.debug("Fin cycle entretien ServiceMonitor")
            except Exception as e:
                self.__logger.exception("ServiceMonitor: erreur generique : " + str(e))
            finally:
                self._attente_event.wait(30)

        self.__logger.info("Fin execution de la boucle d'entretien du service monitor")

    def preparer_gestionnaire_certificats(self):
        params = dict()
        if self._args.dev:
            params['insecure'] = True
        if self._args.secrets:
            params['secrets'] = self._args.secrets
        self._gestionnaire_certificats = GestionnaireCertificatsInstallation(self._docker, self, **params)

        nouveau_secrets_monitor_ajoutes = False  # Flag qui va indiquer si de nouveaux secrets sont ajoutes

        # Verifier si le certificat nginx existe deja - generer un cert self-signed au besoin
        try:
            docker_cert_nginx = self._gestionnaire_docker.charger_config_recente('pki.nginx.cert')
        except AttributeError:
            # Certificat absent, on genere un certificat et cle nginx
            self._gestionnaire_certificats.generer_certificat_nginx_selfsigned()

        # Verifier si le CSR a deja ete genere, sinon le generer
        try:
            csr_config_docker = self._gestionnaire_docker.charger_config_recente('pki.intermediaire.csr')
            data_csr = b64decode(csr_config_docker['config'].attrs['Spec']['Data'])
            self.csr_intermediaire = data_csr
        except AttributeError:
            # Creer CSR pour le service monitor
            csr_info = self._gestionnaire_certificats.generer_csr('intermediaire', insecure=self._args.dev, generer_password=True)
            self.csr_intermediaire = csr_info['request']

        # Verifier si la cle du monitor existe, sinon la generer
        try:
            self._gestionnaire_docker.trouver_secret('pki.monitor.key')
        except PkiCleNonTrouvee:
            # Creer CSR pour le service monitor
            self._gestionnaire_certificats.generer_csr('monitor', insecure=self._args.dev, generer_password=False)
            nouveau_secrets_monitor_ajoutes = True

        # if nouveau_secrets_monitor_ajoutes:
        if nouveau_secrets_monitor_ajoutes:
            try:
                # Besoin reconfigurer le service pour ajouter les secrets et redemarrer
                self._gestionnaire_docker.configurer_monitor()

                # Redemarrer / reconfigurer le monitor
                self.__logger.info("Configuration completee, redemarrer le monitor")
                if not self._args.dev:
                    raise ForcerRedemarrage("Redemarrage")
            except ValueError as ve:
                if not self._args.dev:
                    raise ve
                else:
                    self.__logger.warning("Erreur valeur monitor : %s" % ve)

    def configurer_idmg(self, commande: CommandeMonitor):
        """
        Genere la configuration docker avec le niveau de securite et IDMG. Genere le certificat web SSL au besoin.
        :param commande:
        :return:
        """
        params = commande.contenu
        idmg = params['idmg']
        self._idmg = idmg
        securite = params['securite']
        domaine = params.get('domaine')

        if domaine is not None:
            self.__logger.info("Generer certificat web SSL pour " + domaine)
            self.initialiser_domaine(commande)

        self.sauvegarder_config_millegrille(idmg, securite)

    def initialiser_noeud(self, commande: CommandeMonitor):
        if self.__logger.isEnabledFor(logging.DEBUG):
            self.__logger.debug("Commande initialiser noeud : %s", json.dumps(commande.contenu, indent=2))

        params = commande.contenu
        securite = params['securite']
        self._securite = securite

        if securite == Constantes.SECURITE_PROTEGE:
            self.__initialiser_noeud_protege(commande)
        elif securite == Constantes.SECURITE_PRIVE:
            self.__initialiser_noeud_installation(commande, Constantes.SECURITE_PRIVE)
        elif securite == Constantes.SECURITE_PUBLIC:
            self.__initialiser_noeud_installation(commande, Constantes.SECURITE_PUBLIC)
        else:
            raise Exception("Type de noeud non supporte : " + securite)

    def __initialiser_noeud_protege(self, commande: CommandeMonitor):
        params = commande.contenu
        gestionnaire_docker = self.gestionnaire_docker

        gestionnaire_certs = GestionnaireCertificatsNoeudProtegePrincipal(
            self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
        gestionnaire_certs.generer_motsdepasse()

        # Faire correspondre et sauvegarder certificat de noeud
        secret_intermediaire = gestionnaire_docker.trouver_secret('pki.intermediaire.key')

        with open(os.path.join(self._args.secrets, 'pki.intermediaire.key.pem'), 'rb') as fichier:
            intermediaire_key_pem = fichier.read()
        with open(os.path.join(self._args.secrets, 'pki.intermediaire.passwd.txt'), 'rb') as fichier:
            intermediaire_passwd_pem = fichier.read()

        certificat_pem = params['certificatPem']
        certificat_millegrille = params['chainePem'][-1]
        chaine = params['chainePem']

        # Extraire IDMG
        self.__logger.debug("Certificat de la MilleGrille :\n%s" % certificat_millegrille)
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(certificat_millegrille.encode('utf-8'))
        idmg = clecert_millegrille.idmg

        clecert_recu = EnveloppeCleCert()
        clecert_recu.from_pem_bytes(intermediaire_key_pem, certificat_pem.encode('utf-8'), intermediaire_passwd_pem)
        if not clecert_recu.cle_correspondent():
            raise ValueError('Cle et Certificat intermediaire ne correspondent pas')

        # Verifier si on doit generer un certificat web SSL
        domaine_web = params.get('domaine')
        if domaine_web is not None:
            self.__logger.info("Generer certificat web SSL pour %s" % domaine_web)
            self.initialiser_domaine(commande)

        cert_subject = clecert_recu.formatter_subject()

        # Verifier le type de certificat - il determine le type de noeud:
        # intermediaire = noeud protege, prive = noeud prive, public = noeud public
        self.__logger.debug("Certificat recu : %s", str(cert_subject))
        subject_clecert_recu = clecert_recu.formatter_subject()
        if subject_clecert_recu['organizationName'] != idmg:
            raise Exception("IDMG %s ne correspond pas au certificat de monitor" % idmg)

        type_certificat_recu = subject_clecert_recu['organizationalUnitName']

        # Comencer sauvegarde
        gestionnaire_docker.sauvegarder_config('pki.millegrille.cert', certificat_millegrille)

        if type_certificat_recu != 'intermediaire':
            raise Exception("Type de certificat inconnu : %s" % type_certificat_recu)

        securite = Constantes.SECURITE_PROTEGE
        gestionnaire_docker.sauvegarder_config(
            'pki.intermediaire.cert.' + str(secret_intermediaire['date']),
            certificat_pem
        )
        chaine_intermediaire = '\n'.join([certificat_pem, certificat_millegrille])
        gestionnaire_docker.sauvegarder_config(
            'pki.intermediaire.chain.' + str(secret_intermediaire['date']), chaine_intermediaire)

        # Configurer gestionnaire certificats avec clecert millegrille, intermediaire
        self._gestionnaire_certificats.idmg = idmg
        self._gestionnaire_certificats.set_clecert_millegrille(clecert_millegrille)
        self._gestionnaire_certificats.set_clecert_intermediaire(clecert_recu)

        # Generer nouveau certificat de monitor
        # Charger CSR monitor
        config_csr_monitor = self._gestionnaire_docker.charger_config_recente('pki.monitor.csr')
        data_csr_monitor = b64decode(config_csr_monitor['config'].attrs['Spec']['Data'])
        clecert_monitor = self._gestionnaire_certificats.signer_csr(data_csr_monitor)

        # Sauvegarder certificat monitor
        # Faire correspondre et sauvegarder certificat de noeud
        secret_monitor = gestionnaire_docker.trouver_secret('pki.monitor.key')
        gestionnaire_docker.sauvegarder_config(
            'pki.monitor.cert.' + str(secret_monitor['date']),
            '\n'.join(clecert_monitor.chaine)
        )

        # Supprimer le CSR
        gestionnaire_docker.supprimer_config('pki.monitor.csr.' + str(secret_monitor['date']))

        # Supprimer le CSR
        gestionnaire_docker.supprimer_config('pki.intermediaire.csr.' + str(secret_intermediaire['date']))

        # Terminer configuration swarm docker
        gestionnaire_docker.initialiser_noeud(idmg=idmg)

        self.sauvegarder_config_millegrille(idmg, securite)

        # Regenerer la configuraiton de NGINX (change defaut de /installation vers /vitrine)
        # Redemarrage est implicite (fait a la fin de la prep)
        self._gestionnaire_web.regenerer_configuration(mode_installe=True)

        # Forcer reconfiguration nginx (ajout certificat de millegrille pour validation client ssl)
        try:
            gestionnaire_docker.maj_service('nginx')
        except docker.errors.APIError as apie:
            if apie.status_code == 500:
                self.__logger.warning("Erreur mise a jour, probablement update concurrentes. On attend 15 secondes puis on reessaie")
                self.__event_attente.wait(15)
                gestionnaire_docker.maj_service('nginx')
            else:
                raise apie

        # Redemarrer / reconfigurer le monitor
        self.__logger.info("Configuration completee, redemarrer le monitor")
        gestionnaire_docker.configurer_monitor()

        raise ForcerRedemarrage("Redemarrage")

    def _get_info_noeud(self):
        information_systeme = super()._get_info_noeud()
        information_systeme['csr'] = self.csr_intermediaire.decode('utf-8')
        return information_systeme

    def __initialiser_noeud_installation(self, commande: CommandeMonitor, securite: str):
        """
        Initialise un noeud protege avec un certificat
        :param commande:
        :return:
        """

        params = commande.contenu
        gestionnaire_docker = self.gestionnaire_docker

        if securite == Constantes.SECURITE_PRIVE:
            gestionnaire_certs = GestionnaireCertificatsNoeudPrive(
                self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
            role = ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE
        elif securite == Constantes.SECURITE_PUBLIC:
            gestionnaire_certs = GestionnaireCertificatsNoeudPrive(
                self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
            role = ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC
        else:
            raise Exception("Niveau securite non supporte : %s" % securite)

        gestionnaire_certs.generer_motsdepasse()

        # Faire correspondre et sauvegarder certificat de noeud
        secret_intermediaire = gestionnaire_docker.trouver_secret('pki.intermediaire.key')
        secret_date = secret_intermediaire['date']

        if not self._args.dev:
            nom_fichier_key = 'pki.intermediaire.key.pem'
            nom_fichier_passwd = 'pki.intermediaire.passwd.txt'
        else:
            nom_fichier_key = 'pki.intermediaire.key.%s' % secret_date
            nom_fichier_passwd = 'pki.intermediaire.passwd.%s' % secret_date

        with open(os.path.join(self._args.secrets, nom_fichier_key), 'rb') as fichier:
            intermediaire_key_pem = fichier.read()
        with open(os.path.join(self._args.secrets, nom_fichier_passwd), 'rb') as fichier:
            intermediaire_passwd_pem = fichier.read()
        certificat_pem = params['certificatPem']
        certificat_millegrille = params['chainePem'][-1]
        chaine = params['chainePem']

        # Extraire IDMG
        self.__logger.debug("Certificat de la MilleGrille :\n%s" % certificat_millegrille)
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(certificat_millegrille.encode('utf-8'))
        idmg = clecert_millegrille.idmg

        if self.idmg != idmg:
            raise ValueError("Le IDMG du certificat (%s) ne correspond pas a celui du noeud (%s)", (idmg, self.idmg))

        clecert_recu = EnveloppeCleCert()
        clecert_recu.from_pem_bytes(intermediaire_key_pem, certificat_pem.encode('utf-8'), intermediaire_passwd_pem)
        if not clecert_recu.cle_correspondent():
            raise ValueError('Cle et Certificat intermediaire ne correspondent pas')

        # Verifier si on doit generer un certificat web SSL
        domaine_web = params.get('domaine')
        if domaine_web is not None:
            self.__logger.info("Generer certificat web SSL pour %s" % domaine_web)
            self.initialiser_domaine(commande)

        cert_subject = clecert_recu.formatter_subject()

        # Verifier le type de certificat - il determine le type de noeud:
        # intermediaire = noeud protege, prive = noeud prive, public = noeud public
        self.__logger.debug("Certificat recu : %s", str(cert_subject))
        subject_clecert_recu = clecert_recu.formatter_subject()
        if subject_clecert_recu['organizationName'] != idmg:
            raise Exception("IDMG %s ne correspond pas au certificat de monitor" % idmg)

        type_certificat_recu = subject_clecert_recu['organizationalUnitName']
        if type_certificat_recu != role:
            raise Exception("Type de certificat inconnu : %s" % type_certificat_recu)

        # Comencer sauvegarde
        try:
            gestionnaire_docker.sauvegarder_config('pki.millegrille.cert', certificat_millegrille)
        except APIError as apie:
            if apie.status_code == 400:
                self.__logger.info("pki.millegrille.cert deja present, on ne le change pas : " + str(apie))
            else:
                raise apie

        self.__logger.debug("Sauvegarde certificat recu et cle intermediaire comme cert/cle de monitor prive")
        # securite = Constantes.SECURITE_PRIVE
        clecert_recu.password = None
        cle_monitor = clecert_recu.private_key_bytes
        secret_name, date_key = gestionnaire_docker.sauvegarder_secret(
            ConstantesServiceMonitor.PKI_MONITOR_KEY, cle_monitor, ajouter_date=True)

        gestionnaire_docker.sauvegarder_config(
            'pki.monitor.cert.' + date_key,
            '\n'.join(chaine)
        )

        # Supprimer le CSR
        try:
            gestionnaire_docker.supprimer_config('pki.monitor.csr.' + str(secret_intermediaire['date']))
        except docker.errors.NotFound:
            pass
        try:
            gestionnaire_docker.supprimer_config('pki.intermediaire.csr.' + str(secret_intermediaire['date']))
        except docker.errors.NotFound:
            pass

        # Terminer configuration swarm docker
        gestionnaire_docker.initialiser_noeud(idmg=idmg)

        self.sauvegarder_config_millegrille(idmg, securite)

        # Regenerer la configuraiton de NGINX (change defaut de /installation vers /vitrine)
        # Redemarrage est implicite (fait a la fin de la prep)
        self._gestionnaire_web.regenerer_configuration(mode_installe=True)

        # Forcer reconfiguration nginx (ajout certificat de millegrille pour validation client ssl)
        try:
            gestionnaire_docker.maj_service('nginx')
        except docker.errors.APIError as apie:
            if apie.status_code == 500:
                self.__logger.warning(
                    "Erreur mise a jour, probablement update concurrentes. On attend 15 secondes puis on reessaie")
                Event().wait(15)
                gestionnaire_docker.maj_service('nginx')
            else:
                raise apie

        # Redemarrer / reconfigurer le monitor
        self.__logger.info("Configuration completee, redemarrer le monitor")
        gestionnaire_docker.configurer_monitor()

        raise ForcerRedemarrage("Redemarrage")

    # @property
    # def securite(self):
    #     return self._securite


# class ServiceMonitorExtension(ServiceMonitor):
#     """
#     Monitor pour le noeud d'extension
#     """
#
#     def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
#         super().__init__(args, docker_client, configuration_json)
#         self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
#         self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)
#
#     def run(self):
#         self.__logger.info("Demarrage du ServiceMonitor")
#
#         try:
#             self._charger_configuration()
#             self.preparer_gestionnaire_certificats()
#             self.configurer_millegrille()
#             self.preparer_gestionnaire_commandes()
#             self.preparer_web_api()
#
#             while not self._fermeture_event.is_set():
#                 self._attente_event.clear()
#
#                 try:
#                     self.__logger.debug("Cycle entretien ServiceMonitor")
#
#                     self.verifier_load()
#
#                     self._entretien_modules()
#
#                     if not self._connexion_middleware:
#                         try:
#                             self.connecter_middleware()
#                         except BrokenBarrierError:
#                             self.__logger.warning("Erreur connexion MQ, on va reessayer plus tard")
#
#                     self.__logger_verbose.debug("Fin cycle entretien ServiceMonitor")
#                 except Exception as e:
#                     self.__logger.exception("ServiceMonitor: erreur generique : " + str(e))
#                 finally:
#                     self._attente_event.wait(30)
#
#         except ForcerRedemarrage:
#             self.__logger.info("Configuration initiale terminee, fermeture pour redemarrage")
#             self.exit_code = ConstantesServiceMonitor.EXIT_REDEMARRAGE
#
#         except Exception:
#             self.__logger.exception("Erreur demarrage ServiceMonitor, on abandonne l'execution")
#
#         self.__logger.info("Fermeture du ServiceMonitor")
#         self.fermer()
#
#         # Fermer le service monitor, retourne exit code pour shell script
#         sys.exit(self.exit_code)
#
#     def preparer_gestionnaire_certificats(self):
#         params = dict()
#         if self._args.dev:
#             params['insecure'] = True
#         if self._args.secrets:
#             params['secrets'] = self._args.secrets
#         self._gestionnaire_certificats = GestionnaireCertificatsNoeudPrive(self._docker, self, **params)
#
#     def preparer_gestionnaire_commandes(self):
#         self._gestionnaire_commandes = GestionnaireCommandes(self._fermeture_event, self)
#
#         super().preparer_gestionnaire_commandes()  # Creer pipe et demarrer
#
#     def _initialiser_noeud(self, commande: CommandeMonitor, securite: str):
#         """
#         Initialise un noeud protege avec un certificat
#         :param commande:
#         :return:
#         """
#
#         params = commande.contenu
#         gestionnaire_docker = self.gestionnaire_docker
#
#         if securite == Constantes.SECURITE_PRIVE:
#             gestionnaire_certs = GestionnaireCertificatsNoeudPrive(
#                 self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
#             role = ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE
#         elif securite == Constantes.SECURITE_PUBLIC:
#             gestionnaire_certs = GestionnaireCertificatsNoeudPrive(
#                 self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
#             role = ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC
#         else:
#             raise Exception("Niveau securite non supporte : %s" % securite)
#
#         gestionnaire_certs.generer_motsdepasse()
#
#         # Faire correspondre et sauvegarder certificat de noeud
#         secret_intermediaire = gestionnaire_docker.trouver_secret('pki.intermediaire.key')
#         secret_date = secret_intermediaire['date']
#
#         if not self._args.dev:
#             nom_fichier_key = 'pki.intermediaire.key.pem'
#             nom_fichier_passwd = 'pki.intermediaire.passwd.txt'
#         else:
#             nom_fichier_key = 'pki.intermediaire.key.%s' % secret_date
#             nom_fichier_passwd = 'pki.intermediaire.passwd.%s' % secret_date
#
#         with open(os.path.join(self._args.secrets, nom_fichier_key), 'rb') as fichier:
#             intermediaire_key_pem = fichier.read()
#         with open(os.path.join(self._args.secrets, nom_fichier_passwd), 'rb') as fichier:
#             intermediaire_passwd_pem = fichier.read()
#         certificat_pem = params['certificatPem']
#         certificat_millegrille = params['chainePem'][-1]
#         chaine = params['chainePem']
#
#         # Extraire IDMG
#         self.__logger.debug("Certificat de la MilleGrille :\n%s" % certificat_millegrille)
#         clecert_millegrille = EnveloppeCleCert()
#         clecert_millegrille.cert_from_pem_bytes(certificat_millegrille.encode('utf-8'))
#         idmg = clecert_millegrille.idmg
#
#         if self.idmg != idmg:
#             raise ValueError("Le IDMG du certificat (%s) ne correspond pas a celui du noeud (%s)", (idmg, self.idmg))
#
#         clecert_recu = EnveloppeCleCert()
#         clecert_recu.from_pem_bytes(intermediaire_key_pem, certificat_pem.encode('utf-8'), intermediaire_passwd_pem)
#         if not clecert_recu.cle_correspondent():
#             if self._args.dev is not None:
#                 # Tenter de charger cle pour monitor - mode insecure
#                 try:
#                     config_csr = self.gestionnaire_docker.charger_config_recente('pki.monitor.csr')
#                     date_csr = config_csr['date']
#                     with open(os.path.join(self._args.secrets, 'pki.monitor.key.%s' % date_csr), 'rb') as fichier:
#                         monitor_key_pem = fichier.read()
#                     clecert_recu = EnveloppeCleCert()
#                     clecert_recu.from_pem_bytes(monitor_key_pem, certificat_pem.encode('utf-8'))
#                     if not clecert_recu.cle_correspondent():
#                         raise ValueError('MODE DEV : Cle et Certificat monitor (mode insecure) ne correspondent pas')
#                 except FileNotFoundError:
#                     raise ValueError('MODE DEV : Cle associe au CSR monitor introuvable')
#                 except AttributeError:
#                     raise ValueError('MODE DEV : CSR monitor introuvable')
#             else:
#                 raise ValueError('Cle et Certificat intermediaire ne correspondent pas')
#
#         # Verifier si on doit generer un certificat web SSL
#         domaine_web = params.get('domaine')
#         if domaine_web is not None:
#             self.__logger.info("Generer certificat web SSL pour %s" % domaine_web)
#             self.initialiser_domaine(commande)
#
#         cert_subject = clecert_recu.formatter_subject()
#
#         # Verifier le type de certificat - il determine le type de noeud:
#         # intermediaire = noeud protege, prive = noeud prive, public = noeud public
#         self.__logger.debug("Certificat recu : %s", str(cert_subject))
#         subject_clecert_recu = clecert_recu.formatter_subject()
#         if subject_clecert_recu['organizationName'] != idmg:
#             raise Exception("IDMG %s ne correspond pas au certificat de monitor" % idmg)
#
#         type_certificat_recu = subject_clecert_recu['organizationalUnitName']
#         if type_certificat_recu != role:
#             raise Exception("Type de certificat inconnu : %s" % type_certificat_recu)
#
#         # Comencer sauvegarde
#         try:
#             gestionnaire_docker.sauvegarder_config('pki.millegrille.cert', certificat_millegrille)
#         except APIError as apie:
#             if apie.status_code == 400:
#                 self.__logger.info("pki.millegrille.cert deja present, on ne le change pas : " + str(apie))
#             else:
#                 raise apie
#
#         self.__logger.debug("Sauvegarde certificat recu et cle intermediaire comme cert/cle de monitor prive")
#         # securite = Constantes.SECURITE_PRIVE
#         clecert_recu.password = None
#         cle_monitor = clecert_recu.private_key_bytes
#         secret_name, date_key = gestionnaire_docker.sauvegarder_secret(
#             ConstantesServiceMonitor.PKI_MONITOR_KEY, cle_monitor, ajouter_date=True)
#
#         # if self._args.dev:
#         #     nom_key = ConstantesServiceMonitor.PKI_MONITOR_KEY + date_key
#         #     with open(os.path.join(self._args.secrets, nom_key), 'w') as fichier:
#         #         fichier.write(cle_monitor)
#
#         gestionnaire_docker.sauvegarder_config(
#             'pki.monitor.cert.' + date_key,
#             '\n'.join(chaine)
#         )
#
#         # Supprimer le CSR
#         try:
#             gestionnaire_docker.supprimer_config('pki.monitor.csr.' + str(secret_intermediaire['date']))
#         except docker.errors.NotFound:
#             pass
#         try:
#             gestionnaire_docker.supprimer_config('pki.intermediaire.csr.' + str(secret_intermediaire['date']))
#         except docker.errors.NotFound:
#             pass
#
#         # Terminer configuration swarm docker
#         gestionnaire_docker.initialiser_noeud(idmg=idmg)
#
#         self.sauvegarder_config_millegrille(idmg, securite)
#
#         # Regenerer la configuraiton de NGINX (change defaut de /installation vers /vitrine)
#         # Redemarrage est implicite (fait a la fin de la prep)
#         self._gestionnaire_web.regenerer_configuration(mode_installe=True)
#
#         # Forcer reconfiguration nginx (ajout certificat de millegrille pour validation client ssl)
#         try:
#             gestionnaire_docker.maj_service('nginx')
#         except docker.errors.APIError as apie:
#             if apie.status_code == 500:
#                 self.__logger.warning(
#                     "Erreur mise a jour, probablement update concurrentes. On attend 15 secondes puis on reessaie")
#                 Event().wait(15)
#                 gestionnaire_docker.maj_service('nginx')
#             else:
#                 raise apie
#
#         # Redemarrer / reconfigurer le monitor
#         self.__logger.info("Configuration completee, redemarrer le monitor")
#         gestionnaire_docker.configurer_monitor()
#
#         raise ForcerRedemarrage("Redemarrage")


# Section main
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stdout, format=MonitorConstantes.SERVICEMONITOR_LOGGING_FORMAT)
    logging.getLogger(ServiceMonitor.__name__).setLevel(logging.INFO)

    # ServiceMonitor().run()
    InitialiserServiceMonitor().demarrer()

