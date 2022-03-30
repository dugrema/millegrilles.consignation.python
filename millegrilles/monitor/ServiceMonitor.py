import signal
import logging
import docker
import json
import datetime
import os
import psutil
import tarfile
import io
import lzma
import pytz
import requests

from typing import cast, Optional
from threading import Event
from docker.errors import APIError
from base64 import b64decode

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificats
from millegrilles.monitor.MonitorCommandes import GestionnaireCommandes
from millegrilles.monitor.MonitorComptes import GestionnaireComptesMQ
from millegrilles.monitor.MonitorConstantes import ForcerRedemarrage, ConnexionMiddlewarePasPreteException
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker
from millegrilles.monitor.MonitorRelaiMessages import ConnexionMiddleware
from millegrilles.monitor.MonitorNetworking import GestionnaireWeb
from millegrilles.util.X509Certificate import EnveloppeCleCert
from millegrilles.monitor.MonitorApplications import GestionnaireApplications
from millegrilles.monitor.MonitorWebAPI import ServerWebAPI
from millegrilles.monitor.MonitorConstantes import CommandeMonitor
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorCertificats import ErreurSignatureCertificatException
from millegrilles.util.IpUtils import get_ip
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.ValidateursPki import ValidateurCertificat
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.transaction.FormatteurMessage import FormatteurMessageMilleGrilles, SignateurTransactionSimple


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

        # Initialiser dernier backup d'application comme s'il etait du dans quelques minutes
        date_now = pytz.utc.localize(datetime.datetime.utcnow())
        self._applications_backup_frequence = datetime.timedelta(days=1)
        self._applications_backup_date = date_now - self._applications_backup_frequence + datetime.timedelta(minutes=20)

        # self._verificateur_transactions: Optional[VerificateurTransaction] = None
        self.__validateur_message: Optional[ValidateurMessage] = None

        # Gerer les signaux OS, permet de deconnecter les ressources au besoin
        signal.signal(signal.SIGINT, self.fermer)
        signal.signal(signal.SIGTERM, self.fermer)

        self.exit_code = 0

        self.__generateur_temporaire: Optional[GenerateurTransaction] = None

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
                
            self.__logger.info("Fermeture ServiceMonitor en cours")

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

        mq_pret = self._gestionnaire_mq.attendre_mq(10)  # Healthcheck, attendre 10 secondes

        return mq_pret

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

        # # Verifier si le CSR intermediaire a deja ete genere
        # try:
        #     csr_config_docker = self._gestionnaire_docker.charger_config_recente('pki.intermediaire.csr')
        #     data_csr = b64decode(csr_config_docker['config'].attrs['Spec']['Data'])
        #     self.csr_intermediaire = data_csr
        # except AttributeError:
        #     pass

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

        try:
            hostname_onion = gestionnaire_docker.get_nginx_onionize_hostname()
            dict_infomillegrille['onion'] = hostname_onion
        except:
            pass

        # Verifier si on a le certificat de monitor - indique que le noeud est installe
        try:
            monitor_cert = gestionnaire_docker.charger_config_recente('pki.monitor.cert')
            monitor_cert = b64decode(monitor_cert['config'].attrs['Spec']['Data']).decode('utf-8')
            dict_infomillegrille['certificat'] = monitor_cert
            ca_cert = gestionnaire_docker.charger_config_recente('pki.millegrille.cert')
            ca_cert = b64decode(ca_cert['config'].attrs['Spec']['Data']).decode('utf-8')
            dict_infomillegrille['ca'] = ca_cert
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

    def _get_dict_modules(self) -> dict:
        raise NotImplementedError()
        # return MonitorConstantes.DICT_MODULES_PROTEGES

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

        # S'assurer que tous les certificats sont generes (initialement ou sur suppression forcee)
        # roles = [info['role'] for info in MonitorConstantes.DICT_MODULES_PROTEGES.values() if info.get('role')]
        dict_modules = self._get_dict_modules()  # MonitorConstantes.DICT_MODULES_PROTEGES
        roles = [info['role'] for info in dict_modules.values() if info.get('role')]
        resultat_entretien_certificats = self._supprimer_certificats_expires(roles)

        # Generer certificats expires et manquants pour modules proteges
        for nom_role, info_role in resultat_entretien_certificats.items():
            if not info_role.get('expiration') or info_role.get('est_expire'):
                self.__logger.debug("Generer nouveau certificat role %s", nom_role)
                try:
                    self._gestionnaire_certificats.generer_clecert_module(
                        nom_role, self._nodename, liste_dns=[fqdn_noeud, domaine_noeud])

                    # Reconfigurer tous les services qui utilisent le nouveau certificat
                    self._gestionnaire_docker.maj_services_avec_certificat(nom_role)
                except ErreurSignatureCertificatException as e:
                    self.__logger.warning("Erreur creation certificat : %s", e)

            elif nom_role == 'nginx':
                clecert = info_role['clecert']
                subject_dict = clecert.formatter_subject()
                organization = subject_dict['organizationName']
                if organization != self.idmg:
                    # Le certificat nginx est encore celui d'installation, on en genere un nouveau
                    try:
                        self._gestionnaire_certificats.generer_clecert_module(
                            nom_role, self._nodename, liste_dns=[fqdn_noeud, domaine_noeud])
                        self._gestionnaire_docker.maj_services_avec_certificat(nom_role)
                    except ErreurSignatureCertificatException as e:
                        self.__logger.warning("Erreur creation certificat : %s", e)

        # Entretien des certificats services
        self._entretien_certificats_pki()

        # Entretien certificat nginx - s'assurer que le certificat d'installation est remplace

        # Nettoyer certificats monitor
        self._supprimer_certificats_expires(['monitor'])

        # # Entretien certificats applications
        # self._entretien_certificats_applications()

    def _entretien_certificats_pki(self):
        prefixe_certificats = 'pki.'
        filtre = {
            'name': prefixe_certificats,
            'label': ['mg_type=pki']
        }
        nom_applications = dict()
        for config in self._docker.configs.list(filters=filtre):
            labels = config.attrs['Spec']['Labels']
            app_role = labels['role']
            nom_applications[app_role] = labels

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
                self.__logger.debug("Generer nouveau certificat role %s", nom_role)
                try:
                    self._gestionnaire_certificats.generer_clecert_module(
                        nom_role,
                        domaine_noeud,
                        nom_role,
                        liste_dns=[fqdn_noeud, domaine_noeud, nom_role, nom_role + '.' + domaine_noeud]
                    )

                    # Reconfigurer tous les services qui utilisent le nouveau certificat
                    self._gestionnaire_docker.maj_services_avec_certificat(nom_role)
                except Exception:
                    self.__logger.exception("Erreur creation nouveau certificat %s" % nom_role)

    def _supprimer_certificats_expires(self, roles_entretien: list):
        prefixe_certificats = 'pki.'
        filtre = {'name': prefixe_certificats}

        # Generer tous les certificas qui peuvent etre utilises
        roles = dict()
        for role in roles_entretien:
            roles[role] = {
                'est_expire': True,
            }

        date_courante = datetime.datetime.now(tz=pytz.UTC)

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
                role_info['clecert'] = clecert

                if date_expiration is not None:
                    role_info['expiration'] = date_expiration

                    # Calculer 2/3 de la duree du certificat
                    not_valid_before = clecert.not_valid_before
                    delta_fin_debut = date_expiration.timestamp() - not_valid_before.timestamp()
                    epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
                    date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers, tz=pytz.UTC)

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

        # Entretien du middleware MQ
        # S'assurer que MQ est demarre
        self._gestionnaire_docker.entretien_services('mq')

        # S'assurer que le compte administrateur est configure et MQ est disponible
        self._gestionnaire_mq.entretien()

        if not self.limiter_entretien:
            # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
            self._gestionnaire_docker.entretien_services()

            date_now = pytz.utc.localize(datetime.datetime.utcnow())

            # Entretien web
            if self._web_entretien_date is None or \
                    self._web_entretien_date + self._web_entretien_frequence < date_now:
                self._web_entretien_date = date_now
                self._gestionnaire_web.entretien()

            # Entretien des certificats du monitor, services
            if self._certificats_entretien_date is None or \
                    self._certificats_entretien_date + self._certificats_entretien_frequence < date_now:

                self._certificats_entretien_date = date_now
                self._entretien_certificats()
                self._entretien_secrets_pki()

            # Backup
            if self._applications_backup_date + self._applications_backup_frequence < date_now:
                # Placer la date de backup pour que l'intervalle tombe le lendemain
                self._applications_backup_date = pytz.utc.localize(datetime.datetime(
                    year=date_now.year, month=date_now.month, day=date_now.day, hour=9))

                # Declencher backup quotidien pour les applications
                commande = CommandeMonitor({
                    'commande': Constantes.ConstantesServiceMonitor.COMMANDE_BACKUP_APPLICATION,
                })
                self._gestionnaire_commandes.ajouter_commande(commande)

    def run(self):
        raise NotImplementedError()

    def verifier_load(self):
        cpu_load, cpu_load5, cpu_load10 = psutil.getloadavg()
        if cpu_load > 10.0 or cpu_load5 > 5.0:
            self.limiter_entretien = True
            self.__logger.warning("Charge de travail elevee %s / %s (limite 10.0/5.0), entretien limite" % (cpu_load, cpu_load5))
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
            info_mq['MG_MQ_HOST'] = self._connexion_middleware.configuration.mq_host
            info_mq['MG_MQ_PORT'] = self._connexion_middleware.configuration.mq_port
            info_mq['MG_MQ_URL'] = 'amqps://%s:%d' % (self._connexion_middleware.configuration.mq_host, self._connexion_middleware.configuration.mq_port)
        except:
            # Connexion middleware pas chargee, on tente d'utiliser mdns
            pass
            # if not nowait:
            #     self._attente_event.wait(2)
            #     # services = self._gestionnaire_mdns.get_service(self.idmg, '_mgamqps._tcp')
            #     services = self._gestionnaire_commandes.requete_mdns_acteur(self.idmg)
            #     services_mq = [s for s in services if s.get('type') is not None and s['type'].startswith('_mgamqps._tcp')]
            #     try:
            #         service = services_mq[0]
            #         info_mq['MQ_HOST'] = service['addresses'][0]
            #         info_mq['MQ_PORT'] = service['port']
            #     except IndexError:
            #         pass  # Aucun service disponible

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

        # with lzma.open(os.path.join(path_catalogues, 'catalogue.domaines.json.xz'), 'rt') as fichier:
        #     catalogue_domaines = json.load(fichier)
        # domaine_action = 'transaction.' + catalogue_domaines[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        # self._connexion_middleware.generateur_transactions.emettre_message(catalogue_domaines, domaine_action)

        path_applications = os.path.join(webroot, 'catalogues', 'applications')
        liste_fichiers_apps = os.listdir(path_applications)
        info_apps = [os.path.join(path_applications, f) for f in liste_fichiers_apps if f.endswith('.json.xz')]
        for app_path in info_apps:
            with lzma.open(app_path, 'rt') as fichier:
                app_transaction = json.load(fichier)

            commande = {"catalogue": app_transaction}
            self._connexion_middleware.generateur_transactions.transmettre_commande(commande, domaine='CoreCatalogues', action='catalogueApplication')

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
        routing = 'evenement.monitor.%s.%s' % (self.noeud_id, action)
        if info is None:
            info = dict()
        try:
            self._connexion_middleware.generateur_transactions.emettre_message(info, routing)
        except Exception:
            self.__logger.exception("Erreur transmission evenement monitor")

    @property
    def connexion_middleware(self) -> ConnexionMiddleware:
        if self._connexion_middleware is None:
            raise ConnexionMiddlewarePasPreteException("Connexion middleware n'est pas prete")
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
    def validateur_certificat(self) -> ValidateurCertificat:
        try:
            if self._connexion_middleware is not None:
                validateur = self._connexion_middleware.validateur_certificat
                if validateur is not None:
                    return validateur
        except Exception:
            self.__logger.exception("Erreur chargement validateur messages, on utilise une version offline")
        else:
            self.__logger.warning("Erreur chargement validateur messages, on utilise une version offline")

        if self.__validateur_message is None:
            self.__validateur_message = ValidateurMessage(idmg=self.idmg)

        return self.__validateur_message

    # def generer_csr_intermediaire(self):
    #     csr_info = self.gestionnaire_certificats.generer_csr('intermediaire', insecure=self._args.dev, generer_password=True)
    #     self.csr_intermediaire = csr_info['request']
    #     return self.csr_intermediaire

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
    def generateur_transactions(self) -> GenerateurTransaction:
        return self._connexion_middleware.generateur_transactions

    def get_formatteur_message(self, clecert: EnveloppeCleCert) -> FormatteurMessageMilleGrilles:
        signateur = SignateurTransactionSimple(clecert)
        return FormatteurMessageMilleGrilles(self.idmg, signateur)

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

    @property
    def nom_service_nginx(self):
        return 'nginx'

    def changer_domaine(self, commande):
        params = commande.contenu
        gestionnaire_docker = self.gestionnaire_docker

        domaine = params['domaine']

        try:
            configuration_str = gestionnaire_docker.charger_config('acme.configuration')
            configuration_acme = json.loads(configuration_str)
        except:
            configuration_acme = {
                'domain': '',
                'method': None
            }

        configuration_acme['domain'] = domaine

        # Remplacement de la configuration
        gestionnaire_docker.sauvegarder_config('acme.configuration', json.dumps(configuration_acme).encode('utf-8'))

        # Emettre nouvelle presence avec domaine modifie
        self.emettre_presence()

    def initialiser_domaine(self, commande):
        """
        Obtient un nouveau certificat web TLS avec LetsEncrypt
        """
        params = commande.contenu
        gestionnaire_docker = self.gestionnaire_docker

        # Aller chercher le certificat SSL de LetsEncrypt
        domaine_noeud = params['domaine']
        mode_test = params.get('modeTest') or False
        force = params.get('force') or False
        mode_creation = params.get('modeCreation')

        params_environnement = dict()
        params_secrets = dict()
        mode_dns = False

        commande_str = ''

        methode = {
            'modeCreation': mode_creation,
            'params_environnement': params_environnement,
        }

        if mode_creation == 'dns_cloudns':
            subid = params['cloudns_subauthid']
            params_environnement["CLOUDNS_SUB_AUTH_ID"] = subid
            params_secrets["CLOUDNS_AUTH_PASSWORD"] = params['cloudns_password']
            mode_dns = True
            commande_str = '--dns dns_cloudns'
        else:
            commande_str = '--webroot /usr/share/nginx/html'

        configuration_acme = {
            'domain': domaine_noeud,
            'methode': methode,
            'modeTest': mode_test,
        }

        try:
            # Utiliser dnssleep, la detection de presence du record TXT marche rarement
            dnssleep = params['dnssleep']
            methode['dnssleep'] = dnssleep
            commande_str = commande_str + ' --dnssleep %s' % str(dnssleep)
        except KeyError:
            pass

        # Ajouter le domaine principal
        commande_str = commande_str + ' -d %s' % domaine_noeud

        try:
            domaines_additionnels = params['domainesAdditionnels']
            configuration_acme['domaines_additionnels'] = domaines_additionnels
            commande_str = commande_str + ' -d ' + ' -d '.join(domaines_additionnels)
        except KeyError:
            pass

        if force is True:
            commande_str = '--force ' + commande_str

        if mode_test:
            commande_str = '--test ' + commande_str

        params_combines = list(params_environnement)
        params_combines.extend(params_secrets)

        acme_container_id = gestionnaire_docker.trouver_container_pour_service('acme')
        commande_acme = "acme.sh --issue %s" % commande_str
        configuration_acme['commande'] = commande_acme

        print('commande ACME : %s' % commande_acme)

        # Conserver la configuration ACME immediatement
        self.gestionnaire_docker.sauvegarder_config('acme.configuration', configuration_acme)

        # Retourner la reponse a la commande, poursuivre execution de ACME
        generateur_transactions = self.generateur_transactions
        try:
            mq_properties = commande.mq_properties
            reply_to = mq_properties.reply_to
            correlation_id = mq_properties.correlation_id
            reponse = {'ok': True}
            generateur_transactions.transmettre_reponse(reponse, reply_to, correlation_id)
        except Exception:
            self.__logger.exception("Erreur transmission reponse a initialiser_domaine %s" % domaine_noeud)

        resultat_acme, output_acme = gestionnaire_docker.executer_script_blind(
            acme_container_id,
            commande_acme,
            environment=params_combines
        )

        domaine = 'monitor'
        action = 'resultatAcme'
        partition = self.noeud_id
        rk = 'evenement.%s.%s.%s' % (domaine, partition, action)

        # Verifier resultat. 0=OK, 2=Reutilisation certificat existant
        if resultat_acme not in [0, 2]:
            self.__logger.error("Erreur ACME, code : %d\n%s", resultat_acme, output_acme.decode('utf-8'))
            erreur_string = "Erreur ACME, code : %d" % resultat_acme
            evenement_echec = {
                'ok': False,
                'err': erreur_string,
                'code': resultat_acme,
                'output': output_acme.decode('utf-8')
            }
            self._connexion_middleware.generateur_transactions.emettre_message(
                evenement_echec, rk, action=action, partition=partition, ajouter_certificats=True)
            return
            #raise Exception("Erreur creation certificat avec ACME")

        try:
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

            # gestionnaire_docker.sauvegarder_config('acme.configuration', json.dumps(configuration_acme).encode('utf-8'))
            gestionnaire_docker.sauvegarder_config('pki.web.cert.' + date_secret, fullchain_bytes)

            # Forcer reconfiguration nginx
            gestionnaire_docker.maj_service('nginx')

            evenement_succes = {
                'ok': True,
                'code': resultat_acme,
                'output': output_acme.decode('utf-8')
            }
            self._connexion_middleware.generateur_transactions.emettre_message(
                evenement_succes, rk, action=action, partition=partition, ajouter_certificats=True)
        except Exception:
            self.__logger.exception("Erreur sauvegarde certificat ACME dans docker")
            evenement_erreur = {
                'ok': False,
                'err': 'Erreur sauvegarde certificat ACME dans docker (note: certificat TLS genere OK)',
                'output': output_acme.decode('utf-8')
            }
            self._connexion_middleware.generateur_transactions.emettre_message(
                evenement_erreur, rk, action=action, partition=partition, ajouter_certificats=True)

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

        # Supprimer les configurations (docker.cfg.*) qui ne sont pas requis pour ce niveau de securite
        if securite == Constantes.SECURITE_PROTEGE:
            modules_requis = MonitorConstantes.DICT_MODULES_PROTEGES
        elif securite == Constantes.SECURITE_PRIVE:
            modules_requis = MonitorConstantes.DICT_MODULES_PRIVES
        elif securite == Constantes.SECURITE_PUBLIC:
            modules_requis = MonitorConstantes.DICT_MODULES_PUBLICS
        else:
            raise Exception("Role %s non supporte" % securite)

        for config in self._docker.configs.list(filters={"name": "docker.cfg"}):
            role_nom = config.name.split('.')[-1]
            if role_nom not in modules_requis.keys():
                self.__logger.debug("Retirer configuration %s" % config.name)
                config.remove()

                services_trouves = self._docker.services.list(filters={"name": role_nom})
                for service in services_trouves:
                    self.__logger.info("Desinstaller service %s", service.name)
                    service.remove()


    def _renouveller_certificat_monitor(self, commande: CommandeMonitor):
        raise NotImplementedError("Non supporte")

    def publier_fiche_publique(self, commande: CommandeMonitor):
        fiche = commande.message
        fiche_bytes = json.dumps(fiche).encode('utf-8')
        self._gestionnaire_web.publier_fichier(fiche_bytes, 'fiche.json.gz', True)

    def charger_configuration_acme(self):
        gestionnaire = self._gestionnaire_docker
        try:
            configuration_acme = json.loads(gestionnaire.charger_config('acme.configuration'))
            return configuration_acme
        except IndexError:
            return {'ok': False, 'err': 'Configuration introuvable'}

    def relai_web(self, commande: CommandeMonitor):
        self.__logger.debug("Commande relai web : %s", commande)
        certificat = commande.certificat
        if certificat is None:
            return {'ok': False, 'code': 400, 'err': 'Certificat absent'}
        roles = certificat.get_roles
        if 'core' in roles:
            contenu = commande.contenu

            params = {
                'url': contenu['url'],
                'timeout': contenu.get('timeout') or 20,
            }

            # Copier parametres optionnels
            params_optionnels = ['headers', 'data', 'json']
            for nom_param in params_optionnels:
                if contenu.get(nom_param) is not None:
                    params[nom_param] = contenu[nom_param]

            method: str = contenu.get('method') or 'GET'
            flag_erreur_https = False
            if method.lower() == 'get':
                try:
                    response = requests.get(**params)
                except requests.exceptions.SSLError:
                    self.__logger.debug("Erreur certificat https, ajouter un flag certificat invalide")
                    flag_erreur_https = True
                    params['verify'] = False  # Desactiver verification certificat https
                    response = requests.get(**params)
                except requests.exceptions.ReadTimeout:
                    self.__logger.error("Erreur timeout sur %s", params['url'])
                    return {'ok': False, 'code': 408, 'err': 'Methode inconnue'}
            elif method.lower() == 'post':
                response = requests.post(**params)
            else:
                return {'ok': False, 'code': 400, 'err': 'Methode inconnue'}

            self.__logger.debug("Response : %s" % response)

            if 200 <= response.status_code < 300:
                headers = response.headers
                header_dict = {}
                for header_key in headers.keys():
                    header_dict[header_key] = headers.get(header_key)
                try:
                    json_response = response.json()
                    return {'headers': header_dict, 'json': json_response, 'code': response.status_code, 'verify_ok': not flag_erreur_https}
                except:
                    # Encoder reponse en multibase
                    return {'headers': header_dict, 'text': response.text, 'code': response.status_code, 'verify_ok': not flag_erreur_https}
            else:
                # Erreur
                return {'ok': False, 'code': response.status_code, 'err': response.text}

        else:
            return {'ok': False, 'code': 403, 'err': 'Not authorized'}


