import datetime
import json
import logging
import os
import sys
from threading import BrokenBarrierError

import docker

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificatsNoeudPublic
from millegrilles.monitor.MonitorCommandes import GestionnaireCommandes
from millegrilles.monitor.MonitorConstantes import ForcerRedemarrage, CommandeMonitor, DICT_MODULES_PUBLICS
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker
from millegrilles.monitor.MonitorNetworking import GestionnaireWeb
from millegrilles.monitor.MonitorRelaiMessages import ConnexionMiddlewarePublic
from millegrilles.monitor.ServiceMonitor import ServiceMonitor
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat


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

            # Entretien certificats
            self._gestionnaire_certificats.entretien_certificat()

            # Entretien des certificats du monitor, services
            date_now = datetime.datetime.utcnow()
            if self._certificats_entretien_date is None or \
                    self._certificats_entretien_date + self._certificats_entretien_frequence < date_now:

                # self._entretien_certificats()
                self._entretien_secrets_pki()

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

            # Forcer entretien des applications avec certificat monitor
            self._gestionnaire_docker.maj_services_avec_certificat('monitor')

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
            self._idmg, self._docker, self._fermeture_event, MonitorConstantes.MODULES_REQUIS_PRIVE_PUBLIC.copy(),
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
                try:
                    configuration = self.connexion_middleware.configuration
                except AttributeError:
                    self.__logger.error("Connexion middleware n'est pas prete, configuration secret abandonnee")
                    return

                volume_secrets = '/var/opt/millegrilles_secrets'
                self.__logger.debug("Copie cle/certs vers %s" % volume_secrets)
                fichiers = [
                    (os.path.join(volume_secrets, 'key.pem'), configuration.mq_keyfile),
                    (os.path.join(volume_secrets, 'cert.pem'), configuration.mq_certfile),
                    (os.path.join(volume_secrets, 'millegrille.cert.pem'), configuration.mq_cafile)
                ]

                for fichier in fichiers:
                    try:
                        with open(fichier[0], 'w') as cle_out:
                            with open(fichier[1], 'r') as cle_in:
                                cle_out.write(cle_in.read())
                    except FileNotFoundError:
                        self.__logger.error('Configuration secrets, fichier non trouve : %s' % fichier[1])

    def ajouter_compte(self, certificat: str):
        raise NotImplementedError("Ajouter compte PEM (**non implemente pour public**): %s" % certificat)

    def initialiser_noeud(self, commande: CommandeMonitor):
        if self.__logger.isEnabledFor(logging.DEBUG):
            try:
                self.__logger.debug("Commande initialiser noeud : %s", json.dumps(commande.contenu, indent=2))
            except Exception:
                self.__logger.debug("Commande initialiser noeud : %s", commande.contenu)

        params = commande.contenu
        self._renouveller_certificat_monitor(commande)

    # def _entretien_certificats(self):
    #     """
    #     Entretien certificats des services/modules et du monitor
    #     :return:
    #     """
    #     clecert_monitor = self._gestionnaire_certificats.clecert_monitor
    #
    #     try:
    #         not_valid_before = clecert_monitor.not_valid_before
    #         not_valid_after = clecert_monitor.not_valid_after
    #         self.__logger.debug("Verification validite certificat du monitor : valide jusqu'a %s" % str(clecert_monitor.not_valid_after))
    #
    #         # Calculer 2/3 de la duree du certificat
    #         delta_fin_debut = not_valid_after.timestamp() - not_valid_before.timestamp()
    #         epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
    #         date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers)
    #     except AttributeError:
    #         self.__logger.warning("Certificat monitor inexistant, on le fait renouveller")
    #         date_renouvellement = None
    #
    #     if date_renouvellement is None or date_renouvellement < datetime.datetime.utcnow():
    #         self.__logger.warning("Certificat monitor expire, on genere un nouveau et redemarre immediatement")
    #
    #         # # MAJ date pour creation de certificats
    #         # self._gestionnaire_certificats.maj_date()
    #         #
    #         # self._gestionnaire_certificats.generer_clecert_module('monitor', self.noeud_id)
    #         # self._gestionnaire_docker.configurer_monitor()
    #         # raise ForcerRedemarrage("Redemarrage apres configuration service monitor")
    #     else:
    #         # Verifier si on doit reconfigurer les applications avec le certificat de monitor le plus recent
    #         self._gestionnaire_docker.maj_services_avec_certificat('monitor')

    @property
    def securite(self):
        return Constantes.SECURITE_PUBLIC

    @property
    def role(self):
        return ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC

    @property
    def nom_service_nginx(self):
        return 'nginx_public'

    def _get_dict_modules(self) -> dict:
        return DICT_MODULES_PUBLICS
