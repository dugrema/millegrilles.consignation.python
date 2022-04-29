import json
import logging
from threading import Event
from typing import cast, Optional

import docker
from docker.errors import APIError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.monitor import MonitorConstantes
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificatsInstallation, \
    GestionnaireCertificatsNoeudProtegePrincipal, GestionnaireCertificatsNoeudPrive
from millegrilles.monitor.MonitorConstantes import PkiCleNonTrouvee, ForcerRedemarrage, CommandeMonitor
from millegrilles.monitor.MonitorDocker import GestionnaireModulesDocker
from millegrilles.monitor.MonitorNetworking import GestionnaireWeb
from millegrilles.monitor.MonitorRelaiMessages import ConnexionPrincipal
from millegrilles.monitor.ServiceMonitor import ServiceMonitor
from millegrilles.util.X509Certificate import EnveloppeCleCert, ConstantesGenerateurCertificat


class ServiceMonitorExpire(ServiceMonitor):
    """
    Classe pour un monitor protege avec un certificat expire (incapable de renouveller son certificat).
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)
        self.__event_attente = Event()

        self.__connexion_principal: ConnexionPrincipal = cast(ConnexionPrincipal, None)

        # self.csr_intermediaire = None
        self._securite: Optional[str] = None

    def fermer(self, signum=None, frame=None):
        super().fermer(signum, frame)
        self.__event_attente.set()
        self.__logger.info("Fermeture ServiceMonitor (installeur) en cours")

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
            configuration_services=MonitorConstantes.DICT_MODULES_INSTALLATION,
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
        self.__logger.info("Debut boucle d'entretien du service monitor (installeur)")

        while not self._fermeture_event.is_set():
            if self._fermeture_event.is_set():
                self._attente_event.set()
            else:
                self._attente_event.clear()

            try:
                self.__logger.debug("Cycle entretien ServiceMonitor (installeur)")
                self.verifier_load()

                if not self.limiter_entretien:
                    # S'assurer que les modules sont demarres - sinon les demarrer, en ordre.
                    self._gestionnaire_docker.entretien_services()

                self.__logger_verbose.debug("Fin cycle entretien ServiceMonitor (installeur)")
            except Exception as e:
                self.__logger.exception("ServiceMonitor: erreur generique : " + str(e))
            finally:
                self._attente_event.wait(30)

        self.__logger.info("Fin execution de la boucle d'entretien du service monitor")

    def preparer_gestionnaire_certificats(self):
        pass

        # params = dict()
        # if self._args.dev:
        #     params['insecure'] = True
        # if self._args.secrets:
        #     params['secrets'] = self._args.secrets
        # self._gestionnaire_certificats = GestionnaireCertificatsInstallation(self._docker, self, **params)
        #
        # nouveau_secrets_monitor_ajoutes = False  # Flag qui va indiquer si de nouveaux secrets sont ajoutes
        #
        # # Verifier si la cle du monitor existe, sinon la generer
        # try:
        #     self._gestionnaire_docker.trouver_secret('pki.monitor.key')
        # except PkiCleNonTrouvee:
        #     # Creer CSR pour le service monitor
        #     # self._gestionnaire_certificats.generer_csr('monitor', insecure=self._args.dev, generer_password=False)
        #     # nouveau_secrets_monitor_ajoutes = True
        #     pass
        #
        # # if nouveau_secrets_monitor_ajoutes:
        # if nouveau_secrets_monitor_ajoutes:
        #     try:
        #         # Besoin reconfigurer le service pour ajouter les secrets et redemarrer
        #         self._gestionnaire_docker.configurer_monitor()
        #
        #         # Redemarrer / reconfigurer le monitor
        #         self.__logger.info("Configuration completee, redemarrer le monitor")
        #         if not self._args.dev:
        #             raise ForcerRedemarrage("Redemarrage")
        #     except ValueError as ve:
        #         if not self._args.dev:
        #             raise ve
        #         else:
        #             self.__logger.warning("Erreur valeur monitor : %s" % ve)

    def configurer_idmg(self, commande: CommandeMonitor):
        """
        Genere la configuration docker avec le niveau de securite et IDMG. Genere le certificat web SSL au besoin.
        :param commande:
        :return:
        """
        raise Exception("Changement idmg non supporte")

        # params = commande.contenu
        # idmg = params['idmg']
        # self._idmg = idmg
        # securite = params['securite']
        # domaine = params.get('domaine')
        #
        # if domaine is not None:
        #     self.__logger.info("Generer certificat web SSL pour " + domaine)
        #     self.initialiser_domaine(commande)
        #
        # self.sauvegarder_config_millegrille(idmg, securite)
        #
        # # self.service_monitor.fermer()
        # raise ForcerRedemarrage("Lock %s avec idmg %s" % (securite, idmg))

    def initialiser_noeud(self, commande: CommandeMonitor):
        if self.__logger.isEnabledFor(logging.DEBUG):
            self.__logger.debug("Commande initialiser noeud : %s", json.dumps(commande.contenu, indent=2))

        params = commande.contenu

        gestionnaire_certs = GestionnaireCertificatsNoeudProtegePrincipal(
            self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
        clecert_monitor = gestionnaire_certs.recuperer_monitor_initial(params)

        self.__logger.debug("Certificat intermediaire e tmonitor reinstalle avec succes, redemarrage")

        raise ForcerRedemarrage("Redemarrage")

    def _get_info_noeud(self):
        information_systeme = super()._get_info_noeud()
        # information_systeme['csr'] = self.csr_intermediaire.decode('utf-8')
        return information_systeme

    @property
    def securite(self):
        if self._securite is None:
            raise NotImplementedError("Securite n'existe pas - pas initialise")
        return self._securite