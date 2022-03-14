import datetime
import logging
import sys
from threading import BrokenBarrierError
from typing import Optional

import docker

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.SecuritePKI import CertificatExpire
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificatsNoeudProtegePrincipal
from millegrilles.monitor.MonitorCommandes import GestionnaireCommandes
from millegrilles.monitor.MonitorConstantes import ForcerRedemarrage, CommandeMonitor
from millegrilles.monitor.MonitorRelaiMessages import ConnexionMiddleware, ConnexionMiddlewareProtege
from millegrilles.monitor.ServiceMonitor import ServiceMonitor
from millegrilles.util.X509Certificate import ConstantesGenerateurCertificat


class ServiceMonitorProtege(ServiceMonitor):
    """
    ServiceMonitor pour noeud protege principal
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)

        self._certificat_pret = False  # Flag qui indique que le certificat est pret et valide
        self._connexion_middleware: Optional[ConnexionMiddleware] = None

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

        except CertificatExpire as ce:
            raise ce  # Passer l'execption

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
            self.__logger.exception("Erreur chargement certificats/cles pour monitor. Tenter de regenerer configuration monitor.")
            self._gestionnaire_docker.configurer_monitor()
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

        try:
            not_valid_before = clecert_monitor.not_valid_before
            not_valid_after = clecert_monitor.not_valid_after
            self.__logger.debug("Verification validite certificat du monitor : valide jusqu'a %s" % str(clecert_monitor.not_valid_after))

            # Calculer 2/3 de la duree du certificat
            delta_fin_debut = not_valid_after.timestamp() - not_valid_before.timestamp()
            epoch_deux_tiers = delta_fin_debut / 3 * 2 + not_valid_before.timestamp()
            date_renouvellement = datetime.datetime.fromtimestamp(epoch_deux_tiers)
        except AttributeError:
            self.__logger.warning("Certificat monitor inexistant, on le fait renouveller")
            date_renouvellement = None

        if date_renouvellement is None or date_renouvellement < datetime.datetime.utcnow():
            self.__logger.warning("Certificat monitor expire, on doit attendre une reinitialisation via app web")

            # MAJ date pour creation de certificats
            self._gestionnaire_certificats.maj_date()

            try:
                self._gestionnaire_certificats.generer_clecert_module('monitor', self.noeud_id)
            except Exception:
                raise CertificatExpire("Erreur renouvellement certificat")
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

    @property
    def fermeture_event(self):
        return self._fermeture_event