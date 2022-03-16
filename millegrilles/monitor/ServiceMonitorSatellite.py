import datetime
import logging
import os
import sys
from threading import BrokenBarrierError, Event

import docker

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesServiceMonitor
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.monitor.MonitorCertificats import GestionnaireCertificatsNoeudPrive
from millegrilles.monitor.MonitorCommandes import GestionnaireCommandes
from millegrilles.monitor.MonitorConstantes import ForcerRedemarrage, CommandeMonitor
from millegrilles.monitor.MonitorRelaiMessages import ConnexionMiddlewarePrive
from millegrilles.monitor.ServiceMonitor import ServiceMonitor, ConnexionMiddlewarePasPreteException
from millegrilles.util.X509Certificate import EnveloppeCleCert


class ServiceMonitorSatellite(ServiceMonitor):
    """
    Instance privee, publique ou protegee secondaire
    """

    def __init__(self, args, docker_client: docker.DockerClient, configuration_json: dict):
        super().__init__(args, docker_client, configuration_json)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__logger_verbose = logging.getLogger('verbose.' + __name__ + '.' + self.__class__.__name__)

        self._configuration = TransactionConfiguration()
        self._configuration.loadEnvironment()

        # Flag pour redemarrer les app mode containers apres rotation de certificats
        self.__containers_redemarres_rotation = False

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
            try:
                if self._certificats_entretien_date is None or \
                        self._certificats_entretien_date + self._certificats_entretien_frequence < datetime.datetime.utcnow():

                    self._certificats_entretien_date = datetime.datetime.utcnow()
                    self._entretien_certificats()
                    self._entretien_secrets_pki()

                    # Mettre a jour les certificats utilises par les modules prives
                    try:
                        self.preparer_secrets()
                    except:
                        self.__logger.exception("Erreur traitement preparer_secrets pour monitor satellite")

                    if self.__containers_redemarres_rotation is False:
                        self.__logger.info("Redemarrer containers en mode application suite au redemarrage du monitor (1 fois)")
                        self.__containers_redemarres_rotation = True
                        self.gestionnaire_docker.stop_applications_modecontainer()
            except ConnexionMiddlewarePasPreteException:
                self.__logger.warning("La connexion middleware n'est pas prete - skip entretien certificat")

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
                            try:
                                self.preparer_secrets()
                            except:
                                self.__logger.exception("Erreur preparer secrets monitor satellite")
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

            # Tenter de fermer tous les containers qui requierent un certificat (il a probablement ete mis a jour)
            try:
                self.gestionnaire_docker.stop_applications_modecontainer()
            except Exception:
                self.__logger.exception("Erreur stop applications mode container")

        except Exception:
            self.__logger.exception("Erreur demarrage ServiceMonitor, on abandonne l'execution")

        self.__logger.info("Fermeture du ServiceMonitor")
        self.fermer()

        # Fermer le service monitor, retourne exit code pour shell script
        sys.exit(self.exit_code)

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

        volume_secrets = os.path.join(self.path_secrets, 'shared')  # '/var/opt/millegrilles_secrets'
        try:
            os.makedirs(volume_secrets)
        except FileExistsError:
            pass  # OK

        try:
            configuration = self.connexion_middleware.configuration
        except AttributeError:
            self.__logger.error("Connexion middleware n'est pas prete, configuration secret abandonnee")
            return

        if os.path.exists(volume_secrets):
            self.__logger.debug("Copie cle/certs vers %s" % volume_secrets)
            fichiers = [
                # (os.path.join(volume_secrets, 'key.pem'), configuration.mq_keyfile),
                # (os.path.join(volume_secrets, 'cert.pem'), configuration.mq_certfile),
                (os.path.join(volume_secrets, 'millegrille.cert.pem'), configuration.mq_cafile)
            ]

            for fichier in fichiers:
                try:
                    with open(fichier[0], 'w') as cle_out:
                        with open(fichier[1], 'r') as cle_in:
                            cle_out.write(cle_in.read())
                except FileNotFoundError:
                    self.__logger.exception("Fichier n'existe pas : %s" % fichier[1])

        else:
            raise Exception("Path secret n'existe pas : %s" % volume_secrets)

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

        flag_force_renew = os.environ.get('MGDEBUG_FORCE_RENEW') == '1'
        if flag_force_renew or date_renouvellement is None or date_renouvellement < datetime.datetime.utcnow():
            # MAJ date pour creation de certificats
            self._gestionnaire_certificats.maj_date()

            # Generer un nouveau CSR
            # Verifier si le CSR a deja ete genere, sinon le generer
            csr_pem = self.csr

            # Generer message a transmettre au monitor pour renouvellement
            commande = {
                'csr': csr_pem.decode('utf-8'),
                'securite': self.securite,
                'role': self.securite.split('.')[1]
            }

            try:
                self.connexion_middleware.generateur_transactions.transmettre_commande(
                    commande,
                    domaine='CorePki',
                    action=Constantes.ConstantesServiceMonitor.COMMANDE_SIGNER_NOEUD,
                    exchange=self.securite,
                    correlation_id=ConstantesServiceMonitor.CORRELATION_RENOUVELLEMENT_CERTIFICAT,
                    reply_to=self.connexion_middleware.reply_q,
                    ajouter_certificats=True
                )
            except AttributeError:
                self.__logger.warning("Connexion MQ pas prete, on ne peut pas renouveller le certificat de monitor")
                if self.__logger.isEnabledFor(logging.DEBUG):
                    self.__logger.exception("Connexion MQ pas prete")

        # Nettoyer certificats monitor
        # self._supprimer_certificats_expires(['monitor'])
        super()._entretien_certificats()

    def ajouter_compte(self, certificat: str):
        """
        Emettre demande de creation de compte
        """
        commande = {'certificat_pem': certificat}
        self._connexion_middleware.commande(
            commande, 'servicemonitor',
            action=Constantes.ConstantesServiceMonitor.COMMANDE_AJOUTER_COMPTE
        )

    def _renouveller_certificat_monitor(self, commande: CommandeMonitor):
        """
        Initialise un noeud prive/public avec un certificat
        :param commande:
        :return:
        """

        params = commande.contenu
        self.__logger.info('_renouveller_certificat_monitor avec commande %s' % params)

        erreur_recue = params.get('err')
        if erreur_recue:
            raise ValueError("Erreur renouvellement certificat\n%s" % params)

        gestionnaire_docker = self.gestionnaire_docker

        # Generer CSR, faire requete aupres du certissuer
        role = self.role

        chaine_pem: list = params['certificat']
        certificat_pem: str = chaine_pem[0]

        certificat_millegrille_present = False
        try:
            certificat_millegrille = self.gestionnaire_docker.charger_config('pki.millegrille.cert').decode('utf-8')
            certificat_millegrille_present = True
        except IndexError:
            certificat_millegrille = chaine_pem[-1]
            chaine_pem = chaine_pem[:-1]

        try:
            monitor_key_pem = self._gestionnaire_certificats.get_infocle()['cle_pem']
            clecert_recu = EnveloppeCleCert()
            clecert_recu.from_pem_bytes(monitor_key_pem, ''.join(chaine_pem).encode('utf-8'))
            if not clecert_recu.cle_correspondent():
                raise ValueError('Cle et Certificat monitor ne correspondent pas')
        except Exception as e:
            self.__logger.error("Commande CSR en ereur : %s" % str(params))
            raise e

        # Extraire IDMG
        self.__logger.debug("Certificat de la MilleGrille :\n%s" % certificat_millegrille)
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(certificat_millegrille.encode('utf-8'))
        idmg = clecert_millegrille.idmg

        if self.idmg != idmg:
            raise ValueError("Le IDMG du certificat (%s) ne correspond pas a celui du noeud (%s)", (idmg, self.idmg))

        if certificat_millegrille_present is False:
            self.gestionnaire_docker.sauvegarder_config('pki.millegrille.cert', certificat_millegrille)

        cert_subject = clecert_recu.formatter_subject()

        # Verifier le type de certificat - il determine le type de noeud:
        # prive = noeud prive, public = noeud public
        self.__logger.debug("Certificat recu : %s", str(cert_subject))
        subject_clecert_recu = clecert_recu.formatter_subject()
        if subject_clecert_recu['organizationName'] != idmg:
            raise Exception("IDMG %s ne correspond pas au certificat de monitor" % idmg)

        type_certificat_recu = subject_clecert_recu['organizationalUnitName']
        if type_certificat_recu != role:
            raise Exception("Type de certificat inconnu : %s" % type_certificat_recu)

        self.__logger.debug("Sauvegarde certificat recu et cle comme cert/cle de monitor %s" % self.role)
        clecert_recu.password = None

        cle_monitor = clecert_recu.private_key_bytes
        secret_name, date_key = gestionnaire_docker.sauvegarder_secret(
            ConstantesServiceMonitor.PKI_MONITOR_KEY, cle_monitor, ajouter_date=True)

        gestionnaire_docker.sauvegarder_config(
            'pki.monitor.cert.' + date_key,
            '\n'.join(chaine_pem)
        )

        # Regenerer la configuraiton de NGINX (change defaut de /installation vers /vitrine)
        # Redemarrage est implicite (fait a la fin de la prep)
        self.__logger.debug("Regenerer configuration monitor")
        self._gestionnaire_web.regenerer_configuration(mode_installe=True)

        # Forcer reconfiguration nginx (ajout certificat de millegrille pour validation client ssl)
        try:
            gestionnaire_docker.maj_service('nginx')
        except docker.errors.APIError as apie:
            if apie.status_code == 500:
                self.__logger.warning(
                    "Erreur mise a jour, probablement update concurrentes. On attend 15 secondes puis on reessaie")
                Event().wait(15)
                try:
                    gestionnaire_docker.maj_service('nginx')
                except docker.errors.APIError as apie:
                    self.__logger.exception("Probleme de mise a jour du certificat de nginx")
            else:
                self.__logger.exception("Erreur maj nginx (1) pour rotation certificats")
        except Exception:
            self.__logger.exception("Erreur maj nginx (2) pour rotation certificats")

        env_params = None
        try:
            host = params['host']
            port = params['port']
            env_params = [
                'MG_MQ_HOST=%s' % host,
                'MG_MQ_PORT=%s' % port,
            ]
            self.__logger.info("MAJ connexion MQ avec %s" + str(env_params))
        except KeyError:
            self.__logger.info("Aucune information MQ pour configurer noeud (%s)" % params)

        # Redemarrer / reconfigurer le monitor
        self.__logger.info("Configuration completee, redemarrer le monitor")
        try:
            gestionnaire_docker.configurer_monitor(env_params=env_params)
        except ForcerRedemarrage as fe:
            raise fe
        except Exception as e:
            self.__logger.exception("Erreur reconfiguration certificats monitor, on force le redemarrage")
            raise ForcerRedemarrage("Redemarrage apres erreur")

    @property
    def csr(self):
        return self._gestionnaire_certificats.get_csr()