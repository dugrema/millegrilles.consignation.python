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


class ServiceMonitorInstalleur(ServiceMonitor):

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
            configuration_services=MonitorConstantes.DICT_MODULES_PROTEGES,
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

        # # Verifier si le CSR a deja ete genere, sinon le generer
        # try:
        #     csr_config_docker = self._gestionnaire_docker.charger_config_recente('pki.intermediaire.csr')
        #     data_csr = b64decode(csr_config_docker['config'].attrs['Spec']['Data'])
        #     self.csr_intermediaire = data_csr
        # except AttributeError:
        #     # Creer CSR pour le service monitor
        #     csr_info = self._gestionnaire_certificats.generer_csr('intermediaire', insecure=self._args.dev, generer_password=True)
        #     self.csr_intermediaire = csr_info['request']

        # Verifier si la cle du monitor existe, sinon la generer
        try:
            self._gestionnaire_docker.trouver_secret('pki.monitor.key')
        except PkiCleNonTrouvee:
            # Creer CSR pour le service monitor
            # self._gestionnaire_certificats.generer_csr('monitor', insecure=self._args.dev, generer_password=False)
            # nouveau_secrets_monitor_ajoutes = True
            pass

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

        # self.service_monitor.fermer()
        raise ForcerRedemarrage("Lock %s avec idmg %s" % (securite, idmg))


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
            self._securite = None
            raise Exception("Type de noeud non supporte : " + securite)

    def __initialiser_noeud_protege(self, commande: CommandeMonitor):
        params = commande.contenu
        gestionnaire_docker = self.gestionnaire_docker

        securite = params['securite']
        certificat_millegrille = params['chainePem'][-1]

        gestionnaire_certs = GestionnaireCertificatsNoeudProtegePrincipal(
            self.docker, self, secrets=self._args.secrets, insecure=self._args.dev)
        clecert_monitor = gestionnaire_certs.recuperer_monitor_initial(params)

        # Extraire IDMG
        self.__logger.debug("Certificat de la MilleGrille :\n%s" % certificat_millegrille)
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(clecert_monitor.chaine[-1].encode('utf-8'))
        idmg = clecert_millegrille.idmg

        # Verifier si on doit generer un certificat web SSL
        domaine_web = params.get('domaine')
        if params.get('internetDisponible') is True and domaine_web is not None:
            self.__logger.info("Generer certificat web SSL pour %s" % domaine_web)
            self.initialiser_domaine(commande)

        # # Comencer sauvegarde
        # gestionnaire_docker.sauvegarder_config('pki.millegrille.cert', certificat_millegrille)

        # if type_certificat_recu != 'intermediaire':
        #     raise Exception("Type de certificat inconnu : %s" % type_certificat_recu)

        # securite = params['securite']
        # gestionnaire_docker.sauvegarder_config(
        #     'pki.intermediaire.cert.' + str(intermediaire_key['date']),
        #     certificat_pem
        # )
        # chaine_intermediaire = '\n'.join([certificat_pem, certificat_millegrille])
        # gestionnaire_docker.sauvegarder_config(
        #     'pki.intermediaire.chain.' + str(intermediaire_key['date']), chaine_intermediaire)

        # Configurer gestionnaire certificats avec clecert millegrille, intermediaire
        self._gestionnaire_certificats.idmg = idmg
        self._gestionnaire_certificats.set_clecert_millegrille(clecert_millegrille)
        # self._gestionnaire_certificats.set_clecert_intermediaire(clecert_recu)

        # Generer nouveau certificat de monitor
        # # Charger CSR monitor
        # config_csr_monitor = self._gestionnaire_docker.charger_config_recente('pki.monitor.csr')
        # data_csr_monitor = b64decode(config_csr_monitor['config'].attrs['Spec']['Data'])
        # clecert_monitor = self._gestionnaire_certificats.signer_csr(data_csr_monitor)

        # Sauvegarder certificat monitor
        # Faire correspondre et sauvegarder certificat de noeud
        # secret_monitor = gestionnaire_docker.trouver_secret('pki.monitor.key')
        # gestionnaire_docker.sauvegarder_config(
        #     'pki.monitor.cert.' + str(secret_monitor['date']),
        #     '\n'.join(clecert_monitor.chaine)
        # )

        # # Supprimer le CSR
        # gestionnaire_docker.supprimer_config('pki.monitor.csr.' + str(secret_monitor['date']))
        #
        # # Supprimer le CSR
        # gestionnaire_docker.supprimer_config('pki.intermediaire.csr.' + str(intermediaire_key['date']))

        # Terminer configuration swarm docker
        gestionnaire_docker.initialiser_noeud(idmg=idmg)

        self.sauvegarder_config_millegrille(idmg, securite)

        # Generer les mots de passe pour middleware (secret partage entre monitor et module comme mq et mongo)
        gestionnaire_certs.generer_motsdepasse()

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
        # information_systeme['csr'] = self.csr_intermediaire.decode('utf-8')
        return information_systeme

    def __initialiser_noeud_installation(self, commande: CommandeMonitor, securite: str):
        """
        Initialise un noeud protege avec un certificat
        :param commande:
        :return:
        """
        raise NotImplementedError("Obsolete")

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

        # # Faire correspondre et sauvegarder certificat de noeud
        # secret_intermediaire = gestionnaire_docker.trouver_secret('pki.intermediaire.key')
        # secret_date = secret_intermediaire['date']
        #
        # if not self._args.dev:
        #     nom_fichier_key = 'pki.intermediaire.key.pem'
        #     nom_fichier_passwd = 'pki.intermediaire.passwd.txt'
        # else:
        #     nom_fichier_key = 'pki.intermediaire.key.%s' % secret_date
        #     nom_fichier_passwd = 'pki.intermediaire.passwd.%s' % secret_date
        #
        # with open(os.path.join(self._args.secrets, nom_fichier_key), 'rb') as fichier:
        #     intermediaire_key_pem = fichier.read()
        # with open(os.path.join(self._args.secrets, nom_fichier_passwd), 'rb') as fichier:
        #     intermediaire_passwd_pem = fichier.read()
        certificat_pem = params['certificatPem']

        certificat_millegrille_existe = False
        try:
            certificat_millegrille = self.gestionnaire_docker.charger_config('pki.millegrille.cert')
            certificat_millegrille_existe = True
        except (AttributeError, IndexError):
            certificat_millegrille = params['chainePem'][-1]

        chaine = params['chainePem']

        # Extraire IDMG
        self.__logger.debug("Certificat de la MilleGrille :\n%s" % certificat_millegrille)
        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(certificat_millegrille.encode('utf-8'))
        idmg = clecert_millegrille.idmg

        if self.idmg != idmg:
            raise ValueError("Le IDMG du certificat (%s) ne correspond pas a celui du noeud (%s)", (idmg, self.idmg))

        if certificat_millegrille_existe is False:
            self.gestionnaire_docker.sauvegarder_config('pki.millegrille.cert', certificat_millegrille)

        # clecert_recu = EnveloppeCleCert()
        # clecert_recu.from_pem_bytes(intermediaire_key_pem, certificat_pem.encode('utf-8'), intermediaire_passwd_pem)
        # if not clecert_recu.cle_correspondent():
        #     raise ValueError('Cle et Certificat intermediaire ne correspondent pas')

        # Verifier si on doit generer un certificat web SSL
        domaine_web = params.get('domaine')
        if domaine_web is not None:
            self.__logger.info("Generer certificat web SSL pour %s" % domaine_web)
            self.initialiser_domaine(commande)

        # cert_subject = clecert_recu.formatter_subject()
        #
        # # Verifier le type de certificat - il determine le type de noeud:
        # # intermediaire = noeud protege, prive = noeud prive, public = noeud public
        # self.__logger.debug("Certificat recu : %s", str(cert_subject))
        # subject_clecert_recu = clecert_recu.formatter_subject()
        # if subject_clecert_recu['organizationName'] != idmg:
        #     raise Exception("IDMG %s ne correspond pas au certificat de monitor" % idmg)
        #
        # type_certificat_recu = subject_clecert_recu['organizationalUnitName']
        # if type_certificat_recu != role:
        #     raise Exception("Type de certificat inconnu : %s" % type_certificat_recu)

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
        # clecert_recu.password = None
        # cle_monitor = clecert_recu.private_key_bytes
        # secret_name, date_key = gestionnaire_docker.sauvegarder_secret(
        #     ConstantesServiceMonitor.PKI_MONITOR_KEY, cle_monitor, ajouter_date=True)

        raise NotImplementedError('TODO')
        gestionnaire_docker.sauvegarder_config(
            'pki.monitor.cert.' + date_key,
            '\n'.join(chaine)
        )

        # # Supprimer le CSR
        # try:
        #     gestionnaire_docker.supprimer_config('pki.monitor.csr.' + str(secret_intermediaire['date']))
        # except docker.errors.NotFound:
        #     pass
        # try:
        #     gestionnaire_docker.supprimer_config('pki.intermediaire.csr.' + str(secret_intermediaire['date']))
        # except docker.errors.NotFound:
        #     pass

        # Terminer configuration swarm docker
        gestionnaire_docker.initialiser_noeud(idmg=idmg)

        self.sauvegarder_config_millegrille(idmg, securite)

        # Regenerer la configuraiton de NGINX (change defaut de /installation vers /vitrine)
        # Redemarrage est implicite (fait a la fin de la prep)
        self._gestionnaire_web.regenerer_configuration(mode_installe=True)

        # Forcer reconfiguration nginx (ajout certificat de millegrille pour validation client ssl)
        if securite in [Constantes.SECURITE_PRIVE, Constantes.SECURITE_PUBLIC]:
            nom_service_nginx = 'nginx_public'
        else:
            nom_service_nginx = 'nginx'
        try:
            self._gestionnaire_web.redeployer_nginx(nom_service=nom_service_nginx)
        except docker.errors.APIError as apie:
            if apie.status_code == 500:
                self.__logger.warning(
                    "Erreur mise a jour, probablement update concurrentes. On attend 15 secondes puis on reessaie")
                Event().wait(15)
                # gestionnaire_docker.maj_service('nginx')
                self._gestionnaire_web.redeployer_nginx(nom_service=nom_service_nginx)
            else:
                raise apie

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
        gestionnaire_docker.configurer_monitor(env_params=env_params)

        raise ForcerRedemarrage("Redemarrage")

    @property
    def securite(self):
        if self._securite is None:
            raise NotImplementedError("Securite n'existe pas - pas initialise")
        return self._securite