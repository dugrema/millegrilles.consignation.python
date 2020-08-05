import json
import logging
import os
from json.decoder import JSONDecodeError
from threading import Event, Thread
# from typing import Union

from pymongo.errors import DuplicateKeyError

from millegrilles import Constantes
from millegrilles.monitor.MonitorComptes import GestionnaireComptesMongo, GestionnaireComptesMQ
from millegrilles.util.X509Certificate import EnveloppeCleCert, ConstantesGenerateurCertificat
from millegrilles.monitor.MonitorConstantes import CommandeMonitor
from millegrilles.monitor.MonitorConstantes import ForcerRedemarrage

class GestionnaireCommandes:
    """
    Execute les commandes transmissions au service monitor (via MQ, unix pipe, etc.)
    """

    #def __init__(self, fermeture_event: Event, service_monitor: Union[ServiceMonitor, ServiceMonitorDependant, ServiceMonitorPrincipal]):
    def __init__(self, fermeture_event: Event, service_monitor, path_fifo='/var/opt/millegrilles/monitor.socket'):
        self.__fermeture_event = fermeture_event
        self._service_monitor = service_monitor
        self._path_fifo = path_fifo

        self.__commandes_queue = list()
        self.__action_event = Event()

        self.__thread_fifo: Thread
        self.__thread_commandes: Thread

        self.__socket_fifo = None

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def start(self):
        self.__thread_fifo = Thread(target=self.lire_fifo, name="fifo", daemon=True)
        self.__thread_commandes = Thread(target=self.executer_commandes, name="cmds", daemon=True)

        self.__thread_fifo.start()
        self.__thread_commandes.start()

    def stop(self):
        self.__action_event.set()
        self.__action_event = None

        if self.__socket_fifo:
            self.__socket_fifo.close()

        os.remove(self._path_fifo)

    def ajouter_commande(self, commande: CommandeMonitor):
        self.__commandes_queue.append(commande)
        self.__action_event.set()

    def lire_fifo(self):
        self.__logger.info("Demarrage thread FIFO commandes")

        while not self.__fermeture_event.is_set():
            self.__socket_fifo = open(self._path_fifo, 'r')
            try:
                while True:
                    json_commande = json.load(self.__socket_fifo)
                    self.ajouter_commande(CommandeMonitor(json_commande))
            except JSONDecodeError as jse:
                if jse.pos > 0:
                    self.__logger.exception("Erreur decodage commande : %s", jse.doc)

            self.__action_event.set()
            self.__socket_fifo.close()
            self.__socket_fifo = None

        self.__logger.info("Fermeture thread FIFO commandes")

    def executer_commandes(self):

        while not self.__fermeture_event.is_set():
            self.__action_event.clear()

            try:
                # Executer toutes les commandes, en ordre.
                while True:
                    commande = self.__commandes_queue.pop(0)
                    self.__logger.debug("Executer commande %s", commande.nom_commande)
                    try:
                        self._executer_commande(commande)
                    except ForcerRedemarrage:
                        self.__logger.warning("Commande redemarrage recu, on arrete le monitor")
                        self._service_monitor.arreter()
                    except Exception:
                        self.__logger.exception("Erreur execution commande")
            except IndexError:
                pass

            self.__action_event.wait(30)

    def _executer_commande(self, commande: CommandeMonitor):
        nom_commande = commande.nom_commande
        contenu = commande.contenu

        if nom_commande == 'demarrer_service':
            nom_service = contenu['nom_service']
            gestionnaire_docker = self._service_monitor.gestionnaire_docker
            gestionnaire_docker.demarrer_service(nom_service, **contenu)

        elif nom_commande == 'supprimer_service':
            nom_service = contenu['nom_service']
            gestionnaire_docker = self._service_monitor.gestionnaire_docker
            gestionnaire_docker.supprimer_service(nom_service)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_AJOUTER_COMPTE:
            self.ajouter_comptes(contenu)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_ACTIVER_HEBERGEMENT:
            self.activer_hebergement(contenu)
        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_DESACTIVER_HEBERGEMENT:
            self.desactiver_hebergement(contenu)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION:
            self._service_monitor.gestionnaire_applications.installer_application(commande)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_SUPPRIMER_APPLICATION:
            self._service_monitor.gestionnaire_applications.supprimer_application(commande)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_BACKUP_APPLICATION:
            self._service_monitor.gestionnaire_applications.backup_application(commande)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_RESTORE_APPLICATION:
            self._service_monitor.gestionnaire_applications.restore_application(commande)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_CONFIGURER_DOMAINE:
            self._service_monitor.initialiser_domaine(commande)

        elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_INITIALISER_NOEUD:
            self._service_monitor.initialiser_noeud(commande)

            # ConstantesMonitor.COMMANDE_MAJ_CERTIFICATS_WEB:

            # ConstantesMonitor.COMMANDE_MAJ_CERTIFICATS_PAR_ROLE:

            # ConstantesMonitor.COMMANDE_FERMER_MILLEGRILLES:

        else:
            self.__logger.error("Commande inconnue : %s", nom_commande)

    def ajouter_comptes(self, commande: dict):
        contenu = commande['contenu']
        cert_pem = contenu[Constantes.ConstantesPki.LIBELLE_CERTIFICAT_PEM]
        # chaine_pem = contenu['chaine']

        self._ajouter_compte_pem(cert_pem, commande)

    def _ajouter_compte_pem(self, cert_pem, commande):
        # Charger pem
        certificat = EnveloppeCleCert()
        certificat.cert_from_pem_bytes(cert_pem.encode('utf-8'))
        try:
            gestionnaire_mongo: GestionnaireComptesMongo = self._service_monitor.gestionnaire_mongo
            gestionnaire_mongo.creer_compte(certificat)
        except DuplicateKeyError:
            self.__logger.info("Compte mongo deja cree : " + certificat.subject_rfc4514_string_mq())
        gestionnaire_comptes_mq: GestionnaireComptesMQ = self._service_monitor.gestionnaire_mq
        gestionnaire_comptes_mq.ajouter_compte(certificat)
        # Transmettre reponse d'ajout de compte, au besoin
        properties = commande.get('properties')
        if properties:
            reply_to = properties.reply_to
            correlation_id = properties.correlation_id

            if reply_to and correlation_id:
                self._service_monitor.generateur_transactions.transmettre_reponse(
                    {'resultat_ok': True}, reply_to, correlation_id)

    def activer_hebergement(self, message):
        self._service_monitor.gestionnaire_docker.activer_hebergement()

    def desactiver_hebergement(self, message):
        self._service_monitor.gestionnaire_docker.desactiver_hebergement()

    def traiter_reponse_hebergement(self, message):
        self.__logger.debug("Reponse hebergement: %s" % str(message))
        resultats = message['resultats']
        if len(resultats) > 0:
            self.activer_hebergement(resultats)
        else:
            self.desactiver_hebergement(resultats)

    def traiter_reponse_comptes_noeuds(self, message):
        self.__logger.debug("Reponse comptes noeuds: %s" % str(message))
        resultats = message['resultats']

        for cert in resultats:
            pem = cert[Constantes.ConstantesPki.LIBELLE_CERTIFICAT_PEM]
            self._ajouter_compte_pem(pem, message)

    def inscrire_domaine(self, nom_domaine: str, exchanges_routing: dict):
        self._service_monitor.rediriger_messages_downstream(nom_domaine, exchanges_routing)


class GestionnaireCommandesNoeudProtegeDependant(GestionnaireCommandes):

    def _executer_commande(self, commande: CommandeMonitor):
        nom_commande = commande.nom_commande
        contenu = commande.contenu

        if nom_commande == 'connecter_principal':
            self.commande_connecter_principal(commande)
        else:
            super()._executer_commande(commande)

    def commande_connecter_principal(self, commande: CommandeMonitor):
        contenu = commande.contenu
        config_connexion = {
            'principal_mq_url': contenu['principal_mq_url']
        }
        cert_pem = contenu['pem'].encode('utf-8')

        # Trouver date de la cle du monitor
        secret_cle = self._service_monitor.gestionnaire_docker.trouver_secret(
            'pki.' + ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT + ".key")

        # Inserer certificat du monitor avec la meme date que la cle
        gestionnaire_certificats = self._service_monitor.gestionnaire_certificats
        label_cert = 'pki.' + ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT + ".cert"
        gestionnaire_certificats.ajouter_config(label_cert, cert_pem, secret_cle['date'])

        # S'assurer que le certificat est charge dans la clecert du monitor
        gestionnaire_certificats.clecert_monitor.cert_from_pem_bytes(cert_pem)

        # Inserer configuration de connexion
        label_config_connexion = 'millegrille.connexion'
        config_connexion = json.dumps(config_connexion).encode('utf-8')
        gestionnaire_certificats.ajouter_config(label_config_connexion, config_connexion)

        # Continuer le demarrage du service monitor
        self._service_monitor.trigger_event_attente()