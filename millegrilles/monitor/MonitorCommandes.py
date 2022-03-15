import json
import logging
import os

from os import path
from json.decoder import JSONDecodeError
from threading import Event, Thread
from typing import Optional

from pymongo.errors import DuplicateKeyError

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking
from millegrilles.monitor.MonitorComptes import GestionnaireComptesMongo, GestionnaireComptesMQ
from millegrilles.util.X509Certificate import EnveloppeCleCert, ConstantesGenerateurCertificat
from millegrilles.monitor.MonitorConstantes import CommandeMonitor, ForcerRedemarrage


class GestionnaireCommandes:
    """
    Execute les commandes transmissions au service monitor (via MQ, unix pipe, etc.)
    """
    def __init__(self, fermeture_event: Event, service_monitor, path_fifo='/var/opt/millegrilles/monitor.socket'):
        self.__fermeture_event = fermeture_event
        self._service_monitor = service_monitor
        self._path_fifo = path_fifo

        self.__commandes_queue = list()
        self.__action_event = Event()

        self.__thread_fifo: Thread
        self.__thread_commandes: Thread

        self.__socket_fifo = None
        # self.__pipe_acteur: Optional[PipeActeur] = None
        self.__attente_acteur_mdns = Event()
        self.__reponse_acteur_mdns: Optional[dict] = None
        self.__handler_requetes: Optional[TraitementMQRequetesBlocking] = None

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def start(self):
        self.__thread_fifo = Thread(target=self.lire_fifo, name="fifo", daemon=True)
        self.__thread_commandes = Thread(target=self.executer_commandes, name="cmds", daemon=True)

        self.__thread_fifo.start()
        self.__thread_commandes.start()
        # self.__pipe_acteur = PipeActeur()  # Demarre une thread implicitement

    def stop(self):
        self.__action_event.set()
        self.__action_event = None

        if self.__socket_fifo:
            self.__socket_fifo.close()

        # self.__pipe_acteur.fermer()

        os.remove(self._path_fifo)

    def ajouter_commande(self, commande: CommandeMonitor):
        nom_commande = commande.nom_commande

        self.__logger.debug("Commande acteur recue : %s" % nom_commande)

        # Certaines commandes doivent etre traitees immediatement (thread attente sur reception)
        if nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_ACTEUR_REPONSE_MDNS:
            self.recevoir_reponse_mdns(commande)
        else:
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
                        self._service_monitor.fermer()
                    except Exception:
                        self.__logger.exception("Erreur execution commande")
            except IndexError:
                pass

            self.__action_event.wait(30)

    def _executer_commande(self, commande: CommandeMonitor):
        nom_commande = commande.nom_commande
        mq_properties = commande.mq_properties
        contenu = commande.contenu

        reponse = None
        try:

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

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_APPLICATION:
                reponse = self._service_monitor.gestionnaire_applications.installer_application(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_SUPPRIMER_APPLICATION:
                reponse = self._service_monitor.gestionnaire_applications.supprimer_application(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_BACKUP_APPLICATION:
                self._service_monitor.gestionnaire_applications.backup_application(commande)

            elif nom_commande in [
                Constantes.ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_SNAPSHOT.split('.')[-1],
                Constantes.ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL.split('.')[-1]
            ]:
                self._service_monitor.gestionnaire_applications.backup_application(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_RESTORE_APPLICATION:
                self._service_monitor.gestionnaire_applications.restore_application(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_CONFIGURER_DOMAINE:
                self._service_monitor.initialiser_domaine(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_INSTALLER_NOEUD:
                self._service_monitor.initialiser_noeud(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_CONFIGURER_IDMG:
                self._service_monitor.configurer_idmg(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_CONFIGURER_MQ:
                self._service_monitor.configurer_mq(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_ACTEUR_GET_INFORMATION_NOEUD:
                self._service_monitor.transmettre_info_acteur(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_TRANSMETTRE_CATALOGUES:
                self._service_monitor.transmettre_catalogue_local()
                reponse = {'ok': True}

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_REQUETE_CONFIG_APPLICATION:
                reponse = self._service_monitor.get_configuration_application(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_CONFIGURER_APPLICATION:
                reponse = self._service_monitor.gestionnaire_applications.configurer_application(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_DEMARRER_APPLICATION:
                reponse = self._service_monitor.gestionnaire_applications.commande_demarrer_application(commande)

            # elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_SIGNER_NAVIGATEUR:
            #     reponse = self._service_monitor.gestionnaire_certificats.commande_signer_navigateur(commande)

            # elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_SIGNER_NOEUD:
            #     reponse = self._service_monitor.gestionnaire_certificats.commande_signer_noeud(commande)

            # elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_RENOUVELLER_INTERMEDIAIRE:
            #     reponse = self._service_monitor.gestionnaire_certificats.renouveller_intermediaire(commande)

            # elif nom_commande == Constantes.ConstantesServiceMonitor.EVENEMENT_TOPOLOGIE_FICHEPUBLIQUE:
            #     self.sauvegarder_fiche_publique(commande)

            elif nom_commande == Constantes.ConstantesServiceMonitor.COMMANDE_RELAI_WEB:
                reponse = self._service_monitor.relai_web(commande)

            else:
                self.__logger.error("Commande inconnue : %s", nom_commande)
                return
        except ForcerRedemarrage:
            self._service_monitor.fermer()
        except Exception as err:
            self.__logger.exception("Exception traitement commande")
            reponse = {'err': str(err)}

        if reponse is not None and mq_properties is not None and mq_properties.reply_to is not None:
            # Transmettre la reponse a la commande / requete
            generateur_transactions = self._service_monitor.generateur_transactions
            reply_to = mq_properties.reply_to
            correlation_id = mq_properties.correlation_id
            try:
                generateur_transactions.transmettre_reponse(reponse, reply_to, correlation_id)
            except Exception:
                self.__logger.exception("Erreur transmission reponse a commande %s:\n%s\nReponse :\n%s" % (
                    commande.nom_commande, str(commande.contenu), str(reponse)))

    def sauvegarder_fiche_publique(self, commande):
        self.__logger.debug("Sauvegarder fiche publique : %s" % commande)
        self._service_monitor.publier_fiche_publique(commande)

    def ajouter_comptes(self, commande: dict):
        try:
            contenu = commande['contenu']
        except KeyError:
            contenu = commande
        cert_pem = contenu[Constantes.ConstantesPki.LIBELLE_CERTIFICAT_PEM]
        # chaine_pem = contenu['chaine']

        self._ajouter_compte_pem(cert_pem, commande)

    def _ajouter_compte_pem(self, cert_pem, commande):
        # Charger pem
        # certificat = EnveloppeCleCert()
        # certificat.cert_from_pem_bytes(cert_pem.encode('utf-8'))

        validateur = self._service_monitor.validateur_certificat
        certificat = validateur.valider(cert_pem)

        securite = certificat.get_exchanges

        if Constantes.SECURITE_SECURE in securite:
            # Ajouter compte dans mongo
            try:
                gestionnaire_mongo: GestionnaireComptesMongo = self._service_monitor.gestionnaire_mongo
                if gestionnaire_mongo:
                    gestionnaire_mongo.creer_compte(certificat)
            except DuplicateKeyError:
                self.__logger.info("Compte mongo deja cree : " + certificat.subject_rfc4514_string_mq())
            except KeyError as kerr:
                self.__logger.debug("Certificat ignore " + str(kerr))

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

    def inscrire_domaine(self, nom_domaine: str, exchanges_routing: dict):
        self._service_monitor.rediriger_messages_downstream(nom_domaine, exchanges_routing)

    def transmettre_vers_acteur(self, commande: dict):
        """
        Relai une commande vers l'acteur systeme
        :param commande:
        :return:
        """
        raise NotImplementedError("todo")
        # self.__pipe_acteur.transmettre_commande(commande)

    def requete_mdns_acteur(self, idmg):
        commande = {
            'commande': 'get_mdns_services',
            'idmg': idmg
        }

        raise NotImplementedError("fix me")
        self.__attente_acteur_mdns.clear()
        self.__pipe_acteur.transmettre_commande(commande)
        self.__attente_acteur_mdns.wait(5)
        if self.__attente_acteur_mdns.is_set():
            reponse = self.__reponse_acteur_mdns
            self.__reponse_acteur_mdns = None
            self.__logger.debug("Reponse mdns : %s" % reponse)

            contenu = reponse.get('contenu')
            return contenu
        else:
            raise Exception("Aucune reponse de l'acteur")

    def recevoir_reponse_mdns(self, reponse: CommandeMonitor):
        self.__reponse_acteur_mdns = reponse.contenu
        self.__attente_acteur_mdns.set()

    def initialiser_handler_mq(self, contexte):
        """
        Initialise le handler, le retourne pour le faire enregistrer comme listener sur MQ
        :param contexte:
        :return:
        """
        self.__handler_requetes = TraitementMQRequetesBlocking(contexte, self.__fermeture_event)
        return self.__handler_requetes


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


class PipeActeur:

    def __init__(self, path_socket='/var/opt/millegrilles/acteur.socket'):
        self.__path_socket = path_socket
        self.__event_stop = Event()
        self.__event_action = Event()

        self.__commandes = list()

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        self.__thread = Thread(name='acteur.pipe', target=self.run)

        self.__thread.start()

    def fermer(self):
        if not self.__event_stop.set():
            self.__event_stop.set()
            self.__event_action.set()

    def transmettre_commande(self, commande: dict):
        self.__commandes.append(commande)
        self.__event_action.set()

    def _emit_socket(self, commande_str: str):
        if path.exists(self.__path_socket):
            with open(self.__path_socket, 'w') as pipe:
                pipe.write(commande_str)
        else:
            raise FileNotFoundError(self.__path_socket)

    def run(self):
        while not self.__event_stop.is_set():
            self.__event_action.clear()

            try:
                while not self.__event_stop.is_set() and len(self.__commandes) > 0:
                    commande = self.__commandes.pop(0)

                    # Transmettre la commande sur socket monitor
                    commande_str = json.dumps(commande)
                    self._emit_socket(commande_str)
                    self.__event_stop.wait(0.5)  # Donner le temps au monitor d'extraire la commande
            except FileNotFoundError:
                if self.__logger.isEnabledFor(logging.DEBUG):
                    self.__logger.exception("Pipe n'est pas encore cree, on flush toutes les commandes")
                self.__commandes.clear()

            self.__event_action.wait(10)
