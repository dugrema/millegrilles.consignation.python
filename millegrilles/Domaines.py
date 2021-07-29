# Module avec utilitaires generiques pour mgdomaines
import logging
import json
import datetime
import pytz
import gc
import requests

from typing import cast, Optional
from pika.exceptions import ChannelClosed
from pymongo.errors import OperationFailure
from bson import ObjectId
from threading import Thread, Event, Lock
from cryptography.exceptions import InvalidSignature

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup, ConstantesDomaines
from millegrilles.dao.MessageDAO import JSONHelper, TraitementMessageDomaine, CertificatInconnu, TraitementMessageCallback
from millegrilles.MGProcessus import MGPProcessusDemarreur, MGPProcesseurTraitementEvenements, MGPProcesseurRegeneration, MGProcessus
from millegrilles.util.UtilScriptLigneCommande import ModeleConfiguration
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.dao.MessageDAO import TraitementMQRequetesBlocking
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.util.BackupModule import HandlerBackupDomaine
from millegrilles.util.X509Certificate import EnveloppeCleCert
from millegrilles.util.BackupModule import ArchivesBackupParser
from millegrilles.util.ValidateursPki import ValidateurCertificat
from millegrilles.util.ValidateursMessages import ValidateurMessage


class TraitementMessageDomaineCommande(TraitementMessageDomaine):
    """
    Traite une commande du domaine
    """

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        try:
            enveloppe_certificat = self.gestionnaire.validateur_message.verifier(message_dict)
            reponse = self.traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)
            if reponse is not None and properties.reply_to is not None:
                self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
        except CertificatInconnu as ci:
            fingerprint = ci.fingerprint
            self.message_dao.transmettre_demande_certificat(fingerprint)

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict) -> dict:
        raise NotImplementedError()

    def transmettre_reponse(self, commande, resultats, replying_to, correlation_id=None, ajouter_certificats=False):
        if correlation_id is None:
            correlation_id = commande[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        message_resultat = {
            'resultats': resultats,
        }
        self.gestionnaire.generateur_transactions.transmettre_reponse(
            message_resultat, replying_to, correlation_id, ajouter_certificats=ajouter_certificats)


class TraitementMessageDomaineEvenement(TraitementMessageDomaine):
    """
    Traite un evenement du domaine
    """

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        try:
            enveloppe_certificat = self.gestionnaire.validateur_message.verifier(message_dict)
            self.traiter_evenement(enveloppe_certificat, ch, method, properties, body, message_dict)
        except CertificatInconnu as ci:
            fingerprint = ci.fingerprint
            self.message_dao.transmettre_demande_certificat(fingerprint)

    def traiter_evenement(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        raise NotImplementedError()


class TraitementMessageDomaineRequete(TraitementMessageDomaine):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        routing_key = method.routing_key

        # Verifier si la requete est pour un certificat
        if routing_key and routing_key.startswith('requete.certificat.'):
            fingerprint = routing_key.split('.')[-1]
            self.__logger.debug("Requete certificat %s sur exchange %s" % (fingerprint, method.exchange))
            # self.message_dao.transmettre_demande_certificat(fingerprint)
            return

        try:
            # self.gestionnaire.verificateur_transaction.verifier(message_dict)
            enveloppe_certificat = self.gestionnaire.validateur_message.verifier(message_dict)
            self.traiter_requete(ch, method, properties, body, message_dict, enveloppe_certificat)
        except CertificatInconnu as ci:
            fingerprint = ci.fingerprint
            self.message_dao.transmettre_demande_certificat(fingerprint)
        except InvalidSignature as erreur_signature:
            self.__logger.debug("Erreur signature message: \n%s" % str(message_dict))
            self.transmettre_reponse(
                message_dict, {'error': True, 'message': 'Signature invalide'}, properties.reply_to, properties.correlation_id
            )
            raise erreur_signature
        except KeyError as ke:
            if self.__logger.isEnabledFor(logging.DEBUG):
                self.__logger.exception("Erreur traitement message routing : %s" % method.routing_key)
            else:
                self.__logger.info("Erreur traitement message (routing: %s): %s" % (method.routing_key, str(ke)))

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        resultats = list()
        try:
            for requete in message_dict['requetes']:
                resultat = self.executer_requete(requete)
                resultats.append(resultat)

            # Genere message reponse
            self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)
        except KeyError as ke:
            reponse = {
                'ok': False, 'err': str(ke)
            }
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)

    def executer_requete(self, requete):
        """
        Requetes generiques par composants avec acces protege.

        Exemple:
        {
          'filtre': {
            '_mg-libelle': 'blogpost',
          },
          'projection': {
            "uuid": 1, "_mg-derniere-modification": 1,
            "titre": 1, "titre_fr": 1, "titre_en": 1
          },
          'hint': [
            {'_mg-libelle': 1},
            {'_mg-derniere-modification': -1}
          ],
          'limit': 10,
          'skip': 120,
        }

        :param requete:
        :return:
        """
        collection = self.gestionnaire.get_collection()
        filtre = requete.get('filtre')
        projection = requete.get('projection')
        sort_params = requete.get('sort')
        hint = requete.get('hint')
        limit = requete.get('limit')
        skip = requete.get('skip')

        if projection is None:
            curseur = collection.find(filtre)
        else:
            curseur = collection.find(filtre, projection)

        if sort_params is not None:
            curseur.sort(sort_params)

        if hint is not None:
            # Reformatter les hints avec tuple
            hints_formatte = []
            for hint_elem in hint:
                for key, value in hint_elem.items():
                    hints_formatte.append((key, value))

            curseur.hint(hints_formatte)

        if skip is not None:
            curseur.skip(skip)

        if limit is not None:
            curseur.limit(limit)

        resultats = list()
        for resultat in curseur:
            resultats.append(resultat)

        return resultats

    def transmettre_reponse(self, requete, resultats, replying_to, correlation_id=None, ajouter_certificats=False):
        # enveloppe_val = generateur.soumettre_transaction(requete, 'millegrilles.domaines.Principale.creerAlerte')
        if correlation_id is None:
            correlation_id = requete[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]



        self.gestionnaire.generateur_transactions.transmettre_reponse(
            resultats, replying_to, correlation_id, ajouter_certificats=ajouter_certificats)


class TraitementMessageCedule(TraitementMessageDomaine):

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        if evenement == Constantes.EVENEMENT_CEDULEUR:
            self.traiter_evenement(message_dict)
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))

    def traiter_evenement(self, message):
        self.gestionnaire.traiter_cedule(message)


class TraitementMessagesDomainesDynamiques(TraitementMessageCallback):

    def __init__(self, message_dao, configuration, gestionnaire_domaines, generateur_transactions):
        super().__init__(message_dao, configuration)
        self._gestionnaire_domaines = gestionnaire_domaines
        self.__generateur_transactions = generateur_transactions

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.')[-1]
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)

        reponse = None
        if domaine_action == ConstantesDomaines.COMMANDE_DOMAINE_DEMARRER:
            reponse = self._gestionnaire_domaines.demarrer_domaine(message_dict)
        elif domaine_action == ConstantesDomaines.COMMANDE_DOMAINE_ARRETER:
            self._gestionnaire_domaines.arreter_domaine(message_dict)
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, message_dict))

        if reponse is not None:
            reply_to = properties.reply_to
            correlation_id = properties.correlation_id
            self.__generateur_transactions.transmettre_reponse(reponse, replying_to=reply_to, correlation_id=correlation_id)


class GestionnaireDomainesMilleGrilles(ModeleConfiguration):
    """
    Classe qui agit comme gestionnaire centralise de plusieurs domaines MilleGrilles.
    Cette classe s'occupe des DAOs et du cycle de vie du programme.
    """

    def __init__(self):
        super().__init__()
        self.__domaines_dynamiques = False

        self.__traitement_evenements = None

        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))
        self._gestionnaires = []
        self._stop_event = Event()
        self.__channel = None  # Ouvrir un channel pour savoir quand MQ est pret
        self.__wait_mq_ready = Event()

    def initialiser(self, init_document=True, init_message=True, connecter=True):
        """ L'initialisation connecte RabbitMQ, MongoDB, lance la configuration """
        super().initialiser(init_document, init_message, connecter)
        self.initialiser_2()

    def initialiser_2(self, contexte=None):
        super().initialiser_2(contexte)
        self.contexte.message_dao.register_channel_listener(self)

    def on_channel_open(self, channel):
        super().on_channel_open(channel)
        channel.basic_qos(prefetch_count=10)
        channel.add_on_close_callback(self.on_channel_close)
        self.__channel = channel

        # MQ est pret, on charge les domaines
        self.__wait_mq_ready.set()

    def on_channel_close(self, channel=None, code=None, reason=None):
        self.__wait_mq_ready.clear()
        self.__channel = None

        if not self._stop_event.is_set():
            try:
                self.contexte.message_dao.enter_error_state()
            except Exception:
                self._logger.exception(
                    "Erreur d'activation mode erreur pour connexion MQ, contoleur gestionnaire va se fermer"
                )
                self.arreter()

        self._logger.info("MQ Channel ferme")

    def configurer_parser(self):
        super().configurer_parser()

        self.parser.add_argument(
            '--domaines',
            type=str,
            required=False,
            help="Gestionnaires de domaines a charger. Format: nom_module1:nom_classe1,nom_module2:nom_classe2,[...]"
        )

        self.parser.add_argument(
            '--configuration',
            type=str,
            required=False,
            help="Chemin du fichier de configuration des domaines"
        )

    ''' Charge les domaines listes en parametre '''
    def charger_domaines(self):

        liste_classes_gestionnaires = []

        # Faire liste des domaines args
        liste_domaines = self.args.domaines
        if liste_domaines is not None:
            gestionnaires = liste_domaines.split(',')
            self._logger.info("Chargement des gestionnaires: %s" % str(gestionnaires))

            for gestionnaire in gestionnaires:
                noms_module_class = gestionnaire.strip().split(':')
                nom_module = noms_module_class[0]
                nom_classe = noms_module_class[1]
                classe = self.importer_classe_gestionnaire(nom_module, nom_classe)
                liste_classes_gestionnaires.append(classe)

        # Charger le fichier de configuration json
        chemin_fichier_configuration = self.args.configuration
        if chemin_fichier_configuration is None:
            chemin_fichier_configuration = self.contexte.configuration.domaines_json

        if chemin_fichier_configuration is not None:
            self._logger.info("Charger la configuration a partir du fichier: %s" % chemin_fichier_configuration)

            with open(chemin_fichier_configuration) as json_config:
                configuration_json = json.load(json_config)

            domaines = configuration_json['domaines']
            for domaine in domaines:
                classe = self.importer_classe_gestionnaire(
                    domaine['module'],
                    domaine['classe']
                )
                liste_classes_gestionnaires.append(classe)

        if self.contexte.configuration.domaines_dynamiques:
            # Activer la gestion dynamique des domaines.
            domaines_actifs = self.activer_gestion_dynamique()
            for domaine in domaines_actifs:
                classe = self.importer_classe_gestionnaire(
                    domaine['module'],
                    domaine['classe']
                )
                liste_classes_gestionnaires.append(classe)

        self._logger.info("%d classes de gestionnaires a charger" % len(liste_classes_gestionnaires))

        # On prepare et configure une instance de chaque gestionnaire
        for classe_gestionnaire in liste_classes_gestionnaires:
            # Preparer une instance du gestionnaire
            instance = classe_gestionnaire(self.contexte)
            instance.configurer()  # Executer la configuration du gestionnaire de domaine
            self._gestionnaires.append(instance)

    def activer_gestion_dynamique(self):
        self.__domaines_dynamiques = True

        self.__traitement_evenements = TraitementMessagesDomainesDynamiques(
            self.contexte.message_dao, self.contexte.configuration, self, self.contexte.generateur_transactions)
        domaine_actions = [
            'commande.domaines.' + ConstantesDomaines.COMMANDE_DOMAINE_DEMARRER,
            'commande.domaines.' + ConstantesDomaines.COMMANDE_DOMAINE_ARRETER,
        ]
        self.contexte.message_dao.inscrire_topic(
            Constantes.SECURITE_PROTEGE, domaine_actions, self.__traitement_evenements.callbackAvecAck)

        # Charger les domaines dynamiques pour ce noeud
        noeud_id = self.contexte.configuration.noeud_id

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.ConstantesTopologie.LIBVAL_DOMAINE,
            'noeud_id': noeud_id,
            'actif': True,
        }
        collection = self.contexte.document_dao.get_collection(Constantes.ConstantesTopologie.COLLECTION_DOCUMENTS_NOM)
        configuration_noeud = collection.find(filtre)

        domaines_actifs = list()
        try:
            for config in configuration_noeud:
                config = dict(config)
                config['nom'] = config['domaine']
                domaines_actifs.append(config)
        except AttributeError:
            pass

        return domaines_actifs

    def importer_classe_gestionnaire(self, nom_module, nom_classe):
        self._logger.info("Nom package: %s, Classe: %s" % (nom_module, nom_classe))
        classe_processus = __import__(nom_module, fromlist=[nom_classe])
        classe = getattr(classe_processus, nom_classe)
        self._logger.debug("Classe gestionnaire chargee: %s %s" % (classe.__module__, classe.__name__))
        return classe

    def demarrer_execution_domaines(self):
        for gestionnaire in self._gestionnaires:
            self._logger.debug("Demarrer un gestionnaire")
            gestionnaire.demarrer()

    def exit_gracefully(self, signum=None, frame=None):
        self.arreter()
        super().exit_gracefully()

    def executer(self):
        self.__wait_mq_ready.wait(60)
        if not self.__wait_mq_ready.is_set():
            raise Exception("MQ n'est pas pret apres 60 secondes")

        self.charger_domaines()

        if len(self._gestionnaires) > 0 or self.__domaines_dynamiques:
            self.demarrer_execution_domaines()
        else:
            self._stop_event.set()
            self._logger.fatal("Aucun gestionnaire de domaine n'a ete charge. Execution interrompue.")

        # Surveiller les gestionnaires - si un gestionnaire termine son execution, on doit tout fermer
        try:
            while not self._stop_event.is_set():
                # self.contexte.message_dao.start_consuming()  # Blocking
                # self._logger.debug("Erreur consuming, attendre 5 secondes pour ressayer")

                # Verifier que tous les domaines sont actifs et fonctionnels
                for gestionnaire in self._gestionnaires:
                    gestionnaire.executer_entretien()
                    if not gestionnaire.is_ok:
                        self._logger.error("Gestionnaire domaine %s est en erreur/termine, on arrete le controleur" % gestionnaire.__class__.__name__)
                        self.arreter()

                gc.collect()
                self._stop_event.wait(15)   # Boucler pour maintenance

        except Exception:
            self._logger.exception("Erreur execution controleur de gestionnaires, arret force")
        finally:
            self.arreter()

        self._logger.info("Fin de la boucle executer() dans MAIN")

    def arreter(self):
        self._logger.info("Arret du gestionnaire de domaines MilleGrilles")
        self._stop_event.set()  # Va arreter la boucle de verification des gestionnaires

        # Avertir chaque gestionnaire
        for gestionnaire in self._gestionnaires:
            try:
                gestionnaire.arreter()
            except ChannelClosed as ce:
                self._logger.debug("Channel deja ferme: %s" % str(ce))
            except Exception as e:
                self._logger.warning("Erreur arret gestionnaire %s: %s" % (gestionnaire.__class__.__name__, str(e)))

        self.deconnecter()

    def set_logging_level(self):
        super().set_logging_level()
        """ Utilise args pour ajuster le logging level (debug, info) """
        if self.args.debug:
            self._logger.setLevel(logging.DEBUG)
            logging.getLogger('mgdomaines').setLevel(logging.DEBUG)
        elif self.args.info:
            self._logger.setLevel(logging.INFO)
            logging.getLogger('mgdomaines').setLevel(logging.INFO)

    def demarrer_domaine(self, commande: dict):
        nom = commande['nom']
        module = commande['module']
        nom_classe = commande['classe']

        reponse = {
            'demarre': False
        }
        try:
            gestionnaire, classe = self.trouver_gestionnaire(module, nom_classe)
            if not gestionnaire:
                self._logger.info("Demarrage domaine %s (%s)" % (classe, module))
                gestionnaire = classe(self.contexte)
                gestionnaire.configurer()

                # Demarrer le gestionnaire a l'aide d'une thread temporaire
                thread = Thread(name="demarrer_domaine", target=gestionnaire.demarrer, daemon=True)
                thread.start()
                reponse['demarre'] = True

                self._gestionnaires.append(gestionnaire)

                # Transmettre transaction pour confirmer le demarrage
                transaction = {
                    "noeud_id": self._contexte.configuration.noeud_id,
                    "nom": nom,
                    "module": module,
                    "classe": nom_classe
                }
                domaine_action = Constantes.ConstantesTopologie.TRANSACTION_AJOUTER_DOMAINE_DYNAMIQUE
                confirmation = self._contexte.generateur_transactions.soumettre_transaction(transaction, domaine_action)
                reponse['confirmation'] = confirmation
            else:
                reponse['demarre'] = True
        except Exception as e:
            self._logger.exception("Erreur demarrage domaine dynamique")
            reponse['err'] = str(e)

        return reponse

    def arreter_domaine(self, commande: dict):
        nom = commande['nom']
        module = commande['module']
        nom_classe = commande['classe']

        gestionnaire, classe = self.trouver_gestionnaire(module, nom_classe)
        if gestionnaire:
            self._logger.info("Arret domaine %s (%s)" % (classe, module))
            gestionnaire.arreter()
            self._gestionnaires.remove(gestionnaire)

            # Transmettre transaction pour confirmer la suppression
            transaction = {
                "noeud_id": self._contexte.configuration.noeud_id,
                "nom": nom,
                "module": module,
                "classe": nom_classe
            }
            domaine_action = Constantes.ConstantesTopologie.TRANSACTION_SUPPRIMER_DOMAINE_DYNAMIQUE
            self._contexte.generateur_transactions.soumettre_transaction(transaction, domaine_action)

    def trouver_gestionnaire(self, module: str, classe: str):
        # Charger classe pour comparer directement l'instance
        classe = self.importer_classe_gestionnaire(module, classe)

        for gestionnaire in self._gestionnaires:
            if isinstance(gestionnaire, classe):
                # Instance match, on retourne ce gestionnaire
                return gestionnaire, classe

        return None, classe


class GestionnaireDomaine:
    """ Le gestionnaire de domaine est une superclasse qui definit le cycle de vie d'un domaine. """

    def __init__(self, contexte):

        # Nouvelle approche, utilisation classe contexte pour obtenir les ressources
        self.__contexte = contexte
        self.demarreur_processus = None
        self.json_helper = JSONHelper()
        self.__logger = logging.getLogger("%s.GestionnaireDomaine" % __name__)
        # self._watchers = list()
        self.channel_mq = None
        self._arret_en_cours = False
        self._stop_event = Event()
        self.wait_Q_ready = Event()  # Utilise pour attendre configuration complete des Q
        self.wait_Q_ready_lock = Lock()
        self.wait_Q_ready_delay: int = 30
        self.nb_routes_a_config = 0
        self.__Q_wait_broken = None  # Mis utc a date si on a un timeout pour l'attente de __wait_mq_ready

        self._traitement_evenements = None

        self._consumer_tags_parQ = dict()

        self.__message_presence: dict = cast(dict, None)
        self.__confirmation_setup_transaction = False  # Vrai si la collection de transactions est prete

        self.__requetes_blocking: Optional[TraitementMQRequetesBlocking] = None

        # Cache des enveloppes de rechiffrage (maitre des cles, millegrille, etc)
        self.__enveloppes_rechiffrage = None

        # ''' L'initialisation connecte RabbitMQ, MongoDB, lance la configuration '''
    # def initialiser(self):
    #     self.connecter()  # On doit se connecter immediatement pour permettre l'appel a configurer()

    def configurer(self):
        self._traitement_evenements = self.initialiser_mgprocesseur_evenements()

        self.emettre_presence_domaine()

        self._traitement_evenements.initialiser([self.get_collection_processus_nom()])
        """ Configure les comptes, queues/bindings (RabbitMQ), bases de donnees (MongoDB), etc. """
        self.demarreur_processus = MGPProcessusDemarreur(
            self._contexte, self.get_nom_domaine(), self.get_collection_transaction_nom(),
            self.get_collection_processus_nom(), self._traitement_evenements, gestionnaire=self)

    def initialiser_mgprocesseur_evenements(self):
        """
        Factory pour traitement evenements du domaine
        :return:
        """
        return MGPProcesseurTraitementEvenements(
            self._contexte, self._stop_event, gestionnaire_domaine=self)

    def demarrer(self):
        """ Demarrer une thread pour ce gestionnaire """
        self.__logger.debug("Debut thread gestionnaire %s" % self.__class__.__name__)
        # self.configurer()  # Deja fait durant l'initialisation
        self.__logger.info("On enregistre la queue %s" % self.get_nom_queue())

        self._contexte.message_dao.register_channel_listener(self)
        self.__logger.info("Attente de la Q et des routes sur nouveau listener MQ pour %s" % self.__class__.__name__)
        self.wait_Q_ready.wait(self.wait_Q_ready_delay)  # Donner 30 seconde a MQ

        # Verifier si la collection de transactions est prete
        self.__confirmation_setup_transaction = self.verifier_collection_transactions()
        if not self.__confirmation_setup_transaction:
            self.emettre_presence_domaine()
            Event().wait(3)
            self.__confirmation_setup_transaction = self.verifier_collection_transactions()
            if not self.__confirmation_setup_transaction:
                self.wait_Q_ready.clear()
                self.__logger.error("Erreur initialisation collection Transaction pour %s" % self.get_nom_domaine())

        if not self.wait_Q_ready.is_set():
            self.__Q_wait_broken = datetime.datetime.utcnow()
            if self.nb_routes_a_config > 0:
                self.__logger.error("Les routes de Q du domaine ne sont pas configures correctement, il reste %d a configurer" % self.nb_routes_a_config)
            else:
                self.__logger.warning('wait_Q_read pas set, on va forcer error state sur la connexion pour recuperer')
            self.message_dao.enter_error_state()
        else:
            self.__logger.info("Q et routes prets")

            # Verifier si on doit upgrader les documents avant de commencer a ecouter
            doit_regenerer = self.verifier_version_transactions(self.version_domaine)

            if doit_regenerer:
                self.regenerer_documents()
                self.changer_version_collection(self.version_domaine)

            # Lance le processus de regeneration des rapports sur cedule pour s'assurer d'avoir les donnees a jour
            self.regenerer_rapports_sur_cedule()

        self.__requetes_blocking = TraitementMQRequetesBlocking(self.__contexte, self._stop_event)

    def verifier_collection_transactions(self):
        """
        Detecte si la collection de transactions du domaine est presente.
        Utilise la presence d'index sur la collection (generes par le consignateur de transactions)
        :return:
        """
        nom_collection = self.get_nom_domaine()
        collection_transactions = self.document_dao.get_collection(nom_collection)
        indices = collection_transactions.list_indexes()

        collection_presente = len([index for index in indices]) > 0

        return collection_presente

    def on_channel_open(self, channel):
        """
        Callback pour l"ouverture ou la reouverture du channel MQ
        :param channel:
        :return:
        """
        if self.channel_mq is not None:
            # Fermer le vieux channel
            try:
                self.channel_mq.close()
            finally:
                self.channel_mq = None

        self.channel_mq = channel
        channel.basic_qos(prefetch_count=1)
        channel.add_on_close_callback(self.on_channel_close)

        self.setup_rabbitmq()  # Setup Q et consumers

    def get_queue_configuration(self):
        """
        :return: Liste de Q avec configuration pour le domaine
        """
        raise NotImplementedError("Pas implemente")

    def emettre_presence_domaine(self):
        """
        Emet un evenement pour indiquer que le domaine est present, configuration, cle de routage.
        :return:
        """
        if self.__message_presence is None:
            queue_config = self.get_queue_configuration()
            exchanges = dict()
            for q in queue_config:
                exchange = q['exchange']
                if exchange not in [Constantes.SECURITE_SECURE]:
                    routing = exchanges.get(exchange)
                    if not routing:
                        routing = set()
                        exchanges[exchange] = routing
                    routing.update(q['routing'])

            exchanges_routing = dict()
            for exchange, routing_set in exchanges.items():
                exchanges_routing[exchange] = list(routing_set)

            info_domaine = {
                'idmg': self.__contexte.idmg,
                'noeud_id': self.__contexte.configuration.noeud_id,
                'domaine': self.get_nom_domaine(),
                'sous_domaines': None,
                'exchanges_routing': exchanges_routing,
                'primaire': True,
            }
            self.__message_presence = info_domaine
        routing = 'evenement.presence.domaine'
        self.generateur_transactions.emettre_message(
            self.__message_presence, routing, exchanges=[Constantes.SECURITE_PROTEGE],
            reply_to=self.get_nom_domaine() + '.evenements', correlation_id='presence.domaine',
        )

    def setup_rabbitmq(self, consume=True):
        """
        Callback pour faire le setup de rabbitMQ quand le channel est ouvert. Permet aussi de refaire les binding
        avec les Q apres avoir appele unbind_rabbitmq.
        """
        channel = self.channel_mq
        queues_config = self.get_queue_configuration()

        self.nb_routes_a_config = len([r for r in [q.get('routing') for q in queues_config]])
        self.wait_Q_ready.clear()  # Reset flag au besoin
        # channel = self.message_dao.channel
        for queue_config in queues_config:

            def callback_init_transaction(queue, gestionnaire=self, in_queue_config=queue_config, in_consume=consume):
                if in_consume and in_queue_config.get('callback'):
                    gestionnaire.inscrire_basicconsume(queue, in_queue_config['callback'])

                routing_list = in_queue_config.get('routing')
                if routing_list is not None:
                    for routing in routing_list:
                        channel.queue_bind(
                            exchange=in_queue_config['exchange'],
                            queue=in_queue_config['nom'],
                            routing_key=routing,
                            callback=self.__compter_route
                        )

            args = {}
            if queue_config.get('arguments'):
                args.update(queue_config.get('arguments'))
            if queue_config.get('ttl'):
                args['x-message-ttl'] = queue_config['ttl']

            durable = False
            if queue_config.get('durable'):
                durable = True

            self.__logger.info("Declarer Q %s" % queue_config['nom'])
            channel.queue_declare(
                queue=queue_config['nom'],
                durable=durable,
                callback=callback_init_transaction,
                arguments=args,
            )

    def __compter_route(self, arg1):
        """
        Sert a compter les routes qui sont pretes. Declenche Event wait_Q_ready lorsque complet.
        :param arg1:
        :return:
        """
        # Indiquer qu'une route a ete configuree
        with self.wait_Q_ready_lock:
            self.nb_routes_a_config = self.nb_routes_a_config - 1

            if self.nb_routes_a_config <= 0:
                # Il ne reste plus de routes a configurer, set flag comme pret
                self.wait_Q_ready.set()
                self.__Q_wait_broken = None

    def stop_consuming(self, queue=None):
        """
        Deconnecte les consommateur queues du domaine pour effectuer du travail offline.
        """
        channel = self.channel_mq
        if queue is None:
            tags = channel.consumer_tags
            for tag in tags:
                self.__logger.debug("Removing ctag %s" % tag)
                with self.message_dao.lock_transmettre_message:
                    channel.basic_cancel(consumer_tag=tag, nowait=True)
        else:
            ctag = self._consumer_tags_parQ.get(queue)
            if ctag is not None:
                with self.message_dao.lock_transmettre_message:
                    channel.basic_cancel(consumer_tag=ctag, nowait=True)

    def resoumettre_transactions(self):
        """
        Soumets a nouveau les notifications de transactions non completees du domaine.
        Utilise l'ordre de persistance.
        :return:
        """
        idmg = self.configuration.idmg
        champ_complete = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_COMPLETE)
        champ_persiste = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_DOCUMENT_PERSISTE)
        filtre = {
            champ_complete: False
        }
        hint = [
            (champ_complete, 1),
            (champ_persiste, 1)
        ]

        collection_transactions = self.document_dao.get_collection(self.get_collection_transaction_nom())
        transactions_incompletes = collection_transactions.find(filtre, sort=hint).hint(hint)

        try:
            for transaction in transactions_incompletes:
                self.__logger.debug("Transaction incomplete: %s" % transaction)
                id_document = transaction[Constantes.MONGO_DOC_ID]
                en_tete = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
                uuid_transaction = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
                domaine = en_tete[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
                self.generateur_transactions.transmettre_evenement_persistance(
                    id_document, uuid_transaction, domaine, None)
        except OperationFailure as of:
            self.__logger.error("Collection %s, erreur requete avec hint: %s.\n%s" % (
                self.get_collection_transaction_nom(), str(hint), str(of)))

    def on_channel_close(self, channel=None, code=None, reason=None):
        """
        Callback pour la fermeture du channel
        :param channel:
        :return:
        """
        self.__logger.info("Channel ferme: %s, %s" % (code, reason))
        self.channel_mq = None

    def inscrire_basicconsume(self, queue, callback):
        """
        Inscrit le channel sur la queue.
        :param queue:
        :param callback:
        :return: Consumer tag (ctag)
        """
        if isinstance(queue, str):
            nom_queue = queue
        else:
            nom_queue = queue.method.queue

        self.__logger.info("Queue prete, on enregistre basic_consume %s" % nom_queue)
        with self.message_dao.lock_transmettre_message:
            ctag = self.channel_mq.basic_consume(callback, queue=nom_queue, no_ack=False)

        # Conserver le ctag - permet de faire cancel au besoin (e.g. long running process)
        self._consumer_tags_parQ[nom_queue] = ctag

        return ctag

    def demarrer_watcher_collection(self, nom_collection_mongo: str, routing_key: str, exchange_router=None):
        """
        Enregistre un watcher et demarre une thread qui lit le pipeline dans MongoDB. Les documents sont
        lus au complet et envoye avec la routing_key specifiee.
        :param nom_collection_mongo: Nom de la collection dans MongoDB pour cette MilleGrille
        :param routing_key: Nom du topic a enregistrer,
               e.g. noeuds.source.millegrilles_domaines_SenseursPassifs.affichage.__nom_noeud__.__no_senseur__
        :param exchange_router: Routeur pour determiner sur quels exchanges le document sera place.
        :return:
        """
        # watcher = WatcherCollectionMongoThread(self._contexte, self._stop_event, nom_collection_mongo, routing_key, exchange_router)
        # self._watchers.append(watcher)
        # watcher.start()
        self.__logger.warning("Deprecated: Domaines.demarrer_watcher_collection()")

    def identifier_processus(self, domaine_transaction):
        nom_domaine = self.get_nom_domaine()
        operation = domaine_transaction.replace('%s.' % nom_domaine, '')

        if operation == Constantes.TRANSACTION_ROUTING_DOCINITIAL:
            processus = "%s:millegrilles_MGProcessus:MGProcessusDocInitial" % operation
        elif operation == Constantes.TRANSACTION_ROUTING_UPDATE_DOC:
            processus = "%s:millegrilles_MGProcessus:MGProcessusUpdateDoc" % operation
        else:
            raise TransactionTypeInconnuError("Type de transaction inconnue: routing: %s" % domaine_transaction)

        return processus

    def regenerer_rapports_sur_cedule(self):
        """ Permet de regenerer les documents de rapports sur cedule lors du demarrage du domaine """
        pass

    def regenerer_documents(self, stop_consuming=True):
        self.__logger.info("Regeneration des documents de %s" % self.get_nom_domaine())

        processeur_regeneration = MGPProcesseurRegeneration(self, self.__contexte)
        processeur_regeneration.regenerer_documents(stop_consuming=stop_consuming)

        self.__logger.info("Fin regeneration des documents de %s" % self.get_nom_domaine())

        return {'complet': True}

    def get_collection_transaction_nom(self):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def get_collection_processus_nom(self):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    def get_nom_domaine(self):
        raise NotImplementedError("N'est pas implemente - doit etre definit dans la sous-classe")

    ''' Arrete le traitement des messages pour le domaine '''
    def arreter_traitement_messages(self):
        self._arret_en_cours = True
        self._stop_event.set()
        if self.channel_mq is not None:
            self.channel_mq.close()
        self._traitement_evenements.arreter()

    def demarrer_processus(self, processus, parametres):
        self.demarreur_processus.demarrer_processus(processus, parametres)

    def verifier_version_transactions(self, version_domaine):
        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.get_collection()

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.LIBVAL_CONFIGURATION}
        )
        self.__logger.debug("Document config domaine: %s" % document_configuration)

        doit_regenerer = True
        if document_configuration is not None:
            version_collection = document_configuration.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION)
            if version_collection is None:
                self.__logger.warning(
                    "La collection a une version inconnue a celle du code Python (V%d), on regenere les documents" %
                    version_domaine
                )
            elif version_collection == version_domaine:
                doit_regenerer = False
            elif version_collection > version_domaine:
                message_erreur = "Le code du domaine est V%d, le document de configuration est V%d (plus recent)" % (
                    version_domaine, version_collection
                )
                raise Exception(message_erreur)
            else:
                self.__logger.warning(
                    "La collection a une version inferieure (V%d) a celle du code Python (V%d), on regenere les documents" %
                    (version_collection, version_domaine)
                )

        return doit_regenerer

    def initialiser_document(self, mg_libelle, doc_defaut):
        """
        Insere un document de configuration du domaine, au besoin. Le libelle doit etre unique dans la collection.
        :param mg_libelle: Libelle a donner au document
        :param doc_defaut: Document a inserer.
        :return:
        """
        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.get_collection()

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle}
        )
        if document_configuration is None:
            self.__logger.info("On insere le document %s pour domaine Principale" % mg_libelle)

            # Preparation document de configuration pour le domaine
            configuration_initiale = doc_defaut.copy()
            # maintenant = datetime.datetime.utcnow()
            # configuration_initiale[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = maintenant.timestamp()
            # configuration_initiale[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = maintenant.timestamp()
            nouveau_doc = {
                Constantes.DOCUMENT_INFODOC_SOUSDOCUMENT: configuration_initiale
            }

            # collection_domaine.insert(configuration_initiale)
            domaine_transaction = '%s.%s' % (self.get_nom_domaine(), Constantes.TRANSACTION_ROUTING_DOCINITIAL)
            self.generateur_transactions.soumettre_transaction(nouveau_doc, domaine_transaction)
        else:
            self.__logger.debug("Document de %s pour %s: %s" % (
                mg_libelle, str(document_configuration), self.__class__.__name__
            ))

    def changer_version_collection(self, version):
        nouveau_doc = {
            Constantes.DOCUMENT_INFODOC_SOUSDOCUMENT: {
                Constantes.DOCUMENT_INFODOC_LIBELLE: Constantes.LIBVAL_CONFIGURATION,
                Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION: version
            }
        }

        # collection_domaine.insert(configuration_initiale)
        domaine_transaction = '%s.%s' % (self.get_nom_domaine(), Constantes.TRANSACTION_ROUTING_UPDATE_DOC)
        self.generateur_transactions.soumettre_transaction(nouveau_doc, domaine_transaction)

    def marquer_transaction_en_erreur(self, dict_message):
        # Type de transaction inconnue, on lance une exception
        try:
            id_transaction = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO]
            domaine = dict_message[Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        except KeyError:
            self.__logger.error("Erreur sur transaction, identificateur manquant : %s" % dict_message)
            return

        # Extraire domaine et sous-domaine
        routing = GenerateurTransaction.formatter_routing_evenement(domaine, 'transactionEvenement')

        collection = GestionnaireDomaine.identifier_collection_domaine(domaine)

        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.MONGO_DOC_ID: id_transaction,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: collection,
            Constantes.EVENEMENT_MESSAGE_EVENEMENT: Constantes.EVENEMENT_TRANSACTION_ERREUR_TRAITEMENT,
        }

        self.message_dao.transmettre_message(evenement, routing)

    '''
    Implementer cette methode pour retourner le nom de la queue.

    :returns: Nom de la Q a ecouter.
    '''
    def get_nom_queue(self):
        raise NotImplementedError("Methode non-implementee")

    def get_nom_collection(self):
        raise NotImplementedError("Methode non-implementee")

    def get_collection(self):
        return self.document_dao.get_collection(self.get_nom_collection())

    def get_collection_par_nom(self, nom_collection: str):
        return self.document_dao.get_collection(nom_collection)

    def get_transaction(self, id_transaction):
        collection_transactions = self.document_dao.get_collection(self.get_collection_transaction_nom())
        return collection_transactions.find_one({Constantes.MONGO_DOC_ID: ObjectId(id_transaction)})

    def get_transaction_par_token_resumer(self, token_resumer):
        collection_transactions = self.document_dao.get_collection(self.get_collection_transaction_nom())
        libelle_token = '%s.%s.%s' % (
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
            Constantes.EVENEMENT_RESUMER,
            Constantes.EVENEMENT_MESSAGE_TOKEN
        )
        return collection_transactions.find_one({libelle_token: token_resumer})

    def arreter(self):
        self.__logger.warning("Arret de GestionnaireDomaine")
        self.arreter_traitement_messages()
        self._stop_event.set()
        # for watcher in self._watchers:
        #     try:
        #         watcher.stop()
        #     except Exception as e:
        #         self.__logger.info("Erreur fermeture watcher: %s" % str(e))

    def rapport_stats_transactions(self):
        """
        :return: Rapport des stats sur les transactions de ce domaine/sous-domaine
        """

        collection_domaine = self.document_dao.get_collection(self.get_nom_domaine())

        match = {
            '$match': {
                '_evenements.transaction_complete': True,
            }
        }
        group = {'$group': {
            '_id': None,
            'transactions_count': {'$sum': 1},
            'transactions_backup_count': {'$sum': {'$cond': {'if': {'$eq': ['$_evenements.backup_flag', True]}, 'then': 1, 'else': 0}}}
        }}

        curseur_agg = collection_domaine.aggregate([match, group])
        resultat = curseur_agg.__iter__().next()
        del resultat['_id']

        reponse = {
            'domaine': self.get_nom_domaine(),
        }
        reponse.update(resultat)

        return reponse

    def requete_bloquante(self, domaine_action: str, params: dict = None):
        """
        Effectue une requete MQ sur thread separee.
        :return:
        """
        return self.__requetes_blocking.requete(domaine_action, params)

    @property
    def configuration(self):
        return self._contexte.configuration

    @property
    def message_dao(self):
        return self._contexte.message_dao

    @property
    def document_dao(self):
        return self._contexte.document_dao

    @property
    def generateur_transactions(self):
        return self._contexte.generateur_transactions

    @property
    def verificateur_transaction(self):
        raise NotImplementedError("Deprecated - remplace par validateur_message()")
        # return self._contexte.verificateur_transaction

    @property
    def verificateur_certificats(self):
        raise NotImplementedError("Deprecated - replace par validateur_pki()")
        # return self._contexte.verificateur_certificats

    @property
    def validateur_message(self) -> ValidateurMessage:
        return self._contexte.validateur_message

    @property
    def validateur_pki(self) -> ValidateurCertificat:
        return self._contexte.validateur_message.validateur_pki

    def creer_regenerateur_documents(self):
        return RegenerateurDeDocuments(self)

    @property
    def _contexte(self) -> ContexteRessourcesDocumentsMilleGrilles:
        return self.__contexte

    @property
    def version_domaine(self):
        return Constantes.TRANSACTION_MESSAGE_LIBELLE_VERSION_6

    def executer_entretien(self):
        # S'assurer que le domaine est visible et connu de tous les composants du middleware
        self.emettre_presence_domaine()

    @property
    def is_ok(self):
        """
        :return: False si le gestionnaire ne fonctionne pas bien et requiert un redemarrage complet
        """
        if not self._stop_event.is_set() and not self.wait_Q_ready.is_set():
            # Verifier si on est en train de charger le domaine ou si quelque chose a empeche le deploiement
            if not self.__Q_wait_broken:
                return True
            else:
                # On donne 2 minutes pour tenter de recuperer / se reconnecter a MQ
                return datetime.datetime.utcnow() > self.__Q_wait_broken + datetime.timedelta(minutes=2)
        else:
            return not self._stop_event.is_set()

    @staticmethod
    def identifier_collection_domaine(domaine):

        domaine_split = domaine.split('.')
        nom_collection = domaine_split[0]

        return nom_collection

    def crypter_cle(self, cle_secrete, cert=None):
        """
        Chiffre une cle de maniere asymmetrique
        :param cle_secrete:
        :param cert:
        :return:
        """
        if cert is not None:
            clecert = EnveloppeCleCert(cert=cert)
            return clecert.chiffrage_asymmetrique(cle_secrete)
        else:
            return self._contexte.signateur_transactions.chiffrage_asymmetrique(cle_secrete)

    def dechiffrer_cle(self, cle_chiffree: str):
        return self._contexte.signateur_transactions.dechiffrage_asymmetrique(cle_chiffree)

    @property
    def supporte_regenerer_global(self):
        """
        :return: True si le domaine repond a l'evenement regenerer global
        """
        return True

    @property
    def get_collections_documents(self):
        """
        :return: Liste des collections de documents (e.g. DOMAINE/documents, DOMAINE/rapports, etc.)
        """
        return [self.get_nom_collection()]


class TraitementCommandesSecures(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        nom_domaine = self.gestionnaire.get_collection_transaction_nom()

        if routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_horaire(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_QUOTIDIEN.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_quotidien(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_ANNUEL.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_annuel(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_SNAPSHOT.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_snapshot(message_dict)
        elif action == ConstantesBackup.COMMANDE_BACKUP_RESET_DOMAINE:
            resultat = self.gestionnaire.reset_backup(message_dict)

        else:
            raise ValueError("Commande inconnue: " + routing_key)

        return resultat


class TraitementCommandesProtegees(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict) -> dict:
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        commande = method.routing_key.split('.')[-1]
        nom_domaine = self.gestionnaire.get_collection_transaction_nom()

        resultat = None
        if routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE_GLOBAL:
            resultat = self.gestionnaire.declencher_backup_horaire(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_RESET_GLOBAL:
            resultat = self.gestionnaire.reset_backup(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_HORAIRE.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_horaire(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_QUOTIDIEN.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_quotidien(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_ANNUEL.replace("_DOMAINE_", nom_domaine):
            resultat = self.gestionnaire.declencher_backup_annuel(message_dict)
        elif routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_SNAPSHOT.replace("_DOMAINE_", nom_domaine) or \
            routing_key == ConstantesBackup.COMMANDE_BACKUP_DECLENCHER_SNAPSHOT.replace("_DOMAINE_", 'global'):
            resultat = self.gestionnaire.declencher_backup_snapshot(message_dict)
        elif routing_key == ConstantesDomaines.COMMANDE_GLOBAL_REGENERER:
            if self.gestionnaire.supporte_regenerer_global:
                resultat = self.gestionnaire.regenerer_documents()
        elif action == ConstantesDomaines.COMMANDE_REGENERER:
            resultat = self.gestionnaire.regenerer_documents()
        elif action == ConstantesBackup.COMMANDE_BACKUP_RESET_DOMAINE:
            resultat = self.gestionnaire.reset_backup(message_dict)

        elif action == ConstantesBackup.COMMANDE_BACKUP_RESTAURER_TRANSACTIONS:
            resultat = self.gestionnaire.declencher_restauration_transactions(message_dict, properties)

        else:
            raise ValueError("Commande inconnue: " + routing_key)

        return resultat


class TraitementRequetesProtegees(TraitementMessageDomaineRequete):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        commande = routing_key.split('.')[-1]
        nom_domaine = self.gestionnaire.get_collection_transaction_nom()

        reponse = None
        if commande == ConstantesDomaines.REQUETE_STATS_TRANSACTIONS:
            reponse = self.gestionnaire.rapport_stats_transactions()
        else:
            return super().traiter_requete(ch, method, properties, body, message_dict)

        # Genere message reponse
        if reponse:
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class GestionnaireDomaineStandard(GestionnaireDomaine):
    """
    Implementation des Q standards pour les domaines.
    """

    def __init__(self, contexte):
        super().__init__(contexte)

        self.__traitement_noeud = TraitementMessageDomaineRequete(self)

        # self.__traitement_middleware = TraitementMessageDomaineMiddleware(self)
        # self.__handler_backup = HandlerBackupDomaine(
        #     contexte, self.get_nom_domaine(), self.get_collection_transaction_nom(), self.get_collection())

        self.__handler_backup = self._preparer_handler_backup()

        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_commandes = {
            Constantes.SECURITE_SECURE: TraitementCommandesSecures(self),
            Constantes.SECURITE_PROTEGE: TraitementCommandesProtegees(self),
        }

        self.__logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def configurer(self):
        super().configurer()

        self.__logger.debug("Type gestionnaire : " + self.__class__.__name__)

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        # Index noeud, _mg-libelle
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='mglibelle'
        )
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1)
            ],
            name='datecreation'
        )
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1)
            ],
            name='dernieremodification'
        )

    def get_queue_configuration(self) -> list:
        """
        :return: Liste de configuration pour les Q du domaine
        """

        queues_config = [
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'evenements'),
                'routing': [
                    'evenement.%s.mgpprocessus.*' % self.get_nom_domaine(),
                    'evenement.%s.resumer.*' % self.get_nom_domaine(),
                    'evenement.%s.verifierResumer.*' % self.get_nom_domaine(),
                    'evenement.%s.recevoirTransaction' % self.get_nom_domaine(),
                    # 'evenement.%s.transactionEvenement' % self.get_nom_domaine(),
                ],
                'exchange': self.configuration.exchange_middleware,
                'ttl': 300000,
                'callback': self._traitement_evenements.callbackAvecAck
            },
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'ceduleur'),
                'routing': [
                    'ceduleur.#',
                ],
                'exchange': self.configuration.exchange_middleware,
                'ttl': 30000,
                'callback': self.get_handler_cedule().callbackAvecAck
            }
        ]

        # Ajouter les handles de requete par niveau de securite
        for securite, handler in self.get_handler_requetes().items():
            queues_config.append({
                'nom': '%s.requete.%s' % (self.get_nom_domaine(), securite),
                'routing': [
                    'requete.%s.#.*' % self.get_nom_domaine(),
                    ConstantesDomaines.REQUETE_GLOBAL_PREFIX + '.*',
                ],
                'exchange': securite,
                'ttl': 20000,
                'callback': handler.callbackAvecAck
            })

        for securite, handler in self.get_handler_commandes().items():
            queues_config.append({
                'nom': '%s.commande.%s' % (self.get_nom_queue(), securite),
                'routing': [
                    'commande.%s.#.*' % self.get_nom_domaine(),
                    'commande.global.*'
                ],
                'exchange': securite,
                'ttl': 20000,
                'callback': handler.callbackAvecAck
            })

        return queues_config

    def map_transaction_vers_document(self, transaction: dict, document: dict):
        for key, value in transaction.items():
            if key != Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE and not key.startswith('_'):
                document[key] = value

    def get_handler_requetes_noeuds(self):
        return self.__traitement_noeud

    def get_handler_requetes(self) -> dict:
        return {
            Constantes.SECURITE_PROTEGE: self.get_handler_requetes_noeuds()
        }

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_handler_cedule(self):
        return self.__handler_cedule

    def traiter_cedule(self, evenement):
        """ Appele par __handler_cedule lors de la reception d'un message sur la Q .ceduleur du domaine """

        indicateurs = evenement['indicateurs']
        self.__logger.debug("Cedule domaines: %s" % str(indicateurs))

        # Faire la liste des cedules a declencher
        if 'heure' in indicateurs:
            self.nettoyer_processus()

    def nettoyer_processus(self):
        collection_processus = self.document_dao.get_collection(self.get_collection_processus_nom())

        date_complet = datetime.datetime.utcnow() - datetime.timedelta(days=1)
        date_incomplet = datetime.datetime.utcnow() - datetime.timedelta(days=14)

        filtre_complet = {
            "etape-suivante": {"$exists": False},
            "_mg-derniere-modification": {"$lte": date_complet}
        }
        filtre_incomplet = {
            "etape-suivante": {"$exists": True},
            "_mg-creation": {"$lte": date_incomplet}
        }

        collection_processus.delete_many(filtre_complet)
        collection_processus.delete_many(filtre_incomplet)

    def declencher_backup_horaire(self, declencheur: dict):
        """
        Declenche un backup horaire. Maximum qui peut etre demande est est l'heure precedente.

        :param declencheur:
        :return:
        """
        # Verifier qu'on ne demande pas un backup de l'heure courante
        maintenant = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
        heure_precedente = datetime.datetime(year=maintenant.year, month=maintenant.month, day=maintenant.day, hour=maintenant.hour)

        try:
            heure = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_HEURE], tz=datetime.timezone.utc)
            heure_demandee = datetime.datetime(year=heure.year, month=heure.month, day=heure.day, hour=heure.hour)

            if heure_demandee > heure_precedente:
                # Reculer d'une heure
                heure_demandee = heure_precedente
        except KeyError:
            heure_demandee = heure_precedente

        uuid_rapport = declencheur[ConstantesBackup.CHAMP_UUID_RAPPORT]

        domaine = self.get_nom_domaine()

        self.__logger.info("Declencher backup horaire pour domaine %s, heure %s" % (domaine, str(heure_demandee)))
        routing = domaine
        nom_module = 'millegrilles_Domaines'
        nom_classe = 'BackupHoraire'
        processus = "%s:%s:%s" % (routing, nom_module, nom_classe)

        parametres = {
            'heure': heure_demandee,
            ConstantesBackup.CHAMP_UUID_RAPPORT: uuid_rapport,
        }

        self.demarrer_processus(processus, parametres)

    def reset_backup(self, message_dict):
        self.__logger.debug("Reset backup transactions pour domaine " + self.get_nom_domaine())

        unset_champs = list()
        for champ in [
            Constantes.EVENEMENT_TRANSACTION_BACKUP_RESTAURE,
            Constantes.EVENEMENT_TRANSACTION_BACKUP_HORAIRE_COMPLETE,
            Constantes.EVENEMENT_TRANSACTION_BACKUP_ERREUR]:

            unset_champs.append('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, champ))

        champs = {
            '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT, Constantes.EVENEMENT_TRANSACTION_BACKUP_FLAG): False,
        }

        evenement = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: Constantes.EVENEMENT_MESSAGE_EVENEMENT,
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: self.get_nom_domaine(),
            Constantes.EVENEMENT_MESSAGE_UNSET: unset_champs,
            Constantes.EVENEMENT_MESSAGE_EVENEMENTS: champs,
        }

        domaine_commande = 'commande.%s.transactionReset' % self.get_nom_domaine()

        # self._contexte.message_dao.transmettre_message(evenement, domaine_commande)
        self._contexte.generateur_transactions.emettre_message(evenement, domaine_commande, exchanges=[Constantes.SECURITE_SECURE])

    def declencher_backup_quotidien(self, declencheur: dict):
        jour = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_JOUR], tz=datetime.timezone.utc)
        domaine = declencheur[ConstantesBackup.LIBELLE_DOMAINE]
        uuid_rapport = declencheur[ConstantesBackup.CHAMP_UUID_RAPPORT]
        self.__logger.info("Declencher backup quotidien pour domaine %s, uuid_rapport %s, jour %s" % (
            domaine, uuid_rapport, str(jour)))
        self.handler_backup.creer_backup_quoditien(self.get_nom_domaine(), jour, uuid_rapport)

    def declencher_backup_annuel(self, declencheur: dict):
        annee = datetime.datetime.fromtimestamp(declencheur[ConstantesBackup.LIBELLE_ANNEE], tz=datetime.timezone.utc)
        domaine = declencheur[ConstantesBackup.LIBELLE_DOMAINE]
        uuid_rapport = declencheur[ConstantesBackup.CHAMP_UUID_RAPPORT]
        self.__logger.info("Declencher backup annuel pour domaine %s, uuid_rapport %s, annee %s" % (
            domaine, uuid_rapport, str(annee)))
        self.__handler_backup.creer_backup_annuel(self.get_nom_domaine(), annee, uuid_rapport)

    def declencher_backup_snapshot(self, declencheur: dict):
        # domaine = self.get_nom_domaine()
        # self.__logger.info("Declencher backup snapshot pour domaine %s" % domaine)
        # routing = domaine
        # nom_module = 'millegrilles_Domaines'
        # nom_classe = 'BackupSnapshot'
        # processus = "%s:%s:%s" % (routing, nom_module, nom_classe)
        #
        # parametres = {
        # }
        #
        # self.demarrer_processus(processus, parametres)

        # Verifier qu'on ne demande pas un backup de l'heure courante
        uuid_rapport = declencheur[ConstantesBackup.CHAMP_UUID_RAPPORT]
        url_serveur = declencheur.get('urlServeur')

        if url_serveur == '':
            url_serveur = None

        domaine = self.get_nom_domaine()

        self.__logger.info("Declencher backup snapshot pour domaine %s" % domaine)
        routing = domaine
        nom_module = 'millegrilles_Domaines'
        nom_classe = 'BackupSnapshot'
        processus = "%s:%s:%s" % (routing, nom_module, nom_classe)

        parametres = {
            ConstantesBackup.CHAMP_UUID_RAPPORT: uuid_rapport,
            'url_serveur': url_serveur,
        }

        self.demarrer_processus(processus, parametres)

    def declencher_restauration_transactions(self, declencheur: dict, properties):
        domaine = self.get_nom_domaine()
        self.__logger.info("Declencher restauration domaine %s" % domaine)
        routing = domaine
        nom_module = 'millegrilles_Domaines'
        nom_classe = 'RestaurationTransactions'
        processus = "%s:%s:%s" % (routing, nom_module, nom_classe)

        domaine_action = declencheur['en-tete']['domaine']
        action_globale = False
        if domaine_action.split('.')[1] == 'global':
            action_globale = True

        parametres = {
            'domaine_action': domaine_action,
            'global': action_globale,
            'reply_to': properties.reply_to,
            'correlation_id': properties.correlation_id,
        }
        parametres.update(declencheur)

        self.demarrer_processus(processus, parametres)

    def filtrer_champs_document(self, document, retirer: list = None):
        """
        Enleve les champs internes (qui commencent pas un _), exception _mg-libelle
        :param document:
        :return:
        """
        document_filtre = dict()
        if not retirer:
            retirer = list()

        for key, value in document.items():
            if not key.startswith('_') and key not in retirer or key == Constantes.DOCUMENT_INFODOC_LIBELLE:
                document_filtre[key] = value

        return document_filtre

    def _preparer_handler_backup(self):
        return HandlerBackupDomaine(self._contexte, self.get_nom_domaine(), self.get_collection_transaction_nom(),
                                    self.get_collection())

    @property
    def handler_backup(self):
        return self.__handler_backup


class TraitementRequetesNoeuds(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        enveloppe_certificat = self.gestionnaire.validateur_message.verifier(message_dict)
        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))

        reponse = self.traiter_requete(ch, method, properties, body, message_dict)

        # Genere message reponse
        self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)

    def traiter_requete(self, ch, method, properties, body, message_dict):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        enveloppe_certificat = self.gestionnaire.validateur_message.verifier(message_dict)

        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))
        resultats = list()
        for requete in message_dict['requetes']:
            resultat = self.executer_requete(requete)
            resultats.append(resultat)

        return resultats

    def executer_requete(self, requete):
        self._logger.debug("Requete: %s" % str(requete))
        collection = self.document_dao.get_collection(self._gestionnaire.get_nom_collection())
        filtre = requete.get('filtre')
        projection = requete.get('projection')
        sort_params = requete.get('sort')

        if projection is None:
            curseur = collection.find(filtre)
        else:
            curseur = collection.find(filtre, projection)

        curseur.limit(2500)  # Mettre limite sur nombre de resultats

        if sort_params is not None:
            curseur.sort(sort_params)

        resultats = list()
        for resultat in curseur:
            resultats.append(resultat)

        self._logger.debug("Resultats: %s" % str(resultats))

        return resultats

    def transmettre_reponse(self, requete, resultats, replying_to, correlation_id=None):
        # enveloppe_val = generateur.soumettre_transaction(requete, 'millegrilles.domaines.Principale.creerAlerte')
        if correlation_id is None:
            correlation_id = requete[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        message_resultat = {
            'resultats': resultats,
        }

        self.gestionnaire.generateur_transactions.transmettre_reponse(message_resultat, replying_to, correlation_id)


class ExchangeRouter:
    """
    Classe qui permet de determiner sur quel echange le document doit etre soumis
    """

    def __init__(self, contexte: ContexteRessourcesMilleGrilles):
        self.__contexte = contexte

        self._exchange_public = self.__contexte.configuration.exchange_public
        self._exchange_prive = self.__contexte.configuration.exchange_prive
        self._exchange_protege = self.__contexte.configuration.exchange_noeuds
        self._exchange_secure = self.__contexte.configuration.exchange_middleware

    def determiner_exchanges(self, document: dict) -> list:
        """
        :return: Liste des echanges sur lesquels le document doit etre soumis
        """
        return [self._exchange_protege]


class WatcherCollectionMongoThread:
    """
    Ecoute les changements sur une collection MongoDB et transmet les documents complets sur RabbitMQ.
    """

    def __init__(
            self,
            contexte: ContexteRessourcesDocumentsMilleGrilles,
            stop_event: Event,
            nom_collection_mongo: str,
            routing_key: str,
            exchange_router: ExchangeRouter,
    ):
        """
        :param contexte:
        :param stop_event: Stop event utilise par le gestionnaire.
        :param nom_collection_mongo:
        :param routing_key:
        :param exchange_router: Permet de determiner quels documents vont sur les echanges proteges, prives et publics.
        """
        self.__logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__contexte = contexte
        self.__stop_event = stop_event
        self.__nom_collection_mongo = nom_collection_mongo
        self.__routing_key = routing_key

        self.__exchange_router = exchange_router
        if self.__exchange_router is None:
            self.__exchange_router = ExchangeRouter(contexte)

        self.__collection_mongo = None
        self.__thread = None
        self.__curseur_changements = None

    def start(self):
        self.__logger.info("Demarrage thread watcher:%s vers routing:%s" % (
            self.__nom_collection_mongo, self.__routing_key))
        self.__thread = Thread(name="DocWatcher", target=self.run, daemon=True)
        self.__thread.start()

    def stop(self):
        try:
            self.__curseur_changements.close()
        except AttributeError:
            pass

    def run(self):
        self.__logger.info("Thread watch: %s" % self.__nom_collection_mongo)

        # Boucler tant que le stop event n'est pas active
        while not self.__stop_event.isSet():
            if self.__curseur_changements is not None:
                try:
                    change_event = self.__curseur_changements.next()
                    self.__logger.debug("Watcher event recu: %s" % str(change_event))

                    operation_type = change_event['operationType']
                    if operation_type in ['insert', 'update', 'replace']:
                        full_document = change_event['fullDocument']
                        self._emettre_document(full_document)
                    elif operation_type == 'invalidate':
                        # Curseur ferme
                        self.__logger.warning("Curseur watch a ete invalide, on le ferme.\n%s" % str(change_event))
                        self.__curseur_changements = None
                    elif operation_type in ['delete', 'drop', 'rename']:
                        pass
                    elif operation_type == 'dropDatabase':
                        self.__logger.error("Drop database event : %s" % str(change_event))
                    else:
                        self.__logger.debug("Evenement non supporte: %s" % operation_type)
                        self.__stop_event.wait(0.5)  # Attendre 0.5 secondes, throttle
                except StopIteration:
                    self.__logger.info("Arret watcher dans l'iteration courante")
                    self.__curseur_changements = None
                except Exception:
                    self.__logger.exception("Erreur dans le traitement du watcher")
                    self.__stop_event.wait(1)  # Attendre 1 seconde, throttle

            else:
                self.__stop_event.wait(5)  # Attendre 5 secondes, throttle
                self.__logger.info("Creer pipeline %s" % self.__nom_collection_mongo)
                self._creer_pipeline()

    def _creer_pipeline(self):
        collection_mongo = self.__contexte.document_dao.get_collection(self.__nom_collection_mongo)

        # Tenter d'activer watch par _id pour les documents
        try:
            option = {'full_document': 'updateLookup', 'max_await_time_ms': 1000}
            pipeline = []
            logging.info("Pipeline watch: %s" % str(pipeline))
            self.__curseur_changements = collection_mongo.watch(pipeline, **option)

        except OperationFailure as opf:
            self.__logger.warning("Erreur activation watch, on fonctionne par timer: %s" % str(opf))
            self.__curseur_changements = None

    def _emettre_document(self, document):
        self.__logger.debug("Watcher document recu: %s" % str(document))

        # Ajuster la routing key pour ajouter information si necessaire.
        routing_key = self.__routing_key
        exchanges = self.__exchange_router.determiner_exchanges(document)
        mg_libelle = document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
        if mg_libelle is not None:
            # Remplacer separateurs . par _ pour creer routing key dans MQ
            doc_type = mg_libelle.replace('.', '_')
            routing_key = '%s.%s' % (routing_key, doc_type)

        # Transmettre document sur MQ
        self.__contexte.generateur_transactions.emettre_message(document, routing_key, exchanges)


class TraiteurRequeteDomaineNoeud:
    """
    Execute les requetes faites par les noeuds sur le topic domaine._domaine_.requete.noeud
    """

    def __init__(self):
        pass


class RegenerateurDeDocuments:
    """
    Efface et regenere les /documents d'un domaine.
    """

    def __init__(self, gestionnaire_domaine):
        self._gestionnaire_domaine = gestionnaire_domaine
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self._transactions_resumer = dict()  # Transactions a resumer

    @property
    def contexte(self):
        return self._gestionnaire_domaine.contexte

    def ajouter_transaction_resumer(self, token, transaction):
        self._transactions_resumer[token] = transaction

    def consommer_transaction_resumer(self, token_resumer: str):
        """
        Retourner une transaction qui correspond au token. Supprime la reference.

        :param token_resumer:
        :return:
        """
        transaction = self._transactions_resumer.get(token_resumer)
        if transaction:
            del self._transactions_resumer[token_resumer]

        return transaction

    def supprimer_documents(self):
        """
        Supprime les documents de la collection
        :return:
        """
        collections_documents = self._gestionnaire_domaine.get_collections_documents

        for nom_collection_documents in collections_documents:
            self.__logger.info("Supprimer les documents de %s" % nom_collection_documents)
            collection_documents = self._gestionnaire_domaine.get_collection_par_nom(nom_collection_documents)
            collection_documents.delete_many({})

    def creer_generateur_transactions(self, document_regeneration: dict = None):
        return GroupeurTransactionsARegenerer(self._gestionnaire_domaine, document_regeneration=document_regeneration)


class RegenerateurDeDocumentsSansEffet(RegenerateurDeDocuments):
    """
    Empeche la regeneration d'un domaine
    """

    def supprimer_documents(self):
        pass

    def creer_generateur_transactions(self):
        return GroupeurTransactionsSansEffet()


class GroupeurTransactionsARegenerer:
    """
    Classe qui permet de grouper les transactions d'un domaine pour regenerer les documents.
    Groupe toutes les transactions dans un seul groupe, en ordre de transaction_traitee.
    """

    def __init__(self, gestionnaire_domaine: GestionnaireDomaine, transactions_a_ignorer: list = None, document_regeneration: dict = None):
        """

        :param gestionnaire_domaine:
        :param transactions_a_ignorer: Liste de transactions a ingorer pour regenerer ce domaine.
        """
        self.__gestionnaire_domaine = gestionnaire_domaine
        self.__transactions_a_ignorer = transactions_a_ignorer
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
        self.__complet = False
        self.__document_regeneration = document_regeneration
        self.__nombre_transactions = None
        self.__index_transaction_courante = 0

    def __preparer_curseur_transactions(self):
        nom_collection_transaction = self.__gestionnaire_domaine.get_collection_transaction_nom()
        self.__logger.debug('Preparer curseur transactions sur %s' % nom_collection_transaction)

        collection_transactions = self.__gestionnaire_domaine.document_dao.get_collection(nom_collection_transaction)

        filtre, index = self.__preparer_requete()

        self.__nombre_transactions = collection_transactions.find(filtre).count()

        return collection_transactions.find(filtre).sort(index).hint(index)

    def __preparer_requete(self):
        # Parcourir l'index:
        #  - _evenements.transaction_complete
        #  - _evenements.IDMGtransaction_traitee
        index = [
            ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                        Constantes.EVENEMENT_TRANSACTION_COMPLETE), 1),
            ('%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                           Constantes.EVENEMENT_TRANSACTION_TRAITEE), 1)
        ]

        # Filtre par transaction completee:
        #  - _evenements.transaction_complete = True
        #  - _evenements.IDMG.transaction_traitee existe
        filtre = {
            '$or': [
                {
                    '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                               Constantes.EVENEMENT_TRANSACTION_COMPLETE): True,
                    '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                                  Constantes.EVENEMENT_TRANSACTION_TRAITEE): {'$exists': True}
                },
                {
                    '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT,
                                  Constantes.EVENEMENT_TRANSACTION_BACKUP_RESTAURE): {'$exists': True}
                }
            ],
        }

        if self.__document_regeneration is not None:
            # Ajouter la date de la derniere transaction regeneree comme point de depart
            completee = self.__document_regeneration['complete'] or False
            if completee:
                op = '$gt'
            else:
                op = '$gte'
            date_transaction = self.__document_regeneration['date_traitement']
            filtre[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT + '.' + Constantes.EVENEMENT_TRANSACTION_TRAITEE] = {op: date_transaction}

        if self.__transactions_a_ignorer:
            # Ajouter une liste de transactions a ignorer pour la regeneration
            # Ces transactions n'ont aucun impact sur l'etat des /documents
            libelle_domaine = '%s.%s' % (Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE)
            filtre[libelle_domaine] = {'$nin': self.__transactions_a_ignorer}

        return filtre, index

    def __iter__(self):
        return self.__next__()

    def __next__(self):
        """
        Retourne un curseur Mongo avec les transactions a executer en ordre.
        :return:
        """
        if self.__complet:
            raise StopIteration()

        curseur = self.__preparer_curseur_transactions()
        for valeur in curseur:
            # self.__logger.debug("Transaction: %s" % str(valeur))
            self.__index_transaction_courante = self.__index_transaction_courante + 1
            yield valeur

        self.__complet = True

        return

    @property
    def gestionnaire(self):
        return self.__gestionnaire_domaine

    @property
    def _complet(self):
        return self.__complet

    @property
    def nombre_transactions(self):
        return self.__nombre_transactions

    @property
    def index_transaction_courante(self):
        return self.__index_transaction_courante


class GroupeurTransactionsSansEffet:

    def __init__(self):
        self.__complete = True

    def __iter__(self):
        return self

    def __next__(self):
        if self.__complete:
            raise StopIteration()

        self.__complete = True
        return


class TransactionTypeInconnuError(Exception):

    def __init__(self, msg, routing_key=None):
        if routing_key is not None:
            msg = '%s: %s' % (msg, routing_key)
        super().__init__(msg)
        self.routing_key = routing_key


class BackupHoraire(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        self.__logger.info("Processus backup horaire demarre, %s" % str(self.parametres))
        domaine_action = Constantes.ConstantesMaitreDesCles.DOMAINE_NOM + '.' + Constantes.ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        self.set_requete(domaine_action, dict())
        self.set_etape_suivante(BackupHoraire.executer_backup.__name__)

    def executer_backup(self):
        uuid_rapport = self.parametres[ConstantesBackup.CHAMP_UUID_RAPPORT]
        info_cles = self.parametres['reponse'][0]
        heure = pytz.utc.localize(self.parametres[ConstantesBackup.LIBELLE_HEURE])

        gestionnaire = self.controleur.gestionnaire
        gestionnaire.handler_backup.backup_horaire_domaine(uuid_rapport, heure, info_cles)

        self.set_etape_suivante(BackupHoraire.executer_snapshot.__name__)

        return dict()

    def executer_snapshot(self):
        """
        Optionnel, fait un backup snapshot de toutes les transactions qui n'ont pas ete inclues dans le backup horaire
        :return:
        """
        uuid_rapport = self.parametres[ConstantesBackup.CHAMP_UUID_RAPPORT]
        gestionnaire = self.controleur.gestionnaire
        info_cles = self.parametres['reponse'][0]

        date_courante = datetime.datetime.utcnow()

        # S'assurer que les backup cedules sont deja executes
        gestionnaire.handler_backup.backup_horaire_domaine(uuid_rapport, date_courante, info_cles, snapshot=False)

        # Completer avec le backup snapshot (ne sera pas conserve de facon permanente)
        gestionnaire.handler_backup.backup_horaire_domaine(uuid_rapport, date_courante, info_cles, snapshot=True)

        self.set_etape_suivante()  # Termine

        return dict()


class BackupSnapshot(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        self.__logger.info("Processus backup snapshot demarre, %s" % str(self.parametres))
        domaine_action = Constantes.ConstantesMaitreDesCles.DOMAINE_NOM + '.' + Constantes.ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        self.set_requete(domaine_action, dict())
        self.set_etape_suivante(BackupHoraire.executer_backup.__name__)

    def executer_backup(self):
        uuid_rapport = self.parametres[ConstantesBackup.CHAMP_UUID_RAPPORT]
        url_serveur = self.parametres['url_serveur']
        gestionnaire = self.controleur.gestionnaire
        info_cles = self.parametres['reponse'][0]

        date_courante = datetime.datetime.utcnow()

        # S'assurer que tous les backups cedules sont executes
        gestionnaire.handler_backup.backup_horaire_domaine(uuid_rapport, date_courante, info_cles, snapshot=False, url_serveur=url_serveur)

        # Executer le backup snapshot (ne sera pas conserve de maniere permanente)
        gestionnaire.handler_backup.backup_horaire_domaine(uuid_rapport, date_courante, info_cles, snapshot=True, url_serveur=url_serveur)

        self.set_etape_suivante()  # Termine

        return dict()


class RestaurationTransactions(MGProcessus):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        self.__logger.info("Processus restauration domaine demarre, %s" % str(self.parametres))
        gestionnaire = self.controleur.gestionnaire
        nom_domaine = gestionnaire.get_nom_domaine()
        configuration = self.controleur.configuration

        hostname_fichiers = self.parametres.get('url_serveur')
        if hostname_fichiers is None or hostname_fichiers == '':
            host = self.controleur.configuration.serveur_consignationfichiers_host
            port = self.controleur.configuration.serveur_consignationfichiers_port
            hostname_fichiers = 'https://' + host + ':' + str(port)

        resultat_execution = False
        try:
            evenement_debut_restauration = {
                'evenement': 'debut_restauration',
                'url_serveur': hostname_fichiers,
                'domaine': nom_domaine,
            }
            self.emettre_evenement_restauration(evenement_debut_restauration)

            url = '%s/backup/restaurerDomaine/%s' % (hostname_fichiers, nom_domaine)
            cacert = configuration.mq_cafile
            certkey = (configuration.mq_certfile, configuration.mq_keyfile)
            resultat = requests.get(url, verify=cacert, cert=certkey, stream=True, timeout=30)
            self.__logger.debug("restaurerDomaines: Response code : %d" % resultat.status_code)

            if resultat.status_code == 200:
                # Reponse "initiale" - permet d'executer le traitement de manier asynchrone cote client
                self.transmettre_reponse({'evenement': 'restauration_demarree', 'domaine': nom_domaine})
                self.emettre_evenement_restauration({'evenement': 'debut_restauration', 'domaine': nom_domaine})

                parser = ArchivesBackupParser(
                    self.controleur.contexte
                    # resultat.iter_content(chunk_size=10 * 1024)
                )

                # parser.start().wait(30)
                event_attente = parser.start(stream=resultat.iter_content(chunk_size=10 * 1024))
                event_attente.wait(240)  # Donner 4 minutes pour traiter le domaine
                resultat_execution = event_attente.is_set()

            evenement_fin_restauration = {
                'evenement': 'fin_restauration',
                'domaine': nom_domaine,
                'execution_complete': resultat_execution,
                # 'ok': True,
            }
            if resultat_execution is False:
                evenement_fin_restauration['ok'] = False
                evenement_fin_restauration['evenement'] = 'restauration_annulee'
                evenement_fin_restauration['code'] = resultat.status_code
                evenement_fin_restauration['err'] = resultat.text
            self.emettre_evenement_restauration(evenement_fin_restauration)
            self.set_etape_suivante()  # Termine
        finally:
            # Conserver resultat, arreter traitement si erreur
            reponse = {
                'transactions_restaurees': resultat_execution,
            }

            if resultat_execution is True:
                # Regenerer les documents du domaine
                if self.parametres['global'] is True and self.controleur.gestionnaire.supporte_regenerer_global is False:
                    self.__logger.info("Skip regeneration globale")
                    reponse['evenement'] = 'restauration_terminee'
                    reponse['documents_regeneres'] = False
                    self.transmettre_reponse(reponse)
                    self.emettre_evenement_restauration({
                        'evenement': 'fin_regeneration',
                        'domaine': nom_domaine,
                        'documents_regeneres': True,
                        'ok': True,
                    })

                    self.set_etape_suivante()  # Termine
                else:
                    self.set_etape_suivante()  # Termine
                    #self.set_etape_suivante(RestaurationTransactions.regenerer.__name__)
                    #reponse['regeneration'] = True

            else:
                reponse['evenement'] = 'restauration_annulee'
                reponse['err'] = {'code': 1, 'message': 'Echec de restauration'}
                reponse['ok'] = False
                self.transmettre_reponse(reponse)

        return reponse

    def regenerer(self):
        self.emettre_evenement_restauration({
            'evenement': 'debut_regeneration',
        })

        erreur = None
        try:
            self.controleur.gestionnaire.regenerer_documents()

            self.emettre_evenement_restauration({
                'evenement': 'fin_regeneration',
                'documents_regeneres': True,
            })
        except Exception as e:
            erreur = {'code': 2, 'message': str(e)}
            self.emettre_evenement_restauration({
                'evenement': 'fin_regeneration',
                'documents_regeneres': True,
                'err': erreur
            })

        reponse = {
            'evenement': 'restauration_terminee',
            'transactions_restaurees': self.parametres['transactions_restaurees'],
            'documents_regeneres': True,
        }
        if erreur is not None:
            reponse['documents_regeneres'] = False
            reponse['err'] = erreur

        self.transmettre_reponse(reponse)

        self.set_etape_suivante()  # Termine

    def emettre_evenement_restauration(self, event: dict):
        """
        Emet un evenement pour indiquer a quelle etape de restauration on est rendu
        :param event:
        :return:
        """
        domaine_action = 'evenement.Backup.' + ConstantesBackup.EVENEMENT_BACKUP_RESTAURATION_MAJ
        event['domaine'] = self.controleur.gestionnaire.get_nom_domaine()
        self.controleur.generateur_transactions.emettre_message(event, domaine_action, exchanges=[Constantes.SECURITE_PROTEGE])

    def transmettre_reponse(self, reponse: dict):
        reply_q = self.parametres['reply_to']
        correlation_id = self.parametres['correlation_id']
        self.controleur.generateur_transactions.transmettre_reponse(reponse, reply_q, correlation_id)
