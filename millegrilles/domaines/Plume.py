# Domaine Plume - ecriture de documents
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaine
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import MGProcessus, MGProcessusTransaction
from millegrilles.dao.DocumentDAO import MongoJSONEncoder

import logging
import datetime


class ConstantesPlume:

    DOMAINE_NOM = 'millegrilles.domaines.Plume'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    TRANSACTION_NOUVEAU_DOCUMENT = 'nouveauDocument'
    TRANSACTION_MODIFIER_DOCUMENT = 'modifierDocument'
    TRANSACTION_SUPPRIMER_DOCUMENT = 'supprimerDocument'

    DOCUMENT_PLUME_UUID = 'uuid'
    DOCUMENT_SECURITE = 'securite'
    DOCUMENT_TITRE = 'titre'
    DOCUMENT_CATEGORIES = 'categories'
    DOCUMENT_TEXTE = 'texte'
    DOCUMENT_QUILL_DELTA = 'quilldelta'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_PLUME = 'plume'

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_PLUME = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_PLUME,
        DOCUMENT_PLUME_UUID: None,  # Identificateur unique du document plume
        DOCUMENT_SECURITE: Constantes.SECURITE_PRIVE,       # Niveau de securite
        DOCUMENT_TITRE: None,                               # Titre
        DOCUMENT_CATEGORIES: None,                          # Nom du fichier (libelle affiche a l'usager)
        DOCUMENT_QUILL_DELTA: None,                         # Contenu, delta Quill
        DOCUMENT_TEXTE: None,                               # Texte sans formattage
    }


class GestionnairePlume(GestionnaireDomaine):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        nom_millegrille = contexte.configuration.nom_millegrille

        # Queue message handlers
        self.__handler_transaction = None
        self.__handler_cedule = None
        self.__handler_requetes_noeuds = None

        self.generateur = self.contexte.generateur_transactions

    def configurer(self):
        super().configurer()

        collection_domaine = self.document_dao.get_collection(ConstantesPlume.COLLECTION_DOCUMENTS_NOM)
        # Index noeud, _mg-libelle
        collection_domaine.create_index([
            (ConstantesPlume.DOCUMENT_CATEGORIES, 1)
        ])
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        ])
        collection_domaine.create_index([
            (ConstantesPlume.DOCUMENT_PLUME_UUID, 1)
        ])
        collection_domaine.create_index([
            (ConstantesPlume.DOCUMENT_TITRE, 1)
        ])
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1)
        ])
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, 1)
        ])

        self.initialiser_document(ConstantesPlume.LIBVAL_CONFIGURATION, ConstantesPlume.DOCUMENT_DEFAUT)

    def setup_rabbitmq(self, channel):

        # Queue message handlers
        self.__handler_transaction = TraitementTransactionPersistee(self)
        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_requetes_noeuds = TraitementRequetesNoeuds(self)

        nom_queue_transactions = '%s.%s' % (self.get_nom_queue(), 'transactions')
        nom_queue_ceduleur = '%s.%s' % (self.get_nom_queue(), 'ceduleur')
        nom_queue_processus = '%s.%s' % (self.get_nom_queue(), 'processus')
        nom_queue_requetes_noeuds = '%s.%s' % (self.get_nom_queue(), 'requete.noeuds')

        # Configurer la Queue pour les transactions
        def callback_init_transaction(queue, self=self, callback=self.__handler_transaction.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_transactions,
                routing_key='destinataire.domaine.%s.#' % self.get_nom_queue(),
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_transactions,
            durable=False,
            callback=callback_init_transaction,
        )

        # Configuration la queue pour le ceduleur
        def callback_init_cedule(queue, self=self, callback=self.__handler_cedule.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_ceduleur,
                routing_key='ceduleur.#',
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_ceduleur,
            durable=False,
            callback=callback_init_cedule,
        )

        # Queue pour les processus
        def callback_init_processus(queue, self=self, callback=self.traitement_evenements.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_middleware,
                queue=nom_queue_processus,
                routing_key='processus.domaine.%s.#' % ConstantesPlume.DOMAINE_NOM,
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_processus,
            durable=False,
            callback=callback_init_processus,
        )

        # Queue pour les requetes de noeuds
        def callback_init_requetes_noeuds(queue, self=self, callback=self.__handler_requetes_noeuds.callbackAvecAck):
            self.inscrire_basicconsume(queue, callback)
            channel.queue_bind(
                exchange=self.configuration.exchange_noeuds,
                queue=nom_queue_requetes_noeuds,
                routing_key='requete.%s.#' % ConstantesPlume.DOMAINE_NOM,
                callback=None,
            )

        channel.queue_declare(
            queue=nom_queue_requetes_noeuds,
            durable=False,
            callback=callback_init_requetes_noeuds,
        )

    def ajouter_nouveau_document(self, transaction):
        document_plume = ConstantesPlume.DOCUMENT_PLUME.copy()

        document_plume[ConstantesPlume.DOCUMENT_PLUME_UUID] = \
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        document_plume[ConstantesPlume.DOCUMENT_SECURITE] = transaction[ConstantesPlume.DOCUMENT_SECURITE]
        document_plume[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = datetime.datetime.utcnow()
        document_plume[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = datetime.datetime.utcnow()

        self.__map_transaction_vers_document(transaction, document_plume)

        collection_domaine = self.contexte.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.insert_one(document_plume)

    def modifier_document(self, transaction):
        document_plume = dict()
        self.__map_transaction_vers_document(transaction, document_plume)
        operations = {
            '$set': document_plume,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        filtre = {
            ConstantesPlume.DOCUMENT_PLUME_UUID: transaction[ConstantesPlume.DOCUMENT_PLUME_UUID]
        }

        collection_domaine = self.contexte.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre, operations)

    def supprimer_document(self, transaction):
        filtre = {
            ConstantesPlume.DOCUMENT_PLUME_UUID: transaction[ConstantesPlume.DOCUMENT_PLUME_UUID]
        }
        collection_domaine = self.contexte.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.delete_one(filtre)

    def __map_transaction_vers_document(self, transaction, document_plume):
        document_plume[ConstantesPlume.DOCUMENT_TITRE] = transaction[ConstantesPlume.DOCUMENT_TITRE]
        document_plume[ConstantesPlume.DOCUMENT_TEXTE] = transaction[ConstantesPlume.DOCUMENT_TEXTE]
        document_plume[ConstantesPlume.DOCUMENT_QUILL_DELTA] = transaction[ConstantesPlume.DOCUMENT_QUILL_DELTA]
        categories_string = transaction[ConstantesPlume.DOCUMENT_CATEGORIES]
        if categories_string is not None:
            categories = categories_string.split(' ')
            document_plume[ConstantesPlume.DOCUMENT_CATEGORIES] = categories

    def publier_document(self, uuid_document):
        pass

    def get_nom_queue(self):
        return ConstantesPlume.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesPlume.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesPlume.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPlume.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesPlume.DOMAINE_NOM


class TraitementMessageCedule(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementTransactionPersistee(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        # Verifier quel processus demarrer.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'destinataire.domaine.%s.' % ConstantesPlume.DOMAINE_NOM,
            ''
        )

        # Actions
        if routing_key_sansprefixe == ConstantesPlume.TRANSACTION_NOUVEAU_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionAjouterDocumentPlume"
        elif routing_key_sansprefixe == ConstantesPlume.TRANSACTION_MODIFIER_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionModifierDocumentPlume"
        elif routing_key_sansprefixe == ConstantesPlume.TRANSACTION_SUPPRIMER_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionSupprimerDocumentPlume"
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))

        self._gestionnaire.demarrer_processus(processus, message_dict)


class TraitementRequetesNoeuds(BaseCallback):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


# ******************* Processus *******************
class ProcessusPlume(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesPlume.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPlume.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionAjouterDocumentPlume(ProcessusPlume):
    """
    Processus de d'ajout de nouveau document Plume
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Sauvegarder une nouvelle version d'un fichier """
        transaction = self.charger_transaction()
        self._controleur._gestionnaire_domaine.ajouter_nouveau_document(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusTransactionModifierDocumentPlume(ProcessusPlume):
    """
    Processus de modification de document Plume
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()
        self._controleur._gestionnaire_domaine.modifier_document(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusTransactionSupprimerDocumentPlume(ProcessusPlume):
    """
    Processus de modification de document Plume
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Supprimer le document """
        transaction = self.charger_transaction()
        self._controleur._gestionnaire_domaine.supprimer_document(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusTransactionPublierVersionDocumentPlume(ProcessusPlume):
    """
    Processus de publication d'une version de document Plume
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()

        self.set_etape_suivante()  # Termine

