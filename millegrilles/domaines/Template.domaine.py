# Exemple de domaine
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesNoeuds
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import  MGProcessusTransaction

import logging
import datetime


class ConstantesDomaine:

    DOMAINE_NOM = 'millegrilles.domaines.domaine'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    TRANSACTION_NOUVEAU_DOCUMENT = 'nouveauDocument'

    DOCUMENT_DOMAINE_CHAMP = 'champ'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_DOMAINE = 'domaine'

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_DOMAINE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_DOMAINE,
        DOCUMENT_DOMAINE_CHAMP: None,  # Champ du document
    }


class GestionnaireDuDomaine(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)

        # Queue message handlers
        self.__handler_transaction = TraitementTransactionPersistee(self)
        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_requetes_noeuds = TraitementRequetesNoeuds(self)

        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def configurer(self):
        super().configurer()
        self.initialiser_document(ConstantesDomaine.LIBVAL_CONFIGURATION, ConstantesDomaine.DOCUMENT_DEFAUT)

    def setup_rabbitmq(self, channel):
        super().setup_rabbitmq(channel)

    def ajouter_nouveau_document(self, transaction):
        document_domaine = ConstantesDomaine.DOCUMENT_DOMAINE.copy()

        document_domaine[ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP] = \
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        document_domaine[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = datetime.datetime.utcnow()
        document_domaine[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = datetime.datetime.utcnow()

        self.__map_transaction_vers_document(transaction, document_domaine)

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.insert_one(document_domaine)

        return document_domaine

    def modifier_document(self, transaction):
        document_domaine = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: datetime.datetime.utcnow()
        }
        self.__map_transaction_vers_document(transaction, document_domaine)
        operations = {
            '$set': document_domaine,
        }

        filtre = {
            ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP: transaction[ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP]
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre, operations)

        return document_domaine

    def supprimer_document(self, transaction):
        filtre = {
            ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP: transaction[ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP]
        }
        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.delete_one(filtre)

    def __map_transaction_vers_document(self, transaction, document_domaine):
        document_domaine[ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP] = transaction[ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP]

    def get_document(self, uuid_document):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesDomaine.LIBVAL_DOMAINE,
            ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP: uuid_document,
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        document = collection_domaine.find_one(filtre)

        return document

    def get_nom_queue(self):
        return ConstantesDomaine.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesDomaine.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesDomaine.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesDomaine.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesDomaine.DOMAINE_NOM

    def get_handler_transaction(self):
        return self.__handler_transaction

    def get_handler_cedule(self):
        return self.__handler_cedule

    def get_handler_requetes_noeuds(self):
        return self.__handler_requetes_noeuds


class TraitementMessageCedule(BaseCallback):

    def __init__(self, gestionnaire: GestionnaireDomaineStandard):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementTransactionPersistee(BaseCallback):

    def __init__(self, gestionnaire: GestionnaireDomaineStandard):
        super().__init__(gestionnaire.contexte)
        self._gestionnaire = gestionnaire

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        # Verifier quel processus demarrer.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'destinataire.domaine.%s.' % ConstantesDomaine.DOMAINE_NOM,
            ''
        )

        # Actions
        if routing_key_sansprefixe == ConstantesDomaine.TRANSACTION_NOUVEAU_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionAjouterDocumentPlume"
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))

        self._gestionnaire.demarrer_processus(processus, message_dict)


# ******************* Processus *******************
class ProcessusDomaine(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesDomaine.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesDomaine.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionAjouterDocumentDomaine(ProcessusDomaine):
    """
    Processus de d'ajout de nouveau document Plume
    """

    def initiale(self):
        """ Sauvegarder une nouvelle version d'un fichier """
        transaction = self.charger_transaction()
        document_plume = self._controleur._gestionnaire_domaine.ajouter_nouveau_document(transaction)
        self.set_etape_suivante()  # Termine

        return {
            ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP: document_plume[ConstantesDomaine.DOCUMENT_DOMAINE_CHAMP],
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: document_plume[Constantes.DOCUMENT_INFODOC_DATE_CREATION],
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document_plume[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }


class ProcessusTransactionModifierDocumentDomaine(ProcessusDomaine):
    """
    Processus de modification de document Plume
    """

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()
        document_plume = self._controleur._gestionnaire_domaine.modifier_document(transaction)
        self.set_etape_suivante()  # Termine

        return {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document_plume[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }


class ProcessusTransactionSupprimerDocumentDomaine(ProcessusDomaine):
    """
    Processus de modification de document Plume
    """

    def initiale(self):
        """ Supprimer le document """
        transaction = self.charger_transaction()
        self._controleur._gestionnaire_domaine.supprimer_document(transaction)
        self.set_etape_suivante()  # Termine
