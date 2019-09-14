# Domaine de gestion et d'administration de MilleGrilles
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesNoeuds
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.MGProcessus import  MGProcessusTransaction

import logging
import datetime


class ConstantesParametres:

    DOMAINE_NOM = 'millegrilles.domaines.Parametres'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    TRANSACTION_NOUVEAU_DOCUMENT = 'nouveauDocument'

    DOCUMENT_CHAMP_COURRIEL_ORIGINE = 'origine'
    DOCUMENT_CHAMP_COURRIEL_DESTINATIONS = 'destinations'
    DOCUMENT_CHAMP_HOST = 'host'
    DOCUMENT_CHAMP_PORT = 'port'
    DOCUMENT_CHAMP_USER = 'user'
    DOCUMENT_CHAMP_PASSWORD = 'password'

    DOCUMENT_CHAMP_ACTIF = 'actif'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_EMAIL_SMTP = 'email.stmp'
    LIBVAL_VERSIONS_IMAGES_DOCKER = 'versions.images.docker'
    LIBVAL_CERTS_WEB = 'certs.web'
    LIBVAL_CERTS_SSL = 'certs.ssl'

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_EMAIL_SMTP = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_EMAIL_SMTP,
        DOCUMENT_CHAMP_ACTIF: False,
        DOCUMENT_CHAMP_COURRIEL_ORIGINE: None,
        DOCUMENT_CHAMP_COURRIEL_DESTINATIONS: None,
        DOCUMENT_CHAMP_HOST: None,
        DOCUMENT_CHAMP_PORT: None,
        DOCUMENT_CHAMP_USER: None,
        Constantes.DOCUMENT_SECTION_CRYPTE: None,  # DOCUMENT_CHAMP_PASSWORD
    }


class GestionnaireParametres(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)

        # Queue message handlers
        self.__handler_transaction = TraitementTransactionPersistee(self)
        self.__handler_cedule = TraitementMessageCedule(self)
        self.__handler_requetes_noeuds = TraitementRequetesNoeuds(self)

        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def configurer(self):
        super().configurer()
        self.initialiser_document(ConstantesParametres.LIBVAL_CONFIGURATION, ConstantesParametres.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesParametres.LIBVAL_EMAIL_SMTP, ConstantesParametres.DOCUMENT_EMAIL_SMTP)

    def setup_rabbitmq(self, channel):
        super().setup_rabbitmq(channel)

    def modifier_document_email_smtp(self, transaction):
        document_email_smtp = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: datetime.datetime.utcnow()
        }
        self.map_transaction_vers_document(transaction, document_email_smtp)  # Copier champs transaction vers doc

        operations = {
            '$set': document_email_smtp,
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_EMAIL_SMTP
        }

        collection_domaine = self.contexte.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre, operations)

        return document_email_smtp

    def get_nom_queue(self):
        return ConstantesParametres.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesParametres.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesParametres.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesParametres.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesParametres.DOMAINE_NOM

    def get_handler_transaction(self):
        return self.__handler_transaction

    def get_handler_cedule(self):
        return self.__handler_cedule

    def get_handler_requetes_noeuds(self):
        return self.__handler_requetes_noeuds


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
            'destinataire.domaine.%s.' % ConstantesParametres.DOMAINE_NOM,
            ''
        )

        # Actions
        if routing_key_sansprefixe == ConstantesParametres.TRANSACTION_NOUVEAU_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionAjouterDocumentPlume"
        else:
            raise ValueError("Type de transaction inconnue: routing: %s, message: %s" % (routing_key, evenement))

        self._gestionnaire.demarrer_processus(processus, message_dict)


# ******************* Processus *******************
class ProcessusParametres(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesParametres.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesParametres.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionModifierDocumentDomaine(ProcessusParametres):
    """
    Processus de modification de document Plume
    """

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()
        document_email_smtp = self._controleur._gestionnaire_domaine.modifier_document_email_smtp(transaction)
        self.set_etape_suivante()  # Termine

        return {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document_email_smtp[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }
