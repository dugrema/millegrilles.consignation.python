from millegrilles import Constantes
from millegrilles.Constantes import ConstantesBackup
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete
from millegrilles.MGProcessus import MGProcessusTransaction

import logging


class TraitementRequetesProtegees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_routing_key = method.routing_key.replace('requete.', '')


class TraitementRequetesPubliques(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_routing_key = method.routing_key.replace('requete.', '')


class GestionnaireBackup(GestionnaireDomaineStandard):
    """
    Gestionnaire du domaine de backup
    """

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliques(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegees(self),
        }

    def configurer(self):
        super().configurer()

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(ConstantesPki.LIBVAL_CONFIGURATION, ConstantesPki.DOCUMENT_DEFAUT)

    def get_queue_configuration(self):
        configuration = super().get_queue_configuration()

        return configuration

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

    def get_nom_queue(self):
        return ConstantesBackup.QUEUE_NOM

    def get_nom_queue_certificats(self):
        return ConstantesBackup.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesBackup.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesBackup.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesBackup.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesBackup.DOMAINE_NOM

    def identifier_processus(self, domaine_transaction):
        # if domaine_transaction == ConstantesBackup.TRANSACTION_DOMAINE_NOUVEAU_CERTIFICAT:
        #     processus = "millegrilles_domaines_Pki:ProcessusAjouterCertificat"
        # else:
        #     processus = super().identifier_processus(domaine_transaction)

        processus = super().identifier_processus(domaine_transaction)

        return processus


class ProcessusBackupHoraire(MGProcessusTransaction):

    def initiale(self):
        transaction = self.charger_transaction()
