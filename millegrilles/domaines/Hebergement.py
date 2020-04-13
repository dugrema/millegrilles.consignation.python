# Domaine d'hebergemenet de MilleGrilles par un hote
import logging
import datetime

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesHebergement
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, \
    TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessusTransaction


class TraitementRequetesProtegees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        super().traiter_requete(ch, method, properties, body, message_dict)


class TraitementCommandesHebergementProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key

        resultat = None
        if routing_key == 'commande.%s.%s' % (ConstantesHebergement.DOMAINE_NOM, ConstantesHebergement.COMMANDE_SIGNER_CLE_BACKUP):
            resultat = self.gestionnaire.signer_cle_backup(properties, message_dict)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class GestionnaireHebergement(GestionnaireDomaineStandard):
    """
    Gestionnaire du domaine de l'hebergement de MilleGrilles
    """

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegees(self),
        }

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(ConstantesPki.LIBVAL_CONFIGURATION, ConstantesPki.DOCUMENT_DEFAUT)

    def get_nom_queue(self):
        return ConstantesHebergement.QUEUE_NOM

    def get_nom_queue_certificats(self):
        return ConstantesHebergement.QUEUE_NOM

    def get_nom_collection(self):
        return ConstantesHebergement.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesHebergement.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesHebergement.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesHebergement.DOMAINE_NOM

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesHebergement.TRANSACTION_XXX:
            processus = "millegrilles_domaines_Hebergement:ProcessusXXX"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    # --- Operations du domaine ---

    def creer_domaine_heberge(self) -> str:
        """
        Genere un nouveau domaine heberge.
        :return: Le idmg du nouveau
        """


class ProcessusXXX(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
