import logging

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMaitreDesComptes
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesNoeuds, TraitementCommandesProtegees, \
    TransactionTypeInconnuError


class TraitementRequetesProtegees(TraitementRequetesNoeuds):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesMaitreDesComptes.REQUETE_CHARGER_USAGER:
            reponse = self.gestionnaire.charger_usager(message_dict)
        else:
            # Type de transaction inconnue, on lance une exception
            raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

        return reponse


class TraitementCommandesMaitredesclesProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key

        resultat: dict
        # if routing_key == 'commande.%s.%s' % (ConstantesMaitreDesComptes.DOMAINE_NOM, ConstantesMaitreDesComptes.COMMANDE_SIGNER_CLE_BACKUP):
        #     resultat = self.gestionnaire.AAAA()
        # else:
        #     resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class GestionnaireMaitreDesComptes(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__handler_requetes = {
            Constantes.SECURITE_SECURE: TraitementRequetesProtegees(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegees(self),
        }

        self.__handler_commandes = {
            Constantes.SECURITE_SECURE: TraitementCommandesMaitredesclesProtegees(self),
            Constantes.SECURITE_PROTEGE: TraitementCommandesMaitredesclesProtegees(self),
        }

    def configurer(self):
        super().configurer()

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(ConstantesMaitreDesCles.LIBVAL_CONFIGURATION, ConstantesMaitreDesCles.DOCUMENT_DEFAUT)

    def identifier_processus(self, domaine_transaction):

        if domaine_transaction == ConstantesMaitreDesComptes.TRANSACTION_INSCRIRE_USAGER:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusInscrireUsager"
        elif domaine_transaction == ConstantesMaitreDesComptes.TRANSACTION_AJOUTER_CLE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusAjouterCle"
        elif domaine_transaction == ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_CLES:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerCles"
        elif domaine_transaction == ConstantesMaitreDesComptes.TRANSACTION_MAJ_MOTDEPASSE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusMajMotdepasse"
        elif domaine_transaction == ConstantesMaitreDesComptes.TRANSACTION_SUPPRESSION_MOTDEPASSE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerMotdepasse"
        elif domaine_transaction == ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_USAGER:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerUsager"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_nom_collection(self):
        return ConstantesMaitreDesComptes.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesMaitreDesComptes.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesMaitreDesComptes.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesMaitreDesComptes.DOMAINE_NOM

    def get_nom_queue(self):
        return ConstantesMaitreDesComptes.QUEUE_NOM

    def charger_usager(self, message_dict):
        nom_usager = message_dict[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.LIBVAL_USAGER: nom_usager,
        }

        collection = self.document_dao.get_collection(self.get_nom_collection())
        document_usager = collection.find_one(filtre)
        if document_usager:
            document_filtre = self.filtrer_champs_document(document_usager)
            return document_filtre
        else:
            return {Constantes.EVENEMENT_REPONSE: False}

