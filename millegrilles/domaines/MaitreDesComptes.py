import logging
import datetime

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMaitreDesComptes
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesNoeuds, TraitementCommandesProtegees, \
    TransactionTypeInconnuError
from millegrilles.MGProcessus import MGProcessusTransaction


class TraitementRequetesProtegees(TraitementRequetesNoeuds):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        # Verifier quel processus demarrer. On match la valeur dans la routing key.
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesMaitreDesComptes.REQUETE_CHARGER_USAGER:
            reponse = self.gestionnaire.charger_usager(message_dict)
        elif action == ConstantesMaitreDesComptes.REQUETE_INFO_PROPRIETAIRE:
            reponse = self.gestionnaire.get_info_proprietaire()
        else:
            # Type de transaction inconnue, on lance une exception
            raise TransactionTypeInconnuError("Type de transaction inconnue: message: %s" % message_dict, routing_key)

        return reponse


class TraitementCommandesMaitredesclesProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

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

        action = domaine_transaction.split('.')[-1]

        if action == ConstantesMaitreDesComptes.TRANSACTION_INSCRIRE_PROPRIETAIRE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusInscrireProprietaire"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_INSCRIRE_USAGER:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusInscrireUsager"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_AJOUTER_CLE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusAjouterCle"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_CLES:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerCles"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_MAJ_MOTDEPASSE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusMajMotdepasse"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_SUPPRESSION_MOTDEPASSE:
            processus = "millegrilles_domaines_MaitreDesComptes:ProcessusSupprimerMotdepasse"
        elif action == ConstantesMaitreDesComptes.TRANSACTION_SUPPRIMER_USAGER:
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
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesMaitreDesComptes.LIBVAL_USAGER, ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE]
            },
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }

        collection = self.document_dao.get_collection(self.get_nom_collection())
        document_usager = collection.find_one(filtre)
        if document_usager:
            document_filtre = self.filtrer_champs_document(document_usager)
            return document_filtre
        else:
            return {Constantes.EVENEMENT_REPONSE: False}

    def get_info_proprietaire(self):
        """
        Retourne l'information du proprietaire, si existant.
        :return:
        """
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
        }
        collection = self.document_dao.get_collection(self.get_nom_collection())
        document_proprietaire = collection.find_one(filtre)
        if document_proprietaire:
            document_proprietaire = self.filtrer_champs_document(document_proprietaire)
        else:
            return {Constantes.EVENEMENT_REPONSE: False}

        return document_proprietaire

    def inscrire_proprietaire(self, info_proprietaire: dict):
        date_courante = datetime.datetime.utcnow()

        cle = info_proprietaire[ConstantesMaitreDesComptes.CHAMP_CLE]

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
        }

        doc = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
            ConstantesMaitreDesComptes.CHAMP_CLES: [cle]
        }

        collection = self.document_dao.get_collection(self.get_nom_collection())

        # S'assurer que le document n'existe pas deja
        doc_existant = collection.find_one(filtre)
        if doc_existant:
            raise ValueError("Proprietaire deja assigne pour cette MilleGrille")

        resultat = collection.insert_one(doc)
        if not resultat.inserted_id:
            raise Exception("Erreur prise de possession par le proprietaire, aucun document modifie")

    def inscrire_usager(self, info_usager: dict):
        nom_usager = info_usager[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        date_courante = datetime.datetime.utcnow()

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
        }

        ops = {
            '$set': info_usager,
            '$setOnInsert': set_on_insert,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection.update_one(filtre, ops, upsert=True)
        if not resultat.upserted_id and resultat.matched_count == 0:
            raise Exception("Erreur inscription, aucun document modifie")

    def maj_motdepasse(self, nom_usager: str, motdepasse: dict, est_proprietaire: False):
        set_ops = {
            ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE: motdepasse
        }

        if est_proprietaire:
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE,
            }
            # Pour le proprietaire, on permet de changer le nom d'usager a volonte
            set_ops[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER] = nom_usager
        else:
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
                ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
            }

        ops = {
            '$set': set_ops,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur maj mot de passe, aucun document modifie")

    def suppression_motdepasse(self, nom_usager: str):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [ConstantesMaitreDesComptes.LIBVAL_USAGER, ConstantesMaitreDesComptes.REQUETE_INFO_PROPRIETAIRE]},
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }
        ops = {
            '$unset': {ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE: True},
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur suppression mot de passe, aucun document modifie")

        return {Constantes.EVENEMENT_REPONSE: True}

    def ajouter_cle(self, cle: dict, nom_usager: str = None, est_proprietaire=False, reset_autres_cles=False,):
        if reset_autres_cles:
            op_cle = {'$set': {ConstantesMaitreDesComptes.CHAMP_CLES: [cle]}}
        else:
            op_cle = {'$push': {ConstantesMaitreDesComptes.CHAMP_CLES: cle}}

        if est_proprietaire:
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_PROPRIETAIRE
            }
        else:
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
                ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
            }

        ops = {
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }
        ops.update(op_cle)

        collection = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur ajout cle, aucun document modifie")

    def suppression_cles(self, nom_usager: str):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }
        ops = {
            '$unset': {ConstantesMaitreDesComptes.CHAMP_CLES: True},
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        collection = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection.update_one(filtre, ops)
        if resultat.matched_count != 1:
            raise Exception("Erreur suppression mot de passe, aucun document modifie")

        return {Constantes.EVENEMENT_REPONSE: True}

    def supprimer_usager(self, nom_usager: str):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesMaitreDesComptes.LIBVAL_USAGER,
            ConstantesMaitreDesComptes.CHAMP_NOM_USAGER: nom_usager,
        }
        collection = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection.delete_one(filtre)
        if resultat.deleted_count != 1:
            raise Exception("Erreur suppression usager, aucun document modifie")

        return {Constantes.EVENEMENT_REPONSE: True}


class ProcessusInscrireProprietaire(MGProcessusTransaction):
    """
    Permet au proprietaire de prendre possession de sa MilleGrille.
    """
    def initiale(self):
        transaction = self.transaction_filtree
        self.controleur.gestionnaire.inscrire_proprietaire(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusInscrireUsager(MGProcessusTransaction):
    """
    Inscrit un nouvel usager.
    Note : si l'usager existe deja, fait une mise a jour
    """
    def initiale(self):
        transaction = self.transaction_filtree
        self.controleur.gestionnaire.inscrire_usager(transaction)
        self.set_etape_suivante()  #Termine


class ProcessusMajMotdepasse(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        motdepasse = transaction[ConstantesMaitreDesComptes.CHAMP_MOTDEPASSE]
        est_proprietaire = transaction.get(ConstantesMaitreDesComptes.CHAMP_EST_PROPRIETAIRE) or False
        self.controleur.gestionnaire.maj_motdepasse(nom_usager, motdepasse, est_proprietaire)

        self.set_etape_suivante()  #Termine


class ProcessusSupprimerMotdepasse(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        self.controleur.gestionnaire.suppression_motdepasse(nom_usager)

        self.set_etape_suivante()  #Termine


class ProcessusAjouterCle(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction.get(ConstantesMaitreDesComptes.CHAMP_NOM_USAGER)
        est_proprietaire = transaction.get(ConstantesMaitreDesComptes.CHAMP_EST_PROPRIETAIRE)
        cle = self.transaction[ConstantesMaitreDesComptes.CHAMP_CLE]
        reset_autres_cles = transaction.get(ConstantesMaitreDesComptes.CHAMP_RESET_CLES) or False
        self.controleur.gestionnaire.ajouter_cle(
            cle, nom_usager=nom_usager, est_proprietaire=est_proprietaire, reset_autres_cles=reset_autres_cles)

        self.set_etape_suivante()  #Termine


class ProcessusSupprimerCles(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        self.controleur.gestionnaire.suppression_cles(nom_usager)

        self.set_etape_suivante()  #Termine


class ProcessusSupprimerUsager(MGProcessusTransaction):
    """
    Met a jour un mot de passe d'usager
    """
    def initiale(self):
        transaction = self.transaction

        nom_usager = transaction[ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        self.controleur.gestionnaire.supprimer_usager(nom_usager)

        self.set_etape_suivante()  #Termine
