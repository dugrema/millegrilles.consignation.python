from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction

from pymongo.collection import ReturnDocument

import datetime
import uuid
import logging


class ConstantesAnnuaire:

    DOMAINE_NOM = 'millegrilles.domaines.Annuaire'
    QUEUE_SUFFIXE = DOMAINE_NOM
    COLLECTION_TRANSACTIONS_NOM = QUEUE_SUFFIXE
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM

    LIBVAL_INDEX_MILLEGRILLES = 'index.millegrilles'
    LIBVAL_FICHE_TIERCE = 'fiche.tierce'
    LIBVAL_FICHE_PRIVEE = 'fiche.privee'      # Fiche privee de la millegrille locale
    LIBVAL_FICHE_PUBLIQUE = 'fiche.publique'  # Fiche publique de la millegrille locale signee par le maitredescles

    LIBELLE_DOC_LISTE = 'liste'
    LIBELLE_DOC_SECURITE = '_securite'
    LIBELLE_DOC_LIENS_PUBLICS_HTTPS = 'public_https'
    LIBELLE_DOC_LIENS_PRIVES_MQ = 'prive_mq'
    LIBELLE_DOC_LIENS_PRIVES_HTTPS = 'prive_https'
    LIBELLE_DOC_LIENS_RELAIS = 'relais'
    LIBELLE_DOC_USAGER = 'usager'
    LIBELLE_DOC_DESCRIPTIF = 'descriptif'
    LIBELLE_DOC_CERTIFICAT_RACINE = 'certificat_racine'
    LIBELLE_DOC_CERTIFICAT = 'certificat'
    LIBELLE_DOC_CERTIFICATS_INTERMEDIAIRES = 'certificats_intermediaires'
    LIBELLE_DOC_CERTIFICAT_ADDITIONNELS = 'certificats_additionnels'
    LIBELLE_DOC_EXPIRATION_INSCRIPTION = 'expiration_inscription'
    LIBELLE_DOC_RENOUVELLEMENT_INSCRIPTION = 'renouvellement_inscription'
    LIBELLE_DOC_ABONNEMENTS = 'abonnements'
    LIBELLE_DOC_NOMBRE_FICHES = 'nombre_fiches'
    LIBELLE_DOC_TYPE_FICHE = 'type'
    LIBELLE_DOC_FICHE_PRIVEE = 'fiche_privee'
    LIBELLE_DOC_FICHE_PUBLIQUE = 'fiche_publique'

    TRANSACTION_MAJ_FICHEPRIVEE = '%s.maj.fichePrivee' % DOMAINE_NOM
    TRANSACTION_MAJ_FICHEPUBLIQUE = '%s.maj.fichePublique' % DOMAINE_NOM
    TRANSACTION_MAJ_FICHETIERCE = '%s.maj.ficheTierce' % DOMAINE_NOM

    TEMPLATE_DOCUMENT_INDEX_MILLEGRILLES = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_INDEX_MILLEGRILLES,
        LIBELLE_DOC_LISTE: dict(),  # Dict de ENTREE_INDEX, key=IDMG
    }

    TEMPLATE_DOCUMENT_ENTREE_INDEX = {
        LIBELLE_DOC_DESCRIPTIF: None,
        Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: None,
        LIBELLE_DOC_SECURITE: Constantes.SECURITE_PROTEGE
    }

    TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_PRIVEE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHE_PRIVEE,
        Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: None,
        LIBELLE_DOC_LIENS_PRIVES_MQ: list(),
        LIBELLE_DOC_LIENS_RELAIS: list(),
        LIBELLE_DOC_USAGER: dict(),
        LIBELLE_DOC_DESCRIPTIF: None,
        LIBELLE_DOC_CERTIFICAT_RACINE: None,  # str
        LIBELLE_DOC_CERTIFICAT: None,  # Certificat du maitredescles
        LIBELLE_DOC_CERTIFICATS_INTERMEDIAIRES: None,  # Liste certificats du maitredescles + intermediaires
        LIBELLE_DOC_CERTIFICAT_ADDITIONNELS: None,  # Liste de certificats maitredescles additionnels
    }

    TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_PUBLIQUE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHE_PUBLIQUE,
    }

    TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_TIERCE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHE_TIERCE,
        Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG: None,
        LIBELLE_DOC_LIENS_PUBLICS_HTTPS: list(),
        LIBELLE_DOC_LIENS_PRIVES_MQ: list(),
        LIBELLE_DOC_LIENS_RELAIS: list(),
        LIBELLE_DOC_USAGER: dict(),
        LIBELLE_DOC_DESCRIPTIF: None,
        LIBELLE_DOC_CERTIFICAT_RACINE: None,     # str
        LIBELLE_DOC_CERTIFICATS_INTERMEDIAIRES: None,  # Liste certificats du maitredescles + intermediaires
        LIBELLE_DOC_CERTIFICAT_ADDITIONNELS: None,  # Liste de certificats maitredescles additionnels
        LIBELLE_DOC_SECURITE: Constantes.SECURITE_PROTEGE,
        LIBELLE_DOC_EXPIRATION_INSCRIPTION: None,  # Date d'expiration du certificat
        LIBELLE_DOC_ABONNEMENTS: dict(),  # Dict d'abonnements pour cette MilleGrille
    }


class GestionnaireAnnuaire(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_message = None

    def configurer(self):
        super().configurer()

        # collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        #
        # collection_domaine.create_index(
        #     [
        #         (AnnuaireConstantes.LIBELLE_DOMAINE, 1),
        #         (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
        #     ],
        #     name='domaine-mglibelle'
        # )

    def demarrer(self):
        super().demarrer()

        # Initialiser fiche privee au besoin
        fiche_privee = ConstantesAnnuaire.TEMPLATE_DOCUMENT_FICHE_MILLEGRILLE_PRIVEE.copy()
        fiche_privee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG] = self.configuration.idmg
        with open(self.configuration.pki_cafile, 'r') as fichier:
            ca_pem = fichier.read()
        fiche_privee[ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT_RACINE] = ca_pem
        self.initialiser_document(ConstantesAnnuaire.LIBVAL_FICHE_PRIVEE, fiche_privee)

        # Initialiser index au besoin
        self.initialiser_document(ConstantesAnnuaire.LIBVAL_INDEX_MILLEGRILLES, ConstantesAnnuaire.TEMPLATE_DOCUMENT_INDEX_MILLEGRILLES.copy())

    def get_nom_queue(self):
        return ConstantesAnnuaire.QUEUE_SUFFIXE

    def get_nom_collection(self):
        return ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM

    def get_collection_transaction_nom(self):
        return ConstantesAnnuaire.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesAnnuaire.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesAnnuaire.DOMAINE_NOM

    def traiter_cedule(self, message):
        timestamp_message = message['timestamp']['UTC']
        if timestamp_message[4] % 6 == 0:
            self._logger.debug("Executer entretien annuaire (6 heures)")
            # Declencher la verification des actions sur taches

    def identifier_processus(self, domaine_transaction):
        if domaine_transaction == ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPRIVEE:
            processus = "millegrilles_domaines_Annuaire:ProcessusMajFichePrivee"
        elif domaine_transaction == ConstantesAnnuaire.TRANSACTION_MAJ_FICHEPUBLIQUE:
            processus = "millegrilles_domaines_Annuaire:ProcessusMajFichePublique"
        elif domaine_transaction == ConstantesAnnuaire.TRANSACTION_MAJ_FICHETIERCE:
            processus = "millegrilles_domaines_Annuaire:ProcessusMajFicheTierce"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def maj_fiche_privee(self, fiche):
        self.valider_signature_fiche(fiche)

        # Extraire toutes les valeurs de la transaction qui ne commencent pas par un '_'
        set_ops = dict()
        for key, value in fiche.items():
            if not key.startswith('_') and key != Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE:
                set_ops[key] = value

        # Effectuer la mise a jour
        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_FICHE_PRIVEE
        }

        collection_domaine = self.document_dao.get_collection(ConstantesAnnuaire.COLLECTION_DOCUMENTS_NOM)
        fiche_maj = collection_domaine.find_one_and_update(filtre, update=ops, return_document=ReturnDocument.AFTER)

        # Remettre l'entete et la signature pour pouvoir exporter la fiche
        del fiche_maj['_id']  # Enlever le MongoID
        # del fiche_maj[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]  # Enlever Entete, on va en mettre une nouvelle
        # del fiche_maj[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE]  # Enlever _signature

        # Preparer la fiche pour etre exportee (transaction maj.fiche.tierce)
        fiche_exportee = self.generateur_transactions.preparer_enveloppe(fiche_maj, ConstantesAnnuaire.TRANSACTION_MAJ_FICHETIERCE)
        info_recalculee = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE: fiche_exportee[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE],
            Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE: fiche_exportee[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE],
        }

        # Mettre a jour la fiche avec la nouvelle entete et signature
        collection_domaine.update_one(filtre, {'$set': info_recalculee})

        # Mise a jour index
        descriptif = fiche_exportee.get(ConstantesAnnuaire.LIBELLE_DOC_DESCRIPTIF)
        if descriptif is None:
            descriptif = fiche_exportee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG]

        set_index = {
            '%s.%s.%s' % (
                ConstantesAnnuaire.LIBELLE_DOC_LISTE,
                fiche_exportee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG],
                ConstantesAnnuaire.LIBELLE_DOC_DESCRIPTIF
            ): descriptif,
            '%s.%s.%s' % (
                ConstantesAnnuaire.LIBELLE_DOC_LISTE,
                fiche_exportee[Constantes.TRANSACTION_MESSAGE_LIBELLE_IDMG],
                ConstantesAnnuaire.LIBELLE_DOC_TYPE_FICHE
            ): ConstantesAnnuaire.LIBVAL_FICHE_PRIVEE,
        }
        collection_domaine.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesAnnuaire.LIBVAL_INDEX_MILLEGRILLES},
            {'$set': set_index}
        )

        return fiche_exportee

    def valider_signature_fiche(self, fiche):
        """
        Valide la signature de la fiche en utilisant les certificats racine, intermediaire et _certificat_.
        """
        self._logger.warning("ATTENTION! valider_signature_fiche PAS IMPLEMENTE")
        return True


class ProcessusAnnuaire(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesAnnuaire.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesAnnuaire.COLLECTION_PROCESSUS_NOM


class ProcessusMajFichePrivee(ProcessusAnnuaire):
    """
    Met a jour la fiche privee
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction

        fiche_exportee = self.controleur.gestionnaire.maj_fiche_privee(transaction)

        if fiche_exportee.get(ConstantesAnnuaire.LIBELLE_DOC_CERTIFICAT) is None:
            # Le certificat du maitre des cles n'a pas ete ajoute. On fait une requete.
            domaine = 'millegrilles.domaines.MaitreDesCles.certMaitreDesCles'
            requete = {
                '_evenements': 'certMaitreDesCles'
            }

            self.set_requete(domaine, requete)
            self.set_etape_suivante(ProcessusMajFichePrivee.maj_maitredescles.__name__)

        else:
            self.set_etape_suivante()  # Termine

    def maj_maitredescles(self):
        reponse = self.parametres['reponse'][0]

        self.controleur.gestionnaire.maj_fiche_privee(reponse)

        self.set_etape_suivante()  # Termine


class ProcessusMajFichePublique(ProcessusAnnuaire):
    """
    Ajoute/met a jour et publie la fiche publique
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusMajFicheTierce(ProcessusAnnuaire):
    """
    Ajoute/met a jour une fiche de MilleGrille tierce
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusInscrireMilleGrilleTierceLocalement(ProcessusAnnuaire):
    """
    Processus initial qui mene a generer un certificat de connexion a la MilleGrille locale
    suite a une demande d'une MilleGrille tierce. Genere une notification a l'usager avant de
    repondre a la MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        fiche_privee = transaction[ConstantesAnnuaire.LIBELLE_DOC_FICHE_PRIVEE]

        # Verification et mise a jour de la fiche de millegrille tierce.
        self.controleur.gestionnaire.maj_fiche_privee(fiche_privee)

        self.set_etape_suivante()  # Termine


class ProcessusRefuserInscriptionMilleGrilleTierceLocalement(ProcessusAnnuaire):
    """
    Processus pour refuser l'inscription d'une MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction

        # Verification et mise a jour de la fiche de millegrille tierce.

        self.set_etape_suivante()  # Termine


class ProcessusDemandeInscrireAMilleGrilleTierce(ProcessusAnnuaire):
    """
    Processus qui demande un certificat a une MilleGrille tierce pour la MilleGrille locale.
    Ce processus peut servir pour une demande initiale ou pour le renouvellement du certificat.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusCompleterInscriptionAMilleGrilleTierce(ProcessusAnnuaire):
    """
    Processus qui recoit un certificat de connexion a une MilleGrille tierce.
    Ce certificat est indexe par module de connexion inter-millegrille (celui a qui la cle prive appartient).
    La transaction est re-emise avec routing pki pour etre conservee dans le domaine pki.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusDemarrerConversation(ProcessusAnnuaire):
    """
    Permet de demarrer une conversation avec une MilleGrille tierce.
    Transmet une cle secrete cryptee avec la cle publique dans la fiche tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusRecevoirMessageProtege(ProcessusAnnuaire):
    """
    Recoit un message d'une MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine


class ProcessusTransmettreMessageProtege(ProcessusAnnuaire):
    """
    Transmet un message a une MilleGrille tierce.
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.transaction
        self.set_etape_suivante()  # Termine

