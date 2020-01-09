# Domaine Plume - ecriture de documents
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPlume
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import MGProcessusTransaction

import logging
import datetime


class GestionnairePlume(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

    def configurer(self):
        super().configurer()

        collection_domaine = self.document_dao.get_collection(ConstantesPlume.COLLECTION_DOCUMENTS_NOM)
        # Index noeud, _mg-libelle
        collection_domaine.create_index(
            [
                (ConstantesPlume.LIBELLE_DOC_CATEGORIES, 1)
            ],
            name='categories'
        )
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1)
            ],
            name='mglibelle'
        )
        collection_domaine.create_index(
            [
                (ConstantesPlume.LIBELLE_DOC_PLUME_UUID, 1)
            ],
            name='uuid'
        )
        collection_domaine.create_index(
            [
                (ConstantesPlume.LIBELLE_DOC_TITRE, 1)
            ],
            name='titre'
        )
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_DATE_CREATION, 1)
            ],
            name='creation'
        )
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1)
            ],
            name='dernieremodification'
        )

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesPlume.LIBVAL_CONFIGURATION, ConstantesPlume.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesPlume.LIBVAL_CATALOGUE, ConstantesPlume.DOCUMENT_CATALOGUE)

    def ajouter_nouveau_document(self, transaction):
        document_plume = ConstantesPlume.DOCUMENT_PLUME.copy()

        document_plume[ConstantesPlume.LIBELLE_DOC_PLUME_UUID] = \
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        document_plume[ConstantesPlume.LIBELLE_DOC_SECURITE] = transaction[ConstantesPlume.LIBELLE_DOC_SECURITE]
        document_plume[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = datetime.datetime.utcnow()
        document_plume[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = datetime.datetime.utcnow()

        self.__map_transaction_vers_document(transaction, document_plume)

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.insert_one(document_plume)

        return document_plume

    def modifier_document(self, transaction):
        document_plume = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: datetime.datetime.utcnow()
        }
        self.__map_transaction_vers_document(transaction, document_plume)
        operations = {
            '$set': document_plume,
        }

        filtre = {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: transaction[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre, operations)

        return document_plume

    def supprimer_document(self, transaction):
        filtre = {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: transaction[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]
        }
        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.delete_one(filtre)

    def __map_transaction_vers_document(self, transaction, document_plume):
        document_plume[ConstantesPlume.LIBELLE_DOC_TITRE] = transaction[ConstantesPlume.LIBELLE_DOC_TITRE]
        document_plume[ConstantesPlume.LIBELLE_DOC_TEXTE] = transaction[ConstantesPlume.LIBELLE_DOC_TEXTE]
        document_plume[ConstantesPlume.LIBELLE_DOC_QUILL_DELTA] = transaction.get(ConstantesPlume.LIBELLE_DOC_QUILL_DELTA)
        categories_string = transaction[ConstantesPlume.LIBELLE_DOC_CATEGORIES]
        if categories_string is not None:
            categories = categories_string.split(' ')
            document_plume[ConstantesPlume.LIBELLE_DOC_CATEGORIES] = categories

    def get_document(self, uuid_document):
        filtre = {
            'uuid': uuid_document,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_PLUME
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        document = collection_domaine.find_one(filtre)

        return document

    def publier_document_danscatalogue(self, uuid_document):
        document = self.get_document(uuid_document)
        if document is None:
            raise ValueError("Document uuid: %s non trouve" % uuid_document)

        info_catalogue = {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: document[ConstantesPlume.LIBELLE_DOC_PLUME_UUID],
            ConstantesPlume.LIBELLE_DOC_TITRE: document[ConstantesPlume.LIBELLE_DOC_TITRE],
            ConstantesPlume.LIBELLE_DOC_CATEGORIES: document[ConstantesPlume.LIBELLE_DOC_CATEGORIES],
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }
        set_ops = {
            '%s.%s' % (ConstantesPlume.LIBELLE_DOC_LISTE, uuid_document): info_catalogue
        }
        for categorie in document['categories']:
            set_ops['%s.%s' % (ConstantesPlume.LIBELLE_DOC_CATEGORIES, categorie)] = True

        operations = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        filtre_catalogue = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_CATALOGUE,
            ConstantesPlume.LIBELLE_DOC_SECURITE: Constantes.SECURITE_PUBLIC,
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre_catalogue, operations)

        # Marquer document comme publie
        operations_publie = {
            '$currentDate': {ConstantesPlume.LIBELLE_DOC_DATE_PUBLICATION: True}
        }
        filtre_document = {
            'uuid': uuid_document,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_PLUME
        }
        resultat = collection_domaine.update_one(filtre_document, operations_publie)

    def get_catalogue(self):
        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        filtre_catalogue = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_CATALOGUE,
            ConstantesPlume.LIBELLE_DOC_SECURITE: Constantes.SECURITE_PUBLIC,
        }
        document = collection_domaine.find_one(filtre_catalogue)
        return document

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

    def identifier_processus(self, domaine_transaction):
        # Actions
        if domaine_transaction == ConstantesPlume.TRANSACTION_NOUVEAU_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionAjouterDocumentPlume"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_MODIFIER_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionModifierDocumentPlume"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_SUPPRIMER_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionSupprimerDocumentPlume"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_PUBLIER_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionPublierDocumentPlume"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_DEPUBLIER_DOCUMENT:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionDepublierDocumentPlume"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_CREER_ANNONCE:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionCreerAnnonce"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_SUPPRIMER_ANNONCE:
            processus = "millegrilles_domaines_Plume:ProcessusTransactionSupprimerAnnonce"
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def traiter_cedule(self, evenement):
        pass

    def creer_annonce(self, annonce):
        date_creation = datetime.datetime.utcnow()

        # Calculer le delai de publication par defaut
        delta_publication = datetime.timedelta(seconds=ConstantesPlume.DEFAUT_ATTENTE_PUBLICATION_SECS)
        date_publication = date_creation + delta_publication

        doc_annonce = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_ANNONCE,
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: annonce[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_creation,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_creation,
            ConstantesPlume.LIBELLE_DOC_DATE_ATTENTE_PUBLICATION: date_publication,
            ConstantesPlume.LIBELLE_DOC_TEXTE: annonce[ConstantesPlume.LIBELLE_DOC_TEXTE],
        }

        # Le sujet est optionnel
        sujet = annonce.get(ConstantesPlume.LIBELLE_DOC_SUJET)
        if sujet is not None:
            doc_annonce[ConstantesPlume.LIBELLE_DOC_SUJET] = sujet

        # Verifier si l'annonce en remplace une autre
        remplacement = annonce.get(ConstantesPlume.LIBELLE_DOC_REMPLACE)
        if remplacement is not None:
            doc_annonce[ConstantesPlume.LIBELLE_DOC_REMPLACE] = remplacement

            # Supprimer l'annonce qui est remplacee
            self.supprimer_annonce(remplacement)

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        collection_domaine.insert_one(doc_annonce)

    def supprimer_annonce(self, uuid_annonce):
        pass


class TraitementMessageCedule(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        routing_key = method.routing_key


class TraitementTransactionPersistee(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)

    def traiter_message(self, ch, method, properties, body):
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)

        # Verifier quel processus demarrer.
        routing_key = method.routing_key
        routing_key_sansprefixe = routing_key.replace(
            'destinataire.domaine.%s.' % ConstantesPlume.DOMAINE_NOM,
            ''
        )

        processus = self.gestionnaire.identifier_processus(routing_key_sansprefixe)
        self._gestionnaire.demarrer_processus(processus, message_dict)


class TraitementRequetesNoeuds(TraitementMessageDomaine):

    def __init__(self, gestionnaire):
        super().__init__(gestionnaire)
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def traiter_message(self, ch, method, properties, body):
        routing_key = method.routing_key
        exchange = method.exchange
        message_dict = self.json_helper.bin_utf8_json_vers_dict(body)
        evenement = message_dict.get(Constantes.EVENEMENT_MESSAGE_EVENEMENT)
        enveloppe_certificat = self.gestionnaire.verificateur_transaction.verifier(message_dict)

        self._logger.debug("Certificat: %s" % str(enveloppe_certificat))
        resultats = list()
        for requete in message_dict['requetes']:
            resultat = self.executer_requete(requete)
            resultats.append(resultat)

        # Genere message reponse
        self.transmettre_reponse(message_dict, resultats, properties.reply_to, properties.correlation_id)

    def executer_requete(self, requete):
        self._logger.debug("Requete: %s" % str(requete))
        collection = self.document_dao.get_collection(ConstantesPlume.COLLECTION_DOCUMENTS_NOM)
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
        document_plume = self._controleur.gestionnaire.ajouter_nouveau_document(transaction)
        self.set_etape_suivante()  # Termine

        return {
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: document_plume[ConstantesPlume.LIBELLE_DOC_PLUME_UUID],
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: document_plume[Constantes.DOCUMENT_INFODOC_DATE_CREATION],
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document_plume[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }


class ProcessusTransactionModifierDocumentPlume(ProcessusPlume):
    """
    Processus de modification de document Plume
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()
        document_plume = self._controleur.gestionnaire.modifier_document(transaction)
        self.set_etape_suivante()  # Termine

        return {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document_plume[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }


class ProcessusTransactionSupprimerDocumentPlume(ProcessusPlume):
    """
    Processus de modification de document Plume
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Supprimer le document """
        transaction = self.charger_transaction()
        self._controleur.gestionnaire.supprimer_document(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusTransactionPublierDocumentPlume(ProcessusPlume):
    """
    Processus de publication d'une version de document Plume
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()
        uuid_document = transaction['uuid']

        # Inserer les metadonnes du document dans le catalogue
        self._controleur.gestionnaire.publier_document_danscatalogue(uuid_document)

        self.set_etape_suivante(ProcessusTransactionPublierDocumentPlume.publier_document_vers_web.__name__)  # Termine
        return {'uuid': uuid_document}

    def publier_document_vers_web(self):
        uuid = self.parametres['uuid']
        document = self._controleur.gestionnaire.get_document(uuid)
        routing_key = 'publicateur.plume.publierDocument'

        generateur_transactions = self._controleur.generateur_transactions
        generateur_transactions.emettre_commande_noeuds(document, routing_key)

        self.set_etape_suivante(ProcessusTransactionPublierDocumentPlume.publier_catalogue.__name__)  # Termine

    def publier_catalogue(self):
        catalogue = self._controleur.gestionnaire.get_catalogue()
        routing_key = 'publicateur.plume.catalogue'

        generateur_transactions = self._controleur.generateur_transactions
        generateur_transactions.emettre_commande_noeuds(catalogue, routing_key)

        self.set_etape_suivante()  # Termine


class ProcessusTransactionDepublierDocumentPlume(ProcessusPlume):
    """
    Processus de publication d'une version de document Plume
    """

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()

        self.set_etape_suivante()  # Termine


class ProcessusTransactionCreerAnnonce(ProcessusPlume):
    """
    Generer et publie une nouvelle annonce.
    L'annonce a un delai de prise d'effet pour permettre de la supprimer avant d'etre affichee.
    """

    def initiale(self):
        transaction = self.charger_transaction()
        self.controleur.gestionnaire.creer_annonce(transaction)
        self.set_etape_suivante()  # Termine


class ProcessusTransactionSupprimerAnnonce(ProcessusPlume):

    def initiale(self):
        transaction = self.charger_transaction()
        self.controleur.gestionnaire.supprimer_annonce(transaction)
        self.set_etape_suivante()  # Termine
