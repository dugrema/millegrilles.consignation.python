# Domaine Plume - ecriture de documents
from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import MGProcessusTransaction

import logging
import datetime


class ConstantesPlume:

    DOMAINE_NOM = 'millegrilles.domaines.Plume'
    COLLECTION_NOM = DOMAINE_NOM

    COLLECTION_TRANSACTIONS_NOM = COLLECTION_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_NOM
    QUEUE_NOM = DOMAINE_NOM

    TRANSACTION_NOUVEAU_DOCUMENT = '%s.nouveauDocument' % DOMAINE_NOM
    TRANSACTION_MODIFIER_DOCUMENT = '%s.modifierDocument' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_DOCUMENT = '%s.supprimerDocument' % DOMAINE_NOM
    TRANSACTION_PUBLIER_DOCUMENT = '%s.publierDocument' % DOMAINE_NOM
    TRANSACTION_DEPUBLIER_DOCUMENT = '%s.depublierDocument' % DOMAINE_NOM

    DOCUMENT_PLUME_UUID = 'uuid'
    DOCUMENT_SECURITE = 'securite'
    DOCUMENT_TITRE = 'titre'
    DOCUMENT_CATEGORIES = 'categories'
    DOCUMENT_TEXTE = 'texte'
    DOCUMENT_QUILL_DELTA = 'quilldelta'
    DOCUMENT_LISTE = 'documents'
    DOCUMENT_DATE_PUBLICATION = 'datePublication'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_PLUME = 'plume'
    LIBVAL_CATALOGUE = 'catalogue'
    LIBVAL_CATEGORIE = 'categorie'

    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION
    }

    DOCUMENT_PLUME = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_PLUME,
        DOCUMENT_PLUME_UUID: None,  # Identificateur unique du document plume
        DOCUMENT_SECURITE: Constantes.SECURITE_PRIVE,       # Niveau de securite
        DOCUMENT_TITRE: None,                               # Titre
        DOCUMENT_CATEGORIES: None,                          # Categorie du fichier
        DOCUMENT_QUILL_DELTA: None,                         # Contenu, delta Quill
        DOCUMENT_TEXTE: None,                               # Texte sans formattage
    }

    DOCUMENT_CATALOGUE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CATALOGUE,
        DOCUMENT_SECURITE: Constantes.SECURITE_PUBLIC,      # Niveau de securite du catalogue
        DOCUMENT_CATEGORIES: {},                            # Dict des categories de Plume. Valeur est 'True' (bidon)
        DOCUMENT_LISTE: {},                                 # Dict des documents du catalogue. Cle est uuid,
                                                            # valeur est: {titre, uuid, _mg-derniere-modification, categories).
    }


class GestionnairePlume(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

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
            (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1)
        ])

        self.initialiser_document(ConstantesPlume.LIBVAL_CONFIGURATION, ConstantesPlume.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesPlume.LIBVAL_CATALOGUE, ConstantesPlume.DOCUMENT_CATALOGUE)

    def ajouter_nouveau_document(self, transaction):
        document_plume = ConstantesPlume.DOCUMENT_PLUME.copy()

        document_plume[ConstantesPlume.DOCUMENT_PLUME_UUID] = \
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        document_plume[ConstantesPlume.DOCUMENT_SECURITE] = transaction[ConstantesPlume.DOCUMENT_SECURITE]
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
            ConstantesPlume.DOCUMENT_PLUME_UUID: transaction[ConstantesPlume.DOCUMENT_PLUME_UUID]
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre, operations)

        return document_plume

    def supprimer_document(self, transaction):
        filtre = {
            ConstantesPlume.DOCUMENT_PLUME_UUID: transaction[ConstantesPlume.DOCUMENT_PLUME_UUID]
        }
        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.delete_one(filtre)

    def __map_transaction_vers_document(self, transaction, document_plume):
        document_plume[ConstantesPlume.DOCUMENT_TITRE] = transaction[ConstantesPlume.DOCUMENT_TITRE]
        document_plume[ConstantesPlume.DOCUMENT_TEXTE] = transaction[ConstantesPlume.DOCUMENT_TEXTE]
        document_plume[ConstantesPlume.DOCUMENT_QUILL_DELTA] = transaction.get(ConstantesPlume.DOCUMENT_QUILL_DELTA)
        categories_string = transaction[ConstantesPlume.DOCUMENT_CATEGORIES]
        if categories_string is not None:
            categories = categories_string.split(' ')
            document_plume[ConstantesPlume.DOCUMENT_CATEGORIES] = categories

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
            ConstantesPlume.DOCUMENT_PLUME_UUID: document[ConstantesPlume.DOCUMENT_PLUME_UUID],
            ConstantesPlume.DOCUMENT_TITRE: document[ConstantesPlume.DOCUMENT_TITRE],
            ConstantesPlume.DOCUMENT_CATEGORIES: document[ConstantesPlume.DOCUMENT_CATEGORIES],
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: document[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION],
        }
        set_ops = {
            '%s.%s' % (ConstantesPlume.DOCUMENT_LISTE, uuid_document): info_catalogue
        }
        for categorie in document['categories']:
            set_ops['%s.%s' % (ConstantesPlume.DOCUMENT_CATEGORIES, categorie)] = True

        operations = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        filtre_catalogue = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_CATALOGUE,
            ConstantesPlume.DOCUMENT_SECURITE: Constantes.SECURITE_PUBLIC,
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        resultat = collection_domaine.update_one(filtre_catalogue, operations)

        # Marquer document comme publie
        operations_publie = {
            '$currentDate': {ConstantesPlume.DOCUMENT_DATE_PUBLICATION: True}
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
            ConstantesPlume.DOCUMENT_SECURITE: Constantes.SECURITE_PUBLIC,
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
        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def traiter_cedule(self, evenement):
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
            ConstantesPlume.DOCUMENT_PLUME_UUID: document_plume[ConstantesPlume.DOCUMENT_PLUME_UUID],
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

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Mettre a jour le document """
        transaction = self.charger_transaction()

        self.set_etape_suivante()  # Termine

