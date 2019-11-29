# Domaine de l'interface GrosFichiers
from pymongo.errors import DuplicateKeyError

from millegrilles import Constantes
from millegrilles.Domaines import GestionnaireDomaineStandard
from millegrilles.MGProcessus import MGProcessusTransaction, MGPProcesseur

import logging
import uuid
import datetime
import json


class ConstantesGrosFichiers:
    """ Constantes pour le domaine de GrosFichiers """

    DOMAINE_NOM = 'millegrilles.domaines.GrosFichiers'
    COLLECTION_TRANSACTIONS_NOM = DOMAINE_NOM
    COLLECTION_DOCUMENTS_NOM = '%s/documents' % COLLECTION_TRANSACTIONS_NOM
    COLLECTION_PROCESSUS_NOM = '%s/processus' % COLLECTION_TRANSACTIONS_NOM
    QUEUE_NOM = 'millegrilles.domaines.GrosFichiers'
    QUEUE_ROUTING_CHANGEMENTS = 'noeuds.source.millegrilles_domaines_GrosFichiers'

    TRANSACTION_TYPE_METADATA = 'millegrilles.domaines.GrosFichiers.nouvelleVersion.metadata'
    TRANSACTION_TYPE_TRANSFERTCOMPLETE = 'millegrilles.domaines.GrosFichiers.nouvelleVersion.transfertComplete'

    TRANSACTION_CHAMP_ETIQUETTE = 'etiquette'

    LIBVAL_CONFIGURATION = 'configuration'
    LIBVAL_FICHIER = 'fichier'
    LIBVAL_COLLECTION = 'collection'
    LIBVAL_FAVORIS = 'favoris'
    LIBVAL_RAPPORT = 'rapport'
    LIBVAL_RAPPORT_ACTIVITE = 'rapport.activite'

    DOCUMENT_SECURITE = 'securite'
    DOCUMENT_COMMENTAIRES = 'commentaires'

    DOCUMENT_REPERTOIRE_FICHIERS = 'fichiers'

    DOCUMENT_FICHIER_NOMFICHIER = 'nom'
    DOCUMENT_FICHIER_UUID_DOC = 'uuid'                    # UUID du document de fichier (metadata)
    DOCUMENT_UUID_GENERIQUE = 'documentuuid'            # Represente un UUID de n'import quel type de document
    DOCUMENT_FICHIER_FUUID = 'fuuid'                    # UUID (v1) du fichier
    DOCUMENT_FICHIER_DATEVCOURANTE = 'date_v_courante'  # Date de la version courante
    DOCUMENT_FICHIER_UUIDVCOURANTE = 'fuuid_v_courante'  # FUUID de la version courante
    DOCUMENT_FICHIER_VERSIONS = 'versions'
    DOCUMENT_FICHIER_MIMETYPE = 'mimetype'
    DOCUMENT_FICHIER_TAILLE = 'taille'
    DOCUMENT_FICHIER_SHA256 = 'sha256'
    DOCUMENT_FICHIER_SUPPRIME = 'supprime'
    DOCUMENT_FICHIER_ETIQUETTES = 'etiquettes'

    DOCUMENT_COLLECTION_FICHIERS = 'fichiers'
    DOCUMENT_COLLECTION_LISTEDOCS = 'documents'
    DOCUMENT_COLLECTION_FIGEE = 'figee'

    DOCUMENT_FAVORIS_LISTE = 'favoris'

    DOCUMENT_VERSION_NOMFICHIER = 'nom'
    DOCUMENT_VERSION_DATE_FICHIER = 'date_fichier'
    DOCUMENT_VERSION_DATE_VERSION = 'date_version'
    DOCUMENT_VERSION_DATE_SUPPRESSION = 'date_suppression'

    DOCUMENT_DEFAULT_MIMETYPE = 'application/binary'

    TRANSACTION_NOUVELLEVERSION_METADATA = '%s.nouvelleVersion.metadata' % DOMAINE_NOM
    TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE = '%s.nouvelleVersion.transfertComplete' % DOMAINE_NOM
    TRANSACTION_NOUVELLEVERSION_CLES_RECUES = '%s.nouvelleVersion.clesRecues' % DOMAINE_NOM
    TRANSACTION_COPIER_FICHIER = '%s.copierFichier' % DOMAINE_NOM
    TRANSACTION_RENOMMER_FICHIER = '%s.renommerFichier' % DOMAINE_NOM
    TRANSACTION_COMMENTER_FICHIER = '%s.commenterFichier' % DOMAINE_NOM
    TRANSACTION_CHANGER_LIBELLES_FICHIER = '%s.changerLibellesFichier' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_FICHIER = '%s.supprimerFichier' % DOMAINE_NOM
    TRANSACTION_RECUPERER_FICHIER = '%s.recupererFichier' % DOMAINE_NOM

    TRANSACTION_NOUVELLE_COLLECTION = '%s.nouvelleCollection' % DOMAINE_NOM
    TRANSACTION_RENOMMER_COLLECTION = '%s.renommerCollection' % DOMAINE_NOM
    TRANSACTION_COMMENTER_COLLECTION = '%s.commenterCollection' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_COLLECTION = '%s.supprimerCollection' % DOMAINE_NOM
    TRANSACTION_RECUPERER_COLLECTION = '%s.recupererCollection' % DOMAINE_NOM
    TRANSACTION_FIGER_COLLECTION = '%s.figerCollection' % DOMAINE_NOM
    TRANSACTION_CHANGER_LIBELLES_COLLECTION = '%s.changerLibellesCollection' % DOMAINE_NOM
    TRANSACTION_CREERTORRENT_COLLECTION = '%s.creerTorrentCollection' % DOMAINE_NOM
    TRANSACTION_AJOUTER_FICHIERS_COLLECTION = '%s.ajouterFichiersCollection' % DOMAINE_NOM
    TRANSACTION_RETIRER_FICHIERS_COLLECTION = '%s.retirerFichiersCollection' % DOMAINE_NOM

    TRANSACTION_AJOUTER_FAVORI = '%s.ajouterFavori' % DOMAINE_NOM
    TRANSACTION_SUPPRIMER_FAVORI = '%s.supprimerFavori' % DOMAINE_NOM

    # Document par defaut pour la configuration de l'interface GrosFichiers
    DOCUMENT_DEFAUT = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_CONFIGURATION,
    }

    DOCUMENT_FICHIER = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FICHIER,
        DOCUMENT_FICHIER_UUID_DOC: None,  # Identificateur unique du fichier (UUID trans initiale)
        DOCUMENT_SECURITE: Constantes.SECURITE_SECURE,      # Niveau de securite
        DOCUMENT_COMMENTAIRES: None,                        # Commentaires
        DOCUMENT_FICHIER_NOMFICHIER: None,                  # Nom du fichier (libelle affiche a l'usager)
        DOCUMENT_FICHIER_ETIQUETTES: None,                    # Liste de libelles du fichier
        DOCUMENT_FICHIER_SUPPRIME: False,                   # True si le fichier est supprime
    }

    SOUSDOCUMENT_VERSION_FICHIER = {
        DOCUMENT_FICHIER_FUUID: None,
        DOCUMENT_FICHIER_NOMFICHIER: None,
        DOCUMENT_FICHIER_MIMETYPE: DOCUMENT_DEFAULT_MIMETYPE,
        DOCUMENT_VERSION_DATE_FICHIER: None,
        DOCUMENT_VERSION_DATE_VERSION: None,
        DOCUMENT_FICHIER_TAILLE: None,
        DOCUMENT_FICHIER_SHA256: None,
        DOCUMENT_COMMENTAIRES: None,
    }

    DOCUMENT_COLLECTION = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_COLLECTION,
        DOCUMENT_FICHIER_UUID_DOC: None,        # Identificateur unique du fichier (UUID trans initiale)
        DOCUMENT_COLLECTION_LISTEDOCS: dict(),   # Dictionnaire de fichiers, key=uuid, value=DOCUMENT_COLLECTION_FICHIER
        DOCUMENT_FICHIER_ETIQUETTES: dict(),    # Etiquettes de la collection
        DOCUMENT_FICHIER_SUPPRIME: False,       # True si la collection est supprimee
        DOCUMENT_COLLECTION_FIGEE: False,       # True si la collection est figee (ne peut plus etre modifiee)
        DOCUMENT_COMMENTAIRES: None,
    }

    DOCUMENT_COLLECTION_FICHIER = {
        DOCUMENT_FICHIER_UUID_DOC: None,    # uuid du fichier
        DOCUMENT_FICHIER_FUUID: None,       # fuuid de la version du fichier
        DOCUMENT_FICHIER_NOMFICHIER: None,  # Nom du fichier
        DOCUMENT_VERSION_DATE_FICHIER: None,
        DOCUMENT_FICHIER_TAILLE: None,
        DOCUMENT_COMMENTAIRES: None,
    }

    DOCUMENT_FAVORIS = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_FAVORIS,
        DOCUMENT_FAVORIS_LISTE: list(),     # Liste DOCUMENT_FAVORIS_INFO
    }

    DOCUMENT_FAVORIS_INFO = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: None,      # Type document
        'nom': None,                                    # Nom affiche a l'ecran
        'uuid': None,                                   # Lien vers document, doit etre unique dans la liste de favoris
    }

    # Prototype de document liste de recherche
    # Represente une liste maintenue et triee par un champ particulier (date) de resultats
    # pour acces rapide.
    # Peut etre utilise pour garder une liste des N derniers fichiers changes, fichiers
    # avec libelles '2019 et 'photos', etc.
    DOCUMENT_RAPPORT_RECHERCHE = {
        Constantes.DOCUMENT_INFODOC_LIBELLE: LIBVAL_RAPPORT,
        'description': None,                    # Description (nom) de la liste de recherche
        DOCUMENT_SECURITE: None,                # Niveau de securite de cette liste
        'filtre_libelles': dict(),              # Libelles utilises pour filtrer la liste des changements
        DOCUMENT_COLLECTION_FICHIERS: list(),   # Dictionnaire de fichiers, valeur=DOCUMENT_COLLECTION_FICHIER
        'tri': [{DOCUMENT_VERSION_DATE_FICHIER: -1}],   # Tri de la liste, utilise pour tronquer
        'compte_max': 100,                      # Nombre maximal d'entree dans la liste
    }


class GestionnaireGrosFichiers(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_middleware = None
        self._traitement_noeud = None
        self._traitement_cedule = None
        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_CONFIGURATION, ConstantesGrosFichiers.DOCUMENT_DEFAUT)

        # Ajout document favoris
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_FAVORIS, ConstantesGrosFichiers.DOCUMENT_FAVORIS)

        # Creation liste de recherche speciale pour l'activite des fichiers
        liste_recherche = ConstantesGrosFichiers.DOCUMENT_RAPPORT_RECHERCHE.copy()
        liste_recherche[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesGrosFichiers.LIBVAL_RAPPORT_ACTIVITE
        liste_recherche['description'] = "Activite recente"
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_RAPPORT_ACTIVITE, liste_recherche)

        self.demarrer_watcher_collection(
            ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM, ConstantesGrosFichiers.QUEUE_ROUTING_CHANGEMENTS)

    def get_queue_configuration(self):
        queue_config = super().get_queue_configuration()
        queue_config.append(
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'transactions'),
                'routing': [
                    'destinataire.domaine.%s.#' % self.get_nom_domaine(),
                ],
                'exchange': self.configuration.exchange_noeuds,
                'callback': self.get_handler_transaction().callbackAvecAck
            },
        )
        return queue_config

    def identifier_processus(self, domaine_transaction):
        # Fichiers
        if domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleVersionMetadata"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleVersionTransfertComplete"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_CLES_RECUES:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleVersionClesRecues"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RENOMMER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRenommerDeplacerFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_COMMENTER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionCommenterFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CHANGER_LIBELLES_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionChangerLibellesFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionSupprimerFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RECUPERER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRecupererFichier"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVELLE_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RENOMMER_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRenommerCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_COMMENTER_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionCommenterCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionSupprimerCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RECUPERER_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRecupererCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_FIGER_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionFigerCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CHANGER_LIBELLES_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionChangerLibellesCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CREERTORRENT_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionCreerTorrentCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_AJOUTER_FICHIERS_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAjouterFichiersDansCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RETIRER_FICHIERS_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRetirerFichiersDeCollection"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_AJOUTER_FAVORI:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAjouterFavori"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_FAVORI:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionSupprimerFavori"

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def get_nom_collection(self):
        return ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM

    def get_nom_queue(self):
        return ConstantesGrosFichiers.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesGrosFichiers.COLLECTION_PROCESSUS_NOM

    def initialiser_document(self, mg_libelle, doc_defaut):
        # Configurer MongoDB, inserer le document de configuration de reference s'il n'existe pas
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        # Trouver le document de configuration
        document_configuration = collection_domaine.find_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: mg_libelle}
        )
        if document_configuration is None:
            self._logger.info("On insere le document %s pour domaine GrosFichiers" % mg_libelle)

            super().initialiser_document(doc_defaut[Constantes.DOCUMENT_INFODOC_LIBELLE], doc_defaut)
        else:
            self._logger.info("Document de %s pour GrosFichiers: %s" % (mg_libelle, str(document_configuration)))

    def creer_index(self):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        # Index _mg-libelle
        collection_domaine.create_index([
            (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
        ])

        # Index pour trouver un fichier par UUID
        collection_domaine.create_index([
            (ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID, 1),
        ])

        # Index pour trouver une version de fichier par FUUID
        collection_domaine.create_index([
            ('%s.%s' %
             (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
              ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID),
             1),
        ])

        # Index par SHA256 / taille. Permet de determiner si le fichier existe deja (et juste faire un lien).
        collection_domaine.create_index([
            ('%s.%s' %
             (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
              ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256),
             1),
            ('%s.%s' %
             (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
              ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE),
             1),
        ])

    def get_nom_domaine(self):
        return ConstantesGrosFichiers.DOMAINE_NOM

    def traiter_cedule(self, evenement):
        pass

    def maj_fichier(self, transaction):
        """
        Genere ou met a jour un document de fichier avec l'information recue dans une transaction metadata.
        :param transaction:
        :return: True si c'est la version la plus recent, false si la transaction est plus vieille.
        """
        domaine = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE].get(Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE)
        if domaine != ConstantesGrosFichiers.TRANSACTION_TYPE_METADATA:
            raise ValueError('La transaction doit etre de type metadata. Trouve: %s' % domaine)

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        fuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]

        uuid_generique = transaction.get(ConstantesGrosFichiers.DOCUMENT_UUID_GENERIQUE)
        super_document = None
        if uuid_generique is not None:
            # Chercher a identifier le fichier ou la collection ou cette nouvelle version va aller
            super_document = collection_domaine.find_one({
                Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                    ConstantesGrosFichiers.LIBVAL_COLLECTION,
                    ConstantesGrosFichiers.LIBVAL_FICHIER
                ]},
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_generique
            })

        nom_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]

        set_on_insert = ConstantesGrosFichiers.DOCUMENT_FICHIER.copy()
        set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] =\
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = nom_fichier

        set_on_insert[ConstantesGrosFichiers.DOCUMENT_SECURITE] = transaction[ConstantesGrosFichiers.DOCUMENT_SECURITE]

        operation_currentdate = {
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
        }

        plus_recente_version = True  # Lors d<une MAJ, on change la plus recente version seulement si necessaire
        set_operations = {}
        if super_document is None or super_document.get(Constantes.DOCUMENT_INFODOC_LIBELLE) == ConstantesGrosFichiers.LIBVAL_COLLECTION:
            # Le super document n'est pas un fichier, on genere un nouveau fichier
            # Le nouveau fichier va utiliser le UUID de la transaction
            uuid_fichier = set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
            operation_currentdate[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = True
        else:
            # Le super-document est un fichier. On ajoute une version a ce fichier.
            uuid_fichier = uuid_generique

        # Filtrer transaction pour creer l'entree de version dans le fichier
        masque_transaction = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE,
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES,
        ]
        date_version = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT].get('_estampille')
        info_version = {
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_VERSION: date_version
        }
        for key in transaction.keys():
            if key in masque_transaction:
                info_version[key] = transaction[key]
        set_operations['%s.%s' % (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS, fuuid)] = info_version

        if plus_recente_version:
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_DATEVCOURANTE] = date_version
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE] = \
                transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = \
                transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE] = \
                transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE]

        operations = {
            '$set': set_operations,
            '$currentDate': operation_currentdate,
            '$setOnInsert': set_on_insert
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }

        self._logger.debug("maj_fichier: filtre = %s" % filtre)
        self._logger.debug("maj_fichier: operations = %s" % operations)
        try:
            resultat = collection_domaine.update_one(filtre, operations, upsert=True)
        except DuplicateKeyError as dke:
            self._logger.info("Cle dupliquee sur fichier %s, on ajoute un id unique dans le nom" % fuuid)
            nom_fichier = '%s_%s' % (uuid.uuid1(), transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER])
            set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = nom_fichier
            resultat = collection_domaine.update_one(filtre, operations, upsert=True)

        self._logger.debug("maj_fichier resultat %s" % str(resultat))

        return {'plus_recent': plus_recente_version, 'uuid_fichier': uuid_fichier}

    def renommer_deplacer_fichier(self, uuid_doc, nouveau_nom):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operations = dict()
        set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = nouveau_nom

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_doc,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }

        resultat = collection_domaine.update_one(filtre, {
            '$set': set_operations,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        })
        self._logger.debug('renommer_deplacer_fichier resultat: %s' % str(resultat))

    def maj_commentaire_fichier(self, uuid_fichier, commentaire):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = {
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES: commentaire
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER
        }
        resultat = collection_domaine.update_one(filtre, {
            '$set': set_operation
        })
        self._logger.debug('maj_commentaire_fichier resultat: %s' % str(resultat))

    def maj_libelles_fichier(self, uuid_fichier, libelles: list):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES: libelles
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER
        }
        resultat = collection_domaine.update_one(filtre, {
            '$set': set_operation
        })
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def supprimer_fichier(self, uuid_fichier):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: True,
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_SUPPRESSION: datetime.datetime.utcnow()
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER
        }
        resultat = collection_domaine.update_one(filtre, {
            '$set': set_operation
        })
        self._logger.debug('supprimer_fichier resultat: %s' % str(resultat))

    def recuperer_fichier(self, uuid_fichier):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False
        }
        unset_operation = {
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_SUPPRESSION: True
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER
        }
        resultat = collection_domaine.update_one(filtre, {
            '$set': set_operation,
            '$unset': unset_operation
        })
        self._logger.debug('supprimer_fichier resultat: %s' % str(resultat))

    def creer_collection(self, uuid_collection: str, liste_documents: list, nom_collection: str = None):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        collection = ConstantesGrosFichiers.DOCUMENT_COLLECTION.copy()
        collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = nom_collection
        collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = uuid_collection

        info_documents_collection = dict()
        if liste_documents is not None and len(liste_documents) > 0:
            # Aller chercher les metadonnees pour inserer dans la collection
            uuids_documents = [doc['uuid'] for doc in liste_documents]

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [ConstantesGrosFichiers.LIBVAL_COLLECTION, ConstantesGrosFichiers.LIBVAL_FICHIER]},
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuids_documents}
            }
            curseur_documents = collection_domaine.find(filtre)
            for doc in curseur_documents:
                doc_filtre = self.__filtrer_entree_collection(doc)
                info_documents_collection[doc['uuid']] = doc_filtre

        date_creation = datetime.datetime.utcnow()
        collection[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = date_creation
        collection[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = date_creation
        collection[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS] = info_documents_collection

        # Inserer la nouvelle collection
        resultat = collection_domaine.insert_one(collection)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def renommer_collection(self, uuid_collection: str, nouveau_nom_collection: str):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER: nouveau_nom_collection
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def commenter_collection(self, uuid_collection: str, commentaire: str):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES: commentaire
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('commenter_collection resultat: %s' % str(resultat))

    def supprimer_collection(self, uuid_collection: str):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: True
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def recuperer_collection(self, uuid_collection: str):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def figer_collection(self, uuid_collection: str):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_COLLECTION_FIGEE: True
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def changer_libelles_collection(self, uuid_collection: str, libelles: list):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        nouveaux_libelles = dict()
        for libelle in libelles:
            nouveaux_libelles[libelle] = True

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES: nouveaux_libelles
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def ajouter_documents_collection(self, uuid_collection: str, uuid_documents: list):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        filtre_documents = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [ConstantesGrosFichiers.LIBVAL_FICHIER, ConstantesGrosFichiers.LIBVAL_COLLECTION]},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuid_documents}
        }
        curseur_documents = collection_domaine.find(filtre_documents)

        nouveaux_documents = dict()
        for fichier in curseur_documents:
            fichier_uuid = fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
            entree_document = self.__filtrer_entree_collection(fichier)

            # Ajouter valeurs pour le document dans la liste de changements
            nouveaux_documents['documents.%s' % fichier_uuid] = entree_document

        ops = {
            '$set': nouveaux_documents,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

    def __filtrer_entree_collection(self, entree):
        fichier_uuid = entree[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        type_document = entree[Constantes.DOCUMENT_INFODOC_LIBELLE]

        entree_filtree = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: type_document,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: fichier_uuid,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER: entree.get(
                ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER),
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES: entree.get(ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES),
        }

        if type_document == ConstantesGrosFichiers.LIBVAL_FICHIER:
            fuuid = entree[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE]
            entree_filtree[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE] = fuuid
            entree_filtree[ConstantesGrosFichiers.DOCUMENT_FICHIER_DATEVCOURANTE] = entree[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_DATEVCOURANTE]
            entree_filtree[ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE] = entree[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE]

        return entree_filtree

    def retirer_fichiers_collection(self, uuid_collection: str, uuid_fichiers: list):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        fichiers = dict()
        for uuid in uuid_fichiers:
            fichiers['documents.%s' % uuid] = ''

        ops = {
            '$unset': fichiers,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        # Inserer la nouvelle collection
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug('supprimer fichiers resultat: %s' % str(resultat))

    def maj_fichier_rapports_et_collections(self, uuid_fichier: str):
        """
        Met a jour les listes et collections qui correspondent au fichier.
        :param uuid_fichier:
        :return:
        """

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        fichier = collection_domaine.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
        })
        etiquettes = fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]

        # Mettre a jour les listes - on match sur les etiquettes (toutes les etiquettes de la liste
        # doivent etre presentes dans le document)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_RAPPORT_ACTIVITE
        }
        ops = {
            '$push': {
                'fichiers': {
                    '$each': [fichier],
                    '$sort': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: -1},
                    '$slice': - 200,
                }
            }
        }
        collection_domaine.update(filtre, ops)

    def maj_collections_rapports_et_collections(self, uuid_collection: str):
        """
        Met a jour les listes et collections qui correspondent au fichier.
        :param uuid_fichier:
        :return:
        """

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection = collection_domaine.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        })
        etiquettes = collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]

        # Mettre a jour les listes - on match sur les etiquettes (toutes les etiquettes de la liste
        # doivent etre presentes dans le document)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_RAPPORT_ACTIVITE
        }
        ops = {
            '$push': {
                'fichiers': {
                    '$each': [collection],
                    '$sort': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: -1},
                    '$slice': - 200,
                }
            }
        }
        collection_domaine.update(filtre, ops)

    def ajouter_favori(self, doc_uuid: str):
        self._logger.debug("Ajouter favor %s" % doc_uuid)
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        filtre_docs = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesGrosFichiers.LIBVAL_FICHIER, ConstantesGrosFichiers.LIBVAL_COLLECTION]
            },
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: doc_uuid,
        }
        self._logger.debug("Trouver docs pour favoris: %s" % json.dumps(filtre_docs))
        documents = collection_domaine.find(filtre_docs)

        favoris = list()
        for document in documents:
            # Creer favori
            favori = ConstantesGrosFichiers.DOCUMENT_FAVORIS_INFO.copy()

            favori[Constantes.DOCUMENT_INFODOC_LIBELLE] = document[Constantes.DOCUMENT_INFODOC_LIBELLE]
            favori[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = document[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
            favori[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = document[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]

            favoris.append(favori)

        ops = {
            '$push': {
                ConstantesGrosFichiers.DOCUMENT_FAVORIS_LISTE: {
                    '$each': favoris
                }
            }
        }

        # Le filtre s'assure que le favori n'est pas deja dans la liste ($not...)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FAVORIS,
            ConstantesGrosFichiers.DOCUMENT_FAVORIS_LISTE: {'$not': {'$elemMatch': {'uuid': doc_uuid}}}
        }
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug("Ajout favoris : filtre %s, ops %s" % (str(filtre), json.dumps(ops, indent=4)))

        return resultat

    def supprimer_favori(self, doc_uuid: str):
        self._logger.debug("Supprimer favori %s" % doc_uuid)
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$pull': {
                ConstantesGrosFichiers.DOCUMENT_FAVORIS_LISTE: {
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: doc_uuid
                }
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FAVORIS
        }
        resultat = collection_domaine.update_one(filtre, ops)
        self._logger.debug("Supprimer favoris : filtre %s, ops %s" % (str(filtre), json.dumps(ops, indent=4)))

        return resultat

# ******************* Processus *******************
class ProcessusGrosFichiers(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesGrosFichiers.COLLECTION_PROCESSUS_NOM


class ProcessusGrosFichiersMetadata(ProcessusGrosFichiers):

    def set_etape_suivante(self, etape_suivante=None, token_attente: list = None):
        if etape_suivante is None:
            etape_suivante = ProcessusGrosFichiersMetadata.mettre_a_jour_listes_et_collections.__name__
        super().set_etape_suivante(etape_suivante, token_attente)

    def mettre_a_jour_listes_et_collections(self):
        """
        Met a jour les liens dans les listes et collections correspondantes
        :return:
        """
        # Le processus a deja extrait les uuid vers les parametres (return ...)
        uuid_fichier = self.parametres.get('uuid_fichier')
        uuid_collection = self.parametres.get('uuid_collection')

        if uuid_fichier is not None:
            self._controleur.gestionnaire.maj_fichier_rapports_et_collections(uuid_fichier)

        if uuid_collection is not None:
            self._controleur.gestionnaire.maj_collections_rapports_et_collections(uuid_collection)

        self.set_etape_suivante('finale')  # Executer etape finale


class ProcessusTransactionNouvelleVersionMetadata(ProcessusGrosFichiersMetadata):
    """
    Processus de d'ajout de nouveau fichier ou nouvelle version d'un fichier
    C'est le processus principal qui depend de deux sous-processus:
     -  ProcessusTransactionNouvelleVersionTransfertComplete
     -  ProcessusNouvelleCleGrosFichier (pour securite 3.protege et 4.secure)
    """

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """ Sauvegarder une nouvelle version d'un fichier """
        transaction = self.charger_transaction()

        # Vierifier si le document de fichier existe deja
        self._logger.debug("Fichier existe, on ajoute une version")
        self.set_etape_suivante(
            ProcessusTransactionNouvelleVersionMetadata.ajouter_version_fichier.__name__)

        fuuid = transaction['fuuid']
        document_uuid = transaction.get('documentuuid')  # Represente la collection, si present

        return {'fuuid': fuuid, 'securite': transaction['securite'], 'collection_uuid': document_uuid}

    def ajouter_version_fichier(self):
        # Ajouter version au fichier
        transaction = self.charger_transaction()
        resultat = self._controleur.gestionnaire.maj_fichier(transaction)

        self.set_etape_suivante(
            ProcessusTransactionNouvelleVersionMetadata.attendre_transaction_transfertcomplete.__name__)

        return resultat

    def attendre_transaction_transfertcomplete(self):
        self.set_etape_suivante(
            ProcessusTransactionNouvelleVersionMetadata.confirmer_hash.__name__,
            self._get_tokens_attente())

    def confirmer_hash(self):
        if self.parametres.get('attente_token') is not None:
            # Il manque des tokens, on boucle.
            self._logger.debug('attendre_transaction_transfertcomplete(): Il reste des tokens actifs, on boucle')
            self.set_etape_suivante(
                ProcessusTransactionNouvelleVersionMetadata.confirmer_hash.__name__)
            return

        # Verifie que le hash des deux transactions (metadata, transfer complete) est le meme.

        collection_uuid = self.parametres.get('collection_uuid')
        if collection_uuid is None:
            self.set_etape_suivante()  # Processus termine
        else:
            self.set_etape_suivante(
                ProcessusTransactionNouvelleVersionMetadata.ajouter_a_collection.__name__)

    def ajouter_a_collection(self):
        fichier_uuid = self.parametres.get('uuid_fichier')
        collection_uuid = self.parametres.get('collection_uuid')

        self._controleur._gestionnaire_domaine.ajouter_documents_collection(collection_uuid, [fichier_uuid])

        self.set_etape_suivante()  # Processus termine

    def _get_tokens_attente(self):
        fuuid = self.parametres.get('fuuid')
        tokens = [
            '%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE, fuuid)
        ]

        if self.parametres['securite'] in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]:
            tokens.append('%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_CLES_RECUES, fuuid))

        return tokens


class ProcessusTransactionNouvelleVersionTransfertComplete(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """
        Emet un evenement pour indiquer que le transfert complete est arrive. Comme on ne donne pas de prochaine
        etape, une fois les tokens consommes, le processus sera termine.
        """
        transaction = self.charger_transaction()
        fuuid = transaction.get('fuuid')

        self.set_etape_suivante(ProcessusTransactionNouvelleVersionTransfertComplete.declencher_resumer.__name__)
        return {'fuuid': fuuid}

    def declencher_resumer(self):
        fuuid = self.parametres.get('fuuid')
        token_resumer = '%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE, fuuid)
        self.resumer_processus([token_resumer])

        # Une fois les tokens consommes, le processus sera termine.
        self.set_etape_suivante()


class ProcessusTransactionNouvelleVersionClesRecues(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """
        Emet un evenement pour indiquer que les cles sont recues par le MaitreDesCles.
        """
        transaction = self.charger_transaction()
        fuuid = transaction.get('fuuid')

        token_resumer = '%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_CLES_RECUES, fuuid)
        self.resumer_processus([token_resumer])

        self.set_etape_suivante()  # Termine
        return {'fuuid': fuuid}


class ProcessusTransactionRenommerDeplacerFichier(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_doc = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        nouveau_nom = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER)

        self._controleur._gestionnaire_domaine.renommer_deplacer_fichier(uuid_doc, nouveau_nom)

        # Le resultat a deja ancien_repertoire_uuid. On ajoute le nouveau pour permettre de traiter les deux.
        resultat = {
            'uuid_fichier': uuid_doc
        }

        self.set_etape_suivante()  # Termine

        return resultat


class ProcessusTransactionCommenterFichier(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        commentaire = transaction[ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES]
        self._controleur._gestionnaire_domaine.maj_commentaire_fichier(uuid_fichier, commentaire)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionChangerEtiquettesFichier(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        etiquettes = {}
        for etiquette in transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]:
            etiquettes[etiquette] = True
        self._controleur._gestionnaire_domaine.maj_libelles_fichier(uuid_fichier, etiquettes)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionSupprimerFichier(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        self._controleur._gestionnaire_domaine.supprimer_fichier(uuid_fichier)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionRecupererFichier(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        self._controleur._gestionnaire_domaine.recuperer_fichier(uuid_fichier)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionNouvelleCollection(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        # nom_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]
        documents = transaction.get(ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS)

        uuid_collection = str(uuid.uuid1())

        self._controleur._gestionnaire_domaine.creer_collection(uuid_collection, documents)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionRenommerCollection(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        nouveau_nom_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur._gestionnaire_domaine.renommer_collection(uuid_collection, nouveau_nom_collection)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionCommenterCollection(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        commentaire = transaction[ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES]

        self._controleur._gestionnaire_domaine.commenter_collection(uuid_collection, commentaire)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionSupprimerCollection(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur._gestionnaire_domaine.supprimer_collection(uuid_collection)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionRecupererCollection(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur._gestionnaire_domaine.recuperer_collection(uuid_collection)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionChangerLibellesCollection(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        libelles = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]

        self._controleur._gestionnaire_domaine.changer_libelles_collection(uuid_collection, libelles)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionFigerCollection(ProcessusGrosFichiersMetadata):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        """
        Figer la collection qui va servir a creer le torrent.
        :return:
        """
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur._gestionnaire_domaine.figer_collection(uuid_collection)
        self.set_etape_suivante(ProcessusTransactionFigerCollection.creer_fichier_torrent.__name__)

        return {'uuid_collection': uuid_collection}

    def creer_fichier_torrent(self):
        """
        Generer un fichier torrent et transmettre au module de consignation.
        :return:
        """

        self.set_etape_suivante(ProcessusTransactionFigerCollection.publier_torrent.__name__)

    def publier_torrent(self):
        """
        Transmet des messages pour informer les publicateurs de la creation d'un nouveau torrent.
        :return:
        """

        self.set_etape_suivante()


class ProcessusTransactionAjouterFichiersDansCollection(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        collectionuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        documentsuuid = transaction[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS]
        self._controleur._gestionnaire_domaine.ajouter_documents_collection(collectionuuid, documentsuuid)
        self.set_etape_suivante()


class ProcessusTransactionRetirerFichiersDeCollection(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        collectionuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        documentsuuid = transaction[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS]
        self._controleur._gestionnaire_domaine.retirer_fichiers_collection(collectionuuid, documentsuuid)
        self.set_etape_suivante()


class ProcessusTransactionAjouterFavori(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        doc_uuid = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC)
        self._controleur._gestionnaire_domaine.ajouter_favori(doc_uuid)
        self.set_etape_suivante()


class ProcessusTransactionSupprimerFavori(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        doc_uuid = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC)
        self._controleur._gestionnaire_domaine.supprimer_favori(doc_uuid)
        self.set_etape_suivante()
