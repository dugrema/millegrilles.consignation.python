# Domaine de l'interface GrosFichiers
from pymongo.errors import DuplicateKeyError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGrosFichiers, ConstantesParametres
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete
from millegrilles.MGProcessus import MGProcessusTransaction, MGPProcesseur

import os
import logging
import uuid
import datetime
import json


class TraitementRequetesPubliquesGrosFichiers(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        if routing_key == 'requete.' + ConstantesGrosFichiers.REQUETE_VITRINE_FICHIERS:
            fichiers_vitrine = self.gestionnaire.get_document_vitrine_fichiers()
            self.transmettre_reponse(message_dict, fichiers_vitrine, properties.reply_to, properties.correlation_id)
        elif routing_key == 'requete.' + ConstantesGrosFichiers.REQUETE_VITRINE_ALBUMS:
            fichiers_vitrine = self.gestionnaire.get_document_vitrine_albums()
            self.transmettre_reponse(message_dict, fichiers_vitrine, properties.reply_to, properties.correlation_id)
        elif routing_key == 'requete.' + ConstantesGrosFichiers.REQUETE_COLLECTION_FIGEE:
            uuid_collection = message_dict.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC)
            fichiers_vitrine = self.gestionnaire.get_collection_figee_recente_par_collection(uuid_collection)
            self.transmettre_reponse(message_dict, fichiers_vitrine, properties.reply_to, properties.correlation_id)
        else:
            raise Exception("Requete publique non supportee " + routing_key)


class TraitementRequetesProtegeesGrosFichiers(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        if routing_key == 'requete.' + ConstantesGrosFichiers.REQUETE_VITRINE_FICHIERS:
            fichiers_vitrine = self.gestionnaire.get_document_vitrine_fichiers()
            self.transmettre_reponse(message_dict, fichiers_vitrine, properties.reply_to, properties.correlation_id)
        elif routing_key == 'requete.' + ConstantesGrosFichiers.REQUETE_VITRINE_ALBUMS:
            fichiers_vitrine = self.gestionnaire.get_document_vitrine_albums()
            self.transmettre_reponse(message_dict, fichiers_vitrine, properties.reply_to, properties.correlation_id)
        elif routing_key == 'requete.' + ConstantesGrosFichiers.REQUETE_COLLECTION_FIGEE:
            uuid_collection = message_dict.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC)
            fichiers_vitrine = self.gestionnaire.get_collection_figee_recente_par_collection(uuid_collection)
            self.transmettre_reponse(message_dict, fichiers_vitrine, properties.reply_to, properties.correlation_id)
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)


class GestionnaireGrosFichiers(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_middleware = None
        self._traitement_noeud = None
        self._traitement_cedule = None
        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesGrosFichiers(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesGrosFichiers(self)
        }

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_CONFIGURATION, ConstantesGrosFichiers.DOCUMENT_DEFAUT)

        # Ajout document favoris
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_FAVORIS, ConstantesGrosFichiers.DOCUMENT_FAVORIS)

        # Ajout documents vitrine
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_VITRINE_FICHIERS, ConstantesGrosFichiers.DOCUMENT_VITRINE_FICHIERS)
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_VITRINE_ALBUMS, ConstantesGrosFichiers.DOCUMENT_VITRINE_ALBUMS)

        # Creation liste de recherche speciale pour l'activite des fichiers
        liste_recherche = ConstantesGrosFichiers.DOCUMENT_RAPPORT_RECHERCHE.copy()
        liste_recherche[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesGrosFichiers.LIBVAL_RAPPORT_ACTIVITE
        liste_recherche['description'] = "Activité récente"
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_RAPPORT_ACTIVITE, liste_recherche)

        self.demarrer_watcher_collection(
            ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM, ConstantesGrosFichiers.QUEUE_ROUTING_CHANGEMENTS)

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_queue_configuration(self):
        queue_config = super().get_queue_configuration()
        queue_config.append(
            {
                'nom': '%s.%s' % (self.get_nom_queue(), 'transactions'),
                'routing': [
                    'destinataire.domaine.%s.#' % self.get_nom_domaine(),
                ],
                'exchange': self.configuration.exchange_noeuds,
                'ttl': 300000,
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
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CHANGER_ETIQUETTES_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionChangerEtiquettesFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionSupprimerFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RECUPERER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRecupererFichier"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_DECRYPTER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionDecrypterFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CLESECRETE_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionCleSecreteFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVEAU_FICHIER_DECRYPTE:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouveauFichierDecrypte"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_ASSOCIER_THUMBNAIL:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAssocierThumbnail"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_ASSOCIER_VIDEO_TRANSCODE:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusAssocierVideoTranscode"

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
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CHANGER_ETIQUETTES_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionChangerEtiquettesCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CREERTORRENT_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionCreerTorrentCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_AJOUTER_FICHIERS_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAjouterFichiersDansCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RETIRER_FICHIERS_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRetirerFichiersDeCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CHANGER_SECURITE_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ChangerNiveauSecuriteCollection"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_AJOUTER_FAVORI:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAjouterFavori"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_FAVORI:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionSupprimerFavori"

        # Torrent
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_TORRENT_NOUVEAU:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionTorrentNouveau"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_TORRENT_SEEDING:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionTorrentSeeding"

        # Distribution
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_PUBLIER_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusPublierCollection"

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
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
            ],
            name='mglibelle'
        )

        # Index pour trouver un fichier par UUID
        collection_domaine.create_index(
            [
                (ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID, 1),
            ],
            name='fuuid'
        )

        # Index pour trouver une version de fichier par FUUID
        collection_domaine.create_index(
            [
                ('%s.%s' %
                 (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                  ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID),
                 1),
            ],
            name='versions-fuuid'
        )

        # Index pour trouver une version de fichier par FUUID
        collection_domaine.create_index(
            [
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
                (ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES, 1),
                (ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER, 1),
            ],
            name='recherche'
        )

        # Index pour la recherche temps reel
        collection_domaine.create_index(
            [
                (ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES, 1),
            ],
            name='etiquettes'
        )

        # Index par SHA256 / taille. Permet de determiner si le fichier existe deja (et juste faire un lien).
        collection_domaine.create_index(
            [
                ('%s.%s' %
                 (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                  ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256),
                 1),
                ('%s.%s' %
                 (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                  ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE),
                 1),
            ],
            name='sha256-taille'
        )

    def get_nom_domaine(self):
        return ConstantesGrosFichiers.DOMAINE_NOM

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

    def get_fichier_par_fuuid(self, fuuid):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            '%s.%s' % (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS, fuuid): {
                '$exists': True,
            }
        }
        self._logger.info("Fichier par fuuid: %s" % filtre)

        fichier = collection_domaine.find_one(filtre)

        return fichier

    def get_collection_par_uuid(self, uuid_collection):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        collection = collection_domaine.find_one(filtre)

        return collection

    def get_collection_figee_par_uuid(self, uuid_collection_figee):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection_figee,
        }

        collection = collection_domaine.find_one(filtre)

        return collection

    def get_collection_figee_recente_par_collection(self, uuid_collection):
        collection = self.get_collection_par_uuid(uuid_collection)

        # Determiner la plus recente collection figee
        liste_figees = collection.get(ConstantesGrosFichiers.DOCUMENT_COLLECTIONS_FIGEES)
        if liste_figees is not None:
            info_collection_figee = liste_figees[0]
            uuid_collection_figee = info_collection_figee[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
            collection_figee = self.get_collection_figee_par_uuid(uuid_collection_figee)
            return collection_figee

        return None

    def get_document_vitrine_fichiers(self):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_VITRINE_FICHIERS,
        }
        return collection_domaine.find_one(filtre)

    def get_document_vitrine_albums(self):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_VITRINE_ALBUMS,
        }
        return collection_domaine.find_one(filtre)

    def get_documents_vitrine(self):
        documents = list()
        documents.append(self.get_document_vitrine_albums())
        documents.append(self.get_document_vitrine_fichiers())
        return documents

    def maj_fichier(self, transaction):
        """
        Genere ou met a jour un document de fichier avec l'information recue dans une transaction metadata.
        :param transaction:
        :return: True si c'est la version la plus recent, false si la transaction est plus vieille.
        """
        domaine = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE].get(Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE)
        if domaine not in [ConstantesGrosFichiers.TRANSACTION_TYPE_METADATA, ConstantesGrosFichiers.TRANSACTION_TORRENT_NOUVEAU]:
            raise ValueError('La transaction doit etre de type metadata ou nouveau torrent. Trouve: %s' % domaine)

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

        set_on_insert = ConstantesGrosFichiers.DOCUMENT_FICHIER.copy()
        nom_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]
        set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] =\
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = nom_fichier

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
            ConstantesGrosFichiers.DOCUMENT_SECURITE,
        ]
        date_version = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT].get('_estampille')
        info_version = {
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_VERSION: date_version
        }
        for key in transaction.keys():
            if key in masque_transaction:
                info_version[key] = transaction[key]

        # Extraire l'extension originale
        extension_fichier = os.path.splitext(nom_fichier)[1].lower().replace('.', '')
        if extension_fichier != '':
            info_version[ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL] = extension_fichier
            set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL] = extension_fichier

        set_operations['%s.%s' % (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS, fuuid)] = info_version

        if plus_recente_version:
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_DATEVCOURANTE] = date_version
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE] = \
                transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = \
                transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
            set_operations[ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE] = \
                transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE]
            set_operations[ConstantesGrosFichiers.DOCUMENT_SECURITE] = \
                transaction[ConstantesGrosFichiers.DOCUMENT_SECURITE]

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

        # Mettre a jour les etiquettes du fichier au besoin
        etiquettes = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES)
        if etiquettes is not None:
            self.maj_etiquettes(uuid_fichier, ConstantesGrosFichiers.LIBVAL_FICHIER, etiquettes)

        return {'plus_recent': plus_recente_version, 'uuid_fichier': uuid_fichier, 'info_version': info_version}

    def renommer_deplacer_fichier(self, uuid_doc, changements):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operations = changements

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_doc,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }

        resultat = collection_domaine.update_one(filtre, {
            '$set': set_operations,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        })
        self._logger.debug('renommer_deplacer_fichier resultat: %s' % str(resultat))

    def maj_commentaire_fichier(self, uuid_fichier, changements: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = changements
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER
        }
        resultat = collection_domaine.update_one(filtre, {
            '$set': set_operation
        })
        self._logger.debug('maj_commentaire_fichier resultat: %s' % str(resultat))

    def maj_etiquettes(self, uuid_fichier, type_document, etiquettes: list):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        # Mettre les etiquettes en lowercase, dedupliquer et trier par ordre naturel
        etiquettes_triees = list(set([e.lower() for e in etiquettes]))
        etiquettes_triees.sort()

        set_operation = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES: etiquettes_triees
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: type_document
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

    def renommer_collection(self, uuid_collection: str, changements: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': changements,
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

    def commenter_collection(self, uuid_collection: str, changements: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        ops = {
            '$set': changements,
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

        # Charger la collection et la re-sauvegarder avec _mg-libelle = collection.figee
        # Aussi generer un uuidv1 pour uuid-fige
        collection_figee = collection_domaine.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        })

        # Retirer ObjectID Mongo pour reinserer le document
        del collection_figee[Constantes.MONGO_DOC_ID]

        # Modifier les cles de la collection pour la 'figer'
        uuid_collection_figee = str(uuid.uuid1())
        collection_figee[Constantes.DOCUMENT_INFODOC_LIBELLE] = ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE
        collection_figee[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = uuid_collection_figee
        collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE] = uuid_collection

        # Re-inserer collection (c'est maintenant une copie figee de la collection MongoDB originale)
        resultat_insertion_figee = collection_domaine.insert_one(collection_figee)

        info_collection_figee = {
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_FIGEE_DATE: datetime.datetime.utcnow(),
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection_figee,
        }
        ops = {
            '$push': {
                ConstantesGrosFichiers.DOCUMENT_COLLECTIONS_FIGEES: {
                    '$each': [info_collection_figee],
                    '$sort': {ConstantesGrosFichiers.DOCUMENT_COLLECTION_FIGEE_DATE: -1},
                }
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

        return {
            'uuid_collection_figee': uuid_collection_figee,
            'etiquettes': collection_figee[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]
        }

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
        """
        Effectue une project d'un document de fichier pour l'insertion/maj dans une collection.`
        :param entree:
        :return:
        """
        fichier_uuid = entree[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        type_document = entree[Constantes.DOCUMENT_INFODOC_LIBELLE]

        filtre_fichier = [
            ConstantesGrosFichiers.DOCUMENT_SECURITE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE,
        ]

        filtre_multilingue = [
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER,
        ]

        filtre_version = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE_480P,
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_VERSION,
        ]

        entree_filtree = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: type_document,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: fichier_uuid,
        }

        # Copier valeurs de base
        for cle in filtre_fichier:
            valeur = entree.get(cle)
            if valeur is not None:
                entree_filtree[cle] = valeur

        # Appliquer filtre multilingue
        for key, value in entree.items():
            for champ in filtre_multilingue:
                if key.startswith(champ):
                    entree_filtree[key] = value

        if type_document == ConstantesGrosFichiers.LIBVAL_FICHIER:
            fuuid = entree[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE]
            entree_filtree[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID] = fuuid
            version_courante = entree[ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS].get(fuuid)

            # Copier valeurs specifiques a la version
            for cle in filtre_version:
                valeur = version_courante.get(cle)
                if valeur is not None:
                    entree_filtree[cle] = valeur

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

    def maj_fichier_rapports_et_collections(self, uuid_fichier: str, type_operation: str):
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
        etiquettes = fichier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES)

        # Mettre a jour les listes - on match sur les etiquettes (toutes les etiquettes de la liste
        # doivent etre presentes dans le document)
        self.__ajouter_activite(fichier, type_operation)

    def maj_collections_rapports_et_collections(self, uuid_collection: str, type_operation: str = None):
        """
        Met a jour les listes et collections qui correspondent au fichier.
        :param uuid_collection:
        :param type_operation:
        :return:
        """

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection = collection_domaine.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        })
        # etiquettes = collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]

        # Mettre a jour les listes - on match sur les etiquettes (toutes les etiquettes de la liste
        # doivent etre presentes dans le document)
        self.__ajouter_activite(collection, type_operation)

    def __ajouter_activite(self, activite, type_activite):
        wrapper_activite = {
            'date': datetime.datetime.utcnow(),
            'uuid_activite': str(uuid.uuid1()),
            'type_activite': type_activite,
            'sujet': activite
        }

        ops = {
            '$push': {
                'activites': {
                    '$each': [wrapper_activite],
                    '$sort': {'date': -1},
                    '$slice': 100,
                }
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_RAPPORT_ACTIVITE
        }

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update(filtre, ops)


    def ajouter_favori(self, doc_uuid: str):
        self._logger.debug("Ajouter favor %s" % doc_uuid)
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        filtre_docs = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesGrosFichiers.LIBVAL_FICHIER, ConstantesGrosFichiers.LIBVAL_COLLECTION, ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE]
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

    def creer_torrent(self, uuid_collection_figee):
        """
        Genere un repertoire de seeding et un
        :param uuid_collection_figee:
        :return:
        """

    def associer_hashstring_torrent(self, collection_figee: str, hashstring: str):
        self._logger.debug("associer_seeding_torrent %s, hashstring %s" % (collection_figee, hashstring))
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        # Ajouter hashstring a la collection figee
        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_TORRENT_HASHSTRING: hashstring
            }
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: collection_figee
        }
        collection_figee = collection_domaine.find_one_and_update(filtre, ops)
        self._logger.debug("associer_seeding_torrent : filtre %s, ops %s" % (str(filtre), json.dumps(ops, indent=4)))

        # Ajouter hashstring a la liste des collections figees de la collection originale
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE]
        }
        collection_active = collection_domaine.find_one(filtre)
        liste_collections_figees = collection_active[ConstantesGrosFichiers.DOCUMENT_COLLECTIONS_FIGEES]
        for sommaire_fige in liste_collections_figees:
            if sommaire_fige['uuid'] == collection_figee['uuid']:
                sommaire_fige[ConstantesGrosFichiers.DOCUMENT_TORRENT_HASHSTRING] = hashstring

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_COLLECTIONS_FIGEES: liste_collections_figees
            }
        }
        collection_domaine.update_one(filtre, ops)

    def enregistrer_fichier_decrypte(self, transaction):

        fuuid_crypte = transaction.get('fuuid_crypte')
        fuuid_decrypte = transaction.get('fuuid_decrypte')
        taille = transaction.get('taille')
        sha256_fichier = transaction.get('sha256Hash')
        niveau_securite = transaction.get(ConstantesGrosFichiers.DOCUMENT_SECURITE)
        if niveau_securite is None:
            niveau_securite = Constantes.SECURITE_PRIVE

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        label_versions_fuuid_crypte = '%s.%s' % (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS, fuuid_crypte)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            label_versions_fuuid_crypte: {'$exists': True},
        }
        document_fichier = collection_domaine.find_one(filtre)

        date_now = datetime.datetime.utcnow()

        info_fichier_decrypte = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER: document_fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER],
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_VERSION: date_now,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: fuuid_decrypte,
            ConstantesGrosFichiers.DOCUMENT_SECURITE: Constantes.SECURITE_PRIVE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: document_fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE],
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE: taille,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256: sha256_fichier
        }

        if transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL) is not None:
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL] = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL]

        if transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW) is not None:
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW] = transaction[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW]
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW] = transaction[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW]

        if transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P) is not None:
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P] = transaction[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P]
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P] = transaction[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P]
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE_480P] = transaction[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE_480P]
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256_480P] = transaction[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256_480P]
            info_fichier_decrypte[ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA_VIDEO] = transaction[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA][ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA_VIDEO]

        label_versions_fuuid_decrypte = '%s.%s' % (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS, fuuid_decrypte)
        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_SECURITE: niveau_securite,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE: fuuid_decrypte,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_DATEVCOURANTE: date_now,
                # Taille maj
                label_versions_fuuid_decrypte: info_fichier_decrypte,
            },
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
            }
        }
        collection_domaine.update_one(filtre, ops)

        return {
            'uuid': document_fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC],
            'info_fichier_decrypte': info_fichier_decrypte,
        }

    def associer_video_transcode(self, transaction):
        prefixe_version = '%s.%s' % (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS, transaction['fuuid'])
        set_ops = {
            '%s.%s' % (prefixe_version, ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P): transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P],
            '%s.%s' % (prefixe_version, ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P): transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P],
            '%s.%s' % (prefixe_version, ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA_VIDEO): transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA_VIDEO],
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            prefixe_version: {'$exists': True},
        }

        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        document_fichier = collection_domaine.find_one_and_update(filtre, ops)
        return document_fichier

    def enregistrer_image_info(self, uuid_fichier, image_info):

        fuuid_fichier = image_info[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]

        info_image_maj = dict()
        if image_info.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL) is not None:
            libelle_thumbnail = '%s.%s.%s' % (
                ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                fuuid_fichier,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL
            )
            info_image_maj[libelle_thumbnail] = image_info[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL]

        if image_info.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW) is not None:
            libelle_fuuid_preview = '%s.%s.%s' % (
                ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                fuuid_fichier,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW
            )
            info_image_maj[libelle_fuuid_preview] = image_info[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW]

            libelle_mimetype_preview = '%s.%s.%s' % (
                ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                fuuid_fichier,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW
            )
            info_image_maj[libelle_mimetype_preview] = image_info[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW]

        if len(info_image_maj.keys()) > 0:
            ops = {
                '$set': info_image_maj,
                '$currentDate': {
                    Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
                }
            }

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier
            }

            collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
            collection_domaine.update_one(filtre, ops)

    def maj_fichier_dans_collection(self, uuid_fichier):
        """
        Mettre a jour l'element _documents_ de toutes les collections avec le fichier.
        """
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        fichier = collection_domaine.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
        })

        sommaire_fichier = self.__filtrer_entree_collection(fichier)

        label_versions_fuuid = '%s.%s' % (ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS, uuid_fichier)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            label_versions_fuuid: {'$exists': True},
        }
        ops = {
            '$set': {
                label_versions_fuuid: sommaire_fichier
            }
        }
        collection_domaine.update(filtre, ops)

    def associer_thumbnail(self, fuuid, thumbnail, metadata = None):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            '%s.%s' % (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS, fuuid): {
                '$exists': True,
            }
        }

        set_opts = {
            '%s.%s.%s' % (
                ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                fuuid,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL
            ): thumbnail
        }
        if metadata is not None:
            if metadata.get('data_video') is not None:
                libelle_data_video = '%s.%s.%s' % (
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                    fuuid,
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_DATA_VIDEO
                )
                set_opts[libelle_data_video] = metadata['data_video']

        ops = {
            '$set': set_opts
        }

        self._logger.debug("Ajout thumbnail pour fuuid: %s" % filtre)
        update_info = collection_domaine.update_one(filtre, ops)
        if update_info.matched_count < 1:
            raise Exception("Erreur ajout thumbnail pour fuuid " + fuuid)

    def changer_niveau_securite_collection(self, uuid_collection, niveau_securite):
        """
        Change le niveau de securite de la collection.
        N'inclus pas le traitement des fichiers
        :param uuid:
        :param niveau_securite:
        :return:
        """
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        ops = {
            '$set': {
                ConstantesGrosFichiers.DOCUMENT_SECURITE: niveau_securite
            }
        }

        self._logger.debug("Changement securite pour collection uuid: %s" % uuid_collection)
        update_info = collection_domaine.update_one(filtre, ops)
        if update_info.matched_count < 1:
            raise Exception("Erreur changement securite pour collection " + uuid_collection)

    def changer_securite_fichiers(self, liste_uuid: list, securite_destination: str):
        """
        Change le niveau de securite d'une liste de fichiers.
        N'effectue pas la logique de cryptage/decryptage
        :param liste_uuid: Liste de uuid de fichier
        :param securite_destination: Niveau de securite destination pour les fichiers
        :return:
        """
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operations = dict()
        set_operations[ConstantesGrosFichiers.DOCUMENT_SECURITE] = securite_destination

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': liste_uuid},
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }

        resultat = collection_domaine.update_many(filtre, {
            '$set': set_operations,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        })
        # if resultat.matched_count < len(liste_uuid):
        #     raise Exception("Nombre de fichiers modifies ne correspond pas, changes < demandes (%d < %d)" %
        #                     (resultat.matched_count, len(liste_uuid)))

    def maj_documents_vitrine(self, collection_figee_uuid):
        collection_figee = self.get_collection_figee_par_uuid(collection_figee_uuid)
        self.__maj_vitrine_fichiers(collection_figee)
        self.__maj_vitrine_albums(collection_figee)

    def __maj_vitrine_fichiers(self, collection_figee):
        etiquettes = collection_figee.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES)
        uuid_collection = collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE]

        champs_filtre_collections = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC,
        ]

        champs_filtre_fichiers = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_DATEVCOURANTE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P,
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_VERSION,
        ]

        champs_filtre_multilingue = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_COMMENTAIRES,
        ]

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_VITRINE_FICHIERS,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        ops = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$setOnInsert': set_on_insert,
        }

        if not ConstantesGrosFichiers.LIBELLE_PUBLICATION_CACHERFICHIERS in etiquettes:

            collection_figee_filtree = dict()
            # On met a jour la liste des fichiers
            ops = {
                '$set': {
                    'collections.%s' % uuid_collection: collection_figee_filtree
                }
            }
            for key, value in collection_figee.items():
                if key in champs_filtre_collections:
                    collection_figee_filtree[key] = value
                else:
                    for multikey in champs_filtre_multilingue:
                        if key.startswith(multikey):
                            collection_figee_filtree[key] = value

            if ConstantesGrosFichiers.LIBELLE_PUBLICATION_TOP in etiquettes:
                # Cette collection fournit des fichiers a mettre dans le haut de la page fichiers
                # liste_fichiers_top = list()
                for fichier_uuid, fichier in collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS].items():
                    fichier_filtre = dict()
                    for key, value in fichier.items():
                        if key in champs_filtre_fichiers:
                            fichier_filtre[key] = value
                        else:
                            for multikey in champs_filtre_multilingue:
                                if key.startswith(multikey):
                                    fichier_filtre[key] = value
                    # liste_fichiers_top.append(fichier_filtre)
                    ops['$set']['top.%s'%fichier_uuid] = fichier_filtre

        else:
            # S'assurer que la collection n'est pas publiee dans fichiers
            pass

        self._logger.info("Operation update vitrine.fichiers: %s" % str(ops))

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_VITRINE_FICHIERS}, ops)

    def __maj_vitrine_albums(self, collection_figee):
        etiquettes = collection_figee.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES)
        uuid_collection = collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE]

        # Determiner si on a au moins une image/video
        contient_medias = any(f.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW) is not None for f in collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS].values())
        if not contient_medias:
            return

        champs_filtre_collections = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC,
        ]

        champs_filtre_fichiers = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_DATEVCOURANTE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SHA256,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P,
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_VERSION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL,
        ]

        champs_filtre_multilingue = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_COMMENTAIRES,
        ]

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_VITRINE_FICHIERS,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        ops = {
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$setOnInsert': set_on_insert,
        }

        collection_figee_filtree = dict()
        # On met a jour la liste des fichiers
        ops.update({
            '$set': {
                'collections.%s' % uuid_collection: collection_figee_filtree
            }
        })
        for key, value in collection_figee.items():
            if key in champs_filtre_collections:
                collection_figee_filtree[key] = value
            else:
                for multikey in champs_filtre_multilingue:
                    if key.startswith(multikey):
                        collection_figee_filtree[key] = value

        # Capture un thumbnail/preview pour la collection (au hasard)
        for fichier in collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS].values():
            if fichier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW) is not None:
                collection_figee_filtree[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW] = fichier[
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW]
                collection_figee_filtree[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW] = fichier[
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW]
                collection_figee_filtree[ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL] = fichier[
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL]
                break

        if ConstantesGrosFichiers.LIBELLE_PUBLICATION_TOP in etiquettes:
            # Cette collection fournit des fichiers a mettre dans le carousel de l'album
            for fichier_uuid, fichier in collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS].items():
                if fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW] is not None:
                    fichier_filtre = dict()
                    for key, value in fichier.items():
                        if key in champs_filtre_fichiers:
                            fichier_filtre[key] = value
                        else:
                            for multikey in champs_filtre_multilingue:
                                if key.startswith(multikey):
                                    fichier_filtre[key] = value
                    # liste_fichiers_top.append(fichier_filtre)
                    ops['$set']['top.%s'%fichier_uuid] = fichier_filtre

        else:
            # S'assurer que la collection n'est pas publiee dans fichiers
            pass

        self._logger.info("Operation update vitrine.albums: %s" % str(ops))

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(
            {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_VITRINE_ALBUMS}, ops)


# ******************* Processus *******************
class ProcessusGrosFichiers(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesGrosFichiers.COLLECTION_PROCESSUS_NOM


class ProcessusGrosFichiersActivite(ProcessusGrosFichiers):

    def set_etape_suivante(self, etape_suivante=None, token_attente: list = None):
        if etape_suivante is None:
            etape_suivante = ProcessusGrosFichiersActivite.mettre_a_jour_listes_et_collections.__name__
        super().set_etape_suivante(etape_suivante, token_attente)

    def mettre_a_jour_listes_et_collections(self):
        """
        Met a jour les liens dans les listes et collections correspondantes
        :return:
        """

        # Le processus a deja extrait les uuid vers les parametres (return ...)
        uuid_fichier = self.parametres.get('uuid_fichier')
        uuid_collection = self.parametres.get('uuid_collection')
        type_operation = self.parametres.get('type_operation')
        if type_operation is None:
            type_operation = self.__class__.__name__

        if uuid_fichier is not None:
            self._controleur.gestionnaire.maj_fichier_rapports_et_collections(uuid_fichier, type_operation)

        if uuid_collection is not None:
            self._controleur.gestionnaire.maj_collections_rapports_et_collections(uuid_collection, type_operation)

        self.set_etape_suivante('finale')  # Executer etape finale


class ProcessusTransactionNouvelleVersionMetadata(ProcessusGrosFichiersActivite):
    """
    Processus de d'ajout de nouveau fichier ou nouvelle version d'un fichier
    C'est le processus principal qui depend de deux sous-processus:
     -  ProcessusTransactionNouvelleVersionTransfertComplete
     -  ProcessusNouvelleCleGrosFichier (pour securite 3.protege et 4.secure)
    """

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initiale(self):
        """ Sauvegarder une nouvelle version d'un fichier """
        transaction = self.charger_transaction()

        # Vierifier si le document de fichier existe deja
        self._logger.debug("Fichier existe, on ajoute une version")

        fuuid = transaction['fuuid']
        document_uuid = transaction.get('documentuuid')  # Represente la collection, si present

        transaction = self.charger_transaction()
        resultat = self._controleur.gestionnaire.maj_fichier(transaction)
        resultat.update({
            'fuuid': fuuid,
            'securite': transaction['securite'],
            'collection_uuid': document_uuid,
            'type_operation': 'Nouveau fichier',
            'mimetype': transaction['mimetype'],
        })

        self.set_etape_suivante(
            ProcessusTransactionNouvelleVersionMetadata.confirmer_reception_update_collections.__name__,
            self._get_tokens_attente(resultat))

        return resultat

    def confirmer_reception_update_collections(self):
        # Verifie si la transaction correspond a un document d'image
        self.__logger.debug("Debut confirmer_reception_update_collections")
        mimetype = self.parametres['mimetype'].split('/')[0]
        fuuid = self.parametres['fuuid']
        est_image = mimetype == 'image'
        est_video = mimetype == 'video'

        chiffre = self.parametres['securite'] in [Constantes.SECURITE_PROTEGE]
        if not chiffre and (est_image or est_video):
            tokens_attente = self._get_tokens_attente({'fuuid': fuuid, 'securite': None})

            self.__logger.debug("Token attente image preview: %s" % str(tokens_attente))

            if est_video:
                # Transmettre une commande de transcodage apres cette etape
                transaction_transcoder = {
                    'fuuid': fuuid,
                    'mimetype': mimetype,
                    'extension': self.parametres['info_version']['extension'],
                    'securite': self.parametres['securite'],
                }
                self.ajouter_commande_a_transmettre('commande.grosfichiers.transcoderVideo', transaction_transcoder)

            transaction_image = None
            try:
                id_transaction_image = self.parametres['millegrilles']['domaines']['GrosFichiers'][
                    'nouvelleVersion']['transfertComplete']['_id-transaction']
                transaction_image = self.controleur.gestionnaire.get_transaction(id_transaction_image)
            except Exception as e:
                self.__logger.exception("Erreur chargement preview/thumbnail")

            if transaction_image is not None:
                self.__logger.debug("Enregistrement preview et thumbnail image : %s" % str(transaction_image))
                self.controleur.gestionnaire.enregistrer_image_info(
                    self.parametres['uuid_fichier'], transaction_image)
            else:
                self.__logger.warning("Image ajoutee sans thumbnail/preview (non transmis)")

        # Met a jour les collections existantes avec ce fichier
        uuid_fichier = self.parametres['uuid_fichier']
        self.controleur.gestionnaire.maj_fichier_dans_collection(uuid_fichier)

        # Verifier si le fichier est une image protegee - il faut generer un thumbnail
        self.__logger.debug("Mimetype fichier %s" % self.parametres['mimetype'])
        if chiffre and (est_image or est_video):
            self.__logger.info("Mimetype est une image/video")

            # Transmettre requete pour certificat de consignation.grosfichiers
            self.set_requete('pki.role.fichiers', {})

            self.set_etape_suivante(ProcessusTransactionNouvelleVersionMetadata.attente_cle_decryptage.__name__)
        else:
            self._traitement_collection()

        self.__logger.debug("Fin confirmer_reception_update_collections")

    def attente_cle_decryptage(self):
        fuuid = self.parametres['fuuid']

        fingerprint_fichiers = self.parametres['reponse'][0]['fingerprint']

        # Transmettre transaction au maitre des cles pour recuperer cle secrete decryptee
        transaction_maitredescles = {
            'fuuid': fuuid,
            'fingerprint': fingerprint_fichiers,
        }
        domaine = 'millegrilles.domaines.MaitreDesCles.decryptageGrosFichier'

        # Effectuer requete pour re-chiffrer la cle du document pour le consignateur de transactions
        self.set_requete(domaine, transaction_maitredescles)

        # self.controleur.generateur_transactions.soumettre_transaction(transaction_maitredescles, domaine)

        # token_attente = 'decrypterFichier_cleSecrete:%s' % fuuid
        self.set_etape_suivante(ProcessusTransactionNouvelleVersionMetadata.demander_thumbnail_protege.__name__)

    def demander_thumbnail_protege(self):

        information_cle_secrete = self.parametres['reponse'][1]

        cle_secrete_chiffree = information_cle_secrete['cle']
        iv = information_cle_secrete['iv']

        information_fichier = self.controleur.gestionnaire.get_fichier_par_fuuid(self.parametres['fuuid'])

        self.__logger.debug("Info tran chiffree: cle %s, iv %s" % (cle_secrete_chiffree, iv))

        fuuid = self.parametres['fuuid']
        token_attente = 'associer_thumbnail:%s' % fuuid

        # Transmettre commande a grosfichiers

        commande = {
            'fuuid': fuuid,
            'cleSecreteChiffree': cle_secrete_chiffree,
            'iv': iv,
            'nomfichier': information_fichier['nom'],
            'mimetype': information_fichier['mimetype'],
            'extension': information_fichier.get('extension'),
        }

        self.controleur.generateur_transactions.transmettre_commande(
            commande, ConstantesGrosFichiers.COMMANDE_GENERER_THUMBNAIL_PROTEGE)

        self.set_etape_suivante(ProcessusTransactionNouvelleVersionMetadata.sauvegarde_thumbnail_protege.__name__, [token_attente])

    def sauvegarde_thumbnail_protege(self):
        self._traitement_collection()

    def _traitement_collection(self):
        collection_uuid = self.parametres.get('collection_uuid')
        if collection_uuid is not None:
            fichier_uuid = self.parametres.get('uuid_fichier')
            collection_uuid = self.parametres.get('collection_uuid')

            self._controleur.gestionnaire.ajouter_documents_collection(collection_uuid, [fichier_uuid])

        self.set_etape_suivante()  # Processus termine

    def _get_tokens_attente(self, resultat):
        fuuid = resultat['fuuid']
        tokens = [
            '%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE, fuuid)
        ]

        if resultat['securite'] in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]:
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

        # Verifier si on a recu un thumbnail et preview d'image
        # if transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW) is not None or \
        #         transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_THUMBNAIL) is not None:
        #     self.controleur.gestionnaire.enregistrer_image_info(transaction)

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


class ProcessusTransactionRenommerDeplacerFichier(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_doc = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        champs_multilingues = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER
        ]

        changements = dict()
        for key, value in transaction.items():
            for champ in champs_multilingues:
                if key.startswith(champ):
                    changements[key] = value

        self._controleur.gestionnaire.renommer_deplacer_fichier(uuid_doc, changements)

        # Le resultat a deja ancien_repertoire_uuid. On ajoute le nouveau pour permettre de traiter les deux.
        resultat = {
            'uuid_fichier': uuid_doc
        }

        # Met a jour les collections existantes avec ce fichier
        self.controleur.gestionnaire.maj_fichier_dans_collection(uuid_doc)

        self.set_etape_suivante()  # Termine

        return resultat


class ProcessusTransactionCommenterFichier(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        champs_multilingues = [
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES
        ]

        changements = dict()
        for key, value in transaction.items():
            for champ in champs_multilingues:
                if key.startswith(champ):
                    changements[key] = value

        self._controleur._gestionnaire_domaine.maj_commentaire_fichier(uuid_fichier, changements)

        # Met a jour les collections existantes avec ce fichier
        self.controleur.gestionnaire.maj_fichier_dans_collection(uuid_fichier)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionChangerEtiquettesFichier(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        # Eliminer doublons
        etiquettes = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]
        self._logger.error("Etiquettes: %s" % etiquettes)

        self._controleur._gestionnaire_domaine.maj_etiquettes(uuid_fichier, ConstantesGrosFichiers.LIBVAL_FICHIER, etiquettes)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionSupprimerFichier(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        self._controleur._gestionnaire_domaine.supprimer_fichier(uuid_fichier)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionRecupererFichier(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        self._controleur._gestionnaire_domaine.recuperer_fichier(uuid_fichier)

        self.set_etape_suivante()  # Termine

        return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionNouvelleCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        # nom_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]
        documents = transaction.get(ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS)

        uuid_collection = str(uuid.uuid1())

        self._controleur.gestionnaire.creer_collection(uuid_collection, documents)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionRenommerCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        champs_multilingues = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER
        ]

        changements = dict()
        for key, value in transaction.items():
            for champ in champs_multilingues:
                if key.startswith(champ):
                    changements[key] = value

        self._controleur._gestionnaire_domaine.renommer_collection(uuid_collection, changements)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionCommenterCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        champs_multilingues = [
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES
        ]

        changements = dict()
        for key, value in transaction.items():
            for champ in champs_multilingues:
                if key.startswith(champ):
                    changements[key] = value

        self._controleur._gestionnaire_domaine.commenter_collection(uuid_collection, changements)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionSupprimerCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur._gestionnaire_domaine.supprimer_collection(uuid_collection)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionRecupererCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur._gestionnaire_domaine.recuperer_collection(uuid_collection)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionChangerEtiquettesCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        libelles = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]

        self._controleur._gestionnaire_domaine.maj_etiquettes(uuid_collection, ConstantesGrosFichiers.LIBVAL_COLLECTION, libelles)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionFigerCollection(ProcessusGrosFichiersActivite):
    """
    Fige une collection et genere le torrent.
    Pour les collections privees et publiques, le processus de distribution/publication est enclenche.
    """

    def initiale(self):
        """
        Figer la collection qui va servir a creer le torrent.
        :return:
        """
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        info_collection = self._controleur._gestionnaire_domaine.figer_collection(uuid_collection)
        info_collection['uuid_collection'] = uuid_collection

        self.set_etape_suivante(ProcessusTransactionFigerCollection.creer_fichier_torrent.__name__)

        # Faire une requete pour les parametres de trackers
        requete = {"requetes": [{"filtre": {
            '_mg-libelle': ConstantesParametres.LIBVAL_CONFIGURATION_NOEUDPUBLIC,
        }}]}
        self.set_requete('millegrilles.domaines.Parametres', requete)

        return info_collection

    def creer_fichier_torrent(self):
        """
        Generer un fichier torrent et transmettre au module de consignation.
        :return:
        """
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        parametres = self.parametres

        # Charger la collection et la re-sauvegarder avec _mg-libelle = collection.figee
        # Aussi generer un uuidv1 pour uuid-fige
        collection_figee = collection_domaine.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: parametres['uuid_collection_figee'],
        })

        champs_copier = [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER,
            ConstantesGrosFichiers.DOCUMENT_SECURITE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC,
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES,
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES,
        ]

        documents = []
        commande = {
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS: documents,
        }
        for champ in champs_copier:
            commande[champ] = collection_figee.get(champ)

        for uuid_doc, doc in collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS].items():
            documents.append(doc)

        # Creer le URL pour le tracker torrent
        commande['trackers'] = self.__url_trackers()

        self._logger.info("Commande creation torrent:\n%s" % str(commande))
        self.ajouter_commande_a_transmettre('commande.torrent.creerNouveau', commande)

        securite_collection = collection_figee.get(ConstantesGrosFichiers.DOCUMENT_SECURITE)
        if securite_collection == Constantes.SECURITE_PUBLIC:
            # Une fois le torrent cree, on va publier la collection figee
            self.set_etape_suivante(ProcessusTransactionFigerCollection.publier_collection_figee.__name__)
        else:
            self.set_etape_suivante()  # Termine

    def publier_collection_figee(self):

        requete = {"requetes": [{"filtre": {
            '_mg-libelle': ConstantesParametres.LIBVAL_CONFIGURATION_NOEUDPUBLIC,
        }}]}
        self.set_requete('millegrilles.domaines.Parametres', requete)

        self.set_etape_suivante(ProcessusTransactionFigerCollection.public_collection_sur_noeuds.__name__)

    def public_collection_sur_noeuds(self):

        liste_noeuds = self.parametres['reponse'][1][0]
        uuid_collection_figee = self.parametres['uuid_collection_figee']

        domaine_publier = ConstantesGrosFichiers.TRANSACTION_PUBLIER_COLLECTION
        for noeud in liste_noeuds:
            url_web = noeud['url_web']
            transaction = {
                "uuid": uuid_collection_figee,
                "url_web": url_web,
            }
            self.controleur.generateur_transactions.soumettre_transaction(transaction, domaine_publier)

        self.set_etape_suivante()  # Termine

    def __url_trackers(self):
        # Creer le URL pour le tracker torrent
        reponse_parametres = self.parametres['reponse'][0][0]

        trackers = list()

        # Tracker hard-coded, a corriger
        trackers.append('http://tracker-ipv4.millegrilles.com:6969/announce')

        for noeud_public in reponse_parametres:
            url_public = noeud_public['url_web']
            url_tracker = '%s/announce' % url_public
            trackers.append(url_tracker)

        return trackers


class ProcessusTransactionAjouterFichiersDansCollection(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        collectionuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        documentsuuid = transaction[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS]
        self._controleur.gestionnaire.ajouter_documents_collection(collectionuuid, documentsuuid)
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
        self._controleur.gestionnaire.ajouter_favori(doc_uuid)
        self.set_etape_suivante()


class ProcessusTransactionSupprimerFavori(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        doc_uuid = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC)
        self._controleur.gestionnaire.supprimer_favori(doc_uuid)
        self.set_etape_suivante()


class ProcessusTransactionTorrentNouveau(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()

        # Appliquer quelques changements pour pouvoir reutiliser maj_fichier
        transaction_copie = transaction.copy()
        transaction_copie['nom'] = '%s.torrent' % transaction_copie['nom']
        transaction_copie[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES] = ['torrent']
        transaction_copie['fuuid'] = transaction['uuid']
        transaction_copie['mimetype'] = 'application/x-bittorrent'

        # Conserver l'information du fichier torrent (comme nouveau fichier)
        resultat = self._controleur.gestionnaire.maj_fichier(transaction_copie)

        self.set_etape_suivante()

        return resultat


class ProcessusTransactionTorrentSeeding(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection_figee = transaction['uuid-collection']
        hashstring = transaction['hashstring-torrent']
        self.controleur.gestionnaire.associer_hashstring_torrent(uuid_collection_figee, hashstring)
        self.set_etape_suivante()

        return {'uuid_collection_figee': uuid_collection_figee, 'hashstring': hashstring}


class ProcessusTransactionDecrypterFichier(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def initiale(self):
        transaction = self.charger_transaction()
        fuuid = transaction['fuuid']
        securite_destination = transaction.get(ConstantesGrosFichiers.DOCUMENT_SECURITE)
        if securite_destination is None:
            securite_destination = Constantes.SECURITE_PRIVE

        # Transmettre transaction au maitre des cles pour recuperer cle secrete decryptee
        transaction_maitredescles = {
            'fuuid': fuuid
        }
        domaine = 'millegrilles.domaines.MaitreDesCles.declasserCleGrosFichier'
        # self.controleur.generateur_transactions.soumettre_transaction(transaction_maitredescles, domaine)
        self.ajouter_transaction_a_soumettre(domaine, transaction_maitredescles)

        token_attente = 'decrypterFichier_cleSecrete:%s' % fuuid
        self.set_etape_suivante(ProcessusTransactionDecrypterFichier.decrypter_fichier.__name__, [token_attente])

        return {
            'fuuid': fuuid,
            ConstantesGrosFichiers.DOCUMENT_SECURITE: securite_destination,
        }

    def decrypter_fichier(self):
        # transaction_id = self.parametres['decrypterFichier_cleSecrete'].get('_id-transaction')
        # collection_transaction_nom = self.controleur.gestionnaire.get_collection_transaction_nom()
        # collection_transaction = self.controleur.document_dao.get_collection(collection_transaction_nom)
        # information_cle_secrete = collection_transaction.find_one({'_id': ObjectId(transaction_id)})
        information_cle_secrete = self.parametres['decrypterFichier_cleSecrete']

        cle_secrete = information_cle_secrete['cle_secrete_decryptee']
        iv = information_cle_secrete['iv']

        information_fichier = self.controleur.gestionnaire.get_fichier_par_fuuid(self.parametres['fuuid'])

        self.__logger.info("Info tran decryptee: cle %s, iv %s" % (cle_secrete, iv))

        fuuid = self.parametres['fuuid']
        token_attente = 'decrypterFichier_nouveauFichier:%s' % fuuid

        # Transmettre commande a grosfichiers

        commande = {
            'fuuid': fuuid,
            'cleSecreteDecryptee': cle_secrete,
            'iv': iv,
            'nomfichier': information_fichier['nom'],
            'mimetype': information_fichier['mimetype'],
            'extension': information_fichier.get('extension'),
            'securite': self.parametres[ConstantesGrosFichiers.DOCUMENT_SECURITE],
        }
        self.ajouter_commande_a_transmettre('commande.grosfichiers.decrypterFichier', commande)

        self.set_etape_suivante('finale', [token_attente])


class ProcessusTransactionCleSecreteFichier(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()

        fuuid = transaction.get('fuuid')
        cle_secrete = transaction['cle_secrete_decryptee']
        iv = transaction['iv']
        token_resumer = 'decrypterFichier_cleSecrete:%s' % fuuid
        self.resumer_processus([token_resumer])

        self.set_etape_suivante()

        return {
            'fuuid': fuuid,
            'cle_secrete_decryptee': cle_secrete,
            'iv': iv,
        }


class ProcessusTransactionNouveauFichierDecrypte(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()

        fuuid_crypte = transaction.get('fuuid_crypte')
        fuuid_decrypte = transaction.get('fuuid_decrypte')

        info_fichier = self.controleur.gestionnaire.enregistrer_fichier_decrypte(transaction)
        uuid_fichier = info_fichier['uuid']

        self.controleur.gestionnaire.maj_fichier_dans_collection(uuid_fichier)

        token_resumer = 'decrypterFichier_nouveauFichier:%s' % fuuid_crypte
        self.resumer_processus([token_resumer])

        self.set_etape_suivante()

        return {'fuuid_crypte': fuuid_decrypte, 'fuuid_decrypte': fuuid_decrypte}


class ProcessusTransactionAssocierThumbnail(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()

        fuuid = transaction['fuuid']
        thumbnail = transaction['thumbnail']
        metadata = transaction.get('metadata')

        self.controleur.gestionnaire.associer_thumbnail(fuuid, thumbnail, metadata)

        token_resumer = 'associer_thumbnail:%s' % fuuid
        self.resumer_processus([token_resumer])

        self.set_etape_suivante()


class ChangerNiveauSecuriteCollection(ProcessusGrosFichiers):
    """
    Change le niveau de securite d'une collection (e.g. 4.secure vers 1.public)
    Le comportement est different si on passe d'un niveau crypte a decrypte ou non.
    """
    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        niveau_securite_destination = transaction["niveau_securite_destination"]

        collection_fichiers = self.controleur.gestionnaire.get_collection_par_uuid(uuid_collection)

        # Determiner le sens du changement (moins->plus secure ou plus->moins secure)
        niveau_securite_courant = collection_fichiers[ConstantesGrosFichiers.DOCUMENT_SECURITE]

        niveau_securite_courant_num = niveau_securite_courant.split('.')[0]
        niveau_securite_destination_num = niveau_securite_destination.split('.')[0]

        if niveau_securite_courant_num == niveau_securite_destination:
            self.__logger.warning("Aucun changement au niveau de securite")
        elif niveau_securite_courant_num > niveau_securite_destination:
            # Diminuer le niveau de securite
            self.set_etape_suivante()
            self.__diminuer_securite_fichiers(uuid_collection, niveau_securite_destination)
            self.set_etape_suivante(ChangerNiveauSecuriteCollection.changer_niveau_securite.__name__)
        elif niveau_securite_courant_num < niveau_securite_destination:
            # Augmenter le niveau de securite
            # Aucun impact sur le contenu
            self.controleur.gestionnaire.changer_niveau_securite_collection(uuid_collection, niveau_securite_destination)
            self.set_etape_suivante()

        return {
            'uuid_collection': uuid_collection,
            'niveau_securite_courant_num': niveau_securite_courant_num,
            'niveau_securite_destination': niveau_securite_destination,
            'niveau_securite_destination_num': niveau_securite_destination_num,
        }

    def changer_niveau_securite(self):
        """
        Changer le niveau de securite puis terminer le processus
        """
        uuid_collection = self.parametres['uuid_collection']
        niveau_securite_destination = self.parametres['niveau_securite_destination']

        self.controleur.gestionnaire.changer_niveau_securite_collection(uuid_collection, niveau_securite_destination)

        self.set_etape_suivante()

    def __diminuer_securite_fichiers(self, uuid_collection, securite_destination):
        collection = self.controleur.gestionnaire.get_collection_par_uuid(uuid_collection)

        fichier_diminuer_direct = []
        for fichier in collection[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS].values():
            if fichier.get(ConstantesGrosFichiers.DOCUMENT_SECURITE) in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]:
                # Le fichier est crypte, on transmet une transaction de decryptage
                securite_fichier = fichier[ConstantesGrosFichiers.DOCUMENT_SECURITE]
                if securite_fichier in [Constantes.SECURITE_SECURE, Constantes.SECURITE_PROTEGE]:
                    transaction_decryptage = {
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID],
                        ConstantesGrosFichiers.DOCUMENT_SECURITE: securite_destination,
                    }
                    self.ajouter_transaction_a_soumettre(ConstantesGrosFichiers.TRANSACTION_DECRYPTER_FICHIER, transaction_decryptage)
            else:
                # Le fichier n'est pas crypte, on transmet une transaction de mise a jour
                fichier_diminuer_direct.append(fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC])

        if len(fichier_diminuer_direct) > 0:
            self.controleur.gestionnaire.changer_securite_fichiers(fichier_diminuer_direct, securite_destination)
            for uuid_fichier in fichier_diminuer_direct:
                self.controleur.gestionnaire.maj_fichier_dans_collection(uuid_fichier)


class ProcessusPublierCollection(ProcessusGrosFichiers):
    """
    Publie une collection sur un noeud public (Vitrine)
    """

    def initiale(self):
        transaction = self.transaction
        url_noeud_public = transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
        uuid_collection_figee = transaction[ConstantesParametres.TRANSACTION_CHAMP_UUID]

        # Inserer dans les documents de vitrine
        # Ceci va automatiquement les publier (via watchers MongoDB)
        self.controleur.gestionnaire.maj_documents_vitrine(uuid_collection_figee)

        self.set_requete(ConstantesParametres.REQUETE_NOEUD_PUBLIC, {
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: url_noeud_public,
        })

        self.set_etape_suivante(ProcessusPublierCollection.determiner_type_deploiement.__name__)

        return {
            ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: url_noeud_public,
            ConstantesParametres.TRANSACTION_CHAMP_UUID: uuid_collection_figee,
        }

    def determiner_type_deploiement(self):

        info_noeud_public = self.parametres['reponse'][0][0]
        mode_deploiement = info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_MODE_DEPLOIEMENT]

        if mode_deploiement == 'torrent':
            self.set_etape_suivante(ProcessusPublierCollection.deploiement_torrent.__name__)
        elif mode_deploiement == 's3':
            self.set_etape_suivante(ProcessusPublierCollection.deploiement_s3.__name__)
        else:
            raise Exception("Mode de deploiement inconnu pour noeud public " + self.parametres[
                ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB])

    def deploiement_torrent(self):
        """
        Lancer le processus de deploiement avec Torrents
        :return:
        """
        self.set_etape_suivante(ProcessusPublierCollection.publier_metadonnees_collection.__name__)

    def deploiement_s3(self):
        """
        Demander le fingerprint du certificat de consignationfichiers
        :return:
        """
        self.set_requete('pki.role.fichiers', {})

        self.set_etape_suivante(ProcessusPublierCollection.deploiement_s3_demander_cle_rechiffree.__name__)

    def deploiement_s3_demander_cle_rechiffree(self):
        """
        Demander la cle pour le mot de passe Amazon
        :return:
        """

        fingerprint_fichiers = self.parametres['reponse'][1]['fingerprint']

        transaction_maitredescles = {
            'fingerprint': fingerprint_fichiers,
            "identificateurs_document": {
                "champ": "awsSecretAccessKey",
                "url_web": self.parametres[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB],
            }
        }
        domaine = 'millegrilles.domaines.MaitreDesCles.decryptageDocument'

        # Effectuer requete pour re-chiffrer la cle du document pour le consignateur de transactions
        self.set_requete(domaine, transaction_maitredescles)

        self.set_etape_suivante(ProcessusPublierCollection.deploiement_s3_commande.__name__)

    def deploiement_s3_commande(self):
        """
        Lancer le processus de deploiement avec Amazon S3
        :return:
        """
        info_noeud_public = self.parametres['reponse'][0][0]

        # Extraire liste de fichiers a publier de la collection
        collection_figee_uuid = self.parametres[ConstantesParametres.TRANSACTION_CHAMP_UUID]
        collection_figee = self.controleur.gestionnaire.get_collection_figee_par_uuid(collection_figee_uuid)
        liste_documents = collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS]
        info_documents_a_publier = []
        for document_a_publier in liste_documents.values():
            if document_a_publier[Constantes.DOCUMENT_INFODOC_LIBELLE] == ConstantesGrosFichiers.LIBVAL_FICHIER:

                info_doc = {
                    'nom': document_a_publier['nom'],
                }

                # Gerer l'exception des videos, on publie uniquement le clip mp4 en 480p
                if document_a_publier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P) is not None:
                    # On publie uniquement le video a 480p
                    info_doc.update({
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: document_a_publier[
                            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P],
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: document_a_publier[
                            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P],
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL: 'mp4',
                    })
                else:
                    # C'est un fichier standard
                    info_doc.update({
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: document_a_publier[
                            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID],
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL: document_a_publier[
                            ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL],
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: document_a_publier[
                            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE],
                    })
                info_documents_a_publier.append(info_doc)

                if document_a_publier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW) is not None:
                    # On ajoute aussi l'upload du preview
                    info_preview = {
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: document_a_publier[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW],
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: document_a_publier[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW],
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL: 'jpg',
                    }
                    info_documents_a_publier.append(info_preview)

        # Creer commande de deploiement pour consignationfichiers
        commande_deploiement = {
            "credentials": {
                "accessKeyId": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_ACCESS_KEY],
                "secretAccessKeyChiffre": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_SECRET_KEY_CHIFFRE],
                "region": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_CRED_REGION],
                "cle": self.parametres['reponse'][2]['cle'],
                "iv": self.parametres['reponse'][2]['iv'],
            },
            "region": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_BUCKET_REGION],
            "bucket": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_BUCKET_NAME],
            "dirfichier": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_BUCKET_DIR],
            "fuuidFichiers": info_documents_a_publier,
            "uuid_source_figee": collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE],
            "uuid_collection_figee": collection_figee_uuid,
        }

        self.ajouter_commande_a_transmettre('commande.grosfichiers.publierCollection', commande_deploiement)

        self.set_etape_suivante(ProcessusPublierCollection.publier_metadonnees_collection.__name__)

        return {
            "commande": commande_deploiement
        }

    def publier_metadonnees_collection(self):

        collection_figee_uuid = self.parametres[ConstantesParametres.TRANSACTION_CHAMP_UUID]
        collection_figee = self.controleur.gestionnaire.get_collection_figee_par_uuid(collection_figee_uuid)

        collection_filtree = dict()
        for key, value in collection_figee.items():
            if not key.startswith('_'):
                collection_filtree[key] = value

        url_web = self.parametres[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
        url_web = url_web.replace('.', '_')
        domaine = 'commande.%s.publierCollection' % url_web

        self.controleur.transmetteur.emettre_message_public(collection_filtree, domaine)

        # Publier les documents de sections avec fichiers (fichiers, albums, podcasts, etc.)
        # Note : ajouter un selecteur pour charger uniquement les sections actives (menu du noeud)
        document_fichiers = self.controleur.gestionnaire.get_document_vitrine_fichiers()
        domaine_fichiers = 'commande.%s.publierFichiers' % url_web
        self.controleur.transmetteur.emettre_message_public(document_fichiers, domaine_fichiers)

        document_albums = self.controleur.gestionnaire.get_document_vitrine_albums()
        domaine_albums = 'commande.%s.publierAlbums' % url_web
        self.controleur.transmetteur.emettre_message_public(document_albums, domaine_albums)

        self.set_etape_suivante()


class ProcessusAssocierVideoTranscode(ProcessusGrosFichiers):
    """
    Associe un video a un fichier une fois le transcodage termine
    """

    def initiale(self):
        transaction = self.transaction
        document_fichier = self.controleur.gestionnaire.associer_video_transcode(transaction)
        uuid_fichier = document_fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        self.controleur.gestionnaire.maj_fichier_dans_collection(uuid_fichier)
        self.set_etape_suivante()  # Termine
