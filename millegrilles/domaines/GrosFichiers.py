import os
import logging
import datetime
import json
import uuid
import pytz
import gzip
import multibase

from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError
from cryptography import x509

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGrosFichiers, ConstantesParametres, ConstantesSecurite, ConstantesMaitreDesCles
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees, \
    TraitementMessageDomaineRequete, HandlerBackupDomaine, RegenerateurDeDocuments, GroupeurTransactionsARegenerer, \
    TraitementCommandesProtegees, TraitementMessageDomaineEvenement, MGProcessus
from millegrilles.MGProcessus import MGProcessusTransaction, MGPProcesseur
from millegrilles.util.Chiffrage import CipherMsg2Chiffrer
from millegrilles.util.JSONMessageEncoders import JSONHelper
from millegrilles.SecuritePKI import EnveloppeCertificat


# class TraitementRequetesPubliquesGrosFichiers(TraitementMessageDomaineRequete):
#
#     def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
#         routing_key = method.routing_key
#         action = routing_key.split('.').pop()
#
#         if action == ConstantesGrosFichiers.REQUETE_COLLECTIONS_PUBLIQUES:
#             reponse = self.gestionnaire.get_liste_collections(message_dict)
#         elif action == ConstantesGrosFichiers.REQUETE_DETAIL_COLLECTIONS_PUBLIQUES:
#             reponse = self.gestionnaire.get_detail_collections(message_dict)
#             reponse = {'liste_collections': reponse}
#         else:
#             raise Exception("Requete publique non supportee " + routing_key)
#
#         if reponse:
#             self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementEvenementProtege(TraitementMessageDomaineEvenement):

    def traiter_evenement(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.').pop()

        if action == ConstantesGrosFichiers.EVENEMENTS_CONFIRMATION_MAJ_COLLECTIONPUBLIQUE:
            self.gestionnaire.maj_collection_publique(message_dict)
        elif action == 'publicAwsS3':
            self.gestionnaire.traiter_evenement_awss3(message_dict)
        elif action == 'transcodageProgres':
            self.gestionnaire.traiter_evenement_fichiers(message_dict, routing_key)
        elif action == 'transcodageErreur':
            self.gestionnaire.traiter_evenement_fichiers(message_dict, routing_key)
        else:
            raise Exception("GrosFichiers evenement protege inconnu : " + routing_key)


class TraitementRequetesPriveesGrosFichiers(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        action = routing_key.split('.').pop()

        if action == ConstantesGrosFichiers.REQUETE_PERMISSION_DECHIFFRAGE_PRIVE:
            reponse = self.gestionnaire.generer_permission_dechiffrage_fichier_prive(message_dict, enveloppe_certificat)
        elif action == ConstantesGrosFichiers.REQUETE_COLLECTION_PERSONNELLE:
            reponse = self.gestionnaire.get_contenu_collection_personnelle(message_dict)
        else:
            return {'ok': False, 'err': 'Requete non supportee'}

        if reponse:
            if not isinstance(reponse, dict):
                reponse = {'resultat': reponse}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class TraitementRequetesProtegeesGrosFichiers(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        action = '.'.join(routing_key.split('.')[-2:])
        domaine_action = routing_key.split('.').pop()

        if action == ConstantesGrosFichiers.REQUETE_ACTIVITE_RECENTE:
            reponse = {'resultats': self.gestionnaire.get_activite_recente(message_dict)}
        elif action == ConstantesGrosFichiers.REQUETE_CORBEILLE:
            reponse = {'resultats': self.gestionnaire.get_corbeille(message_dict)}
        elif action == ConstantesGrosFichiers.REQUETE_COLLECTIONS:
            reponse = {'resultats': self.gestionnaire.get_collections(message_dict)}
        elif action == ConstantesGrosFichiers.REQUETE_FAVORIS:
            reponse = {'resultats': self.gestionnaire.get_favoris(message_dict)}
        elif action == ConstantesGrosFichiers.REQUETE_CONTENU_COLLECTION:
            reponse = {'resultats': self.gestionnaire.get_contenu_collection(message_dict)}
        elif action == ConstantesGrosFichiers.REQUETE_DOCUMENTS_PAR_UUID:
            reponse = {'resultats': self.gestionnaire.get_documents_par_uuid(message_dict)}
        elif domaine_action == ConstantesGrosFichiers.REQUETE_COLLECTION_PERSONNELLE:
            reponse = self.gestionnaire.get_contenu_collection_personnelle(message_dict)
        elif domaine_action == ConstantesGrosFichiers.REQUETE_DOCUMENT_PAR_FUUID:
            reponse = self.gestionnaire.get_document_par_fuuid(message_dict)
        elif domaine_action == ConstantesGrosFichiers.REQUETE_PERMISSION_DECHIFFRAGE_PUBLIC:
            reponse = self.gestionnaire.generer_permission_dechiffrage_fichier_public(message_dict)
        elif domaine_action == ConstantesGrosFichiers.REQUETE_PERMISSION_DECHIFFRAGE_PRIVE:
            reponse = self.gestionnaire.generer_permission_dechiffrage_fichier_prive(message_dict, enveloppe_certificat)
        elif domaine_action == ConstantesGrosFichiers.REQUETE_COLLECTIONS_PUBLIQUES:
            reponse = self.gestionnaire.get_liste_collections(message_dict)
        elif domaine_action == ConstantesGrosFichiers.REQUETE_DETAIL_COLLECTIONS_PUBLIQUES:
            reponse = self.gestionnaire.get_detail_collections(message_dict)
        elif domaine_action == ConstantesGrosFichiers.REQUETE_TRANSFERTS_EN_COURS:
            reponse = self.gestionnaire.get_transferts_en_cours()
        elif domaine_action == ConstantesGrosFichiers.REQUETE_CONVERSIONS_MEDIA_ENCOURS:
            reponse = self.gestionnaire.get_conversion_media_en_cours()
        else:
            super().traiter_requete(ch, method, properties, body, message_dict, enveloppe_certificat)
            return

        if reponse:
            if not isinstance(reponse, dict):
                reponse = {'resultat': reponse}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)


class GrosfichiersTraitementCommandesProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict) -> dict:
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        if action == ConstantesGrosFichiers.COMMANDE_REGENERER_PREVIEWS:
            return self.gestionnaire.regenerer_previews(message_dict)
        elif action == ConstantesGrosFichiers.COMMANDE_TRANSCODER_VIDEO:
            return self.gestionnaire.declencher_transcodage_video(message_dict, properties)
        elif action == ConstantesGrosFichiers.COMMANDE_RESET_FICHIERS_PUBLIES:
            return self.gestionnaire.reset_fichiers_publies(message_dict)
        elif action == ConstantesGrosFichiers.COMMANDE_CLEAR_FICHIER_PUBLIE:
            return self.gestionnaire.clear_fichier_publie(message_dict)
        # elif action == ConstantesGrosFichiers.COMMANDE_UPLOAD_COLLECTIONS_PUBLIQUES:
        #     self.gestionnaire.maj_collection_publique(message_dict)
        #     return {'ok': True}
        elif action == ConstantesGrosFichiers.COMMANDE_REGENERER_COLLECTIONFICHIERS:
            self.gestionnaire.creer_trigger_collectionfichiers(message_dict)
        elif action == ConstantesGrosFichiers.COMMANDE_ASSOCIER_COLLECTION:
            self.gestionnaire.associer_fichier_collection(message_dict)
        else:
            return super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)


class HandlerBackupGrosFichiers(HandlerBackupDomaine):

    def __init__(self, contexte):
        super().__init__(contexte,
                         ConstantesGrosFichiers.DOMAINE_NOM,
                         ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM,
                         ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

    def _extraire_certificats(self, transaction, heure: datetime.datetime) -> dict:
        info_transaction = super()._extraire_certificats(transaction, heure)

        heure_str = heure.strftime('%H')

        # Extraire les fuuids
        domaine_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE]
        fuuid_dict = dict()
        info_transaction['fuuid_grosfichiers'] = fuuid_dict

        if domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA:
            # Ajouter information pour le backup du fichier
            nom_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]

            fuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
            hachage = fuuid  # transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE]

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_ASSOCIER_PREVIEW:
            # Ajouter information pour le backup du fichier de preview
            fuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW]
            hachage = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE_PREVIEW]

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_ASSOCIER_VIDEO_TRANSCODE:
            # Ajouter information pour le backup du fichier de preview
            fuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_VIDEO]
            hachage = fuuid

        else:
            # Aucune information de fichier a ajouter
            return info_transaction

        fuuid_dict[fuuid] = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE: hachage,
            'heure': heure_str,
        }

        return info_transaction


class GestionnaireGrosFichiers(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._traitement_middleware = None
        self._traitement_noeud = None
        self._traitement_cedule = None
        self._logger = logging.getLogger("%s.GestionnaireRapports" % __name__)

        self.__handler_requetes_noeuds = {
            # Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesGrosFichiers(self),
            Constantes.SECURITE_PRIVE: TraitementRequetesPriveesGrosFichiers(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesGrosFichiers(self)
        }

        self.__handler_commandes = super().get_handler_commandes()
        self.__handler_commandes[Constantes.SECURITE_PROTEGE] = GrosfichiersTraitementCommandesProtegees(self)

        self.__handler_evenements_proteges = TraitementEvenementProtege(self)

        self.__handler_backup = HandlerBackupGrosFichiers(self._contexte)

    @staticmethod
    def extension_fichier(nom_fichier):
        extension = nom_fichier.split('.')[-1].lower()
        return extension

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def get_queue_configuration(self) -> list:
        """
        :return: Liste de configuration pour les Q du domaine
        """

        queues_config = super().get_queue_configuration()

        queues_config.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'evenements_proteges'),
            'routing': [
                'evenements.%s.#.*' % self.get_nom_domaine(),
                'evenement.fichiers.publicAwsS3',
                'evenement.fichiers.*.transcodageProgres',
                'evenement.fichiers.*.transcodageErreur',
            ],
            'exchange': self.configuration.exchange_protege,
            'ttl': 300000,
            'callback': self.__handler_evenements_proteges.callbackAvecAck
        })

        return queues_config

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_CONFIGURATION, ConstantesGrosFichiers.DOCUMENT_DEFAUT)

        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA, {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA
        })

        self.initialiser_document(ConstantesGrosFichiers.LIBVAL_PUBLICATION_FICHIERS, {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_PUBLICATION_FICHIERS
        })

        # self.demarrer_watcher_collection(
        #     ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM, ConstantesGrosFichiers.QUEUE_ROUTING_CHANGEMENTS)

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def identifier_processus(self, domaine_transaction):
        domaine_action = domaine_transaction.split('.').pop()

        # Fichiers
        if domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleVersionMetadata"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RENOMMER_DOCUMENT:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRenommerDocument"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionSupprimerFichier"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RECUPERER_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRecupererFichier"
        elif domaine_action == ConstantesGrosFichiers.TRANSACTION_DECRIRE_FICHIER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionDecricreFichier"
        elif domaine_action == ConstantesGrosFichiers.TRANSACTION_DECRIRE_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionDecricreCollection"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_ASSOCIER_PREVIEW:  # deprecate, remplacer par ASSOCIER_CONVERSIONS
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAssocierPreview"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_ASSOCIER_CONVERSIONS:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAssocierConversions"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_ASSOCIER_VIDEO_TRANSCODE:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusAssocierVideoTranscode"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVELLE_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouvelleCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_AJOUTER_FICHIERS_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionAjouterFichiersDansCollection"
        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_RETIRER_FICHIERS_COLLECTION:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionRetirerFichiersDeCollection"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_CHANGER_FAVORIS:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionChangerFavoris"

        elif domaine_transaction == ConstantesGrosFichiers.TRANSACTION_NOUVEAU_FICHIER_USAGER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionNouveauFichierUsager"
        elif domaine_action == ConstantesGrosFichiers.TRANSACTION_SUPPRIMER_FICHIER_USAGER:
            processus = "millegrilles_domaines_GrosFichiers:ProcessusTransactionSupprimerFichierUsager"

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
        # else:
        #    self._logger.info("Document de %s pour GrosFichiers: %s" % (mg_libelle, str(document_configuration)))

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

        # Appartenance aux collections
        collection_domaine.create_index(
            [
                (ConstantesGrosFichiers.DOCUMENT_COLLECTIONS, 1),
            ],
            name='collections'
        )

        # Index par SHA256 / taille. Permet de determiner si le fichier existe deja (et juste faire un lien).
        collection_domaine.create_index(
            [
                ('%s.%s' %
                 (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                  ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE),
                 1),
                ('%s.%s' %
                 (ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                  ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE),
                 1),
            ],
            name='hachage-taille'
        )

        # Index par SHA256 / taille. Permet de determiner si le fichier existe deja (et juste faire un lien).
        collection_domaine.create_index(
            [
                (ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC, 1),
            ],
            name='document-uuid'
        )

        # Index fuuid version courante
        collection_domaine.create_index(
            [
                (ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE, 1),
            ],
            name='document-fuuid-vcourante'
        )

        # Index tous les fuuids dans un fichier
        collection_domaine.create_index(
            [
                (ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS, 1),
            ],
            name='document-liste-fuuids'
        )

        # CollectionFichiers
        collection_collectionfichiers = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_COLLECTIONFICHIERS_NOM)
        collection_collectionfichiers.create_index(
            [
                (ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC, 1),
            ],
            name='uuid-collection'
        )

    def get_nom_domaine(self):
        return ConstantesGrosFichiers.DOMAINE_NOM

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

        minutes = evenement['timestamp']['UTC'][4]

        if minutes % 15 == 3:
            self.resoumettre_conversions_manquantes()

    def creer_regenerateur_documents(self):
        return RegenerateurGrosFichiers(self)

    def get_fichier_par_uuid(self, uuid_fichier):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
        }
        self._logger.info("Fichier par uuid: %s" % filtre)

        fichier = collection_domaine.find_one(filtre)

        return fichier

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

    def get_activite_recente(self, params: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
                ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
            ]},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }

        sort_order = [
            (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1),
            (ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC, 1),
        ]

        skip = params.get('skip') or 0
        limit = params.get('limit') or 100

        curseur_documents = collection_domaine.find(filtre).sort(sort_order).skip(skip).limit(limit)

        documents = self.mapper_fichier_version(curseur_documents)

        return documents

    def get_corbeille(self, params: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
                ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
            ]},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: True,
        }

        sort_order = [
            (ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_SUPPRESSION, -1),
            (ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC, 1),
        ]

        skip = params.get('skip') or 0
        limit = params.get('limit') or 100

        curseur_documents = collection_domaine.find(filtre).sort(sort_order).skip(skip).limit(limit)

        documents = self.mapper_fichier_version(curseur_documents)

        return documents

    def mapper_fichier_version(self, curseur_documents, extra_out: dict = None):
        # Extraire docs du curseur, filtrer donnees
        documents = list()
        liste_fuuids = list()
        for doc in curseur_documents:
            doc_filtre = dict()
            for key, value in doc.items():
                if key not in ['versions', '_id']:
                    doc_filtre[key] = value
            libelle_doc = doc[Constantes.DOCUMENT_INFODOC_LIBELLE]
            if libelle_doc == ConstantesGrosFichiers.LIBVAL_FICHIER:
                fuuid_v_courante = doc['fuuid_v_courante']
                doc_filtre['version_courante'] = doc['versions'][fuuid_v_courante]
                liste_fuuids.extend(doc[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS])
            documents.append(doc_filtre)

        if extra_out is not None:
            extra_out[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS] = liste_fuuids

        return documents

    def mapper_favoris(self, curseur_documents):
        # Extraire docs du curseur, filtrer donnees
        documents = list()
        for doc in curseur_documents:
            doc_filtre = dict()
            for key, value in doc.items():
                if key in [
                    'uuid',
                    'nom_fichier',
                    'nom_collection',
                    Constantes.DOCUMENT_INFODOC_LIBELLE,
                    Constantes.DOCUMENT_INFODOC_SECURITE,
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_TITRE,
                ]:
                    doc_filtre[key] = value
            documents.append(doc_filtre)

        return documents

    def verifier_acces_certificat(self, enveloppe_certificat: EnveloppeCertificat):
        acces = dict()
        try:
            exchanges = enveloppe_certificat.get_exchanges

            if Constantes.SECURITE_PROTEGE or Constantes.SECURITE_SECURE in exchanges:
                securite = Constantes.SECURITE_PROTEGE
            elif Constantes.SECURITE_PRIVE in exchanges:
                securite = Constantes.SECURITE_PRIVE
            else:
                securite = Constantes.SECURITE_PUBLIC

            acces['securite'] = securite

        except x509.extensions.ExtensionNotFound:
            # Verifier si on a un certificat avec delegation globale ou un user_id
            delegation_globale = enveloppe_certificat.get_delegation_globale
            if delegation_globale in ['proprietaire', 'delegue']:
                acces['securite'] = Constantes.SECURITE_PROTEGE
            else:
                try:
                    roles = enveloppe_certificat.get_roles
                    if Constantes.ConstantesMaitreDesComptes.CHAMP_COMPTE_PRIVE in roles:
                        # Acces prive
                        acces['securite'] = Constantes.SECURITE_PRIVE
                except KeyError:
                    pass  # OK

        return acces

    def get_collections(self, params: dict):

        # Verifier le niveau d'acces du demandeur
        enveloppe_certificat = self.validateur_message.verifier(params)
        acces = self.verifier_acces_certificat(enveloppe_certificat)
        securite = acces.get('securite') or Constantes.SECURITE_PUBLIC
        niveaux_securite = ConstantesSecurite.cascade_public(securite)

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': niveaux_securite},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }
        projection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: True,
            Constantes.DOCUMENT_INFODOC_SECURITE: True,
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION: True,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: True,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TITRE: True,
        }

        limit = params.get('limit') or 1000

        curseur_documents = collection_domaine.find(filtre, projection).limit(limit)

        # Extraire docs du curseur, filtrer donnees
        documents = self.mapper_fichier_version(curseur_documents)

        return documents

    def get_favoris(self, params: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ]},
            ConstantesGrosFichiers.DOCUMENT_FAVORIS: {'$exists': True},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }
        projection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: True,
            Constantes.DOCUMENT_INFODOC_SECURITE: True,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER: True,
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION: True,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: True,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_TITRE: True,
        }

        limit = params.get('limit') or 1000

        curseur_documents = collection_domaine.find(filtre, projection).limit(limit)

        # Extraire docs du curseur, filtrer donnees
        documents = self.mapper_favoris(curseur_documents)

        return documents

    def get_contenu_collection(self, params: dict):
        # Verifier le niveau d'acces du demandeur
        enveloppe_certificat = self.validateur_message.verifier(params)
        acces = self.verifier_acces_certificat(enveloppe_certificat)
        securite = acces.get('securite') or Constantes.SECURITE_PUBLIC

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        uuid_collection = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        # Charger objet collection
        filtre_collection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        hint_collection = [
            (ConstantesGrosFichiers.DOCUMENT_COLLECTIONS, 1)
        ]
        info_collection = collection_domaine.find_one(filtre_collection, hint=hint_collection)

        # Verifier si on doit generer une permission (requis pour collection privee ou protegee)
        try:
            securite_collection = info_collection[Constantes.DOCUMENT_INFODOC_SECURITE]
        except TypeError:
            # Collection inconnue, retourner erreur
            return {'err': True, 'code': 'NOTFOUND', 'message': 'Collection %s inconnue' % uuid_collection}

        if securite in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]:
            permission = None  # Certificat donne acces directement, permission non requise
        elif securite == Constantes.SECURITE_PRIVE:
            permission = {
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: 12 * 60 * 60,  # 12 heures
                Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PRIVE,
            }
        else:
            permission = None

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_COLLECTIONS: {'$all': [uuid_collection]},
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ]},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }

        hint_fichiers = [
            (ConstantesGrosFichiers.DOCUMENT_COLLECTIONS, 1)
        ]

        sort_keys = params.get('sort_keys')
        sort_key = [
            (ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER, 1),
            (ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC, 1),
        ]
        if sort_keys is not None:
            sort_key = [(k, 1) for k in sort_keys]
            sort_key.append((ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC, 1))

        skip = params.get('skip') or 0
        limit = params.get('limit') or 1000

        curseur_documents = collection_domaine.find(filtre).collation({'locale': 'en'}).hint(hint_fichiers).sort(sort_key).skip(skip).limit(limit)
        extra_out = dict()
        documents = self.mapper_fichier_version(curseur_documents, extra_out)

        reponse = {
            'collection': info_collection,
            'documents': documents,
        }

        if permission is not None:
            permission[ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES] = extra_out[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS]
            permission = self.generateur_transactions.preparer_enveloppe(permission, ConstantesMaitreDesCles.REQUETE_PERMISSION)
            reponse['permission'] = permission

        return reponse

    def get_documents_par_uuid(self, params: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        uuid_collection = params[ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS]
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuid_collection},
        }

        hint = [
            (ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC, 1)
        ]

        limit = params.get('limit') or 1000

        curseur_documents = collection_domaine.find(filtre).hint(hint).limit(limit)
        documents = self.mapper_fichier_version(curseur_documents)

        return documents

    def get_document_par_fuuid(self, params: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        fuuid = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS + '.' + fuuid: {'$exists': True},
        }

        document_fuuid = collection_domaine.find_one(filtre)
        if document_fuuid is not None:
            # Aplatir liste de versions, conserver seulement celle qui est demandee
            document_fuuid['versions'] = {fuuid: document_fuuid['versions'][fuuid]}
            return document_fuuid

        return {'ok': False, 'fuuid': fuuid, 'err': 'Non trouve'}

    def get_torrent_par_collection(self, uuid_collection):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_TORRENT_COLLECTION_UUID: uuid_collection,
        }
        self._logger.debug("Fichier torrent par collection: %s" % filtre)

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

    @property
    def handler_backup(self):
        return self.__handler_backup

    def maj_fichier(self, transaction):
        """
        Genere ou met a jour un document de fichier avec l'information recue dans une transaction metadata.
        :param transaction:
        :return: True si c'est la version la plus recent, false si la transaction est plus vieille.
        """
        domaine = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE].get(Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE)
        if domaine not in [ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_METADATA, ConstantesGrosFichiers.TRANSACTION_NOUVEAU_FICHIER_USAGER]:
            raise ValueError('La transaction doit etre de type metadata ou nouveau torrent. Trouve: %s' % domaine)

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        fuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]

        addToSet = dict()
        addToSet[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS] = fuuid

        uuid_collection = transaction.get(ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID)
        if(uuid_collection):
            addToSet[ConstantesGrosFichiers.DOCUMENT_COLLECTIONS] = uuid_collection

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
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE,
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

        mimetype = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE)
        if mimetype is not None:
            set_operations[ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES + '.' + fuuid] = mimetype

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

        operations = {
            '$set': set_operations,
            '$currentDate': operation_currentdate,
            '$setOnInsert': set_on_insert
        }
        if len(addToSet.items()) > 0:
            operations['$addToSet'] = addToSet

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }

        self._logger.debug("maj_fichier: filtre = %s" % filtre)
        self._logger.debug("maj_fichier: operations = %s" % operations)
        try:
            fichier_maj = collection_domaine.find_one_and_update(
                filtre, operations, upsert=True, return_document=ReturnDocument.AFTER)
        except DuplicateKeyError as dke:
            self._logger.info("Cle dupliquee sur fichier %s, on ajoute un id unique dans le nom" % fuuid)
            nom_fichier = '%s_%s' % (uuid.uuid1(), transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER])
            set_on_insert[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = nom_fichier
            fichier_maj = collection_domaine.find_one_and_update(
                filtre, operations, upsert=True, return_document=ReturnDocument.AFTER)

        if fichier_maj is None:
            raise Exception("Erreur ajout/maj fichier %s" % uuid_fichier)
        self._logger.debug("maj_fichier resultat %s" % str(fichier_maj))

        self.emettre_evenement_fichier_maj(fuuid, fichier_maj)

        # Mettre a jour les etiquettes du fichier au besoin
        etiquettes = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES)
        if etiquettes is not None:
            self.maj_etiquettes(uuid_fichier, ConstantesGrosFichiers.LIBVAL_FICHIER, etiquettes)

        fichier_maj['version_courante'] = fichier_maj['versions'][fuuid]

        return {
            'plus_recent': plus_recente_version,
            'uuid_fichier': uuid_fichier,
            'info_version': info_version,
            'fichier': fichier_maj
        }

    def emettre_evenement_fichier_maj(self, fuuid, fichier: dict = None, action=ConstantesGrosFichiers.EVENEMENT_MAJ_FICHIER):
        if fichier is None:
            collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
            filtre = {
                ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: {'$all': [fuuid]}
            }
            fichier = collection_domaine.find_one(filtre)

        fichier = fichier.copy()
        fichier['version_courante'] = fichier['versions'][fuuid]

        extra_out = dict()
        domaine_action = 'evenement.grosfichiers.' + action
        evenement = self.mapper_fichier_version([fichier], extra_out).pop()
        evenement.update(extra_out)

        self.generateur_transactions.emettre_message(
            evenement,
            domaine_action,
            exchanges=[Constantes.SECURITE_PROTEGE]
        )

        # Emettre un evenement plus limite sur exchange prive, uniquement les ids
        evenement_prive = {
            'uuid': evenement['uuid'],
            'fuuid': fuuid,
        }
        try:
            evenement_prive['collections'] = evenement['collections']
        except KeyError:
            evenement_prive['collections'] = list()

        self.generateur_transactions.emettre_message(
            evenement_prive,
            domaine_action,
            exchanges=[Constantes.SECURITE_PRIVE]
        )

        # Emettre commande de mise a jour de collectionFichiers
        uuid_collections = fichier.get(ConstantesGrosFichiers.DOCUMENT_COLLECTIONS)
        if uuid_collections is not None:
            params = {ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS: uuid_collections}
            self.creer_trigger_collectionfichiers(params)

    def get_niveau_securite_fichier(self, fuuid, collections: list = None):
        if collections is None:
            collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
            filtre = {
                ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: {'$all': [fuuid]}
            }
            fichier = collection_domaine.find_one(filtre)
            collections = fichier.get('collections')

        # Par defaut, niveau est 3.protege
        niveau_securite = Constantes.SECURITE_PROTEGE

        if collections is None or len(collections) == 0:
            return niveau_securite

        filtre_collections = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': collections},
            Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]},
        }
        projection_collection = [Constantes.DOCUMENT_INFODOC_SECURITE]

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        curseur_collections = collection_domaine.find(filtre_collections, projection=projection_collection)

        # Verifier qu'au moins une collection est de securite 1.public
        for coll in curseur_collections:
            sec_coll = coll[Constantes.DOCUMENT_INFODOC_SECURITE]
            if sec_coll == Constantes.SECURITE_PUBLIC:
                niveau_securite = Constantes.SECURITE_PUBLIC
            elif niveau_securite == Constantes.SECURITE_PROTEGE and sec_coll == Constantes.SECURITE_PRIVE:
                niveau_securite = Constantes.SECURITE_PRIVE

        return niveau_securite

    def renommer_document(self, uuid_doc, changements: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_doc,
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER, ConstantesGrosFichiers.LIBVAL_COLLECTION
            ]},
        }
        document_a_modifier = collection_domaine.find_one(filtre)

        nouveau_nom = changements['nom']

        set_ops = dict()
        if document_a_modifier is not None:
            # Determiner si on a un fichier ou collection
            libval = document_a_modifier[Constantes.DOCUMENT_INFODOC_LIBELLE]
            if libval == ConstantesGrosFichiers.LIBVAL_FICHIER:
                set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = nouveau_nom
            elif libval == ConstantesGrosFichiers.LIBVAL_COLLECTION:
                set_ops[ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION] = nouveau_nom

            resultat = collection_domaine.update_one(filtre, {
                '$set': set_ops,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            })

            if resultat.matched_count != 1:
                raise Exception("Erreur renommer fichier/collection, mismatch count : %d" % resultat.matched_count)
        else:
            self._logger.error('renommer_deplacer_fichier aucun document trouve pour uuid : %s' % uuid_doc)

    # def maj_collection_publique(self, evenement: dict):
    #     """
    #     Met a jour une collection publique - s'assure que les fichiers sont deployes au besoin
    #     :param evenement:
    #     :return:
    #     """
    #
    #     # Declencher processus d'entretien - va publier fichiers sur noeuds publics
    #     nom_module = 'millegrilles_domaines_GrosFichiers'
    #     nom_classe = 'ProcessusEntretienCollectionPublique'
    #     processus = "%s:%s" % (nom_module, nom_classe)
    #     self.demarrer_processus(processus, evenement)

    def maj_description_fichier(self, uuid_fichier, transaction: dict):
        """
        Met a jour les champs de description (titre, description, commentaires)
        :param uuid_fichier:
        :param transaction:
        :return:
        """
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = dict()
        champs = ['nom_fichier', 'titre', 'description']
        for champ in champs:
            try:
                set_operation[champ] = transaction[champ]
            except KeyError:
                pass

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER
        }
        resultat = collection_domaine.find_one_and_update(filtre, {
            '$set': set_operation,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }, return_document=ReturnDocument.AFTER)
        self._logger.debug('maj_description_fichier resultat: %s' % str(resultat))

        return resultat

    def maj_description_collection(self, uuid_collection, transaction: dict):
        """
        Met a jour les champs de description (titre, description, commentaires)
        :param uuid_collection:
        :param transaction:
        :return:
        """
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = dict()
        champs = ['nom_collection', 'titre', 'description', 'securite']
        for champ in champs:
            try:
                set_operation[champ] = transaction[champ]
            except KeyError:
                pass

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION
        }
        resultat = collection_domaine.find_one_and_update(
            filtre,
            {
                '$set': set_operation,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            },
            return_document=ReturnDocument.AFTER
        )

        self._logger.debug('maj_description_collection resultat: %s' % str(resultat))
        return resultat

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

    def supprimer_fichier(self, uuids_documents: list):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: True,
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_SUPPRESSION: datetime.datetime.utcnow()
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuids_documents},
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
                ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
            ]}
        }
        resultat = collection_domaine.update_many(filtre, {
            '$set': set_operation
        })
        if resultat.matched_count != len(uuids_documents):
            raise Exception("Erreur supprimer documents, match count %d != %d" % (resultat.matched_count, len(uuids_documents)))

    def recuperer_fichier(self, uuids_documents: list):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        set_operation = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False
        }
        unset_operation = {
            ConstantesGrosFichiers.DOCUMENT_VERSION_DATE_SUPPRESSION: True
        }
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuids_documents},
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ]}
        }
        resultat = collection_domaine.update_many(filtre, {
            '$set': set_operation,
            '$unset': unset_operation
        })
        if resultat.matched_count != len(uuids_documents):
            raise Exception("Erreur recuperer documents, match count %d != %d" % (resultat.matched_count, len(uuids_documents)))

    def creer_collection(self, uuid_collection: str, nom_collection: str = None, uuid_parent: str = None, creer_parent=False):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        collection = ConstantesGrosFichiers.DOCUMENT_COLLECTION.copy()
        collection[ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION] = nom_collection
        collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = uuid_collection

        if uuid_parent:
            self._logger.debug("Creer collection %s avec parent %s" % (uuid_collection, uuid_parent))
            collection[ConstantesGrosFichiers.DOCUMENT_COLLECTIONS] = [uuid_parent]

            if creer_parent is True:
                # Verifier si le parent existe, le creer au besoin
                filtre_parent = {ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_parent}
                doc_parent = collection_domaine.find_one(filtre_parent)
                if doc_parent is None:
                    # Creer la collection parent
                    self.creer_collection(uuid_parent, uuid_parent)

        date_creation = datetime.datetime.utcnow()
        collection[Constantes.DOCUMENT_INFODOC_DATE_CREATION] = date_creation
        collection[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = date_creation

        # Inserer la nouvelle collection
        resultat = collection_domaine.insert_one(collection)
        self._logger.debug('maj_libelles_fichier resultat: %s' % str(resultat))

        self.creer_trigger_collectionfichiers({ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection})

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

        self.creer_trigger_collectionfichiers({ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection})

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

        self.creer_trigger_collectionfichiers({ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection})

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

        self.creer_trigger_collectionfichiers({ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection})

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

        self.creer_trigger_collectionfichiers({ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection})

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
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuid_documents},
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesGrosFichiers.LIBVAL_FICHIER, ConstantesGrosFichiers.LIBVAL_COLLECTION]
            },
        }

        addtoset_ops = {
            ConstantesGrosFichiers.DOCUMENT_COLLECTIONS: uuid_collection
        }

        ops = {
            '$addToSet': addtoset_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        resultats = collection_domaine.update_many(filtre_documents, ops)
        if resultats.matched_count != len(uuid_documents):
            raise Exception("Erreur association collection, %d != %d" % (resultats.matched_count, len(uuid_documents)))

        self.creer_trigger_collectionfichiers({ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection})

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

    def retirer_fichiers_collection(self, uuid_collection: str, uuid_documents: list = None, fuuid_documents: list = None):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        if uuid_documents is None:
            uuid_documents = list()

        if fuuid_documents is not None:
            filtre_fuuids = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: {'$in': fuuid_documents}
            }
            curseur_fichiers = collection_domaine.find(filtre_fuuids)
            uuid_fichiers = [u['uuid'] for u in curseur_fichiers]
            uuid_documents.extend(uuid_fichiers)

        filtre_documents = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': uuid_documents},
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
                ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
            ]},
        }

        pull_ops = {
            ConstantesGrosFichiers.DOCUMENT_COLLECTIONS: uuid_collection
        }

        ops = {
            '$pull': pull_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        resultats = collection_domaine.update_many(filtre_documents, ops)
        if resultats.matched_count != len(uuid_documents):
            raise Exception("Erreur retrait collection, %d != %d" % (resultats.matched_count, len(uuid_documents)))

        self.creer_trigger_collectionfichiers({ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection})

    def changer_favoris(self, docs_uuids: dict):
        self._logger.debug("Ajouter favor %s" % docs_uuids)
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        date_courante = datetime.datetime.utcnow()

        # Separer uuids a ajouter au favoris et ceux a supprimer (False)
        uuids_ajouter = list()
        uuids_supprimer = list()
        for uuid_doc, value in docs_uuids.items():
            if value is True:
                uuids_ajouter.append(uuid_doc)
            elif value is False:
                uuids_supprimer.append(uuid_doc)

        filtre_docs = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {
                '$in': [ConstantesGrosFichiers.LIBVAL_FICHIER, ConstantesGrosFichiers.LIBVAL_COLLECTION, ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE]
            },
        }
        filtre_docs_supprimer = filtre_docs.copy()
        filtre_docs_supprimer[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = {'$in': uuids_supprimer}
        filtre_docs_ajouter = filtre_docs.copy()
        filtre_docs_ajouter[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = {'$in': uuids_ajouter}

        op_ajouter = {
            '$set': {'favoris': date_courante}
        }
        op_supprimer = {
            '$unset': {'favoris': ''}
        }

        # On fait deux operations, une pour ajouter les favoris et une pour supprimer
        self._logger.debug("Ajouter favoris : %s", uuids_ajouter)
        resultat = collection_domaine.update_many(filtre_docs_ajouter, op_ajouter)
        if resultat.matched_count != len(uuids_ajouter):
            raise Exception("Erreur ajout favoris, compte different du nombre fourni")

        self._logger.debug("Supprimer favoris : %s", uuids_supprimer)
        resultat = collection_domaine.update_many(filtre_docs_supprimer, op_supprimer)
        if resultat.matched_count != len(uuids_supprimer):
            raise Exception("Erreur ajout favoris, compte different du nombre fourni")

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

    def associer_video_transcode(self, transaction):
        fuuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
        mimetype = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
        resolution = transaction['height']
        bitrate = transaction['bitrate']

        fuuid_video = transaction['fuuidVideo']

        # Cle de format du video
        cle_video = ';'.join([mimetype, str(resolution), str(bitrate)])

        info_video = {
            'fuuid': fuuid_video,
            'hachage': fuuid_video,
            'mimetype': mimetype,
            'codecVideo': transaction['codec'],
            'width': transaction['width'],
            'height': resolution,
            'bitrate': bitrate,
            'taille': transaction['tailleFichier'],
        }

        set_ops = {
            'versions.%s.video.%s' % (fuuid_fichier, cle_video): info_video,
            ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES + '.' + fuuid_video: mimetype,
        }

        addtoset_ops = {
            ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: fuuid_video
        }

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            'versions.' + fuuid_fichier: {'$exists': True},
        }

        ops = {
            '$set': set_ops,
            '$addToSet': addtoset_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        document_fichier = collection_domaine.find_one_and_update(filtre, ops)

        # MAJ document medias, retirer la demande de video (complete)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA
        }
        unset_ops = {
            'video.' + fuuid_fichier + '.' + cle_video: True,
            'video.' + fuuid_fichier + '.' + mimetype: True,
        }
        ops = {'$unset': unset_ops, '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}}
        fichier_maj = collection_domaine.find_one_and_update(filtre, ops, return_document=ReturnDocument.AFTER)

        try:
            self.emettre_evenement_fichier_maj(fuuid_fichier)
        except Exception as e:
            self._logger.error("Erreur tranmission evenement maj fichier: %s" % str(e))

        return document_fichier

    def progres_video_transcode(self, message: dict):
        fuuid_fichier = message[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
        mimetype = message[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
        resolution = message['height']
        bitrate = message['videoBitrate']

        # Cle de format du video
        cle_video = ';'.join([mimetype, str(resolution), str(bitrate)])
        cle_progres = '.'.join(['video', fuuid_fichier, cle_video, 'pct_progres'])
        cle_activite = '.'.join(['video', fuuid_fichier, cle_video, 'derniere_activite'])
        progres = message['pctProgres']

        set_ops = {
            cle_progres: progres
        }
        ops = {
            '$set': set_ops,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
                cle_activite: True,
            }
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA,
        }

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(filtre, ops)

    def resoumettre_conversions_manquantes(self):
        filtre_doc_media = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA}
        collection_documents = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        document_conversion_media = collection_documents.find_one(filtre_doc_media)
        self._logger.debug("Resoumettre les conversions manquantes : %s" % str(document_conversion_media))

        # Si le debut de resoumission depasse ce timestamp, on abandonne
        ts_limite_resoumission = datetime.datetime.utcnow() - datetime.timedelta(minutes=2)

        set_ops = dict()
        unset_ops = dict()
        current_date = dict()
        if document_conversion_media:
            previews_en_cours = document_conversion_media.get(ConstantesGrosFichiers.DOCUMENT_POSTERS)

            if previews_en_cours:
                for fuuid, doc in previews_en_cours.items():
                    debut_resoumission = doc.get('debut_resoumission')

                    if debut_resoumission is None:
                        self._logger.debug("Debut periode resoumission preview %s" % fuuid)
                        debut_resoumission = datetime.datetime.utcnow()
                        set_ops['previews.%s.debut_resoumission' % fuuid] = debut_resoumission

                    if debut_resoumission < ts_limite_resoumission:
                        self._logger.debug("Fin tentative resoumissions preview %s, echec" % fuuid)
                        unset_ops['previews.%s' % fuuid] = True
                    else:
                        # Resoumettre demande de conversion
                        commande_preview = doc.copy()
                        # if securite == Constantes.SECURITE_PROTEGE:
                        #     # Creer une permission de dechiffrage pour recuperer la cle du fichier
                        #     commande_permission = self.preparer_information_fichier(fuuid)
                        #     commande_preview[
                        #         ConstantesGrosFichiers.DOCUMENT_FICHIER_COMMANDE_PERMISSION] = commande_permission

                        current_date['previews.%s.derniere_activite' % fuuid] = True

                        mimetype = doc['mimetype'].split('/')[0]
                        if mimetype == 'video':
                            routing_key = 'commande.fichiers.genererPreviewVideo'
                        elif mimetype == 'image':
                            routing_key = 'commande.fichiers.genererPreviewImage'
                        else:
                            routing_key = None

                        if routing_key is not None:
                            self.generateur_transactions.transmettre_commande(commande_preview, routing_key)

            task_expiree = pytz.utc.localize(datetime.datetime.utcnow()) - datetime.timedelta(minutes=30)

            transcodage_en_cours = document_conversion_media.get(ConstantesGrosFichiers.DOCUMENT_VIDEO)
            if transcodage_en_cours is not None:
                # Nettoyer tous les elements vides
                for key, value in transcodage_en_cours.items():
                    if value is None or len(value) == 0:
                        unset_ops['.'.join([ConstantesGrosFichiers.DOCUMENT_VIDEO, key])] = True
                    else:
                        for task_key, task_value in value.items():
                            if task_value is None or len(task_value) == 0:
                                unset_ops['.'.join([ConstantesGrosFichiers.DOCUMENT_VIDEO, key, task_key])] = True
                            elif task_value.get('derniere_activite') and (task_value.get('pctProgres') is not None or task_value.get('err') is not None):
                                derniere_activite = pytz.utc.localize(task_value.get('derniere_activite'))
                                if derniere_activite < task_expiree:
                                    unset_ops['.'.join([ConstantesGrosFichiers.DOCUMENT_VIDEO, key, task_key])] = True
                            else:
                                # Task sans date derniere activite (c'est un bug, cleanup)
                                unset_ops['.'.join([ConstantesGrosFichiers.DOCUMENT_VIDEO, key, task_key])] = True

        current_date[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION] = True
        ops = {
            '$currentDate': current_date
        }
        if len(set_ops.keys()) > 0:
            ops['$set'] = set_ops
        if len(unset_ops.keys()) > 0:
            ops['$unset'] = unset_ops

        collection_documents.update_one(filtre_doc_media, ops)

        self._logger.debug("Set ops : %s\nUnset ops: %s" % (set_ops, unset_ops))

    def preparer_information_fichier(self, fuuid, fichier: dict = None, info_version: dict = None, roles: list = None, duree: int = 120):
        if roles is None:
            roles = ['fichiers']

        liste_hachage = list()
        permission = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: fuuid,
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_ROLES_PERMIS: roles,
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: duree,
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: liste_hachage,
        }

        if fichier:
            uuid_fichier = fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = uuid_fichier
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER] = fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]
            try:
                liste_hachage.extend(fichier[ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS])
            except KeyError:
                pass

        fuuid_associes = list()

        try:
            if info_version is None:
                info_version = fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS][fuuid]
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = info_version[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL] = info_version[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL]
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE] = info_version[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_TAILLE]
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW] = info_version[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW]
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW] = info_version[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW]
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_PREVIEW] = info_version[
                ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_PREVIEW]

            fuuid_associes.append(info_version[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW])
            liste_hachage.append(info_version[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID])
            liste_hachage.append(info_version[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE_PREVIEW])
        except (KeyError, TypeError):
            pass

        # Ajouter permissions fichiers attaches/directement lies (video)
        try:
            video = info_version['video']
            for value_dict in video.values():
                fuuid_associes.append(value_dict['fuuid'])
                liste_hachage.append(value_dict[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE])
        except (KeyError, TypeError):
            pass

        if len(fuuid_associes) > 0:
            permission[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_ASSOCIES] = fuuid_associes

        # Signer
        # generateur_transactions = self._contexte.generateur_transactions
        # commande_permission = generateur_transactions.preparer_enveloppe(
        #     permission,
        #     '.'.join([Constantes.ConstantesMaitreDesCles.DOMAINE_NOM,
        #               Constantes.ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER])
        # )

        return permission

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
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE,
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
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE,
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

    def ajouter_conversion_poster(self, info: dict):

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA
        }

        info_copy = info.copy()
        info_copy['derniere_activite'] = datetime.datetime.utcnow()
        set_ops = {
            ConstantesGrosFichiers.DOCUMENT_POSTERS + '.' + info['fuuid']: info_copy
        }

        ops = {'$set': set_ops, '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}}

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(filtre, ops)

    def ajouter_transcodage_video(self, info: dict, mimetype='video/mp4', resolution=480, bitrate=600000):

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA
        }

        info_copy = info.copy()
        info_copy['derniere_activite'] = datetime.datetime.utcnow()
        # info_copy['progres'] = 0
        key_doc = '.'.join([
            ConstantesGrosFichiers.DOCUMENT_VIDEO,
            info['fuuid'],
            ';'.join([mimetype, str(resolution), str(bitrate)])
        ])
        set_ops = {
            key_doc: info_copy
        }

        ops = {'$set': set_ops, '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}}

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(filtre, ops)

    def associer_preview(self, transaction: dict):
        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        fuuid = transaction['fuuid']
        mimetype_preview = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW) or 'image/jpg'
        uuid_document = transaction['uuid']

        # Sauvegarder preview
        filtre_fichier = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesGrosFichiers.LIBVAL_FICHIER,
                ConstantesGrosFichiers.LIBVAL_COLLECTION,
                ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE
            ]},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_document
        }
        set_ops_fichier = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FLAG_PREVIEW: True,
            # ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES + '.' + fuuid: mimetype_preview,
        }
        for key in [
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE_PREVIEW,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_DATA_VIDEO,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE_VIDEO,
        ]:
            value = transaction.get(key)
            if value:
                key_version = '.'.join([
                    ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS,
                    fuuid,
                    key,
                ])
                set_ops_fichier[key_version] = value

        fuuid_preview = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW)
        if fuuid_preview is not None:
            set_ops_fichier[ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES + '.' + fuuid_preview] = mimetype_preview

        ops_fichier = {
            '$set': set_ops_fichier,
            '$addToSet': {
                # Ajouter fuuid poster a la liste des fuuids associes au fichier
                ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW]
            },
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        fichier_maj = collection_domaine.find_one_and_update(filtre_fichier, ops_fichier, return_document=ReturnDocument.AFTER)
        self.emettre_evenement_fichier_maj(fuuid, fichier_maj, ConstantesGrosFichiers.EVENEMENT_ASSOCIATION_POSTER)

        # MAJ document medias, retirer la demande de preview (complete)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA
        }
        unset_ops = {
            ConstantesGrosFichiers.DOCUMENT_POSTERS + '.' + fuuid: True
        }
        ops = {
            '$unset': unset_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        collection_domaine.update_one(filtre, ops)

    def associer_conversions(self, params: dict):
        """
        Sert a associer les conversions et autre information d'une image (width, height, etc.).
        :param params:
        :return:
        """
        uuid_fichier = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        fuuid_fichier = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
        conversions_images = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_IMAGES]
        width = params.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_WIDTH)
        height = params.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_HEIGHT)
        mimetype = params.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE)
        anime = params.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_ANIME) or False
        metadata = params.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA)

        prefixe_versions = ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS + '.' + fuuid_fichier

        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }
        set_ops = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FLAG_PREVIEW: True,
            prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_IMAGES: conversions_images,
            prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_ANIME: anime,
        }
        if mimetype is not None:
            set_ops[prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE] = mimetype
            set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_MIMETYPES + '.' + fuuid_fichier] = mimetype
        if width is not None and height is not None:
            set_ops[prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_WIDTH] = width
            set_ops[prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_HEIGHT] = height
        if metadata is not None:
            set_ops[prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_METADATA] = metadata

            # Tenter extraction de details metadata
            try:
                duration_str = metadata['duration']
                duration_split = duration_str.split(':')
                duration_td = datetime.timedelta(hours=int(duration_split[0]), minutes=int(duration_split[1]), seconds=int(float(duration_split[2])))
                duration = int(duration_td.total_seconds())
                set_ops[prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_DURATION] = duration
            except (TypeError, KeyError, IndexError, AttributeError):
                pass

            try:
                codec_video = metadata['video'].split(' ')[0]
                set_ops[prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_CODEC_VIDEO] = codec_video
            except (KeyError, IndexError, AttributeError):
                pass

            try:
                codec_audio = metadata['audio'].split(' ')[0]
                set_ops[prefixe_versions + '.' + ConstantesGrosFichiers.DOCUMENT_FICHIER_CODEC_AUDIO] = codec_audio
            except (KeyError, IndexError, AttributeError):
                pass

        fuuids = set()

        # Creer mapping fuuid/mimetype
        for info_image in conversions_images.values():
            fuuid_image = info_image[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE]
            fuuids.add(fuuid_image)

            mimetype_image = info_image[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
            set_ops[ConstantesGrosFichiers.CHAMP_FUUID_MIMETYPES + '.' + fuuid_image] = mimetype_image

        # Legacy, recreer ancienne approche _preview (utiliser poster)
        info_poster = conversions_images['poster']
        set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW] = info_poster[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE]
        set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE_PREVIEW] = info_poster[ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE]
        set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW] = info_poster[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE]
        set_ops[ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_PREVIEW] = 'jpg'

        ops = {
            '$set': set_ops,
            '$addToSet': {ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: {'$each': list(fuuids)}},
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection_grosfichiers = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        resultat = collection_grosfichiers.find_one_and_update(filtre, ops, return_document=ReturnDocument.AFTER)
        self.emettre_evenement_fichier_maj(fuuid_fichier, resultat, ConstantesGrosFichiers.EVENEMENT_ASSOCIATION_CONVERSIONS)

        # MAJ document medias, retirer la demande de preview (complete)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA
        }
        unset_ops = {
            ConstantesGrosFichiers.DOCUMENT_POSTERS + '.' + fuuid_fichier: True
        }
        ops = {
            '$unset': unset_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        collection_grosfichiers.update_one(filtre, ops)

        return resultat

    def generer_permission_dechiffrage_fichier_public(self, params: dict):
        fuuid = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        # Recuperer le fichier
        filtre_fichier = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: {'$all': [fuuid]},
        }
        projection_fichier = ['collections', 'uuid', 'versions.' + fuuid, 'nom_fichier', ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS]
        fichier = collection_domaine.find_one(filtre_fichier, projection=projection_fichier)

        try:
            liste_collections = fichier['collections']
        except (TypeError, KeyError):
            fichier_public = False
        else:
            # Verifier que le fichier est bien dans au moins une collection publique
            filtre_collections = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': liste_collections},
                Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PUBLIC,
            }
            projection_collection = [Constantes.DOCUMENT_INFODOC_SECURITE]
            curseur_collections = collection_domaine.find(filtre_collections, projection=projection_collection)

            # Verifier qu'au moins une collection est de securite 1.public
            fichier_public = any([s[Constantes.DOCUMENT_INFODOC_SECURITE] == Constantes.SECURITE_PUBLIC for s in curseur_collections])

        if fichier_public:
            try:
                info_version = fichier['versions'][fuuid]
            except KeyError:
                info_version = None

            duree_12h = 12*60*60
            permission = self.preparer_information_fichier(fuuid, fichier, info_version, duree=duree_12h)
            return permission

        # Erreur, le fichier n'est pas public
        return {'err': "Le fichier n'est pas public", 'fuuid': fuuid}

    def generer_permission_dechiffrage_fichier_prive(self, params, enveloppe_certificat: EnveloppeCertificat):
        fuuid = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)

        # Recuperer le fichier
        filtre_fichier = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: {'$all': [fuuid]},
        }

        projection_fichier = [
            'collections',
            'uuid',
            'versions.' + fuuid,
            'nom_fichier',
            ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_MIMETYPES,
            ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS,
        ]
        fichier = collection_domaine.find_one(filtre_fichier, projection=projection_fichier)

        try:
            mimetype = fichier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_MIMETYPES)[fuuid]
        except KeyError:
            mimetype = None

        try:
            liste_collections = fichier['collections']
        except (TypeError, KeyError):
            fichier_prive = False
        else:
            # Verifier que le fichier est bien dans au moins une collection publique
            filtre_collections = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': liste_collections},
                Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]},
            }
            projection_collection = [Constantes.DOCUMENT_INFODOC_SECURITE]
            curseur_collections = collection_domaine.find(filtre_collections, projection=projection_collection)

            # Verifier qu'au moins une collection est de securite 1.public ou 2.prive
            fichier_prive = any([s[Constantes.DOCUMENT_INFODOC_SECURITE] in [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE] for s in
                                  curseur_collections])

        if fichier_prive:
            try:
                info_version = fichier['versions'][fuuid]
            except KeyError:
                info_version = {ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: mimetype}

            duree_12h = 12 * 60 * 60
            roles = [ConstantesGrosFichiers.DOMAINE_NOM]
            permission = self.preparer_information_fichier(fuuid, fichier, info_version, roles=roles, duree=duree_12h)
            return permission

        # Erreur, le fichier n'est pas public
        return {'err': "Le fichier n'est pas prive", 'fuuid': fuuid}

    def get_liste_collections(self, params: dict):
        """
        Retourne liste de toutes les collections publiques
        :param params:
        :return:
        """
        filtre_securite = [Constantes.SECURITE_PUBLIC]
        if params.get('prive') is True:
            filtre_securite.append(Constantes.SECURITE_PRIVE)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': filtre_securite},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }
        projection = ['uuid', 'nom_collection', 'titre', 'description']

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        curseur = collection_domaine.find(filtre, projection=projection)

        colls = [c for c in curseur]
        for c in colls:
            del c['_id']  # Supprimer champ _id

        return colls

    def get_detail_collections(self, params: dict):
        """
        Retourne liste de toutes les collections publiques et privees (si param['prive']=True)
        :param params:
        :return:
        """
        filtre_securite = [Constantes.SECURITE_PUBLIC]
        if params.get('prive') is True:
            filtre_securite.append(Constantes.SECURITE_PRIVE)

        filtre_collections = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': filtre_securite},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }

        try:
            uuid_collections = params[ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS]
            filtre_collections[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = {'$in': uuid_collections}
        except KeyError:
            pass  # OK, on recupere toutes les collections

        projection_collection = ['uuid', 'nom_collection', 'titre', 'description']

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        curseur_collections = collection_domaine.find(filtre_collections, projection=projection_collection)

        dict_collection_par_uuid = dict()
        for c in curseur_collections:
            # del c['_id']  # Supprimer champ _id
            dict_collection_par_uuid[c['uuid']] = c

        # Charger les fichiers pour toutes les collections
        filtre_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }

        labels_collection_uuids = list()
        for collection_uuid in dict_collection_par_uuid.keys():
            labels_collection_uuids.append({'collections': collection_uuid})

        if len(labels_collection_uuids) > 0:
            filtre_fichiers['$or'] = labels_collection_uuids
            projection_fichiers = [
                'uuid', 'mimetype', 'uuid_preview', 'mimetype_preview',
                'nom_fichier', 'titre', 'description', 'collections',
                'versions', 'taille', 'fuuid_v_courante'
            ]
            curseur_fichiers = collection_domaine.find(filtre_fichiers, projection=projection_fichiers)

            for f in curseur_fichiers:
                # Placer le fichier dans toutes les collections correspondantes
                fuuid_v_courante = f['fuuid_v_courante']
                fichier_mappe = f['versions'][fuuid_v_courante].copy()
                fichier_mappe.update(f)

                del fichier_mappe['_id']
                del fichier_mappe['collections']
                del fichier_mappe['versions']
                del fichier_mappe['fuuid_v_courante']

                # fichier_mappe.update(f['versions'][fuuid_v_courante])

                for uuid_collection_fichier in f.get('collections'):
                    try:
                        collection_fichier = dict_collection_par_uuid[uuid_collection_fichier]
                        try:
                            collection_fichier['fichiers'].append(fichier_mappe)
                        except KeyError:
                            # Initialiser nouvelle liste
                            collection_fichier['fichiers'] = [fichier_mappe]
                    except KeyError:
                        pass  # OK, la collection n'est pas dans la liste a remplir

        liste_collections = list()
        for c in dict_collection_par_uuid.values():
            del c['_id']

            # Signer chaque collection
            enveloppe = self.generateur_transactions.preparer_enveloppe(c)
            liste_collections.append(enveloppe)

        return liste_collections

    def get_transferts_en_cours(self):
        """
        Retourne le document de transferts en cours (AWS S3, ...)
        :return:
        """
        collection = self.get_collection()
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_UPLOAD_AWSS3,
        }
        doc_transferts = collection.find_one(filtre)
        return {ConstantesGrosFichiers.DOCUMENT_UPLOAD_LIST: doc_transferts.get(ConstantesGrosFichiers.DOCUMENT_UPLOAD_LIST)}

    def get_conversion_media_en_cours(self):
        """
        :return: Document de conversion media en cours
        """
        collection = self.get_collection()
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA,
        }
        doc_transcodage = collection.find_one(filtre)

        del doc_transcodage['_id']

        return {ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA: doc_transcodage}

    def get_info_collections_fichier(self, uuid_fichier: str):
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_fichier,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }
        collection_grosfichiers = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        fichier = collection_grosfichiers.find_one(filtre, projection=['collections'])

        try:
            collections_fichier = fichier[ConstantesGrosFichiers.DOCUMENT_COLLECTIONS]
        except (KeyError, TypeError):
            pass  # Pas de fichier ou de collections
        else:
            filtre = {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: {'$in': collections_fichier},
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
                Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PUBLIC,
            }
            curseur_collections = collection_grosfichiers.find(filtre)
            id_collections_publiques = [c[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] for c in curseur_collections]

            if len(id_collections_publiques) > 0:
                params = {ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS: id_collections_publiques}
                detail_collections_publiques = self.get_detail_collections(params)
                return detail_collections_publiques

    def regenerer_previews(self, params: dict):
        """
        Regenere les previews manquants sur les fichiers de media (video, images)
        :return:
        """
        collection_documents = self.get_collection()

        target_fichiers = dict()

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: {'$regex': '^(video|image)'},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }

        if params is not None:
            try:
                target_fichiers['uuid'] = {'$in': params['uuid']}
            except KeyError:
                pass  # OK

        if len(target_fichiers) == 0:
            # Utilise une requete sur tous les ficheirs non generes
            target_fichiers = {'$or': [
                {ConstantesGrosFichiers.DOCUMENT_FICHIER_FLAG_PREVIEW: False},
                {ConstantesGrosFichiers.DOCUMENT_FICHIER_FLAG_PREVIEW: {'$exists': False}},
            ]}

        filtre.update(target_fichiers)

        curseur = collection_documents.find(filtre)

        conversions_resoumises = False
        for f in curseur:
            self._logger.debug("Media sans preview : %s" % str(f))

            # Aplatir document avec fuuid courant
            info = f.copy()
            fuuid_courant = f[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE]
            info.update(f[ConstantesGrosFichiers.DOCUMENT_FICHIER_VERSIONS][fuuid_courant])

            mimetype = info['mimetype'].split('/')[0]
            commande_preview = self.preparer_generer_poster(info)

            if mimetype == 'video':
                domaine_action = 'commande.fichiers.genererPreviewVideo'
            elif mimetype == 'image':
                domaine_action = 'commande.fichiers.genererPreviewImage'
            else:
                continue  # Type inconnu

            self.generateur_transactions.transmettre_commande(commande_preview, domaine_action)
            conversions_resoumises = True

        # Transmettre commande pour commencer le traitement
        if conversions_resoumises is False:
            # S'assurer de nettoyer le document de conversions en cours si aucune conversion n'est trouvee
            # Ne pas executer cette requete si on a deja transmis des documents ... fait generer previews en double
            self.resoumettre_conversions_manquantes()

        return {'ok': True}

    def preparer_generer_poster(self, info: dict):
        """
        Transmettre une commande de creation de poster
        :param info:
        :return:
        """

        # Sauvegarder demande conversion
        self.ajouter_conversion_poster(info)

        commande_preview = info.copy()
        for c in info.keys():
            if c.startswith('_'):
                del commande_preview[c]

        # Aplatir version courante
        try:
            version_courante = commande_preview['versions'][commande_preview['fuuid_v_courante']]
            commande_preview['version_courante'] = version_courante
            del commande_preview['versions']
        except KeyError:
            pass  # OK - ce n'est pas un message charge a partir de la collection

        # if securite == Constantes.SECURITE_PROTEGE:
        # Creer une permission de dechiffrage pour recuperer la cle du fichier
        # commande_permission = self.preparer_information_fichier(fuuid)
        # commande_preview[ConstantesGrosFichiers.DOCUMENT_FICHIER_COMMANDE_PERMISSION] = commande_permission

        # mimetype = info['mimetype'].split('/')[0]

        return commande_preview

        # if mimetype == 'video':
        #     self.ajouter_commande_a_transmettre('commande.fichiers.genererPreviewVideo', commande_preview)
        # elif mimetype == 'image':
        #     self.ajouter_commande_a_transmettre('commande.fichiers.genererPreviewImage', commande_preview)

    def declencher_transcodage_video(self, commande: dict, properties=None):
        """
        Declenche le transcodage d'un video.
        :param commande:
        :return:
        """

        fuuid = commande['fuuid']
        collection_fichiers = self.get_collection()

        # Preparer permission
        filtre_fichier = {
            'versions.%s' % fuuid: {'$exists': True},
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }
        info_fichier = collection_fichiers.find_one(filtre_fichier)
        if info_fichier is None:
            return {'ok': False, 'fuuid': fuuid, 'err': 'Fichier inconnu'}

        info_version = info_fichier['versions'][fuuid]

        # Marquer document media
        resolution = commande['resolutionVideo']
        mimetype = commande['mimetype']
        bitrate = commande['bitrateVideo']
        self.ajouter_transcodage_video(info_version, mimetype=mimetype, resolution=resolution, bitrate=bitrate)

        # Transmettre commande a consignation_fichiers
        commande_transcodage = {
            'fuuid': fuuid,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE: fuuid,
            'mimetype': commande['mimetype']
        }
        champs_optionnels = ['bitrateAudio', 'resolutionVideo', 'bitrateVideo', 'codecAudio', 'codecVideo']
        for champ in champs_optionnels:
            try:
                commande_transcodage[champ] = commande[champ]
            except KeyError:
                pass  # OK

        domaine_action = 'commande.fichiers.transcoderVideo'
        reply_to = properties.reply_to
        correlation_id = properties.correlation_id
        self.generateur_transactions.transmettre_commande(
            commande_transcodage, domaine_action, reply_to=reply_to, correlation_id=correlation_id)

        return {'ok': True}

    def uploader_fichiers_manquants_awss3(self, uuid_collection, noeud_ids):
        """
        Extrait la liste des fichiers qui n'ont pas encore ete publies vers AWS S3 pour une collection
        :param uuid_collection:
        :param noeud_ids:
        :return:
        """

        # Charger document de tracking d'upload de fichiers
        collection_fichiers = self.get_collection()

        # Identifier tous les fichiers qui font partie de la collection et qui ne sont pas publies sur tous les noeuds
        or_noeud_ids = list()
        for noeud_id in noeud_ids:
            valeur = {ConstantesGrosFichiers.DOCUMENT_NOEUD_IDS_PUBLIES: {'$not': {'$all': [noeud_id]}}}
            or_noeud_ids.append(valeur)

        filtre_documents_non_publies = {
            ConstantesGrosFichiers.DOCUMENT_COLLECTIONS: {'$in': [uuid_collection]},
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
            '$or': or_noeud_ids,
        }

        filtre_document_upload = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_UPLOAD_AWSS3,
        }
        try:
            info_fichier = collection_fichiers.find_one(filtre_document_upload)
            upload_list_existante = info_fichier.get(ConstantesGrosFichiers.DOCUMENT_UPLOAD_LIST) or list()
        except AttributeError:
            upload_list_existante = list()

        ajouter_documents = list()
        info_commande_upload = list()

        curseur = collection_fichiers.find(filtre_documents_non_publies)
        for fichier in curseur:
            # Verifier si le fichier est deja en cours d'upload
            uuid_fichier = fichier['uuid']
            for noeud_id in noeud_ids:
                # Verifier si le fichier/noeud_id est deja dans la liste
                fichier_deja_dans_liste = [f for f in upload_list_existante if f['fuuid'] == fichier['fuuid_v_courante'] and f['noeud_id'] == noeud_id]
                if len(fichier_deja_dans_liste) == 0:
                    self._logger.debug("Uploader fichier %s vers noeud_id %s" % (uuid_fichier, noeud_id))

                    # Mettre a jour le document d'upload
                    ajouter_documents.append({
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: fichier[
                            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE],
                        ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: fichier[
                            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC],
                        ConstantesGrosFichiers.DOCUMENT_DERNIERE_ACTIVITE: datetime.datetime.utcnow(),
                        'noeud_id': noeud_id,
                        ConstantesGrosFichiers.DOCUMENT_PROGRES: 0,
                    })

                    info_commande_upload.append({
                        'noeud_id': noeud_id,
                        'fichier': fichier,
                    })
                    # self.commande_upload_fichier_awss3(noeud_id, fichier)

        if len(ajouter_documents) > 0:
            push_opts = {
                ConstantesGrosFichiers.DOCUMENT_UPLOAD_LIST: {'$each': ajouter_documents},
            }
            setoninsert_document_upload = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_UPLOAD_AWSS3,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            }
            ops = {
                '$push': push_opts,
                '$setOnInsert': setoninsert_document_upload,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            }

            resultat = collection_fichiers.update_one(filtre_document_upload, ops, upsert=True)

            if resultat.matched_count != 1 and resultat.upserted_id is None:
                raise Exception("Erreur maj fichier tracking upload AWS S3")

            for info in info_commande_upload:
                self.commande_upload_fichier_awss3(info['noeud_id'], info['fichier'])

        self._logger.debug("Fin uploader_fichiers_manquants_awss3")

    def commande_upload_fichier_awss3(self, noeud_id: str, fichier_info: dict):

        fuuid = fichier_info['fuuid_v_courante']
        commande = fichier_info.copy()
        del commande['versions']
        commande.update(fichier_info['versions'][fuuid])
        self._logger.debug("Commande update : " + str(commande))

        # Ajouter permission pour dechiffrer le fichier local - c'est un fichier public, on met une longue permission
        # pour permettre traitement de grosses batch
        permission = self.generer_permission_dechiffrage_fichier_public({'fuuid': fuuid})
        commande['permission'] = permission
        commande['noeud_id'] = noeud_id

        domaine_action = 'commande.fichiers.publierAwsS3'
        self.generateur_transactions.transmettre_commande(commande, domaine_action)

    def traiter_evenement_awss3(self, evenement: dict):
        """
        Permet de suivre le progres d'upload de fichiers avec AWS S3
        :param evenement:
        :return:
        """
        etat = evenement.get('etat')
        if etat == 'succes':
            # Upload termine avec succes, on marque le fuuid comme
            self.terminer_upload_awss3(evenement)
        elif etat == 'echec':
            # Echec d'upload
            self.echec_upload_awss3(evenement)
        else:
            # Upload en cours, on met a jour le document de tracking AWS S3
            self.marquer_progres_awss3(evenement)

    def terminer_upload_awss3(self, evenement: dict):
        fuuid = evenement['fuuid']
        noeud_id = evenement['noeud_id']
        collection = self.get_collection()

        # Marquer le document de fichiers (et sa version fuuid) comme uploade pour noeud
        filtre_fichier = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE: fuuid,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
        }
        addtoset_ops_fichier = {
            ConstantesGrosFichiers.DOCUMENT_NOEUD_IDS_PUBLIES: noeud_id,
            'versions.%s.%s' % (fuuid, ConstantesGrosFichiers.DOCUMENT_NOEUD_IDS_PUBLIES): noeud_id,
        }
        ops_fichier = {
            '$addToSet': addtoset_ops_fichier,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        collection.update_one(filtre_fichier, ops_fichier)

        # Mettre a jour le document de tracking
        filtre_tracking = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_UPLOAD_AWSS3
        }
        pull_ops_tracking = {
            ConstantesGrosFichiers.DOCUMENT_UPLOAD_LIST: {'fuuid': fuuid, 'noeud_id': noeud_id}
        }
        ops_tracking = {
            '$pull': pull_ops_tracking,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        collection.update_one(filtre_tracking, ops_tracking)

    def echec_upload_awss3(self, evenement: dict):
        # Mettre a jour le document de tracking
        fuuid = evenement['fuuid']
        noeud_id = evenement['noeud_id']
        filtre_tracking = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_UPLOAD_AWSS3,
            ConstantesGrosFichiers.DOCUMENT_UPLOAD_LIST: {
                '$elemMatch': {'fuuid': fuuid, 'noeud_id': noeud_id}
            }
        }
        set_ops_tracking = {
            'upload_list.$.derniere_activite': datetime.datetime.utcnow(),
            'upload_list.$.progres': -1,
            'upload_list.$.etat': 'echec',
        }
        ops_tracking = {
            '$set': set_ops_tracking,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection = self.get_collection()
        resultat = collection.update_one(filtre_tracking, ops_tracking)

        if resultat.matched_count != 1:
            raise Exception("Erreur traitement mise a jour evenement (echec) AWS S3 - fichier tracking non trouve")

    def marquer_progres_awss3(self, evenement: dict):
        # Mettre a jour le document de tracking
        fuuid = evenement['fuuid']
        noeud_id = evenement['noeud_id']
        etat = evenement.get('etat') or 'N/A'
        filtre_tracking = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_UPLOAD_AWSS3,
            ConstantesGrosFichiers.DOCUMENT_UPLOAD_LIST: {
                '$elemMatch': {'fuuid': fuuid, 'noeud_id': noeud_id}
            }
        }
        set_ops_tracking = {
            'upload_list.$.derniere_activite': datetime.datetime.utcnow(),
            'upload_list.$.progres': evenement['progres'],
            'upload_list.$.etat': etat,
        }
        ops_tracking = {
            '$set': set_ops_tracking,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        collection = self.get_collection()
        resultat = collection.update_one(filtre_tracking, ops_tracking)

        if resultat.matched_count != 1:
            raise Exception("Erreur traitement mise a jour evenement progres AWS S3 - fichier tracking non trouve")

    def reset_fichiers_publies(self, commande: dict):
        """
        Reset la valeur noeuds_ids_publies pour un noeud.
        :param commande:
        :return:
        """
        noeud_id = commande['noeud_id']
        collection = self.get_collection()
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_NOEUD_IDS_PUBLIES: {'$all': [noeud_id]},
        }
        pull_ops = {
            ConstantesGrosFichiers.DOCUMENT_NOEUD_IDS_PUBLIES: noeud_id
        }
        ops = {
            '$pull': pull_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        collection.update_many(filtre, ops)

    def clear_fichier_publie(self, commande: dict):
        try:
            self.terminer_upload_awss3(commande)
        except Exception as e:
            return {'ok': False, 'err': str(e)}
        else:
            return {'ok': True}

    def find_collection_usager(self, user_id: str):
        """
        Trouve la collection correspondant au user_id
        :param user_id:
        :return:
        """
        filtre = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: user_id,
        }
        collection = self.get_collection()
        collection_usager = collection.find_one(filtre)

        if collection_usager is None:
            # Verifier si on a la collection systeme pour les usagers
            filtre = {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: ConstantesGrosFichiers.LIBVAL_UUID_COLLECTION_USAGERS
            }
            collection_usagers = collection.find_one(filtre)

            if collection_usagers is not None:
                uuid_collection_usagers = collection_usagers[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
                raise CollectionAbsenteException(uuid_parent=uuid_collection_usagers)
            else:
                # La collection system usagers n'existe pas
                raise CollectionAbsenteException()

        return collection_usager

    def get_contenu_collection_personnelle(self, message: dict):
        # Recuperer user_id du message
        entete = message[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        estampille = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())
        expiration_requete = date_courante - datetime.timedelta(minutes=1)
        if estampille < expiration_requete.timestamp():  # or estampille > date_courante.timestamp():
            return {'err': 'Estampille requete expiree ou invalide'}

        certificat = self.validateur_message.verifier(message, utiliser_idmg_message=True)
        user_id = certificat.get_user_id

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_COLLECTIONS: {'$all': [user_id]},
        }
        collection = self.get_collection()
        curseur = collection.find(filtre)

        # Extraire la liste des fichiers
        fichiers = self.mapper_fichier_version(curseur)

        # Generer permission pour recuperer les cles des fichiers
        fuuid_fichiers = list()
        # fuuid_fichiers.extend( [f[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE] for f in fichiers] )

        for fichier in fichiers:
            fuuid_fichiers.append(fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUIDVCOURANTE])
            v_courante = fichier['version_courante']
            videos = v_courante.get(ConstantesGrosFichiers.DOCUMENT_VIDEO)

            if v_courante.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW):
                fuuid_fichiers.append(v_courante[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW])

            if videos is not None:
                # Extraire tous les fuuid videos (pour toutes les resolutions)
                fuuid_videos = [vid[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID] for vid in videos.values()]
                fuuid_fichiers.extend(fuuid_videos)

        permission = self.generer_permission(fuuid_fichiers, user_id=user_id)

        reponse = {
            'fichiers': fichiers,
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_PERMISSION: permission,
        }

        return reponse

    def generer_permission(self, fuuids: list, user_id: str = None) -> dict:
        permission = {
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: fuuids,
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: 12 * 60 * 60,  # 12 heures
        }
        if user_id:
            permission[Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_USERID] = user_id

        permission = self.generateur_transactions.preparer_enveloppe(permission, Constantes.ConstantesMaitreDesCles.REQUETE_PERMISSION)

        return permission

    def traiter_evenement_fichiers(self, message: dict, routing_key: str):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_TRANSCODAGE_MEDIA
        }

        params_vid = list()
        params_vid.append(message['mimetype'])
        try:
            params_vid.append(str(message['height']))
        except KeyError:
            pass
        try:
            params_vid.append(str(message['videoBitrate']))
        except KeyError:
            pass
        key_doc = '.'.join([
            ConstantesGrosFichiers.DOCUMENT_VIDEO,
            message['fuuid'],
            ';'.join(params_vid)
        ])

        set_ops = dict()

        action = routing_key.split('.').pop()
        if action == 'transcodageProgres':
            set_ops[key_doc + '.pctProgres'] = message['pctProgres']
        elif action == 'transcodageErreur':
            set_ops[key_doc + '.err'] = message['err']

        ops = {
            '$set': set_ops,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
                key_doc + '.derniere_activite': True,
            }
        }

        collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_domaine.update_one(filtre, ops)

    def creer_trigger_collectionfichiers(self, params: dict, reply_to: str = None, correlation_id: str = None):
        """
        Genere un evenement de trigger pour regenerer la collectionFichiers
        :param uuid_collection:
        :return:
        """
        params = params.copy()
        if reply_to:
            params['reply_to'] = reply_to
        if correlation_id:
            params['correlation_id'] = correlation_id

        uuid_collections = set()
        liste_collections = params.get(ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS) or list()
        uuid_collection = params.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC)
        if uuid_collection is not None:
            uuid_collections.add(uuid_collection)
        if liste_collections is not None:
            uuid_collections.update(liste_collections)

        for uuid_collection in liste_collections:
            params[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC] = uuid_collection
            self.demarrer_processus('millegrilles_domaines_GrosFichiers:ProcessusGenererCollectionFichiers', params)

    def associer_fichier_collection(self, params: dict):
        """
        Verifier si le fichier est deja dans la collection - creer une transaction au besoin.
        :param params:
        :return:
        """
        fuuid = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID]
        uuid_collection = params[ConstantesGrosFichiers.CHAMP_UUID_COLLECTION]

        collection_fichiers = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_LISTE_FUUIDS: {'$all': [fuuid]},
        }
        doc_fichier = collection_fichiers.find_one(filtre)

        collections_fichier = doc_fichier.get(ConstantesGrosFichiers.DOCUMENT_COLLECTIONS)
        if collections_fichier is None or uuid_collection not in collections_fichier:
            # Collection manquante. Creer la transaction d'ajout pour le fichier.
            uuid_fichier = doc_fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
            transaction = {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
                ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS: [uuid_fichier],
            }
            domaine_action = ConstantesGrosFichiers.TRANSACTION_AJOUTER_FICHIERS_COLLECTION
            self.generateur_transactions.soumettre_transaction(transaction, domaine_action)

    def generer_collectionfichiers(self, params: dict, enveloppes_rechiffrage: dict = None):
        collection_grosfichiers = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
        collection_collectionfichiers = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_COLLECTIONFICHIERS_NOM)

        uuid_collection = params[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        filtre_collection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }
        champs_collections = [
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION,
            Constantes.DOCUMENT_INFODOC_SECURITE,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME,
            ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES,
        ]
        collection_doc = collection_grosfichiers.find_one(filtre_collection)

        securite = collection_doc[Constantes.DOCUMENT_INFODOC_SECURITE]
        filtre_collectionfichiers = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }

        if securite == Constantes.SECURITE_PROTEGE:
            # Les collections protegees ne doivent pas etre generees ou exportees
            collection_collectionfichiers.delete_one(filtre_collectionfichiers)
            return

        contenu = dict()
        for champ in champs_collections:
            valeur = collection_doc.get(champ)
            if valeur is not None:
                contenu[champ] = valeur

        # Trouver tous les fichiers inclus dans cette collection
        filtre_fichiers = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_FICHIER,
            ConstantesGrosFichiers.DOCUMENT_COLLECTIONS: {'$all': [uuid_collection]},
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: False,
        }
        curseur_fichiers = collection_grosfichiers.find(filtre_fichiers)

        extra_out = dict()
        fichiers = self.mapper_fichier_version(curseur_fichiers, extra_out)
        contenu[ConstantesGrosFichiers.DOCUMENT_COLLECTION_FICHIERS] = fichiers

        set_ops = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
            Constantes.DOCUMENT_INFODOC_SECURITE: securite,
            ConstantesGrosFichiers.CHAMP_DATE_CREATION: collection_doc[
                Constantes.DOCUMENT_INFODOC_DATE_CREATION],
            ConstantesGrosFichiers.CHAMP_DATE_MODIFICATION: datetime.datetime.utcnow(),
            ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME: collection_doc[ConstantesGrosFichiers.DOCUMENT_FICHIER_SUPPRIME],
        }
        unset_ops = dict()

        if securite == Constantes.SECURITE_PUBLIC:
            # Copier le contenu tel quel
            set_ops.update(contenu)

            unset_ops['hachage_bytes'] = True
            unset_ops['contenu_chiffre'] = True
            unset_ops['permission'] = True

        elif securite == Constantes.SECURITE_PRIVE:
            # Chiffrer le contenu
            identificateurs_documents = {
                'type': 'CollectionFichiers',
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
            }

            # Permission de dechiffrage des fichiers (on va l'inserer dans le contenu chiffre)
            fuuids = extra_out['fuuids']
            fuuids = list(set(fuuids))  # Dedupe
            permission = {
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: fuuids,
                Constantes.DOCUMENT_INFODOC_SECURITE: securite,
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: 10 * 365 * 24 * 60 * 60,  # 10 ans
            }
            permission = self.generateur_transactions.preparer_enveloppe(permission, ConstantesMaitreDesCles.REQUETE_PERMISSION)
            contenu['permission'] = permission

            contenu_chiffre, hachage_bytes = self.chiffrer_contenu(
                contenu, enveloppes_rechiffrage, identificateurs_documents)

            # Ajouter permission de dechiffrage du forum_post (contenu chiffre)
            permission = {
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: [hachage_bytes],
                Constantes.DOCUMENT_INFODOC_SECURITE: securite,
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: 10 * 365 * 24 * 60 * 60,  # 10 ans
            }
            permission = self.generateur_transactions.preparer_enveloppe(permission, ConstantesMaitreDesCles.REQUETE_PERMISSION)
            set_ops['permission'] = permission
            set_ops['hachage_bytes'] = hachage_bytes
            set_ops['contenu_chiffre'] = contenu_chiffre

            unset_ops['nom_collection'] = True
            unset_ops['fichiers'] = True

        document_forum_posts = self.generateur_transactions.preparer_enveloppe(
            set_ops,
            domaine='GrosFichiers.' + ConstantesGrosFichiers.LIBVAL_COLLECTION_FICHIERS,
            ajouter_certificats=True
        )

        ops = {
            '$set': document_forum_posts,
        }
        if len(unset_ops) > 0:
            ops['$unset'] = unset_ops

        collection_collectionfichiers.update(filtre_collectionfichiers, ops, upsert=True)

    def chiffrer_contenu(self, contenu, enveloppes_rechiffrage, identificateurs_documents):
        json_helper = JSONHelper()
        contenu = json_helper.dict_vers_json(contenu)
        contenu = gzip.compress(contenu)
        cipher = CipherMsg2Chiffrer(encoding_digest='base58btc')
        cipher.start_encrypt()
        contenu = cipher.update(contenu)
        contenu += cipher.finalize()
        hachage_bytes = cipher.digest
        # Chiffrer la cle secrete pour chaque enveloppe
        cles = dict()
        for fp, enveloppe in enveloppes_rechiffrage.items():
            cle_chiffree = cipher.chiffrer_motdepasse_enveloppe(enveloppe)
            cle_chiffree = multibase.encode('base64', cle_chiffree).decode('utf-8')
            cles[fp] = cle_chiffree
        commande_maitrecles = {
            'domaine': 'Forum',
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: identificateurs_documents,
            'format': 'mgs2',
            'cles': cles,
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: hachage_bytes,
        }
        commande_maitrecles.update(cipher.get_meta())
        # Transmettre commande de sauvegarde de cle
        self.generateur_transactions.transmettre_commande(
            commande_maitrecles, 'commande.MaitreDesCles.' + ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE)
        contenu_chiffre = multibase.encode('base64', contenu).decode('utf-8')
        return contenu_chiffre, hachage_bytes


class RegenerateurGrosFichiers(RegenerateurDeDocuments):

    def __init__(self, gestionnaire_domaine):
        super().__init__(gestionnaire_domaine)

    def creer_generateur_transactions(self):

        transactions_a_ignorer = [
            # ConstantesGrosFichiers.TRANSACTION_DECRYPTER_FICHIER,
        ]

        return GroupeurTransactionsARegenerer(self._gestionnaire_domaine, transactions_a_ignorer)


# ******************* Processus *******************
class ProcessusGrosFichiers(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesGrosFichiers.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesGrosFichiers.COLLECTION_PROCESSUS_NOM

    def evenement_maj_fichier(self, uuid_fichier: str):
        """
        Verifie si le changement a un impact sur les collections publiques et transmet un evenement
        pour chaque collection publique affectee.
        :param uuid_fichier: fichier qui a ete mis a jour
        :return:
        """
        doc_fichier = self.controleur.gestionnaire.get_fichier_par_uuid(uuid_fichier)
        # Emettre un evenement pour chaque collection publique
        try:
            doc_fichier['version_courante'] = doc_fichier['versions'][doc_fichier['fuuid_v_courante']]
            domaine_action = 'evenement.grosfichiers.' + ConstantesGrosFichiers.EVENEMENT_MAJ_FICHIER
            self.generateur_transactions.emettre_message(
                doc_fichier,
                domaine_action,
                exchanges=[Constantes.SECURITE_PROTEGE],
                ajouter_certificats=True
            )
        except TypeError:
            pass  # None, pas de collections publiques

    def evenement_maj_collection(self, uuid_collection: str):
        """
        Verifie si le changement a un impact sur les collections publiques et transmet un evenement
        pour chaque collection publique affectee.
        :param uuid_fichier: fichier qui a ete mis a jour
        :return:
        """
        doc_collection = self.controleur.gestionnaire.get_collection_par_uuid(uuid_collection)
        # Emettre un evenement pour chaque collection publique
        try:
            domaine_action = 'evenement.grosfichiers.' + ConstantesGrosFichiers.EVENEMENT_MAJ_COLLECTION
            self.generateur_transactions.emettre_message(
                doc_collection,
                domaine_action,
                exchanges=[Constantes.SECURITE_PROTEGE],
                ajouter_certificats=True
            )
        except (AttributeError, TypeError):
            pass  # Ok


class ProcessusGrosFichiersActivite(ProcessusGrosFichiers):
    pass


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

        # info-version :
        #   "date_version": ISODate("2020-04-09T13:22:16.000Z"),
        #   "fuuid": "20805bb0-7a65-11ea-8d47-6740c3cdc870",
        #   "securite": "3.protege",
        #   "nom_fichier": "IMG_0005.JPG",
        #   "taille": 265334,
        #   "mimetype": "image/jpeg",
        #   "sha256": "a99e771ebda5b9c599852782d5317334b2358aeb78931e3ba569a29d95ce5ae1",
        #   "extension": "jpg",

    def initiale(self):
        """ Sauvegarder une nouvelle version d'un fichier """
        transaction = self.charger_transaction()
        resultat = self._controleur.gestionnaire.maj_fichier(transaction)

        # Vierifier si le document de fichier existe deja
        fuuid = transaction['fuuid']
        document_uuid = transaction.get(ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID)   # Represente la collection, si present
        nom_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]
        extension = GestionnaireGrosFichiers.extension_fichier(nom_fichier)
        resultat = {
            'uuid': resultat['uuid_fichier'],
            'fuuid': fuuid,
            'collection_uuid': document_uuid,
            'mimetype': transaction['mimetype'],
            'extension': extension,
            'nom_fichier': transaction['nom_fichier'],
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE: fuuid,
        }

        # Verifier s'il y a un traitement supplementaire a faire
        mimetype = self.transaction['mimetype'].split('/')[0]
        if mimetype in ['video', 'image']:
            self._traiter_media(resultat)
        elif document_uuid is not None:
            # Le fichier pourrait avoir ete ajoute dans une collection publique
            try:
                self.evenement_maj_fichier(resultat['uuid'])
            except Exception:
                self.__logger.exception("Erreur verification collection publique")

        self.set_etape_suivante()  # Termine

        return resultat

    def _traiter_media(self, info: dict):
        # # Transmettre une commande de transcodage
        mimetype = info['mimetype'].split('/')[0]
        commande_preview = self.controleur.gestionnaire.preparer_generer_poster(info)
        if mimetype == 'video':
            self.ajouter_commande_a_transmettre('commande.fichiers.genererPreviewVideo', commande_preview)
        elif mimetype == 'image':
            self.ajouter_commande_a_transmettre('commande.fichiers.genererPreviewImage', commande_preview)


# class ProcessusTransactionDemandeThumbnailProtege(ProcessusGrosFichiersActivite):
#     """
#     Transaction qui sert a synchroniser la demande et reception d'un thumbnail protege.
#     """
#     def initiale(self):
#
#         transaction = self.transaction
#         fuuid = transaction['fuuid']
#         uuid_fichier = transaction['uuid_fichier']
#
#         # Transmettre requete pour certificat de consignation.grosfichiers
#         self.set_requete('pki.role.fichiers', {})
#
#         # Le processus est en mode regeneration
#         # self._traitement_collection()
#         token_attente = 'associer_thumbnail:%s' % fuuid
#         if not self._controleur.is_regeneration:
#             self.set_etape_suivante(ProcessusTransactionDemandeThumbnailProtege.attente_cle_decryptage.__name__,
#                                     [token_attente])
#         else:
#             self.set_etape_suivante(ProcessusTransactionDemandeThumbnailProtege.persister.__name__, [token_attente])  # Termine
#
#         return {
#             'fuuid': fuuid,
#             'uuid_fichier': uuid_fichier,
#         }
#
#     def attente_cle_decryptage(self):
#         fuuid = self.parametres['fuuid']
#
#         fingerprint_fichiers = self.parametres['reponse'][0]['fingerprint']
#
#         # Transmettre transaction au maitre des cles pour recuperer cle secrete decryptee
#         transaction_maitredescles = {
#             'fuuid': fuuid,
#             'fingerprint': fingerprint_fichiers,
#         }
#         domaine = 'millegrilles.domaines.MaitreDesCles.decryptageGrosFichier'
#
#         # Effectuer requete pour re-chiffrer la cle du document pour le consignateur de transactions
#         self.set_requete(domaine, transaction_maitredescles)
#
#         # self.controleur.generateur_transactions.soumettre_transaction(transaction_maitredescles, domaine)
#
#         # token_attente = 'decrypterFichier_cleSecrete:%s' % fuuid
#         self.set_etape_suivante(ProcessusTransactionDemandeThumbnailProtege.demander_thumbnail_protege.__name__)
#
#     def demander_thumbnail_protege(self):
#         information_cle_secrete = self.parametres['reponse'][1]
#
#         cle_secrete_chiffree = information_cle_secrete['cle']
#         iv = information_cle_secrete['iv']
#
#         information_fichier = self.controleur.gestionnaire.get_fichier_par_fuuid(self.parametres['fuuid'])
#
#         fuuid = self.parametres['fuuid']
#         token_attente = 'associer_thumbnail:%s' % fuuid
#
#         # Transmettre commande a grosfichiers
#
#         commande = {
#             'fuuid': fuuid,
#             'cleSecreteChiffree': cle_secrete_chiffree,
#             'iv': iv,
#             'nomfichier': information_fichier['nom'],
#             'mimetype': information_fichier['mimetype'],
#             'extension': information_fichier.get('extension'),
#         }
#
#         self.controleur.generateur_transactions.transmettre_commande(
#             commande, ConstantesGrosFichiers.COMMANDE_GENERER_THUMBNAIL_PROTEGE)
#
#         self.set_etape_suivante(ProcessusTransactionDemandeThumbnailProtege.persister.__name__, [token_attente])
#
#     def persister(self):
#
#         # MAJ Collections associes au fichier
#         self.controleur.gestionnaire.maj_fichier_dans_collection(self.parametres['uuid_fichier'])
#
#         self.set_etape_suivante()  # Termine


# class ProcessusTransactionNouvelleVersionTransfertComplete(ProcessusGrosFichiers):
#
#     def __init__(self, controleur: MGPProcesseur, evenement):
#         super().__init__(controleur, evenement)
#
#     def initiale(self):
#         """
#         Emet un evenement pour indiquer que le transfert complete est arrive. Comme on ne donne pas de prochaine
#         etape, une fois les tokens consommes, le processus sera termine.
#         """
#         transaction = self.charger_transaction()
#         fuuid = transaction.get('fuuid')
#         token_resumer = '%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_TRANSFERTCOMPLETE, fuuid)
#         self.resumer_processus([token_resumer])
#
#         # Une fois les tokens consommes, le processus sera termine.
#         self.set_etape_suivante(ProcessusTransactionNouvelleVersionTransfertComplete.attente_token.__name__)
#
#         return {'fuuid': fuuid}
#
#     def attente_token(self):
#         self.set_etape_suivante()  # Termine


# class ProcessusTransactionNouvelleVersionClesRecues(ProcessusGrosFichiers):
#
#     def __init__(self, controleur: MGPProcesseur, evenement):
#         super().__init__(controleur, evenement)
#
#     def initiale(self):
#         """
#         Emet un evenement pour indiquer que les cles sont recues par le MaitreDesCles.
#         """
#         transaction = self.charger_transaction()
#         fuuid = transaction.get('fuuid')
#
#         token_resumer = '%s:%s' % (ConstantesGrosFichiers.TRANSACTION_NOUVELLEVERSION_CLES_RECUES, fuuid)
#         self.resumer_processus([token_resumer])
#
#         self.set_etape_suivante()  # Termine
#         return {'fuuid': fuuid}


class ProcessusTransactionRenommerDocument(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_doc = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        nouveau_nom = transaction[ConstantesGrosFichiers.DOCUMENT_VERSION_NOMFICHIER]

        self._controleur.gestionnaire.renommer_document(uuid_doc, {'nom': nouveau_nom})

        # Tenter de mettre a jour fichier et document
        self.evenement_maj_fichier(uuid_doc)

        self.set_etape_suivante()  # Termine


class ProcessusTransactionDecricreFichier(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        resultat = self._controleur.gestionnaire.maj_description_fichier(uuid_fichier, transaction)

        self.evenement_maj_fichier(uuid_fichier)

        self.set_etape_suivante()  # Termine

        return resultat


class ProcessusTransactionDecricreCollection(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        doc_collection = self._controleur.gestionnaire.maj_description_collection(uuid_collection, transaction)

        self.evenement_maj_collection(uuid_collection)

        self.set_etape_suivante()  # Termine

        return doc_collection


# class ProcessusTransactionChangerEtiquettesFichier(ProcessusGrosFichiersActivite):
#
#     def __init__(self, controleur: MGPProcesseur, evenement):
#         super().__init__(controleur, evenement)
#         self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))
#
#     def initiale(self):
#         transaction = self.charger_transaction()
#         uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
#
#         # Eliminer doublons
#         etiquettes = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]
#         self.__logger.error("Etiquettes: %s" % etiquettes)
#
#         self._controleur.gestionnaire.maj_etiquettes(uuid_fichier, ConstantesGrosFichiers.LIBVAL_FICHIER, etiquettes)
#
#         self.set_etape_suivante()  # Termine
#
#         return {'uuid_fichier': uuid_fichier}


class ProcessusTransactionSupprimerFichier(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuids_documents = transaction[ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS]
        self._controleur.gestionnaire.supprimer_fichier(uuids_documents)

        self.set_etape_suivante()  # Termine

        for d in uuids_documents:
            self.evenement_maj_fichier(d)

        return {'uuids_documents': uuids_documents}


class ProcessusTransactionRecupererFichier(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuids_documents = transaction[ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS]
        self._controleur.gestionnaire.recuperer_fichier(uuids_documents)

        for uuid_doc in uuids_documents:
            try:
                self.evenement_maj_fichier(uuid_doc)
            except AttributeError:
                try:
                    self.evenement_maj_collection(uuid_doc)
                except AttributeError:
                    pass  # OK

        self.set_etape_suivante()  # Termine

        return {'uuids_documents': uuids_documents}


class ProcessusTransactionNouvelleCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()

        uuid_transaction = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        nom_collection = transaction[ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION]
        uuid_collection = transaction.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC) or uuid_transaction
        uuid_parent = transaction.get(ConstantesGrosFichiers.DOCUMENT_UUID_PARENT)
        creer_parent = transaction.get(ConstantesGrosFichiers.CHAMP_CREER_PARENT)

        self._controleur.gestionnaire.creer_collection(uuid_collection, nom_collection, uuid_parent, creer_parent)

        self.evenement_maj_collection(uuid_collection)

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

        self._controleur.gestionnaire.renommer_collection(uuid_collection, changements)

        self.evenement_maj_collection(uuid_collection)

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

        self._controleur.gestionnaire.commenter_collection(uuid_collection, changements)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionSupprimerCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur.gestionnaire.supprimer_collection(uuid_collection)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


class ProcessusTransactionRecupererCollection(ProcessusGrosFichiersActivite):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        self._controleur.gestionnaire.recuperer_collection(uuid_collection)

        self.set_etape_suivante()  # Termine

        return {'uuid_collection': uuid_collection}


# class ProcessusTransactionChangerEtiquettesCollection(ProcessusGrosFichiersActivite):
#
#     def __init__(self, controleur: MGPProcesseur, evenement):
#         super().__init__(controleur, evenement)
#
#     def initiale(self):
#         transaction = self.charger_transaction()
#         uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
#         libelles = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES]
#
#         self._controleur.gestionnaire.maj_etiquettes(uuid_collection, ConstantesGrosFichiers.LIBVAL_COLLECTION, libelles)
#
#         self.set_etape_suivante()  # Termine
#
#         return {'uuid_collection': uuid_collection}


# class ProcessusTransactionFigerCollection(ProcessusGrosFichiersActivite):
#     """
#     Fige une collection et genere le torrent.
#     Pour les collections privees et publiques, le processus de distribution/publication est enclenche.
#     """
#
#     def initiale(self):
#         """
#         Figer la collection qui va servir a creer le torrent.
#         :return:
#         """
#         transaction = self.charger_transaction()
#         uuid_collection = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
#
#         info_collection = self._controleur.gestionnaire.figer_collection(uuid_collection)
#         info_collection['uuid_collection'] = uuid_collection
#
#         self.set_etape_suivante(ProcessusTransactionFigerCollection.creer_fichier_torrent.__name__)
#
#         # Faire une requete pour les parametres de trackers
#         requete = {"requetes": [{"filtre": {
#             '_mg-libelle': ConstantesParametres.LIBVAL_CONFIGURATION_NOEUDPUBLIC,
#         }}]}
#         self.set_requete('millegrilles.domaines.Parametres', requete)
#
#         return info_collection
#
#     def creer_fichier_torrent(self):
#         """
#         Generer un fichier torrent et transmettre au module de consignation.
#         :return:
#         """
#         collection_domaine = self.document_dao.get_collection(ConstantesGrosFichiers.COLLECTION_DOCUMENTS_NOM)
#
#         parametres = self.parametres
#
#         # Charger la collection et la re-sauvegarder avec _mg-libelle = collection.figee
#         # Aussi generer un uuidv1 pour uuid-fige
#         collection_figee = collection_domaine.find_one({
#             Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesGrosFichiers.LIBVAL_COLLECTION_FIGEE,
#             ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: parametres['uuid_collection_figee'],
#         })
#
#         champs_copier = [
#             ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER,
#             ConstantesGrosFichiers.DOCUMENT_SECURITE,
#             ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC,
#             ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE,
#             ConstantesGrosFichiers.DOCUMENT_FICHIER_ETIQUETTES,
#             ConstantesGrosFichiers.DOCUMENT_COMMENTAIRES,
#         ]
#
#         documents = []
#         commande = {
#             ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS: documents,
#         }
#         for champ in champs_copier:
#             commande[champ] = collection_figee.get(champ)
#
#         for uuid_doc, doc in collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS].items():
#             documents.append(doc)
#
#         # Creer le URL pour le tracker torrent
#         commande['trackers'] = self.__url_trackers()
#
#         self.__logger.info("Commande creation torrent:\n%s" % str(commande))
#         self.ajouter_commande_a_transmettre('commande.torrent.creerNouveau', commande)
#
#         token_attente_torrent = 'collection_figee_torrent:%s' % parametres['uuid_collection_figee']
#
#         securite_collection = collection_figee.get(ConstantesGrosFichiers.DOCUMENT_SECURITE)
#         if securite_collection == Constantes.SECURITE_PUBLIC:
#             # Une fois le torrent cree, on va publier la collection figee
#             self.set_etape_suivante(
#                 ProcessusTransactionFigerCollection.publier_collection_figee.__name__,
#                 token_attente=[token_attente_torrent]
#             )
#         else:
#             self.set_etape_suivante(token_attente=[token_attente_torrent])  # Termine
#
#     def publier_collection_figee(self):
#
#         requete = {"requetes": [{"filtre": {
#             '_mg-libelle': ConstantesParametres.LIBVAL_CONFIGURATION_NOEUDPUBLIC,
#         }}]}
#         self.set_requete('millegrilles.domaines.Parametres', requete)
#
#         self.set_etape_suivante(ProcessusTransactionFigerCollection.public_collection_sur_noeuds.__name__)
#
#     def public_collection_sur_noeuds(self):
#
#         liste_noeuds = self.parametres['reponse'][1][0]
#         uuid_collection_figee = self.parametres['uuid_collection_figee']
#
#         domaine_publier = ConstantesGrosFichiers.TRANSACTION_PUBLIER_COLLECTION
#         for noeud in liste_noeuds:
#             url_web = noeud['url_web']
#             transaction = {
#                 "uuid": uuid_collection_figee,
#                 "url_web": url_web,
#             }
#             self.controleur.generateur_transactions.soumettre_transaction(transaction, domaine_publier)
#
#         self.set_etape_suivante()  # Termine
#
#     def __url_trackers(self):
#         # Creer le URL pour le tracker torrent
#         reponse_parametres = self.parametres['reponse'][0][0]
#
#         trackers = list()
#
#         # Tracker hard-coded, a corriger
#         trackers.append('http://tracker-ipv4.millegrilles.com:6969/announce')
#
#         for noeud_public in reponse_parametres:
#             url_public = noeud_public['url_web']
#             url_tracker = '%s/announce' % url_public
#             trackers.append(url_tracker)
#
#         return trackers


class ProcessusTransactionAjouterFichiersDansCollection(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        collection_uuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        documents_uuids = transaction[ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS]
        self._controleur.gestionnaire.ajouter_documents_collection(collection_uuid, documents_uuids)
        self.set_etape_suivante()

        for uuid_fichier in documents_uuids:
            # Mettre a jour fichier/collection
            try:
                self.evenement_maj_fichier(uuid_fichier)
            except AttributeError:
                pass  # OK, pas un fichier
                try:
                    self.evenement_maj_collection(uuid_fichier)
                except AttributeError:
                    pass  # OK, pas une collection


class ProcessusTransactionRetirerFichiersDeCollection(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        collectionuuid = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        documents_uuids = transaction[ConstantesGrosFichiers.DOCUMENT_LISTE_UUIDS]
        self._controleur.gestionnaire.retirer_fichiers_collection(collectionuuid, documents_uuids)
        self.set_etape_suivante()

        for uuid_fichier in documents_uuids:
            self.evenement_maj_fichier(uuid_fichier)


class ProcessusTransactionChangerFavoris(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        docs_uuids = transaction.get(ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS)
        self._controleur.gestionnaire.changer_favoris(docs_uuids)
        for doc_uuid in docs_uuids:
            self.evenement_maj_collection(doc_uuid)
        self.set_etape_suivante()


# class ProcessusTransactionCleSecreteFichier(ProcessusGrosFichiers):
#
#     def __init__(self, controleur: MGPProcesseur, evenement):
#         super().__init__(controleur, evenement)
#
#     def initiale(self):
#         transaction = self.charger_transaction()
#
#         fuuid = transaction.get('fuuid')
#         cle_secrete = transaction['cle_secrete_decryptee']
#         iv = transaction['iv']
#         token_resumer = 'decrypterFichier_cleSecrete:%s' % fuuid
#         self.resumer_processus([token_resumer])
#
#         self.set_etape_suivante()
#
#         return {
#             'fuuid': fuuid,
#             'cle_secrete_decryptee': cle_secrete,
#             'iv': iv,
#         }


class ProcessusTransactionAssocierPreview(ProcessusGrosFichiers):

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        self.controleur.gestionnaire.associer_preview(transaction)

        try:
            self.evenement_maj_fichier(transaction['uuid'])
        except Exception:
            self.__logger.exception("Erreur verification collection publique")

        self.set_etape_suivante()


class ProcessusTransactionAssocierConversions(ProcessusGrosFichiers):
    """
    Associe les conversions (differentes versions/resolutions) d'une image.
    """

    def __init__(self, controleur: MGPProcesseur, evenement):
        super().__init__(controleur, evenement)

    def initiale(self):
        transaction = self.charger_transaction()
        self.controleur.gestionnaire.associer_conversions(transaction)

        try:
            self.evenement_maj_fichier(transaction['uuid'])
        except Exception:
            self.__logger.exception("Erreur verification collection publique")

        self.set_etape_suivante()


# class ProcessusPublierCollection(ProcessusGrosFichiers):
#     """
#     Publie une collection sur un noeud public (Vitrine)
#     """
#
#     def initiale(self):
#         transaction = self.transaction
#         url_noeud_public = transaction[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
#         uuid_collection_figee = transaction[ConstantesParametres.TRANSACTION_CHAMP_UUID]
#
#         # Inserer dans les documents de vitrine
#         # Ceci va automatiquement les publier (via watchers MongoDB)
#         self.controleur.gestionnaire.maj_documents_vitrine(uuid_collection_figee)
#
#         self.set_requete(ConstantesParametres.REQUETE_NOEUD_PUBLIC, {
#             ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: url_noeud_public,
#         })
#
#         self.set_etape_suivante(ProcessusPublierCollection.determiner_type_deploiement.__name__)
#
#         return {
#             ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB: url_noeud_public,
#             ConstantesParametres.TRANSACTION_CHAMP_UUID: uuid_collection_figee,
#         }
#
#     def determiner_type_deploiement(self):
#
#         info_noeud_public = self.parametres['reponse'][0][0]
#         mode_deploiement = info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_MODE_DEPLOIEMENT]
#
#         if mode_deploiement == 'torrent':
#             self.set_etape_suivante(ProcessusPublierCollection.deploiement_torrent.__name__)
#         elif mode_deploiement == 's3':
#             self.set_etape_suivante(ProcessusPublierCollection.deploiement_s3.__name__)
#         else:
#             raise Exception("Mode de deploiement inconnu pour noeud public " + self.parametres[
#                 ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB])
#
#     def deploiement_torrent(self):
#         """
#         Lancer le processus de deploiement avec Torrents
#         :return:
#         """
#         self.set_etape_suivante(ProcessusPublierCollection.publier_metadonnees_collection.__name__)
#
#     def deploiement_s3(self):
#         """
#         Demander le fingerprint du certificat de consignationfichiers
#         :return:
#         """
#         self.set_requete('pki.role.fichiers', {})
#
#         self.set_etape_suivante(ProcessusPublierCollection.deploiement_s3_demander_cle_rechiffree.__name__)
#
#     def deploiement_s3_demander_cle_rechiffree(self):
#         """
#         Demander la cle pour le mot de passe Amazon
#         :return:
#         """
#
#         fingerprint_fichiers = self.parametres['reponse'][1]['fingerprint']
#
#         transaction_maitredescles = {
#             'fingerprint': fingerprint_fichiers,
#             "identificateurs_document": {
#                 "champ": "awsSecretAccessKey",
#                 "url_web": self.parametres[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB],
#             }
#         }
#         domaine = 'millegrilles.domaines.MaitreDesCles.decryptageDocument'
#
#         # Effectuer requete pour re-chiffrer la cle du document pour le consignateur de transactions
#         self.set_requete(domaine, transaction_maitredescles)
#
#         self.set_etape_suivante(ProcessusPublierCollection.deploiement_s3_commande.__name__)
#
#     def deploiement_s3_commande(self):
#         """
#         Lancer le processus de deploiement avec Amazon S3
#         :return:
#         """
#         info_noeud_public = self.parametres['reponse'][0][0]
#
#         # Extraire liste de fichiers a publier de la collection
#         collection_figee_uuid = self.parametres[ConstantesParametres.TRANSACTION_CHAMP_UUID]
#         collection_figee = self.controleur.gestionnaire.get_collection_figee_par_uuid(collection_figee_uuid)
#         liste_documents = collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_LISTEDOCS]
#         info_documents_a_publier = []
#         for document_a_publier in liste_documents.values():
#             if document_a_publier[Constantes.DOCUMENT_INFODOC_LIBELLE] == ConstantesGrosFichiers.LIBVAL_FICHIER:
#
#                 info_doc = {
#                     'nom': document_a_publier['nom'],
#                 }
#
#                 # Gerer l'exception des videos, on publie uniquement le clip mp4 en 480p
#                 if document_a_publier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P) is not None:
#                     # On publie uniquement le video a 480p
#                     info_doc.update({
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: document_a_publier[
#                             ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_480P],
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: document_a_publier[
#                             ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_480P],
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL: 'mp4',
#                     })
#                 else:
#                     # C'est un fichier standard
#                     info_doc.update({
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: document_a_publier[
#                             ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID],
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL: document_a_publier[
#                             ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL],
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: document_a_publier[
#                             ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE],
#                     })
#                 info_documents_a_publier.append(info_doc)
#
#                 if document_a_publier.get(ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW) is not None:
#                     # On ajoute aussi l'upload du preview
#                     info_preview = {
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID: document_a_publier[ConstantesGrosFichiers.DOCUMENT_FICHIER_FUUID_PREVIEW],
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE: document_a_publier[ConstantesGrosFichiers.DOCUMENT_FICHIER_MIMETYPE_PREVIEW],
#                         ConstantesGrosFichiers.DOCUMENT_FICHIER_EXTENSION_ORIGINAL: 'jpg',
#                     }
#                     info_documents_a_publier.append(info_preview)
#
#         # Creer commande de deploiement pour consignationfichiers
#         commande_deploiement = {
#             "credentials": {
#                 "accessKeyId": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_ACCESS_KEY],
#                 "secretAccessKeyChiffre": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_SECRET_KEY_CHIFFRE],
#                 "region": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_CRED_REGION],
#                 "cle": self.parametres['reponse'][2]['cle'],
#                 "iv": self.parametres['reponse'][2]['iv'],
#             },
#             "region": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_BUCKET_REGION],
#             "bucket": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_BUCKET_NAME],
#             "dirfichier": info_noeud_public[ConstantesParametres.DOCUMENT_CHAMP_AWS_BUCKET_DIR],
#             "fuuidFichiers": info_documents_a_publier,
#             "uuid_source_figee": collection_figee[ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID_SOURCE_FIGEE],
#             "uuid_collection_figee": collection_figee_uuid,
#         }
#
#         self.ajouter_commande_a_transmettre('commande.grosfichiers.publierCollection', commande_deploiement)
#
#         self.set_etape_suivante(ProcessusPublierCollection.publier_metadonnees_collection.__name__)
#
#         return {
#             "commande": commande_deploiement
#         }
#
#     def publier_metadonnees_collection(self):
#
#         collection_figee_uuid = self.parametres[ConstantesParametres.TRANSACTION_CHAMP_UUID]
#         collection_figee = self.controleur.gestionnaire.get_collection_figee_par_uuid(collection_figee_uuid)
#
#         collection_filtree = dict()
#         for key, value in collection_figee.items():
#             if not key.startswith('_'):
#                 collection_filtree[key] = value
#
#         url_web = self.parametres[ConstantesParametres.DOCUMENT_PUBLIQUE_URL_WEB]
#         url_web = url_web.replace('.', '_')
#         domaine = 'commande.%s.publierCollection' % url_web
#
#         self.controleur.transmetteur.emettre_message_public(collection_filtree, domaine)
#
#         # Publier les documents de sections avec fichiers (fichiers, albums, podcasts, etc.)
#         # Note : ajouter un selecteur pour charger uniquement les sections actives (menu du noeud)
#         document_fichiers = self.controleur.gestionnaire.get_document_vitrine_fichiers()
#         domaine_fichiers = 'commande.%s.publierFichiers' % url_web
#         self.controleur.transmetteur.emettre_message_public(document_fichiers, domaine_fichiers)
#
#         document_albums = self.controleur.gestionnaire.get_document_vitrine_albums()
#         domaine_albums = 'commande.%s.publierAlbums' % url_web
#         self.controleur.transmetteur.emettre_message_public(document_albums, domaine_albums)
#
#         self.set_etape_suivante()


class ProcessusAssocierVideoTranscode(ProcessusGrosFichiers):
    """
    Associe un video a un fichier une fois le transcodage termine
    """

    def initiale(self):
        transaction = self.transaction

        document_fichier = self.controleur.gestionnaire.associer_video_transcode(transaction)
        uuid_document = document_fichier[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        try:
            self.evenement_maj_fichier(uuid_document)
        except Exception:
            self.__logger.exception("Erreur verification collection publique")

        self.set_etape_suivante()  # Termine


# class ProcessusEntretienCollectionPublique(ProcessusGrosFichiers):
#     """
#     Effectue l'entretien d'une colleciton publique incluant la publication des fichiers manquants (sync)
#     """
#
#     def initiale(self):
#         # Faire la liste des noeuds Amazon Web Services S3
#         domaine_requete = 'Topologie.listerNoeudsAWSS3'
#         self.set_requete(domaine_requete, dict())
#         self.set_etape_suivante(ProcessusEntretienCollectionPublique.publier_fichiers_awss3.__name__)
#
#     def publier_fichiers_awss3(self):
#         parametres = self.parametres
#         try:
#             uuid_collection = parametres['uuid']
#         except KeyError:
#             domaine_requete = 'GrosFichiers.' + Constantes.ConstantesMaitreDesCles.REQUETE_COLLECTIONS_PUBLIQUES
#             self.set_requete(domaine_requete, dict())
#             self.set_etape_suivante(ProcessusEntretienCollectionPublique.publier_toutes_collections.__name__)
#         else:
#             self._uploader_collection(uuid_collection)
#             self.set_etape_suivante()  # Termine
#
#     def publier_toutes_collections(self):
#         reponse_noeuds_awss3 = self.parametres['reponse'][1]
#         collections_publiques = reponse_noeuds_awss3['resultat']
#
#         for collection_publique in collections_publiques:
#             uuid_collection = collection_publique['uuid']
#             self._uploader_collection(uuid_collection)
#
#     def _uploader_collection(self, uuid_collection):
#         reponse_noeuds_awss3 = self.parametres['reponse'][0]
#         noeud_ids = reponse_noeuds_awss3['noeud_ids']
#
#         # Pour chaque noeud, verifier s'il y a des fichiers qui n'ont pas encore ete telecharge vers AWS S3
#         self.controleur.gestionnaire.uploader_fichiers_manquants_awss3(uuid_collection, noeud_ids)


class ProcessusTransactionNouveauFichierUsager(ProcessusGrosFichiers):

    def initiale(self):
        # Extraire usager du certificat
        # transaction = self.transaction

        certificat: EnveloppeCertificat = self.certificat
        est_acces_prive = certificat.est_acces_prive()
        user_id = certificat.get_user_id

        if user_id is None and est_acces_prive is not True:
            raise Exception("Niveau de securite ne permet pas d'ajouter un fichier")

        # Identifier collection personelle de l'usager. Creer la collection au besoin.
        try:
            collection_usager = self.controleur.gestionnaire.find_collection_usager(user_id)
        except CollectionAbsenteException as cae:
            # La collection usager n'existe pas. La creer avant de poursuivre.
            nom_usager = certificat.subject_common_name
            domaine_action = ConstantesGrosFichiers.TRANSACTION_NOUVELLE_COLLECTION
            transaction_creer_collection = {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: user_id,
                ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION: nom_usager,
                ConstantesGrosFichiers.DOCUMENT_UUID_PARENT: ConstantesGrosFichiers.LIBVAL_UUID_COLLECTION_USAGERS,
            }

            if cae.uuid_parent is None:
                # Creer le parent au besoin
                transaction_creer_collection[ConstantesGrosFichiers.CHAMP_CREER_PARENT] = True

            self.ajouter_transaction_a_soumettre(domaine_action, transaction_creer_collection, blocking=True)
            self.set_etape_suivante(ProcessusTransactionNouveauFichierUsager.conserver_fichier.__name__)
            return

        # Conserver le fichier de l'usager
        uuid_collection = collection_usager[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]
        resultat = self.conserver_fichier(uuid_collection)

        self.set_etape_suivante()  # Termine

        return resultat

    def conserver_fichier(self, collection_usager: str = None):
        # Extraire usager du certificat
        transaction = self.transaction

        certificat = self.certificat
        user_id = certificat.get_user_id

        if collection_usager is None:
            info_collection = self.controleur.gestionnaire.find_collection_usager(user_id)
            collection_usager = info_collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        # Injecter la collection personnelle de l'usager
        transaction[ConstantesGrosFichiers.DOCUMENT_COLLECTION_UUID] = collection_usager

        resultat = self._controleur.gestionnaire.maj_fichier(transaction)

        # Vierifier si le document de fichier existe deja
        fuuid = transaction['fuuid']
        nom_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_NOMFICHIER]
        extension = GestionnaireGrosFichiers.extension_fichier(nom_fichier)
        resultat = {
            'uuid': resultat['uuid_fichier'],
            'fuuid': fuuid,
            'fichier': resultat['fichier'],
            'collection_uuid': collection_usager,
            'mimetype': transaction['mimetype'],
            'extension': extension,
            'nom_fichier': transaction['nom_fichier'],
            ConstantesGrosFichiers.DOCUMENT_FICHIER_HACHAGE: fuuid,
        }

        # Verifier s'il y a un traitement supplementaire a faire
        mimetype = self.transaction['mimetype'].split('/')[0]
        if mimetype in ['video', 'image']:
            self._traiter_media(resultat)

        # Tenter de mettre a jour fichier et document
        self.evenement_maj_fichier(resultat['uuid'])

        return resultat

    def _traiter_media(self, info: dict):
        # # Transmettre une commande de transcodage
        mimetype = info['mimetype'].split('/')[0]
        commande_preview = self.controleur.gestionnaire.preparer_generer_poster(info)
        if mimetype == 'video':
            self.ajouter_commande_a_transmettre('commande.fichiers.genererPreviewVideo', commande_preview)

            fuuid = info['fuuid']

            # Transmettre commande transcodage video pour formats web
            domaine = 'commande.fichiers.transcoderVideo'
            mimetype = 'video/mp4'
            resolution = 480
            bitrate = 600000

            commande = {
                'fuuid': fuuid,
                'mimetype': mimetype,
                'height': resolution,
                'videoBitrate': bitrate,
            }
            self.ajouter_commande_a_transmettre(domaine, commande)
            self.controleur.gestionnaire.ajouter_transcodage_video(info, mimetype, resolution, bitrate)

            # commande = {'fuuid': fuuid, 'mimetype': 'video/webm'}
            # self.ajouter_commande_a_transmettre(domaine, commande)

        elif mimetype == 'image':
            self.ajouter_commande_a_transmettre('commande.fichiers.genererPreviewImage', commande_preview)


class ProcessusTransactionSupprimerFichierUsager(ProcessusGrosFichiers):

    def initiale(self):
        certificat = self.certificat
        niveaux_securite = certificat.get_exchanges
        user_id = certificat.get_user_id

        if user_id is None or not any([n in ConstantesSecurite.cascade_secure(Constantes.SECURITE_PRIVE) for n in niveaux_securite]):
            raise Exception("Niveau de securite ne permet pas de supprimer un fichier")

        transaction = self.transaction
        uuid_fichier = transaction[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC]

        # Note : la suppression de fichier usager ne fait que retirer le lien a la collection de l'usager
        #        le fichier devient orphelin sauf s'il est aussi utilise ailleurs (e.g. forum)
        uuid_collection = user_id
        self.controleur.gestionnaire.retirer_fichiers_collection(uuid_collection, [uuid_fichier])

        # Tenter de mettre a jour fichier et document
        self.evenement_maj_fichier(uuid_fichier)

        self.set_etape_suivante()  # Termine
        return {
            'ok': True
        }


class ProcessusGenererCollectionFichiers(MGProcessus):

    def initiale(self):
        self.set_requete('MaitreDesCles.' + ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES, dict())
        self.set_etape_suivante(ProcessusGenererCollectionFichiers.generer_collectionfichiers.__name__)

    def generer_collectionfichiers(self):

        params = self.parametres

        reponse_requete_certs = params['reponse'][0]
        certs = [
            reponse_requete_certs['certificat'],
            reponse_requete_certs['certificat_millegrille'],
        ]
        # Preparer les certificats avec enveloppe, par fingerprint
        enveloppes_rechiffrage = dict()
        for cert in certs:
            enveloppe = EnveloppeCertificat(certificat_pem=cert)
            fp = enveloppe.fingerprint
            enveloppes_rechiffrage[fp] = enveloppe

        self.controleur.gestionnaire.generer_collectionfichiers(params, enveloppes_rechiffrage)

        self.set_etape_suivante()  # Termine


class CollectionAbsenteException(Exception):

    def __init__(self, *args, uuid_parent: str = None, **kwargs):
        super().__init__(args, kwargs)
        self.__uuid_parent = uuid_parent

    @property
    def uuid_parent(self):
        return self.__uuid_parent
