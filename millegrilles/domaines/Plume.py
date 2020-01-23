# Domaine Plume - ecriture de documents
from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPlume
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, ExchangeRouter
from millegrilles.dao.MessageDAO import TraitementMessageDomaine
from millegrilles.MGProcessus import MGProcessusTransaction

import logging
import datetime


class TraitementRequetesPubliquesParametres(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        if routing_key == 'requete.' + ConstantesPlume.REQUETE_CHARGER_ANNONCES_RECENTES:
            noeud_publique = self.gestionnaire.get_annonces_recentes()
            self.transmettre_reponse(message_dict, noeud_publique, properties.reply_to, properties.correlation_id)
        else:
            raise Exception("Requete publique non supportee " + routing_key)


class TraitementRequetesProtegeesParametres(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        if routing_key == 'requete.' + ConstantesPlume.REQUETE_CHARGER_ANNONCES_RECENTES:
            noeud_publique = self.gestionnaire.get_annonces_recentes()
            self.transmettre_reponse(message_dict, noeud_publique, properties.reply_to, properties.correlation_id)
        else:
            super().traiter_requete(ch, method, properties, body, message_dict)


class PlumeExchangeRouter(ExchangeRouter):

    def determiner_exchanges(self, document):
        """
        :return: Liste des echanges sur lesquels le document doit etre soumis
        """
        exchanges = set()
        mg_libelle = document.get(Constantes.DOCUMENT_INFODOC_LIBELLE)
        if mg_libelle in [ConstantesPlume.LIBVAL_ANNONCES_RECENTES]:
            exchanges.add(self._exchange_public)
            exchanges.add(self._exchange_prive)
            exchanges.add(self._exchange_protege)
        else:
            exchanges.add(self._exchange_protege)

        return list(exchanges)


class GestionnairePlume(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self._logger = logging.getLogger("%s.%s" % (__name__, self.__class__.__name__))

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesParametres(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesParametres(self)
        }

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
                (Constantes.DOCUMENT_INFODOC_LIBELLE, 1),
                (Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION, -1)
            ],
            name='mglibelle_derniermodif'
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

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(ConstantesPlume.LIBVAL_CONFIGURATION, ConstantesPlume.DOCUMENT_DEFAUT)
        self.initialiser_document(ConstantesPlume.LIBVAL_CATALOGUE, ConstantesPlume.DOCUMENT_CATALOGUE)
        self.initialiser_document(ConstantesPlume.LIBVAL_ANNONCES_RECENTES, ConstantesPlume.DOCUMENT_ANNONCES_RECENTES)
        self.initialiser_document(ConstantesPlume.LIBVAL_VITRINE_ACCUEIL, ConstantesPlume.DOCUMENT_VITRINE_ACCUEIL)
        self.initialiser_document(ConstantesPlume.LIBVAL_BLOGPOSTS_RECENTS, ConstantesPlume.DOCUMENT_BLOGPOSTS_RECENTS)

        self.demarrer_watcher_collection(
            ConstantesPlume.COLLECTION_DOCUMENTS_NOM,
            ConstantesPlume.QUEUE_ROUTING_CHANGEMENTS,
            PlumeExchangeRouter(self._contexte)
        )

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
        elif domaine_transaction == ConstantesPlume.TRANSACTION_MAJ_ACCUEIL_VITRINE:
            processus = "millegrilles_domaines_Plume:ProcessuMajAccueilVitrine"

        elif domaine_transaction == ConstantesPlume.TRANSACTION_MAJ_BLOGPOST:
            processus = "millegrilles_domaines_Plume:ProcessuMajBlogpostVitrine"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_PUBLIER_BLOGPOST:
            processus = "millegrilles_domaines_Plume:ProcessuPublierBlogpostVitrine"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_RETIRER_BLOGPOST:
            processus = "millegrilles_domaines_Plume:ProcessuRetirerBlogpostVitrine"
        elif domaine_transaction == ConstantesPlume.TRANSACTION_SUPPRIMER_BLOGPOST:
            processus = "millegrilles_domaines_Plume:ProcessuSupprimerBlogpostVitrine"

        else:
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def traiter_cedule(self, evenement):
        pass

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

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
        liste_remplacement = None
        remplacement = annonce.get(ConstantesPlume.LIBELLE_DOC_REMPLACE)
        if remplacement is not None:
            doc_annonce[ConstantesPlume.LIBELLE_DOC_REMPLACE] = remplacement
            liste_remplacement = [remplacement]

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        collection_domaine.insert_one(doc_annonce)

        # Mettre a jour le document avec toutes les annonces
        self.maj_annonces_recentes([doc_annonce], liste_remplacement)

    def supprimer_annonce(self, uuid_annonce):
        self.maj_annonces_recentes(supprimer_annonces=[uuid_annonce])

    def maj_annonces_recentes(self, nouvelles_annonces: list = None, supprimer_annonces: list = None):
        """
        Met a jour le document d'annonces recentes.

        :param nouvelles_annonces: Liste de dictionnaires d'annonces a ajouter
        :param supprimer_annonces: Liste de uuid d'annonces a supprimer
        :return:
        """
        # Ajouter les valeurs en ordre croissant de timestamp.
        # Garder les "nombre_resultats_limite" plus recents (~1 semaine)
        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_ANNONCES_RECENTES
        }

        # Les deux operations sont separees pour eviter l'erreur :
        # "pymongo.errors.WriteError: Updating the path 'annonces' would create a conflict at 'annonces'"

        if supprimer_annonces is not None:
            self._logger.debug("Supprimer annonces %s" % str(supprimer_annonces))
            ops_pull = {
                '$pull': {
                    ConstantesPlume.LIBELLE_DOC_ANNONCES: {
                        ConstantesPlume.LIBELLE_DOC_PLUME_UUID: {'$in': supprimer_annonces}
                    }
                }
            }
            collection_domaine.update_one(filtre, ops_pull)

        if nouvelles_annonces is not None:
            # Filtrer les champs indesirables dans chaque annonce
            annonces_filtrees = list()
            for annonce in nouvelles_annonces:
                annonce_filtree = {}
                for cle, valeur in annonce.items():
                    if cle in ConstantesPlume.FILTRE_DOC_ANNONCES_RECENTES:
                        annonce_filtree[cle] = valeur
                annonces_filtrees.append(annonce_filtree)

            ops_push = {
                '$push': {
                    ConstantesPlume.LIBELLE_DOC_ANNONCES: {
                        '$each': annonces_filtrees,
                        '$sort': {Constantes.DOCUMENT_INFODOC_DATE_CREATION: -1},
                        '$slice': ConstantesPlume.DEFAUT_NOMBRE_ANNONCES_RECENTES,
                    }
                }
            }
            collection_domaine.update_one(filtre, ops_push)

    def get_annonces_recentes(self):
        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        annonces_recentes = collection_domaine.find_one({
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_ANNONCES_RECENTES
        })
        return annonces_recentes

    def maj_accueil_vitrine(self, info_accueil):

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_VITRINE_ACCUEIL
        }

        ops = {
            '$set': info_accueil
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        return collection_domaine.find_and_modify(filtre, ops, new=True)

    def get_blogpost(self, uuid_blogpost):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_BLOGPOST,
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: uuid_blogpost,
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        return collection_domaine.find_one(filtre)

    def maj_blogpost(self, transaction):

        uuid_blogpost = transaction.get(ConstantesPlume.LIBELLE_DOC_PLUME_UUID)
        if uuid_blogpost is None:
            # Utiliser le uuid-transaction
            uuid_blogpost = transaction[
                Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_BLOGPOST,
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: uuid_blogpost,
        }

        blogpost = {}
        if transaction.get(ConstantesPlume.LIBELLE_DOC_IMAGE) is not None:
            blogpost[ConstantesPlume.LIBELLE_DOC_IMAGE] = transaction[ConstantesPlume.LIBELLE_DOC_IMAGE]

        champs = [
            ConstantesPlume.LIBELLE_DOC_TITRE,
            ConstantesPlume.LIBELLE_DOC_TEXTE,
        ]

        # Copier les champs de la transaction
        for key, value in transaction.items():
            for champ in champs:
                if key.startswith(champ):
                    blogpost[key] = value

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_BLOGPOST,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: uuid_blogpost,
        }

        ops = {
            '$set': blogpost,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
            '$setOnInsert': set_on_insert,
        }

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())
        return collection_domaine.find_and_modify(filtre, ops, upsert=True, new=True)

    def publier_blogpost(self, uuid_blogpost):

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())

        # Mettre a jour date publication et charger blogpost
        filtre_blogpost = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_BLOGPOST,
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: uuid_blogpost
        }
        ops = {
            '$currentDate': {ConstantesPlume.LIBELLE_DOC_DATE_PUBLICATION: True}
        }
        blogpost = collection_domaine.find_and_modify(filtre_blogpost, ops)

        # Mettre a jour document blogposts recents
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_BLOGPOSTS_RECENTS,
        }

        # Filtrer les champs qui ne doivent pas etre exportes
        retirer_champs = [
            Constantes.MONGO_DOC_ID, Constantes.DOCUMENT_INFODOC_LIBELLE
        ]
        for champ in retirer_champs:
            del blogpost[champ]

        uuid_blogpost = blogpost[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]

        set_ops = {
            '%s.%s' % (ConstantesPlume.LIBELLE_DOC_BLOGPOSTS, uuid_blogpost): blogpost
        }

        ops = {
            '$set': set_ops,
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
                ConstantesPlume.LIBELLE_DOC_DATE_PUBLICATION: True,
            },
        }

        return collection_domaine.find_and_modify(filtre, ops, upsert=True, new=True)

    def retirer_blogpost(self, uuid_blogpost, supprimer=False):
        """
        Retire un blogpost deja publie.
        :param uuid_blogpost:
        :param supprimer: Si True, supprime aussi le document du blogpost.
        :return:
        """

        collection_domaine = self.document_dao.get_collection(self.get_nom_collection())

        # Retirer date publication blogpost
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_BLOGPOST,
            ConstantesPlume.LIBELLE_DOC_PLUME_UUID: uuid_blogpost
        }
        if supprimer:
            collection_domaine.delete_one(filtre)
        else:
            ops = {
                '$unset': {ConstantesPlume.LIBELLE_DOC_DATE_PUBLICATION: True},
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
            }
            collection_domaine.update_one(filtre, ops)

        # Retirer blogpost de recents et autres documents
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPlume.LIBVAL_BLOGPOSTS_RECENTS,
        }

        ops = {
            '$unset': {'%s.%s' % (ConstantesPlume.LIBELLE_DOC_BLOGPOSTS, uuid_blogpost): True},
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        return collection_domaine.find_and_modify(filtre, ops, upsert=True, new=True)


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
        uuid_annonce = transaction[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]
        self.controleur.gestionnaire.supprimer_annonce(uuid_annonce)
        self.set_etape_suivante()  # Termine


class ProcessuMajAccueilVitrine(ProcessusPlume):

    def initiale(self):
        transaction = self.charger_transaction()

        champs_multilingues = [
            ConstantesPlume.LIBELLE_DOC_VITRINE_BIENVENUE,
            'texte',
            'titre'
        ]

        info_accueil = dict()

        for key, value in transaction.items():
            for champ in champs_multilingues:
                if key.startswith(champ):
                    info_accueil[key] = value

        # Preparer la section de donnees du portail accueil
        if transaction.get('colonnes') is not None:
            portail = [
                {
                    'type': 'deck',
                    'cartes': transaction.get('colonnes'),
                }
            ]
            info_accueil['portail'] = portail

        accueil_modifie = self.controleur.gestionnaire.maj_accueil_vitrine(info_accueil)

        if transaction['operation'] == 'publier':
            # Publier la mise a jour
            domaine_publier = 'commande.publierAccueil'
            self.controleur.transmetteur.emettre_message_public(accueil_modifie, domaine_publier)

        self.set_etape_suivante()  # Termine


class ProcessusPublierBlogposts(ProcessusPlume):

    def publier_blogposts_recents(self, blogposts_recents):
        domaine_publier = 'commande.publierBlogpostsRecents'

        champs_retirer = [
            Constantes.MONGO_DOC_ID,
            Constantes.DOCUMENT_INFODOC_LIBELLE,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION,
        ]

        blogposts_filtres = blogposts_recents.copy()
        for champ in champs_retirer:
            del blogposts_filtres[champ]

        self.controleur.transmetteur.emettre_message_public(blogposts_filtres, domaine_publier)


class ProcessuMajBlogpostVitrine(ProcessusPublierBlogposts):

    def initiale(self):
        transaction = self.charger_transaction()

        document_maj = self.controleur.gestionnaire.maj_blogpost(transaction)

        operation = transaction.get('operation')
        info_retour = {}
        if operation == 'publier':
            uuid_blogpost = document_maj[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]
            # Recuperer document
            blogposts_recents = self.controleur.gestionnaire.publier_blogpost(uuid_blogpost)
            info_retour[ConstantesPlume.LIBELLE_DOC_DATE_PUBLICATION] = blogposts_recents[ConstantesPlume.LIBELLE_DOC_DATE_PUBLICATION]

            # Publier blogpost
            self.publier_blogposts_recents(blogposts_recents)

        self.set_etape_suivante()  # Termine

        return info_retour


class ProcessuPublierBlogpostVitrine(ProcessusPublierBlogposts):

    def initiale(self):
        transaction = self.charger_transaction()

        uuid_blogpost = transaction[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]

        # Recuperer document
        blogposts_recents = self.controleur.gestionnaire.publier_blogpost(uuid_blogpost)

        # Publier blogpost
        self.publier_blogposts_recents(blogposts_recents)

        self.set_etape_suivante()  # Termine


class ProcessuRetirerBlogpostVitrine(ProcessusPublierBlogposts):

    def initiale(self):
        transaction = self.charger_transaction()

        uuid_blogpost = transaction[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]

        # Publier blogpost
        blogposts_recents = self.controleur.gestionnaire.retirer_blogpost(uuid_blogpost)

        # Transmettre message pour retirer la publication
        self.publier_blogposts_recents(blogposts_recents)

        self.set_etape_suivante()  # Termine


class ProcessuSupprimerBlogpostVitrine(ProcessusPublierBlogposts):

    def initiale(self):
        transaction = self.charger_transaction()

        uuid_blogpost = transaction[ConstantesPlume.LIBELLE_DOC_PLUME_UUID]

        # Publier blogpost
        blogposts_recents = self.controleur.gestionnaire.retirer_blogpost(uuid_blogpost, supprimer=True)

        # Transmettre message pour retirer la publication
        self.publier_blogposts_recents(blogposts_recents)

        self.set_etape_suivante()  # Termine


