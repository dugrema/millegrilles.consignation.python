import logging
import datetime
import pytz

from pymongo import ReturnDocument

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPublication, ConstantesGrosFichiers
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees, TraitementMessageDomaineRequete
from millegrilles.MGProcessus import MGProcessusTransaction


class TraitementRequetesPubliquesPublication(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesPublication.REQUETE_CONFIGURATION_SITE:
            reponse = self.gestionnaire.get_configuration_site(message_dict)
        elif domaine_action == ConstantesPublication.REQUETE_POSTS:
            reponse = self.gestionnaire.get_posts(message_dict)
            reponse = {'liste_posts': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_SITES_POUR_NOEUD:
            reponse = self.gestionnaire.get_sites_par_noeud(message_dict)
            reponse = {'liste_sites': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_LISTE_SITES:
            reponse = self.gestionnaire.get_liste_sites()
            reponse = {'resultats': reponse}
        else:
            reponse = {'err': 'Commande invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementRequetesProtegeesPublication(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesPublication.REQUETE_CONFIGURATION_SITE:
            reponse = self.gestionnaire.get_configuration_site(message_dict)
        elif domaine_action == ConstantesPublication.REQUETE_POSTS:
            reponse = self.gestionnaire.get_posts(message_dict)
            reponse = {'liste_posts': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_SITES_POUR_NOEUD:
            reponse = self.gestionnaire.get_sites_par_noeud(message_dict)
            reponse = {'liste_sites': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_LISTE_SITES:
            reponse = self.gestionnaire.get_liste_sites()
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_LISTE_CDN:
            reponse = self.gestionnaire.get_liste_cdns(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_SITE_PAGES:
            reponse = self.gestionnaire.get_partie_pages(message_dict)
            reponse = {'resultats': reponse}
        else:
            reponse = {'err': 'Commande invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class GestionnairePublication(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesPublication(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesPublication(self)
        }

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def demarrer(self):
        super().demarrer()
        # self.initialiser_document(Constantes.LIBVAL_CONFIGURATION, ConstantesPublication.DOCUMENT_DEFAUT)

    def creer_index(self):
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        collection_posts = self.document_dao.get_collection(ConstantesPublication.COLLECTION_POSTS_NOM)

        # Index _mg-libelle
        collection_sites.create_index([(ConstantesPublication.CHAMP_SITE_ID, 1)], name='site_id')
        collection_posts.create_index([(Constantes.DOCUMENT_INFODOC_LIBELLE, 1)], name='mglibelle')

        collection_sites.create_index([(ConstantesPublication.CHAMP_NOEUDS_URLS, 1)], name='noeuds_urls')

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

        # minutes = evenement['timestamp']['UTC'][4]
        #
        # if minutes % 15 == 3:
        #     self.resoumettre_conversions_manquantes()

    def identifier_processus(self, domaine_transaction):
        domaine_action = domaine_transaction.split('.').pop()
        if domaine_action == ConstantesPublication.TRANSACTION_CREER_SITE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionCreerSite"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_SITE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajSite"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_POST:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPost"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_CDN:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajCdn"
        elif domaine_action == ConstantesPublication.TRANSACTION_SUPPRIMER_CDN:
            processus = "millegrilles_domaines_Publication:ProcessusSupprimerCdn"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_SECTION:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajSection"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_PARTIEPAGE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPartiepage"

        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_nom_collection(self):
        return ConstantesPublication.COLLECTION_CONFIGURATION_NOM

    def get_nom_queue(self):
        return ConstantesPublication.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesPublication.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPublication.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesPublication.DOMAINE_NOM

    def get_liste_sites(self):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG
        }
        projection = [
            ConstantesPublication.CHAMP_SITE_ID,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION,
            ConstantesPublication.CHAMP_NOM_SITE,
            ConstantesPublication.CHAMP_LANGUAGES,
        ]
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        curseur = collection_site.find(filtre, projection=projection)

        sites = list()
        for site in curseur:
            del site['_id']
            sites.append(site)

        return sites

    def get_liste_cdns(self, params: dict):
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre = dict()
        curseur = collection_cdns.find(filtre)

        cdns = [c for c in curseur]

        return cdns

    def maj_section(self, params: dict):
        """
        Maj (ou cree) une section de site.
        :param params:
        :return:
        """
        entete = params[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        version_id = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        section_id = params.get(ConstantesPublication.CHAMP_SECTION_ID) or version_id

        set_ops = dict()

        champs = ['securite', 'entete', 'collections', 'parties_pages', 'forums']
        for key, value in params.items():
            if key in champs:
                set_ops[key] = value

        ops = {
            '$set': set_ops
        }

        if version_id == section_id:
            ops['$setOnInsert'] = {
                ConstantesPublication.CHAMP_SECTION_ID: version_id,
                ConstantesPublication.CHAMP_SITE_ID: params[ConstantesPublication.CHAMP_SITE_ID],
                ConstantesPublication.CHAMP_TYPE_SECTION: params[ConstantesPublication.CHAMP_TYPE_SECTION]
            }
            upsert = True
        else:
            upsert = False

        filtre = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id,
        }

        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
        doc_section = collection_sections.find_one_and_update(filtre, ops, upsert=upsert, return_document=ReturnDocument.AFTER)

        site_id = doc_section[ConstantesPublication.CHAMP_SITE_ID]  # site_id pas inclus dans les updates

        # Transmettre commande mise a jour du site
        # TODO

        return doc_section

    def maj_partie_page(self, params: dict):
        """
        Sauvegarde une partie de page (section, paragraphe, div, etc.)
        :param params:
        :return:
        """
        version_id = params['en-tete']['uuid_transaction']
        page_id = params.get(ConstantesPublication.CHAMP_PARTIEPAGE_ID) or version_id
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        entete = params[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        date_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        date_transaction = datetime.datetime.fromtimestamp(date_transaction, tz=pytz.utc)

        set_ops = {
            ConstantesPublication.CHAMP_VERSION_ID: version_id,
            ConstantesPublication.CHAMP_DATE_MODIFICATION: date_transaction,
            ConstantesPublication.CHAMP_DIRTY_PARTIEPAGE: True,
        }

        champs_supportes = ConstantesPublication.CHAMPS_DONNEES_PAGE.copy()
        for key in params:
            if key in champs_supportes:
                set_ops[key] = params[key]

        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        filtre = {
            ConstantesPublication.CHAMP_PARTIEPAGE_ID: page_id,
        }

        if page_id == version_id:
            upsert = True
            # Recuperer site_id a partir de la section
            collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
            section = collection_sections.find_one(
                {ConstantesPublication.CHAMP_SECTION_ID: params[ConstantesPublication.CHAMP_SECTION_ID]})
            site_id = section[ConstantesPublication.CHAMP_SECTION_ID]
            ops['$setOnInsert'] = {
                # Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_PAGE,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                ConstantesPublication.CHAMP_PARTIEPAGE_ID: version_id,
                ConstantesPublication.CHAMP_SITE_ID: site_id,
                ConstantesPublication.CHAMP_SECTION_ID: params[ConstantesPublication.CHAMP_SECTION_ID],
                # ConstantesPublication.CHAMP_CSS_PAGE: params[ConstantesPublication.CHAMP_CSS_PAGE],
                ConstantesPublication.CHAMP_DATE_CREATION: date_transaction,
            }
        else:
            # Empecher update d'un post si la transaction est plus vieille que la derniere
            # transaction a modifier le post.
            upsert = False  # Eviter de creer des doublons
            filtre[ConstantesPublication.CHAMP_DATE_MODIFICATION] = {'$lt': date_transaction}

        collection_pages = self.document_dao.get_collection(ConstantesPublication.COLLECTION_PARTIES_PAGES)
        page = collection_pages.find_one_and_update(
            filtre, ops, upsert=upsert,
            projection={ConstantesPublication.CHAMP_SECTION_ID: True},
            return_document=ReturnDocument.AFTER
        )

        if page is None:
            return {'ok': False, 'err': 'Echec ajout page'}

        # Recuperer la section_id du post - la transaction ne contient pas la section_id sur update de post
        section_id = page[ConstantesPublication.CHAMP_SECTION_ID]

        # Associer fichier media au post (si applicable)
        # if params.get(ConstantesPublication.CHAMP_MEDIA_UUID):
        #     transaction_media_collection = {
        #         ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: forum_id,
        #         ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS: [params[ConstantesForum.CHAMP_MEDIA_UUID]],
        #     }
        #     self.generateur_transactions.soumettre_transaction(
        #         transaction_media_collection,
        #         ConstantesGrosFichiers.TRANSACTION_AJOUTER_FICHIERS_COLLECTION
        #     )

        # # Flag dirty sur section
        # filtre = {ConstantesPublication.CHAMP_SECTION_ID: section_id}
        # ops = {'$set': {ConstantesPublication.CHAMP_DIRTY_SECTION: True}}
        # collection_forums = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SEC)
        # collection_forums.update_one(filtre, ops)

        # Commande mise a jour forum posts et post comments
        # commande = {ConstantesForum.CHAMP_FORUM_IDS: [forum_id]}
        # domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS
        # self.generateur_transactions.transmettre_commande(commande, domaine_action)
        #
        # commande = {ConstantesForum.CHAMP_POST_IDS: [post_id]}
        # domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_POSTS_COMMENTAIRES
        # self.generateur_transactions.transmettre_commande(commande, domaine_action)

        return {'ok': True}

    def get_partie_pages(self, params: dict):
        site_id = params[ConstantesPublication.CHAMP_SITE_ID]
        section_id = params.get(ConstantesPublication.CHAMP_SECTION_ID)

        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        if section_id is not None:
            filtre[ConstantesPublication.CHAMP_SECTION_ID] = section_id

        collection_sitepages = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITE_PAGES)
        curseur = collection_sitepages.find(filtre)

        site_pages = [c for c in curseur]

        return site_pages

    def get_configuration_site(self, params: dict):
        site_id = params['site_id']
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id
        }
        hints = [(ConstantesPublication.CHAMP_SITE_ID, 1)]
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        noeud_config = collection_site.find_one(filtre, hint=hints)

        return noeud_config

    def get_sites_par_noeud(self, params: dict) -> list:
        noeud_id = params['noeud_id']
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_NOEUDS_URLS + '.' + noeud_id: {'$exists': True}
        }
        hints = [(ConstantesPublication.CHAMP_NOEUDS_URLS, 1)]

        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        curseur = collection_site.find(filtre, hint=hints)

        sites = list()
        for site in curseur:
            del site['_id']
            enveloppe = self.generateur_transactions.preparer_enveloppe(site)
            sites.append(enveloppe)

        return sites

    def get_posts(self, params: dict):
        post_ids = params[ConstantesPublication.CHAMP_POST_IDS]
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_POST,
            ConstantesPublication.CHAMP_POST_ID: {'$in': post_ids}
        }

        collection_posts = self.document_dao.get_collection(ConstantesPublication.COLLECTION_POSTS_NOM)
        projection = [
            ConstantesPublication.CHAMP_POST_ID,
            ConstantesPublication.CHAMP_HTML,
            ConstantesPublication.CHAMP_DATE_POST,
        ]
        curseur = collection_posts.find(filtre, projection=projection)

        docs = list()
        for d in curseur:
            doc_signe = self.generateur_transactions.preparer_enveloppe(d)
            docs.append(doc_signe)

        return docs

    def creer_site(self, params: dict):
        uuid_transaction = params['en-tete']['uuid_transaction']
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())
        site = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,
            ConstantesPublication.CHAMP_SITE_ID: uuid_transaction,
            Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PUBLIC,
        }
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        resultat = collection_site.insert_one(site)
        if resultat.acknowledged is not True:
            return {'ok': False, 'err': 'Echec ajout document de site'}

        # Transmettre transaction pour creer une collection "grosfichiers" pour les fichiers du site
        domaine_action = ConstantesGrosFichiers.TRANSACTION_NOUVELLE_COLLECTION
        transaction_creer_collection = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_transaction,
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION: uuid_transaction,
            ConstantesGrosFichiers.DOCUMENT_UUID_PARENT: ConstantesGrosFichiers.LIBVAL_UUID_COLLECTION_SITES,
            ConstantesGrosFichiers.CHAMP_CREER_PARENT: True,
        }
        self.generateur_transactions.soumettre_transaction(transaction_creer_collection, domaine_action)

        # # Trigger creation du forumPosts
        # commande = {ConstantesForum.CHAMP_FORUM_IDS: [uuid_transaction]}
        # domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS
        # self.generateur_transactions.transmettre_commande(commande, domaine_action)
        #
        # # Emettre evenement de modification de forums
        # domaine_action = 'Forum.' + ConstantesForum.EVENEMENT_MAJ_FORUMS
        # exchanges = ConstantesSecurite.cascade_protege(Constantes.SECURITE_PROTEGE)
        # self.generateur_transactions.emettre_message(
        #     site, 'evenement.' + domaine_action, domaine_action=domaine_action, exchanges=exchanges)

        return {'site': site}

    def maj_site(self, transaction: dict):
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        try:
            site_id = transaction[ConstantesPublication.CHAMP_SITE_ID]
        except KeyError:
            # Par defaut le site id est l'identificateur unique de la transaction
            site_id = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        self.__logger.debug("Maj site id: %s" % site_id)

        filtre = {
            # Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_SITE_ID: site_id
        }

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow()
        }
        # set_on_insert.update(filtre)

        # Nettoyer la transaction de champs d'index, copier le reste dans le document
        set_ops = dict()
        for key, value in transaction.items():
            if key not in [Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, ConstantesPublication.CHAMP_SITE_ID] and \
                    key.startswith('_') is False:
                set_ops[key] = value

        ops = {
            # '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        if len(set_ops) > 0:
            ops['$set'] = set_ops

        doc_site = collection_site.find_one_and_update(filtre, ops, return_document=ReturnDocument.AFTER)

        securite_site = doc_site[Constantes.DOCUMENT_INFODOC_SECURITE]

        # Maj de la collection de fichiers associee (securite et nom)
        transaction_maj_collection = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: site_id,
            Constantes.DOCUMENT_INFODOC_SECURITE: securite_site,
        }
        nom_site = doc_site.get(ConstantesPublication.CHAMP_NOM_SITE)
        if nom_site:
            transaction_maj_collection[ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION] = nom_site
        self.generateur_transactions.soumettre_transaction(transaction_maj_collection, 'GrosFichiers.' + ConstantesGrosFichiers.TRANSACTION_DECRIRE_COLLECTION)

        return doc_site

    def maj_post(self, transaction: dict):
        collection_post = self.document_dao.get_collection(ConstantesPublication.COLLECTION_POSTS_NOM)

        post_id = transaction[ConstantesPublication.CHAMP_POST_ID]

        self.__logger.debug("Maj post id: %s" % post_id)

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_POST,
            ConstantesPublication.CHAMP_POST_ID: post_id
        }

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow()
        }
        set_on_insert.update(filtre)

        # Nettoyer la transaction de champs d'index, copier le reste dans le document
        set_ops = dict()
        for key, value in transaction.items():
            if key not in [ConstantesPublication.CHAMP_POST_ID] and \
                    key.startswith('_') is False:
                set_ops[key] = value

        # Ajouter signature, derniere_modification, certificat
        estampille = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
            Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        derniere_modification = datetime.datetime.fromtimestamp(estampille)
        set_ops[Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE] = transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_SIGNATURE]
        set_ops[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS] = transaction[
            Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS]

        set_ops[ConstantesPublication.CHAMP_DATE_POST] = estampille

        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        resultat = collection_post.update_one(filtre, ops, upsert=True)

        if resultat.upserted_id is None and resultat.matched_count != 1:
            raise Exception("Erreur maj post " + post_id)

    def maj_cdn(self, params: dict):
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        entete = params[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        cdn_id = params.get('cdn_id') or entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        configuration = params.get('configuration') or dict()

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
            'type_cdn': params['type_cdn'],
            'cdn_id': cdn_id,
        }
        set_ops = {
            'active': params.get('active') or False,
        }
        champs = ['description']
        for champ in champs:
            if params.get(champ):
                set_ops[champ] = params[champ]

        set_ops.update(configuration)

        filtre = {
            'cdn_id': cdn_id,
        }
        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        doc_maj = collection_cdns.find_one_and_update(filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        return doc_maj

    def supprimer_cdn(self, params: dict):
        cdn_id = params['cdn_id']
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)

        filtre = {
            'cdn_id': cdn_id,
        }
        resultat = collection_cdns.delete_one(filtre)
        if resultat.deleted_count != 1:
            raise ValueError("cdn_id %s ne correspond pas a un document" % cdn_id)


class ProcessusPublication(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesPublication.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPublication.COLLECTION_PROCESSUS_NOM


class ProcessusTransactionCreerSite(MGProcessusTransaction):

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction
        doc_site = self.controleur.gestionnaire.creer_site(transaction)

        self.set_etape_suivante()  # Termine

        return {'site': doc_site}


class ProcessusTransactionMajSite(MGProcessusTransaction):
    """
    Processus pour modifier la configuration d'un site
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction
        doc_site = self.controleur.gestionnaire.maj_site(transaction)

        try:
            site_id = transaction[ConstantesPublication.CHAMP_SITE_ID]
        except KeyError:
            # Par defaut le site id est l'identificateur unique de la transaction
            site_id = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        self._transmettre_maj(site_id)

        self.set_etape_suivante()  # Termine

        return {'site': doc_site}

    def _transmettre_maj(self, site_id: str):
        # Preparer evenement de confirmation, emission sur exchange 1.public
        site_config = self.controleur.gestionnaire.get_configuration_site({'site_id': site_id})

        # Retransmettre sur exchange 1.public pour maj live
        self.generateur_transactions.emettre_message(
            site_config,
            'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_SITE,
            exchanges=[Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE],
            ajouter_certificats=True
        )


class ProcessusTransactionMajPost(MGProcessusTransaction):
    """
    Processus pour modifier la configuration d'un site
    """

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction

        # Verifier si on a _certificat ou si on doit l'ajouter
        try:
            transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS]
        except KeyError:
            domaine_requete = 'requete.Pki.' + Constantes.ConstantesPki.REQUETE_CERTIFICAT

            fingerprint_certificat = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_FINGERPRINT_CERTIFICAT]

            params = {'fingerprint': fingerprint_certificat}
            self.set_requete(domaine_requete, params)
            self.set_etape_suivante(ProcessusTransactionMajPost.recevoir_certificat.__name__)  # Recevoir certificat
        else:
            self.controleur.gestionnaire.maj_post(transaction)
            self._transmettre_maj(transaction[ConstantesPublication.CHAMP_POST_ID])
            self.set_etape_suivante()  # Termine

    def recevoir_certificat(self):
        transaction = self.transaction

        # Injecter certificat
        certificat_info = self.parametres['reponse'][0]
        certs_list = [certificat_info['certificats_pem'][c] for c in certificat_info['chaine']]
        transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_CERTIFICAT_INCLUS] = certs_list

        self.controleur.gestionnaire.maj_post(transaction)
        self._transmettre_maj(transaction[ConstantesPublication.CHAMP_POST_ID])
        self.set_etape_suivante()  # Termine

    def _transmettre_maj(self, post_id: str):
        # Preparer evenement de confirmation, emission sur exchange 1.public
        post = self.controleur.gestionnaire.get_posts(
            {ConstantesPublication.CHAMP_POST_IDS: [post_id]})

        message_posts = {'liste_posts': post}

        # Retransmettre sur exchange 1.public pour maj live
        self.generateur_transactions.emettre_message(
            message_posts,
            'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_POST,
            exchanges=[Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE],
            ajouter_certificats=True
        )


class ProcessusTransactionMajCdn(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction

        # Verifier si on a _certificat ou si on doit l'ajouter
        doc_maj = self.controleur.gestionnaire.maj_cdn(transaction)

        self.set_etape_suivante()  # Termine

        return {'cdn': doc_maj}


class ProcessusSupprimerCdn(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction

        # Verifier si on a _certificat ou si on doit l'ajouter
        self.controleur.gestionnaire.supprimer_cdn(transaction)

        self.set_etape_suivante()  # Termine

        return {'ok': True}


class ProcessusTransactionMajSection(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction

        # Verifier si on a _certificat ou si on doit l'ajouter
        doc_section = self.controleur.gestionnaire.maj_section(transaction)

        self.set_etape_suivante()  # Termine

        return {'section': doc_section}


class ProcessusTransactionMajPartiepage(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction

        # Verifier si on a _certificat ou si on doit l'ajouter
        partie_page = self.controleur.gestionnaire.maj_partie_page(transaction)

        self.set_etape_suivante()  # Termine

        return {'partie_page': partie_page}
