import logging
import datetime
import pytz
import math

from pymongo import ReturnDocument

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPublication, ConstantesGrosFichiers
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees, \
    TraitementMessageDomaineRequete, TraitementCommandesProtegees, TraitementMessageDomaineEvenement
from millegrilles.MGProcessus import MGProcessusTransaction, MGProcessus


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
        elif domaine_action == ConstantesPublication.REQUETE_LISTE_SECTIONS_SITE:
            reponse = self.gestionnaire.get_liste_sections_site(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_LISTE_CDN:
            reponse = self.gestionnaire.get_liste_cdns(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesPublication.REQUETE_PARTIES_PAGE:
            reponse = self.gestionnaire.get_partie_pages(message_dict)
            reponse = {'resultats': reponse}
        else:
            reponse = {'err': 'Commande invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementCommandesProtegeesPublication(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        reponse = None
        if domaine_action == ConstantesPublication.COMMANDE_PUBLIER_SITE:
            self.gestionnaire.maj_ressources_site(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_PAGE:
            self.gestionnaire.maj_ressources_page(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_FICHIERS:
            self.gestionnaire.trigger_publication_fichiers(message_dict)
        else:
            reponse = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        if reponse is not None:
            replying_to = properties.reply_to
            correlation_id = properties.correlation_id
            if replying_to is not None and correlation_id is not None:
                self.transmettre_reponse(message_dict, reponse, replying_to, correlation_id)


class TraitementEvenementsFichiers(TraitementMessageDomaineEvenement):

    def traiter_evenement(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == 'publierFichier':
            self.gestionnaire.traiter_evenement_publicationfichier(message_dict)


class GestionnairePublication(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesPublication(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesPublication(self)
        }

        self.__handler_commandes = {
            Constantes.SECURITE_PROTEGE: TraitementCommandesProtegeesPublication(self),
        }

        self.__traitement_publication_fichiers = TraitementEvenementsFichiers(self,)

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

    def get_handler_commandes(self) -> dict:
        handlers = super().get_handler_commandes()
        handlers.update(self.__handler_commandes)
        return handlers

    def get_queue_configuration(self):
        queue_config = super().get_queue_configuration()

        queue_config.append({
            'nom': '%s.%s' % (self.get_nom_queue(), 'evenementsPublication'),
            'routing': [
                'evenement.fichiers.publierFichier',
            ],
            'exchange': self.configuration.exchange_protege,
            'ttl': 300000,
            'callback': self.__traitement_publication_fichiers.callbackAvecAck
        })

        return queue_config

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
            # Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG
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

    def get_liste_sections_site(self, params: dict):
        site_id = params[ConstantesPublication.CHAMP_SITE_ID]
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
        curseur = collection_site.find(filtre)

        sections = list()
        for site in curseur:
            del site['_id']
            sections.append(site)

        return sections

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

        champs = ['securite', 'entete', 'collections', 'parties_pages', 'liste_forums', 'toutes_collections', 'tous_forums']
        for key, value in params.items():
            if key in champs:
                set_ops[key] = value

        ops = dict()
        if len(set_ops) > 0:
            ops['$set'] = set_ops

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
        doc_section = collection_sections.find_one_and_update(filtre, ops, upsert=upsert,
                                                              return_document=ReturnDocument.AFTER)

        site_id = doc_section[ConstantesPublication.CHAMP_SITE_ID]  # site_id pas inclus dans les updates

        # Declencher publication des collections
        collections_fichiers = doc_section.get('collections') or list()
        for c in collections_fichiers:
            params = {'uuid_collection': c, 'section_id': section_id, 'site_id': site_id}
            self.demarrer_processus('millegrilles_domaines_Publication:ProcessusPublierCollectionGrosFichiers', params)

        # Ajouter la nouvelle section au site
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        filtre = {ConstantesPublication.CHAMP_SITE_ID: site_id}
        ops = {
            '$currentDate': {
                Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
            }
        }

        if version_id == section_id:
            # Nouvelle section, on l'active par defaut
            ops['$push'] = {ConstantesPublication.CHAMP_LISTE_SECTIONS: section_id}

        doc_site = collection_sites.find_one_and_update(filtre, ops, return_document=ReturnDocument.AFTER)

        # Retransmettre sur exchange 1.public pour maj live
        self.generateur_transactions.emettre_message(
            doc_site,
            'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_SITE,
            ajouter_certificats=True
        )

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
            site_id = section[ConstantesPublication.CHAMP_SITE_ID]
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
        doc_page = collection_pages.find_one_and_update(
            filtre, ops, upsert=upsert,
            # projection={ConstantesPublication.CHAMP_SECTION_ID: True},
            return_document=ReturnDocument.AFTER
        )

        if doc_page is None:
            return {'ok': False, 'err': 'Echec ajout page'}

        # Recuperer la section_id du post - la transaction ne contient pas la section_id sur update de post
        section_id = doc_page[ConstantesPublication.CHAMP_SECTION_ID]

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

        return doc_page

    def get_partie_pages(self, params: dict):
        site_id = params.get(ConstantesPublication.CHAMP_SITE_ID)
        section_id = params.get(ConstantesPublication.CHAMP_SECTION_ID)

        filtre = {
            # ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        if section_id is not None:
            filtre[ConstantesPublication.CHAMP_SECTION_ID] = section_id
        elif site_id is not None:
            filtre[ConstantesPublication.CHAMP_SITE_ID] = site_id
        else:
            return {'err': 'Aucun site_id ou section_id fourni'}

        collection_partiespages = self.document_dao.get_collection(ConstantesPublication.COLLECTION_PARTIES_PAGES)
        curseur = collection_partiespages.find(filtre)

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

        return site

    def maj_site(self, transaction: dict):
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        try:
            site_id = transaction[ConstantesPublication.CHAMP_SITE_ID]
        except KeyError:
            # Par defaut le site id est l'identificateur unique de la transaction
            site_id = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

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
        self.generateur_transactions.soumettre_transaction(transaction_maj_collection,
                                                           'GrosFichiers.' + ConstantesGrosFichiers.TRANSACTION_DECRIRE_COLLECTION)



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

    def get_site(self, site_id):
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        doc_site = collection_sites.find_one(filtre)
        return doc_site

    def maj_ressources_site(self, params: dict):
        site_id = params[ConstantesPublication.CHAMP_SITE_ID]
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        doc_site = collection_sites.find_one(filtre)

        champs_site = [
            ConstantesPublication.CHAMP_SITE_ID,
            ConstantesPublication.CHAMP_LANGUAGES,
            ConstantesPublication.CHAMP_TITRE,
            Constantes.DOCUMENT_INFODOC_SECURITE,
            ConstantesPublication.CHAMP_LISTE_SOCKETIO,
        ]
        contenu_signe = dict()
        for key, value in doc_site.items():
            if key in champs_site:
                contenu_signe[key] = value

        # Ajouter tous les CDNs pour ce site
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        liste_cdn_ids = doc_site['listeCdn']
        filtre_cdns = {'cdn_id': {'$in': liste_cdn_ids}, 'active': True}
        curseur_cdns = collection_cdns.find(filtre_cdns)
        mapping_cdns = list()
        for cdn in curseur_cdns:
            mapping = {
                'type_cdn': cdn['type_cdn'],
            }
            access_point_url = cdn.get('accesPointUrl')
            if access_point_url is not None:
                mapping['access_point_url'] = access_point_url

            mapping_cdns.append(mapping)
        contenu_signe['cdns'] = mapping_cdns

        # Aller chercher references des sections
        # Chaque section est un fichier accessible via son uuid
        liste_sections_id = doc_site[ConstantesPublication.CHAMP_LISTE_SECTIONS]
        filtre_sections = {
            ConstantesPublication.CHAMP_SECTION_ID: {'$in': liste_sections_id}
        }
        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
        curseur_sections = collection_sections.find(filtre_sections)
        sections_dict = dict()
        for s in curseur_sections:
            sections_dict[s[ConstantesPublication.CHAMP_SECTION_ID]] = s

        # Ajouter sections en ordre
        sections_liste = list()
        contenu_signe[ConstantesPublication.CHAMP_LISTE_SECTIONS] = sections_liste
        uuid_to_map = set()  # Conserver tous les uuid a mapper
        for section_id in doc_site[ConstantesPublication.CHAMP_LISTE_SECTIONS]:
            doc_section = sections_dict[section_id]
            type_section = doc_section[ConstantesPublication.CHAMP_TYPE_SECTION]

            section = {
                ConstantesPublication.CHAMP_TYPE_SECTION: type_section,
                ConstantesPublication.CHAMP_ENTETE: doc_section.get(ConstantesPublication.CHAMP_ENTETE),
            }

            if type_section in [ConstantesPublication.LIBVAL_FICHIERS, ConstantesPublication.LIBVAL_ALBUM]:
                uuid_collections = doc_section[ConstantesPublication.CHAMP_COLLECTIONS]
                section[ConstantesPublication.CHAMP_COLLECTIONS] = uuid_collections
                uuid_to_map.update(uuid_collections)
            else:
                section[ConstantesPublication.CHAMP_SECTION_ID] = section_id
                uuid_to_map.add(section_id)

            sections_liste.append(section)

        # Aller chercher les valeurs ipns pour tous les champs uuid (si applicable)
        uuid_to_ipns = dict()
        for uuid_elem in uuid_to_map:
            uuid_to_ipns[uuid_elem] = 'TODO'
        contenu_signe['ipns_map'] = uuid_to_ipns

        contenu_signe = self.generateur_transactions.preparer_enveloppe(
            contenu_signe, 'Publication.' + ConstantesPublication.LIBVAL_SITE_CONFIG)

        set_ops = {
            'contenu_signe': contenu_signe,
            'sites': [site_id],
        }
        set_on_insert = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {ConstantesPublication.CHAMP_DATE_MODIFICATION: True},
        }
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        doc_site = collection_ressources.find_one_and_update(
            filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

    def maj_ressources_page(self, params: dict):
        # Charger page
        section_id = params[ConstantesPublication.CHAMP_SECTION_ID]
        collection_sections = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
        filtre = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id
        }
        section = collection_sections.find_one(filtre)
        site_id = section[ConstantesPublication.CHAMP_SITE_ID]

        parties_page_ids = section[ConstantesPublication.CHAMP_PARTIES_PAGES]
        collection_partiespage = self.document_dao.get_collection(ConstantesPublication.COLLECTION_PARTIES_PAGES)
        filtre_partiespage = {
            ConstantesPublication.CHAMP_PARTIEPAGE_ID: {'$in': parties_page_ids}
        }
        curseur_parties = collection_partiespage.find(filtre_partiespage)

        parties_page = dict()
        fuuids = list()
        for p in curseur_parties:
            pp = dict()
            for key, value in p.items():
                if not key.startswith('_'):
                    pp[key] = value
            if p.get('media'):
                fuuids_media = p['media'].get('fuuids')
                fuuids.extend(fuuids_media)
            elif p.get('colonnes'):
                for c in p['colonnes']:
                    media = c.get('media')
                    if media is not None:
                        fuuids_media = media.get('fuuids')
                        fuuids.extend(fuuids_media)

            pp_id = pp[ConstantesPublication.CHAMP_PARTIEPAGE_ID]
            parties_page[pp_id] = pp

        parties_page_ordonnees = list()
        for pp_id in section[ConstantesPublication.CHAMP_PARTIES_PAGES]:
            parties_page_ordonnees.append(parties_page[pp_id])

        contenu_signe = {
            ConstantesPublication.CHAMP_PARTIES_PAGES: parties_page_ordonnees,
        }
        contenu_signe = self.generateur_transactions.preparer_enveloppe(
            contenu_signe, 'Publication.' + ConstantesPublication.LIBVAL_PAGE)

        set_ops = {
            'contenu_signe': contenu_signe,
            'sites': [site_id],
            'fuuids': fuuids,
        }

        set_on_insert = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_PAGE,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {ConstantesPublication.CHAMP_DATE_MODIFICATION: True},
        }
        filtre = {
            ConstantesPublication.CHAMP_SECTION_ID: section_id,
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_PAGE,
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        doc_page = collection_ressources.find_one_and_update(
            filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        # Ajouter les fichiers requis comme ressource pour le site
        doc_site = self.get_site(site_id)
        flag_public = doc_site['securite'] == Constantes.SECURITE_PUBLIC
        self.maj_ressources_fuuids(fuuids, sites=[site_id], public=flag_public)

        return doc_page

    def maj_ressources_fuuids(self, fuuids: list, sites: list = None, public=False):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        for fuuid in fuuids:
            set_on_insert = {
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                'fuuid': fuuid,
            }
            set_ops = dict()
            push_ops = dict()
            add_to_set_ops = dict()

            if public is True:
                set_ops['public'] = True

            if sites is not None:
                for s in sites:
                    add_to_set_ops['sites'] = s

            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                'fuuid': fuuid,
            }
            ops = {
                '$setOnInsert': set_on_insert,
                '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
            }
            if len(set_ops) > 0:
                ops['$set'] = set_ops
            if len(push_ops) > 0:
                ops['$push'] = push_ops
            if len(add_to_set_ops) > 0:
                ops['$addToSet'] = add_to_set_ops
            collection_ressources.update_one(filtre, ops, upsert=True)

    def preparer_publication(self):

        # Mettre a jour CDN des ressources par site
        # Pour chaque site, charger liste CDNs et faire un "update ressources [cdn]requis = True where site_id in sites"

        # Faire un tri des CDNs pour trouver l'ordre de publication (e.g. CDN pour le plus de sites en premier)

        # Parcourir les types de ressources en ordre et demander publication (message fichiers)
        # Ordre = INSERTS, UPDATES (1. code, 2.contenu, 3.config), DELETES

        pass

    def get_ressource_collection(self, uuid_collection):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIERS,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }
        res_collection = collection_ressources.find_one(filtre)
        return res_collection

    def ajouter_site_fichiers(self, uuid_collection, site_id):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIERS,
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_collection,
        }
        ops = {
            '$addToSet': {'sites': site_id}
        }
        collection_ressources.update_one(filtre, ops)

    def creer_ressource_collection(self, site_id, info_collection: dict, liste_fichiers: list):
        contenu_signe = {}
        contenu_signe.update(info_collection)
        contenu_signe['fichiers'] = liste_fichiers

        contenu_signe = self.generateur_transactions.preparer_enveloppe(contenu_signe, 'Publication.fichiers')

        set_ops = {
            'contenu_signe': contenu_signe,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIERS,
            'uuid': info_collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC],
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        add_to_set = {
            'sites': site_id,
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIERS,
            'uuid': info_collection[ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC],
        }
        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$addToSet': add_to_set,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources.update_one(filtre, ops, upsert=True)

        # Creer les entrees manquantes de fichiers
        fuuids = set()
        flag_public = info_collection.get('securite') == Constantes.SECURITE_PUBLIC
        for f in liste_fichiers:
            fuuids.update(f['fuuids'])
        self.maj_ressources_fuuids(list(fuuids), [site_id], public=flag_public)

    def trigger_publication_fichiers(self, params: dict):
        """
        Declenche la publication de tous les fichiers de CDN actifs lie a au moins un site.
        :return:
        """
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        # Faire la liste de tous les CDNs utilises dans au moins 1 site
        cdns_associes = set()
        curseur_sites = collection_sites.find()
        sites_par_cdn_dict = dict()
        for s in curseur_sites:
            cdns = s.get('listeCdn')
            if cdns is not None:
                cdns_associes.update(cdns)
                for cdn in cdns:
                    try:
                        liste_sites = sites_par_cdn_dict[cdn]
                    except KeyError:
                        liste_sites = list()
                        sites_par_cdn_dict[cdn] = liste_sites
                    liste_sites.append(s[ConstantesPublication.CHAMP_SITE_ID])
        cdns_associes = list(cdns_associes)

        # Recuperer la liste de CDNs actifs
        collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        filtre = {
            ConstantesPublication.CHAMP_CDN_ID: {'$in': cdns_associes},
            'active': True,
        }
        curseur_cdns = collection_cdns.find(filtre)

        dict_cdns = dict()
        for cdn in curseur_cdns:
            cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
            liste_sites = sites_par_cdn_dict[cdn_id]
            cdn['sites'] = liste_sites
            dict_cdns[cdn_id] = cdn

            # Recuperer la liste de fichiers qui ne sont pas publies dans tous les CDNs de la liste
            collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
            filtre_fichiers = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
                'sites': {'$in': liste_sites},
                'distribution_complete': {'$not': {'$all': [cdn_id]}},
            }
            curseur_res_fichiers = collection_ressources.find(filtre_fichiers)

            # Creer les commandes de publication (consignation fichiers) pour tous les fichiers/CDN
            for fichier in curseur_res_fichiers:
                self.commande_publier_fichier(fichier, cdn)

        pass

    def commande_publier_fichier(self, res_fichier: dict, cdn_info: dict):
        type_cdn = cdn_info['type_cdn']
        cdn_id = cdn_info['cdn_id']
        fuuid = res_fichier['fuuid']

        self.__logger.debug("Publication sur CDN_ID:%s fichier %s" % (cdn_id, str(fuuid)))

        if type_cdn == 'sftp':
            self.commande_publier_fichier_sftp(res_fichier, cdn_info)
        else:
            raise Exception("Type cdn non supporte %s" % type_cdn)

        # Ajouter flag de publication dans la ressource
        ops = {
            '$set': {'distribution_progres.' + cdn_id: False},
            '$currentDate': {'distribution_maj': True}
        }
        filtre_fichier_update = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            'fuuid': fuuid,
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources.update_one(filtre_fichier_update, ops)

    def commande_publier_fichier_sftp(self, res_fichier: dict, cdn_info: dict):
        fuuid = res_fichier['fuuid']
        cdn_id = cdn_info['cdn_id']
        flag_public = res_fichier.get('public') or False
        if flag_public:
            securite = Constantes.SECURITE_PUBLIC
        else:
            securite = Constantes.SECURITE_PRIVE

        params = {
            'fuuid': fuuid,
            'cdn_id': cdn_id,
            'host': cdn_info['host'],
            'port': cdn_info['port'],
            'username': cdn_info['username'],
            'basedir': cdn_info['repertoireRemote'],
            # 'mimetype': 'image/gif',
            'securite': securite,
        }
        domaine = 'commande.fichiers.publierFichierSftp'
        self.generateur_transactions.transmettre_commande(params, domaine)

    def commande_publier_fichier_ipfs(self):
        params = {
            'fuuid': self.__fuuid,
            'mimetype': 'image/gif',
            'securite': '1.public',
        }
        domaine = 'commande.fichiers.publierFichierIpfs'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_ipfs')

    def commande_publier_fichier_awss3(self):
        secret_chiffre = 'm0M2DADXJBB4wF/4n1rNum71zBH5f3E/dDpRjUof8pqMXvDG8SzvD5Q'
        permission = self.preparer_permission_secretawss3(secret_chiffre)

        params = {
            'uuid': str(uuid4()),
            'fuuid': self.__fuuid,
            'mimetype': 'image/gif',
            # 'securite': '1.public',
            'bucketRegion': 'us-east-1',
            'credentialsAccessKeyId': 'AKIA2JHYIVE5E3HWIH7K',
            # 'secretAccessKey': self.__awss3_secret_access_key,
            'secretAccessKey_chiffre': 'm0M2DADXJBB4wF/4n1rNum71zBH5f3E/dDpRjUof8pqMXvDG8SzvD5Q',
            'permission': permission,
            'bucketName': 'millegrilles',
            'bucketDirfichier': 'mg-dev4/fichiers',
        }
        domaine = 'commande.fichiers.publierFichierAwsS3'
        self.generateur.transmettre_commande(
            params, domaine, reply_to=self.queue_name, correlation_id='commande_publier_fichier_awss3')

    def traiter_evenement_publicationfichier(self, params: dict):
        cdn_id = params['cdn_id']
        fuuid = params['fuuid']
        flag_complete = params.get('complete') or False
        err = params.get('err') or False
        current_bytes = params.get('current_bytes')
        total_bytes = params.get('total_bytes')

        # Determiner type evenement
        set_ops = dict()
        unset_ops = dict()
        add_to_set = dict()
        if flag_complete:
            # Publication completee
            unset_ops['distribution_encours.' + cdn_id] = True
            unset_ops['distribution_progres.' + cdn_id] = True
            unset_ops['distribution_erreur.' + cdn_id] = True
            add_to_set['distribution_complete'] = cdn_id
        elif err is not False:
            # Erreur
            unset_ops['distribution_encours.' + cdn_id] = True
            unset_ops['distribution_progres.' + cdn_id] = True
            set_ops['distribution_erreur.' + cdn_id] = err
        elif current_bytes is not None and total_bytes is not None:
            # Progres
            progres = math.floor(current_bytes * 100 / total_bytes)
            set_ops['distribution_progres.' + cdn_id] = progres

        ops = {
            '$currentDate': {'distribution_maj': True}
        }
        if len(set_ops) > 0:
            ops['$set'] = set_ops
        if len(unset_ops) > 0:
            ops['$unset'] = unset_ops
        if len(add_to_set) > 0:
            ops['$addToSet'] = add_to_set

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_FICHIER,
            'fuuid': fuuid,
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        collection_ressources.update_one(filtre, ops)


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
            site_id = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][
                Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]
        self._transmettre_maj(site_id)

        commande = {
            ConstantesPublication.CHAMP_SITE_ID: site_id
        }
        self.ajouter_commande_a_transmettre('commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_SITE, commande)

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

        commande = {
            ConstantesPublication.CHAMP_SECTION_ID: doc_section[ConstantesPublication.CHAMP_SECTION_ID]
        }
        self.ajouter_commande_a_transmettre('commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_PAGE, commande)

        self.set_etape_suivante()  # Termine

        return {'section': doc_section}


class ProcessusTransactionMajPartiepage(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction

        # Verifier si on a _certificat ou si on doit l'ajouter
        partie_page = self.controleur.gestionnaire.maj_partie_page(transaction)

        commande = {
            ConstantesPublication.CHAMP_SECTION_ID: partie_page[ConstantesPublication.CHAMP_SECTION_ID]
        }
        self.ajouter_commande_a_transmettre('commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_PAGE, commande)

        self.set_etape_suivante()  # Termine

        return {'partie_page': partie_page}


class ProcessusPublierCollectionGrosFichiers(MGProcessus):

    def initiale(self):
        params = self.parametres

        # Verifier si la collection existe deja dans ressources
        uuid_collection = params['uuid_collection']
        res_collection = self.controleur.gestionnaire.get_ressource_collection(uuid_collection)

        if res_collection is None:
            # Requete vers grosfichiers pour recuperer le contenu de la collection et initialiser tous les fichiers
            requete = {'uuid': uuid_collection}
            domaine_action = Constantes.ConstantesGrosFichiers.REQUETE_CONTENU_COLLECTION
            self.set_requete(domaine_action, requete)
            self.set_etape_suivante(ProcessusPublierCollectionGrosFichiers.traiter_nouvelle_collection.__name__)
        else:
            # S'assurer que la collection a le site_id
            site_id = params['site_id']
            if site_id not in res_collection['sites']:
                self.controleur.gestionnaire.ajouter_site_fichiers(uuid_collection, site_id)
            self.set_etape_suivante()  # Termine

    def traiter_nouvelle_collection(self):
        contenu_collection = self.parametres['reponse'][0]
        site_id = self.parametres['site_id']

        info_collection = contenu_collection['collection']
        liste_documents = contenu_collection['documents']

        self.controleur.gestionnaire.creer_ressource_collection(site_id, info_collection, liste_documents)

        self.set_etape_suivante()  # Termine


class ProcessusPublierFichierIpfs(MGProcessus):

    def initiale(self):
        fuuid = self.parametres['fuuid']
        securite = self.parametres.get('securite') or Constantes.SECURITE_PRIVE
        commande = {
            'securite': securite,
            'fuuid': fuuid,
        }
        domaine_action = 'commande.fichiers.publierFichierIpfs'
        self.ajouter_commande_a_transmettre(domaine_action, commande, blocking=True)
        self.set_etape_suivante(ProcessusPublierFichierIpfs.creer_transaction.__name__)

    def creer_transaction(self):
        reponse = self.parametres['reponse'][0]

        self.set_etape_suivante()  # Termine
