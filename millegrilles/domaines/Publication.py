import logging
import datetime
import pytz

from pymongo import ReturnDocument

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPublication, ConstantesGrosFichiers
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees, \
    TraitementMessageDomaineRequete, TraitementCommandesProtegees, TraitementMessageDomaineEvenement, \
    TraitementMessageDomaineCommande
from millegrilles.MGProcessus import MGProcessusTransaction
from millegrilles.util.PublicationRessources import GestionnaireCascadePublication
from millegrilles.SecuritePKI import EnveloppeCertificat


class TraitementRequetesPubliquesPublication(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesPublication.REQUETE_CONFIGURATION_SITES_NOEUD:
            reponse = self.gestionnaire.get_configuration_sites_par_noeud(message_dict)
        elif domaine_action == ConstantesPublication.REQUETE_LISTE_SITES:
            reponse = self.gestionnaire.get_liste_sites()
            reponse = {'resultats': reponse}
        else:
            reponse = {'err': 'Requete invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementRequetesPriveesPublication(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesPublication.REQUETE_PERMISSION_PRIVEE:
            reponse = self.gestionnaire.get_permission_privee(enveloppe_certificat)
        else:
            reponse = {'err': 'Requete invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementCommandesPubliquesPublication(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        reponse = None
        if domaine_action == ConstantesPublication.COMMANDE_POUSSER_SECTIONS:
            reponse = self.gestionnaire.pousser_sections(message_dict, properties)
        else:
            super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementRequetesProtegeesPublication(TraitementRequetesProtegees):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesPublication.REQUETE_CONFIGURATION_SITE:
            reponse = self.gestionnaire.get_configuration_site(message_dict)
        elif domaine_action == ConstantesPublication.REQUETE_SITES_POUR_NOEUD:
            reponse = self.gestionnaire.get_configuration_sites_par_noeud(message_dict)
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
        elif domaine_action == ConstantesPublication.REQUETE_ETAT_PUBLICATION:
            reponse = self.gestionnaire.get_etat_publication()
        elif domaine_action == ConstantesPublication.REQUETE_ETAT_SITE:
            reponse = self.gestionnaire.get_ressource_site(message_dict)
        elif domaine_action == ConstantesPublication.REQUETE_CONFIGURATION_MAPPING:
            reponse = self.gestionnaire.get_configuration_mapping(message_dict)
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

        # Extraire differents composants pour acceder aux fonctionnalites
        cascade: GestionnaireCascadePublication = self.gestionnaire.cascade
        triggers = cascade.triggers
        ressources = cascade.ressources

        reponse = None
        if domaine_action == ConstantesPublication.COMMANDE_PUBLIER_SITE:
            ressources.maj_ressources_site(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_PAGE:
            ressources.maj_ressources_page(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_FICHIERS:
            triggers.trigger_publication_fichiers(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_SECTIONS:
            cascade.continuer_publication_sections()
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_WEBAPPS:
            triggers.commande_trigger_publication_webapps(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_DATASECTION:
            cascade.commande_publier_upload_datasection(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_SITECONFIGURATION:
            triggers.emettre_publier_configuration(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_MAPPING:
            cascade.commande_publier_upload_mapping(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_UPLOAD_SITECONFIGURATION:
            cascade.commande_publier_upload_siteconfiguration(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_PUBLIER_COMPLET:
            compte = triggers.demarrer_publication_complete(message_dict)
            reponse = {'ok': True, 'compte': compte}
        elif domaine_action == ConstantesPublication.COMMANDE_CONTINUER_PUBLICATION:
            cascade.continuer_publication(message_dict)
        elif domaine_action == ConstantesPublication.COMMANDE_RESET_RESSOURCES:
            matched_count = ressources.reset_ressources(message_dict)
            reponse = {'ok': True, 'matched_count': matched_count}
        elif domaine_action == ConstantesPublication.COMMANDE_POUSSER_SECTIONS:
            reponse = self.gestionnaire.pousser_sections(message_dict, properties)
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

        gestionnaire_publication = self.gestionnaire
        cascade: GestionnaireCascadePublication = gestionnaire_publication.cascade

        if domaine_action == 'publierFichier':
            cascade.traiter_evenement_publicationfichier(message_dict)
        elif domaine_action in ['majFichier', 'associationPoster']:
            cascade.traiter_evenement_maj_fichier(message_dict, routing_key)


class GestionnairePublication(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesPublication(self),
            Constantes.SECURITE_PRIVE: TraitementRequetesPriveesPublication(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegeesPublication(self)
        }

        self.__handler_commandes = {
            Constantes.SECURITE_PUBLIC: TraitementCommandesPubliquesPublication(self),
            Constantes.SECURITE_PROTEGE: TraitementCommandesProtegeesPublication(self),
        }

        self.__traitement_publication_fichiers = TraitementEvenementsFichiers(self,)

        self.__gestionnaire_cascade = GestionnaireCascadePublication(self, contexte)

    @property
    def cascade(self):
        return self.__gestionnaire_cascade

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB
        self.preparer_documents()

    def demarrer(self):
        super().demarrer()

    def creer_index(self):
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        # Index _mg-libelle
        collection_sites.create_index([(ConstantesPublication.CHAMP_SITE_ID, 1)], name='site_id')
        collection_sites.create_index([(ConstantesPublication.CHAMP_NOEUDS_URLS, 1)], name='noeuds_urls')

    def preparer_documents(self):
        # S'assurer d'avoir une configuration pour webapps
        filtre_webapps = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS}
        maintenant = datetime.datetime.utcnow()
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: maintenant,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: maintenant,
        }
        collection_configuration = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
        ops_webapps = {'$setOnInsert': set_on_insert}
        collection_configuration.update(filtre_webapps, ops_webapps, upsert=True)

    def identifier_processus(self, domaine_transaction):
        domaine_action = domaine_transaction.split('.').pop()
        if domaine_action == ConstantesPublication.TRANSACTION_CREER_SITE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionCreerSite"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_SITE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajSite"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_MAPPING:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajMapping"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_CDN:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajCdn"
        elif domaine_action == ConstantesPublication.TRANSACTION_SUPPRIMER_CDN:
            processus = "millegrilles_domaines_Publication:ProcessusSupprimerCdn"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_SECTION:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajSection"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_PARTIEPAGE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPartiepage"
        elif domaine_action == ConstantesPublication.TRANSACTION_CLE_IPNS:
            processus = "millegrilles_domaines_Publication:ProcessusSauvegarderCleIpns"
        elif domaine_action == ConstantesPublication.TRANSACTION_SET_SITE_DEFAUT:
            processus = "millegrilles_domaines_Publication:ProcessusSetSiteDefaut"

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
                'evenement.grosfichiers.majFichier',
                'evenement.grosfichiers.associationPoster',
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
            Constantes.DOCUMENT_INFODOC_SECURITE,
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

    def get_configuration_mapping(self, params: dict):
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
        }
        collection_configuration = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
        doc_mapping = collection_configuration.find_one(filtre)

        return doc_mapping

    def get_configuration_site(self, params: dict):
        site_id = params['site_id']
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id
        }
        hints = [(ConstantesPublication.CHAMP_SITE_ID, 1)]
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        noeud_config = collection_site.find_one(filtre, hint=hints)

        return noeud_config

    def get_ressource_site(self, params: dict):
        site_id = params['site_id']
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_SITE_ID: site_id
        }
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        res_site = collection_ressources.find_one(filtre)

        filtre_webapp = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_WEBAPPS}
        res_webapps = collection_ressources.find_one(filtre_webapp)

        resultat = {
            'site': res_site,
            'webapp': res_webapps,
        }

        return resultat

    def get_configuration_sites_par_noeud(self, params: dict):
        # noeud_id = params.get('noeud_id')
        #
        # sites = dict()
        # configuration_par_url = dict()
        # cdns = dict()
        #
        # filtre = {
        #     ConstantesPublication.CHAMP_NOEUD_ID: noeud_id
        # }
        # collection_cdns = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CDNS)
        # curseur_cdn = collection_cdns.find(filtre)
        #
        # collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        # for cdn in curseur_cdn:
        #     cdn_id = cdn[ConstantesPublication.CHAMP_CDN_ID]
        #     filtre_site = {ConstantesPublication.CHAMP_LISTE_CDNS: {'$all': [cdn_id]}}
        #     curseur_sites = collection_sites.find(filtre_site)
        #     for site in curseur_sites:
        #         sites[site[ConstantesPublication.CHAMP_SITE_ID]] = site
        #
        # site_defaut = None
        # if len(sites) == 1:
        #     # Le site par defaut est le seul disponible
        #     site_defaut = list(sites.values())[0]
        # # else:
        # #     raise NotImplementedError("Implementer support de plusieurs sites")
        #
        # if site_defaut is not None:
        #     configuration_par_url['defaut'] = site_defaut[ConstantesPublication.CHAMP_SITE_ID]
        #
        # # Verifier si la ressource du site est prete (contenu)
        # if len(sites) > 0:
        #     # Ok, format simple avec une seule configuration
        #     reponse_sites = list()
        #     for site in sites.values():
        #         site_id = site[ConstantesPublication.CHAMP_SITE_ID]
        #
        #         # Note : La methode genere le contenu uniquement s'il n'est pas deja present
        #         doc_res_site = self.preparer_siteconfig_publication(None, site_id)
        #         contenu = doc_res_site[ConstantesPublication.CHAMP_CONTENU_SIGNE]
        #
        #         reponse_sites.append(contenu)
        #
        #         for cdn_site in contenu['cdns']:
        #             cdns[cdn_site[ConstantesPublication.CHAMP_CDN_ID]] = cdn_site
        #
        #     mapping = {
        #         'cdns': list(cdns.values()),
        #         'sites': configuration_par_url,
        #     }
        #     mapping = self.generateur_transactions.preparer_enveloppe(
        #         mapping, 'Publication.sites', ajouter_certificats=True)
        #
        #     return {
        #         'mapping': mapping,
        #         'sites': reponse_sites,
        #     }
        # else:
        #     return {'err': 'Aucuns sites associes a ce noeud'}

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        projection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: True,
            ConstantesPublication.CHAMP_CONTENU_SIGNE: True,
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesPublication.LIBVAL_MAPPING,
                ConstantesPublication.LIBVAL_SITE_CONFIG,
            ]}
        }
        curseur = collection_ressources.find(filtre, projection=projection)
        doc_mapping = None
        sites = list()
        for doc in curseur:
            type_doc = doc[Constantes.DOCUMENT_INFODOC_LIBELLE]
            if type_doc == ConstantesPublication.LIBVAL_MAPPING:
                doc_mapping = doc
            elif type_doc == ConstantesPublication.LIBVAL_SITE_CONFIG:
                sites.append(doc)

        reponse = {
            'mapping': doc_mapping,
            'sites': sites,
        }

        return reponse

    def get_etat_publication(self):
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        projection = {ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES}
        filtre = {ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES: {'$exists': True}}
        curseur_progres = collection_ressources.find(filtre, projection=projection)

        cdn_sets = set()
        for cp in curseur_progres:
            progres = cp[ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES]
            cdn_sets.update(progres.keys())

        en_cours = dict()

        for cdn_id in cdn_sets:
            types_res = dict()

            aggregation_pipe = [
                {'$match': {
                    ConstantesPublication.CHAMP_DISTRIBUTION_PROGRES + '.' + cdn_id: {
                        '$exists': True,
                        '$ne': dict()
                    },
                    Constantes.DOCUMENT_INFODOC_LIBELLE: {'$nin': [
                        ConstantesPublication.LIBVAL_SECTION_FICHIERS,
                        ConstantesPublication.LIBVAL_SECTION_ALBUM,
                    ]}
                }},
                {'$group': {
                    '_id': '$_mg-libelle',
                    'count': {'$sum': 1},
                }}
            ]
            curseur = collection_ressources.aggregate(aggregation_pipe)

            for resultat in curseur:
                self.__logger.debug("Resultat : %s" % str(resultat))
                type_section = resultat['_id']
                count_section = resultat['count']
                types_res[type_section] = count_section

            if len(types_res) > 0:
                en_cours[cdn_id] = types_res

        filtre_erreurs = {
            ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: {'$exists': True}
        }
        projection_erreurs = {
            ConstantesPublication.CHAMP_DISTRIBUTION_ERREUR: True,
            Constantes.DOCUMENT_INFODOC_LIBELLE: True,
            ConstantesPublication.CHAMP_SITE_ID: True,
            ConstantesPublication.CHAMP_SECTION_ID: True,
            'uuid': True,
            'fuuid': True,
        }
        curseur_erreurs = collection_ressources.find(filtre_erreurs, projection=projection_erreurs, limit=1000)
        erreurs = [e for e in curseur_erreurs]

        reponse = {
            'erreurs': erreurs,
            'en_cours': en_cours,
            'cdns': list(cdn_sets),
        }

        return reponse

    def get_site(self, site_id):
        collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        filtre = {
            ConstantesPublication.CHAMP_SITE_ID: site_id,
        }
        doc_site = collection_sites.find_one(filtre)
        return doc_site

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

        self.__gestionnaire_cascade.invalidateur.invalider_ressources_siteconfig(site_id)
        self.__gestionnaire_cascade.invalidateur.invalider_ressource_mapping()

        # Retirer champs de contenu publie du site
        filtre_site_ressources = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_SITE_ID: site_id
        }
        # self.reset_publication_ressource(filtre_site_ressources)
        # self.maj_ressources_site(filtre_site_ressources)

        securite_site = doc_site[Constantes.DOCUMENT_INFODOC_SECURITE]

        # Maj de la collection de fichiers associee (securite et nom)
        transaction_maj_collection = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: site_id + '/fichiers',
            Constantes.DOCUMENT_INFODOC_SECURITE: securite_site,
        }
        nom_site = doc_site.get(ConstantesPublication.CHAMP_NOM_SITE)
        if nom_site:
            transaction_maj_collection[ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION] = nom_site

        self.generateur_transactions.soumettre_transaction(
            transaction_maj_collection, 'GrosFichiers.' + ConstantesGrosFichiers.TRANSACTION_DECRIRE_COLLECTION)

        return doc_site

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

        champs = ['securite', 'entete', 'collections', 'parties_pages', 'liste_forums']
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
        doc_section = collection_sections.find_one_and_update(
            filtre, ops, upsert=upsert, return_document=ReturnDocument.AFTER)

        site_id = doc_section[ConstantesPublication.CHAMP_SITE_ID]  # site_id pas inclus dans les updates

        # Ajouter la nouvelle section au site
        if version_id == section_id:
            # Nouvelle section, on l'active par defaut
            collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
            filtre = {ConstantesPublication.CHAMP_SITE_ID: site_id}
            ops = {
                '$push': {ConstantesPublication.CHAMP_LISTE_SECTIONS: section_id},
                '$currentDate': {
                    Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True,
                }
            }
            collection_sites.find_one_and_update(filtre, ops, return_document=ReturnDocument.AFTER)

        # Invalider la ressource siteconfig pour publication
        self.__gestionnaire_cascade.invalidateur.invalider_ressources_siteconfig(site_id)

        # Declencher publication des collections
        collections_fichiers = doc_section.get('collections') or list()
        for c in collections_fichiers:
            params = {
                'uuid_collection': c,
                'section_id': section_id,
                'site_id': site_id
            }
            self.demarrer_processus('millegrilles_domaines_Publication:ProcessusPublierCollectionGrosFichiers', params)

        # # Retransmettre sur exchange 1.public pour maj live
        # self.generateur_transactions.emettre_message(
        #     doc_site,
        #     'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_SITE,
        #     ajouter_certificats=True
        # )

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

        # self.maj_ressources_page({ConstantesPublication.CHAMP_SECTION_ID: section_id})
        self.__gestionnaire_cascade.invalidateur.invalider_ressources_pages([section_id])

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

    def maj_mapping(self, transaction: dict):
        champs = [ConstantesPublication.CHAMP_SITE_DEFAUT]

        set_ops = dict()
        for champ in champs:
            valeur = transaction.get(champ)
            if valeur is not None:
                set_ops[champ] = valeur

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
        }
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_on_insert.update(filtre)

        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }
        collection_configuration = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
        doc_mapping = collection_configuration.update(filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        # Invalider ressource mapping
        self.__gestionnaire_cascade.invalidateur.invalider_ressource_mapping()

        return doc_mapping

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

        # Invalider tous les sites - fait regenerer tous les CDNs. Update mapping aussi (pour CDNs)
        self.__gestionnaire_cascade.invalidateur.invalider_ressources_siteconfig()
        self.__gestionnaire_cascade.invalidateur.invalider_ressource_mapping()

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

    def pousser_sections(self, params: dict, properties):
        """
        Pousse le contenu des sections. Utilise par serveur Vitrine (CDN MQ).
        :param params:
        :param properties:
        :return:
        """
        reply_to = properties.reply_to

        noeud_id = params.get('noeud_id')
        # A FAIRE : trouver liste de site_ids via CDN MQ

        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)

        # Charger sections avec du contenu (e.g. collection fichiers, pages)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: {'$in': [
                ConstantesPublication.LIBVAL_SECTION_PAGE,
                ConstantesPublication.LIBVAL_COLLECTION_FICHIERS
            ]},
            ConstantesPublication.CHAMP_CONTENU_SIGNE: {'$exists': True},
            # ConstantesPublication.CHAMP_SITE_ID: {'$in': site_ids} ... OR liste_sites... ,  # A FAIRE
        }

        projection = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: True,
            ConstantesPublication.CHAMP_TYPE_SECTION: True,
            ConstantesPublication.CHAMP_SECTION_ID: True,
            'uuid': True,
            ConstantesPublication.CHAMP_CONTENU_SIGNE: True,
        }

        curseur_sections = collection_ressources.find(filtre, projection=projection)

        correlation_id = 'publication.section'
        for section in curseur_sections:
            section[ConstantesPublication.CHAMP_TYPE_SECTION] = section[Constantes.DOCUMENT_INFODOC_LIBELLE]
            self.generateur_transactions.transmettre_reponse(
                section, replying_to=reply_to, correlation_id=correlation_id, ajouter_certificats=True)

        return {'ok': True}

    def sauvegarder_cle_ipns(self, identificateur_document, params):
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }

        type_document = identificateur_document[Constantes.DOCUMENT_INFODOC_LIBELLE]
        if type_document == ConstantesPublication.LIBVAL_WEBAPPS:
            collection_doc = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
            filtre = identificateur_document
            set_on_insert.update(filtre)
        elif type_document == ConstantesPublication.LIBVAL_SITE_CONFIG:
            collection_doc = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
            filtre = {
                ConstantesPublication.CHAMP_SITE_ID: identificateur_document[ConstantesPublication.CHAMP_SITE_ID]
            }
        elif type_document == ConstantesPublication.LIBVAL_COLLECTION_FICHIERS:
            collection_doc = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
            filtre = {
                ConstantesPublication.CHAMP_SECTION_ID: identificateur_document['uuid'],
            }
            set_on_insert[ConstantesPublication.CHAMP_TYPE_SECTION] = type_document
        else:
            collection_doc = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SECTIONS)
            filtre = {
                ConstantesPublication.CHAMP_SECTION_ID: identificateur_document[ConstantesPublication.CHAMP_SECTION_ID],
            }
            set_on_insert[ConstantesPublication.CHAMP_TYPE_SECTION] = type_document

        cle_id = params['cleId']
        cle_chiffree = params['cle_chiffree']

        ops = {
            '$set': {
                'ipns_id': cle_id,
                'ipns_cle_chiffree': cle_chiffree,
            },
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        # collection_res = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        resultat = collection_doc.update_one(filtre, ops, upsert=True)

        # Sauvegarder dans les ressources aussi (va etre recopiee au besoin)
        collection_ressources = self.document_dao.get_collection(ConstantesPublication.COLLECTION_RESSOURCES)
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: datetime.datetime.utcnow(),
        }
        set_on_insert.update(identificateur_document)
        collection_ressources.update_one(identificateur_document, ops, upsert=True)

    def set_site_defaut(self, params: dict):
        site_id = params[ConstantesPublication.CHAMP_SITE_DEFAUT]

        # Sauvegarder dans la configuration de mapping
        collection_configuration = self.document_dao.get_collection(ConstantesPublication.COLLECTION_CONFIGURATION_NOM)
        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow(),
        }
        set_ops = {
            ConstantesPublication.CHAMP_SITE_DEFAUT: site_id,
        }
        ops = {
            '$set': set_ops,
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_MAPPING,
        }
        doc_mapping = collection_configuration.find_one_and_update(filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        # Invalider le mapping
        self.__gestionnaire_cascade.invalidateur.invalider_ressource_mapping()

        return doc_mapping

    def get_permission_privee(self, enveloppe_certificat: EnveloppeCertificat):
        """
        Retourne une permission signee pour dechiffrer du contenu prive dans le domaine Publication
        :param enveloppe_certificat:
        :return:
        """
        set_exchanges = set(enveloppe_certificat.get_exchanges)
        set_requis = set(Constantes.ConstantesSecurite.cascade_secure(Constantes.SECURITE_PRIVE))
        if len(set_exchanges.intersection(set_requis)) == 0:
            return {'ok': False, 'err': 'Permission refusee'}

        permission = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_DOMAINE: ConstantesPublication.DOMAINE_NOM,
            'roles_permis': ['Publication'],
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: 12 * 60 * 60,  # 12 heures

            # Indiquer que l'identificateur de documents doit contenir l'element securite = 2.prive
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                Constantes.DOCUMENT_INFODOC_SECURITE: Constantes.SECURITE_PRIVE,
            }
        }

        permission_signee = self.generateur_transactions.preparer_enveloppe(permission, 'permission', ajouter_certificats=True)

        return permission_signee


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

        # self._transmettre_maj(site_id)

        # commande = {
        #     ConstantesPublication.CHAMP_SITE_ID: site_id
        # }
        # self.ajouter_commande_a_transmettre('commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_SITE, commande)

        self.set_etape_suivante()  # Termine

        return {'site': doc_site}

    def _transmettre_maj(self, site_id: str):
        # Preparer evenement de confirmation, emission sur exchange 1.public
        site_config = self.controleur.gestionnaire.get_configuration_site({'site_id': site_id})

        # Retransmettre sur exchange 1.public pour maj live
        self.generateur_transactions.emettre_message(
            site_config,
            'evenement.Publication.' + ConstantesPublication.EVENEMENT_CONFIRMATION_MAJ_SITECONFIG,
            exchanges=[Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE],
            ajouter_certificats=True
        )


class ProcessusTransactionMajMapping(MGProcessusTransaction):

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction
        doc_mapping = self.controleur.gestionnaire.maj_mapping(transaction)

        self.set_etape_suivante()  # Termine

        return {'mapping': doc_mapping}


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
        type_section = doc_section[ConstantesPublication.CHAMP_TYPE_SECTION]

        # if type_section == 'pages':  # Fix label section => ConstantesPublication.LIBVAL_PAGE:
        #     # Traitement special pour publier une section de type page
        #     self.ajouter_commande_a_transmettre(
        #         'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_PAGE, commande)
        # else:
        #     self.ajouter_commande_a_transmettre(
        #         'commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_SECTIONS, commande)

        self.set_etape_suivante()  # Termine

        return {'section': doc_section}


class ProcessusTransactionMajPartiepage(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction

        # Verifier si on a _certificat ou si on doit l'ajouter
        partie_page = self.controleur.gestionnaire.maj_partie_page(transaction)

        # commande = {
        #     ConstantesPublication.CHAMP_SECTION_ID: partie_page[ConstantesPublication.CHAMP_SECTION_ID]
        # }
        # self.ajouter_commande_a_transmettre('commande.Publication.' + ConstantesPublication.COMMANDE_PUBLIER_PAGE, commande)

        self.set_etape_suivante()  # Termine

        return {'partie_page': partie_page}


class ProcessusSauvegarderCleIpns(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction
        identificateur_document = transaction['identificateur_document']
        self.controleur.gestionnaire.sauvegarder_cle_ipns(identificateur_document, transaction)

        self.set_etape_suivante()


class ProcessusSetSiteDefaut(MGProcessusTransaction):

    def initiale(self):
        transaction = self.transaction
        doc_mapping = self.controleur.gestionnaire.set_site_defaut(transaction)

        self.set_etape_suivante()

        return {
            'ok': True,
            'mapping': doc_mapping,
        }
