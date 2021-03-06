from pymongo.errors import DuplicateKeyError

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesPublication
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementRequetesProtegees, TraitementMessageDomaineRequete
from millegrilles.MGProcessus import MGProcessusTransaction

import logging
import uuid
import datetime
import json


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


class GestionnairePublication(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes_noeuds = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliquesPublication(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesPubliquesPublication(self)
        }

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def demarrer(self):
        super().demarrer()
        self.initialiser_document(Constantes.LIBVAL_CONFIGURATION, ConstantesPublication.DOCUMENT_DEFAUT)

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
        if domaine_action == ConstantesPublication.TRANSACTION_MAJ_SITE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajSite"
        elif domaine_action == ConstantesPublication.TRANSACTION_MAJ_POST:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPost"
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes_noeuds

    def get_nom_collection(self):
        return ConstantesPublication.COLLECTION_SITES_NOM

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

    def maj_site(self, transaction: dict):
        collection_site = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)

        try:
            site_id = transaction[ConstantesPublication.CHAMP_SITE_ID]
        except KeyError:
            # Par defaut le site id est l'identificateur unique de la transaction
            site_id = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID]

        self.__logger.debug("Maj site id: %s" % site_id)

        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesPublication.LIBVAL_SITE_CONFIG,
            ConstantesPublication.CHAMP_SITE_ID: site_id
        }

        set_on_insert = {
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: datetime.datetime.utcnow()
        }
        set_on_insert.update(filtre)

        # Nettoyer la transaction de champs d'index, copier le reste dans le document
        set_ops = dict()
        for key, value in transaction.items():
            if key not in [Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE, ConstantesPublication.CHAMP_SITE_ID] and \
                    key.startswith('_') is False:
                set_ops[key] = value

        ops = {
            '$setOnInsert': set_on_insert,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }
        if len(set_ops) > 0:
            ops['$set'] = set_ops

        resultat = collection_site.update_one(filtre, ops, upsert=True)

        if resultat.upserted_id is None and resultat.matched_count != 1:
            raise Exception("Erreur maj site " + site_id)

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


class ProcessusPublication(MGProcessusTransaction):

    def get_collection_transaction_nom(self):
        return ConstantesPublication.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesPublication.COLLECTION_PROCESSUS_NOM


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
        self.controleur.gestionnaire.maj_site(transaction)

        self._transmettre_maj(transaction['site_id'])

        self.set_etape_suivante()  # Termine

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