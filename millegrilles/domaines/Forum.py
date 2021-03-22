from millegrilles import Constantes
from millegrilles.Constantes import ConstantesForum
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, \
    TraitementMessageDomaineCommande, TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessusTransaction

import logging
import datetime


class TraitementRequetesPubliques(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesForum.REQUETE_FORUMS:
            reponse = self.gestionnaire.get_forums_publics(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_FORUM_POSTS:
            reponse = self.gestionnaire.get_forums_posts_publics(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_POSTS:
            reponse = self.gestionnaire.get_posts_publics(message_dict)
            reponse = {'resultats': reponse}
        else:
            reponse = {'err': 'Commande invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementRequetesPrivees(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesForum.REQUETE_FORUMS:
            reponse = self.gestionnaire.get_forums_prives(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_FORUM_POSTS:
            reponse = self.gestionnaire.get_forums_posts_prives(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_POSTS:
            reponse = self.gestionnaire.get_posts_prives(message_dict)
            reponse = {'resultats': reponse}
        else:
            reponse = {'err': 'Commande invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementRequetesProtegees(TraitementRequetesPrivees):

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if False:
            pass
        else:
            reponse = super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementCommandesPrivees(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        if action == ConstantesForum.COMMANDE_VOTER:
            resultat = self.gestionnaire.ajouter_vote(message_dict)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class TraitementCommandesForumProtegees(TraitementCommandesProtegees):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        if action == ConstantesForum.COMMANDE_VOTER:
            resultat = self.gestionnaire.ajouter_vote(message_dict)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class GestionnaireForum(GestionnaireDomaineStandard):

    def __init__(self, contexte):
        super().__init__(contexte)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

        self.__handler_requetes = {
            Constantes.SECURITE_PUBLIC: TraitementRequetesPubliques(self),
            Constantes.SECURITE_PRIVE: TraitementRequetesPrivees(self),
            Constantes.SECURITE_PROTEGE: TraitementRequetesProtegees(self)
        }

        self.__handler_commandes = {
            Constantes.SECURITE_PRIVE: TraitementCommandesPrivees(self),
            Constantes.SECURITE_PROTEGE: TraitementCommandesProtegees(self)
        }

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def demarrer(self):
        super().demarrer()

    def creer_index(self):
        pass
        # collection_sites = self.document_dao.get_collection(ConstantesPublication.COLLECTION_SITES_NOM)
        # collection_posts = self.document_dao.get_collection(ConstantesPublication.COLLECTION_POSTS_NOM)
        #
        # # Index _mg-libelle
        # collection_sites.create_index([(ConstantesPublication.CHAMP_SITE_ID, 1)], name='site_id')
        # collection_posts.create_index([(Constantes.DOCUMENT_INFODOC_LIBELLE, 1)], name='mglibelle')
        #
        # collection_sites.create_index([(ConstantesPublication.CHAMP_NOEUDS_URLS, 1)], name='noeuds_urls')

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

        # minutes = evenement['timestamp']['UTC'][4]
        #
        # if minutes % 15 == 3:
        #     self.resoumettre_conversions_manquantes()

    def identifier_processus(self, domaine_transaction):
        domaine_action = domaine_transaction.split('.').pop()
        if domaine_action == ConstantesForum.TRANSACTION_CREER_FORUM:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajSite"
        elif domaine_action == ConstantesForum.TRANSACTION_MODIFIER_FORUM:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPost"
        elif domaine_action == ConstantesForum.TRANSACTION_AJOUTER_POST:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPost"
        elif domaine_action == ConstantesForum.TRANSACTION_MODIFIER_POST:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPost"
        elif domaine_action == ConstantesForum.TRANSACTION_AJOUTER_COMMENTAIRE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPost"
        elif domaine_action == ConstantesForum.TRANSACTION_MODIFIER_COMMENTAIRE:
            processus = "millegrilles_domaines_Publication:ProcessusTransactionMajPost"
        else:
            # Type de transaction inconnue, on lance une exception
            processus = super().identifier_processus(domaine_transaction)

        return processus

    def get_handler_requetes(self) -> dict:
        return self.__handler_requetes

    def get_handler_commandes(self) -> dict:
        return self.__handler_commandes

    def get_nom_collection(self):
        return self.get_nom_collection_forums()

    def get_nom_collection_forums(self):
        return ConstantesForum.COLLECTION_FORUMS_NOM

    def get_nom_collection_posts(self):
        return ConstantesForum.COLLECTION_POSTS_NOM

    def get_nom_collection_forum_posts(self):
        return ConstantesForum.COLLECTION_FORUMS_POSTS_NOM

    def get_nom_collection_forum_commentaires(self):
        return ConstantesForum.COLLECTION_COMMENTAIRES_NOM

    def get_nom_collection_forum_votes(self):
        return ConstantesForum.COLLECTION_VOTES_NOM

    def get_nom_queue(self):
        return ConstantesForum.QUEUE_NOM

    def get_collection_transaction_nom(self):
        return ConstantesForum.COLLECTION_TRANSACTIONS_NOM

    def get_collection_processus_nom(self):
        return ConstantesForum.COLLECTION_PROCESSUS_NOM

    def get_nom_domaine(self):
        return ConstantesForum.DOMAINE_NOM

    def get_liste_forums(self):
        collection_site = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        curseur = collection_site.find()

        forums = list()
        for forum in curseur:
            del forum['_id']
            forums.append(forum)

        return forums


class ProcessusTransactionCreationForum(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction
        self.controleur.gestionnaire.creer_forum(transaction)

        self.set_etape_suivante()  # Termine

        return {'ok': True}

