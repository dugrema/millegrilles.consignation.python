import logging
import datetime
import pytz
import multibase
import gzip

from pymongo import ReturnDocument

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesSecurite, ConstantesForum, ConstantesGrosFichiers, ConstantesMaitreDesCles
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, \
    TraitementMessageDomaineCommande, TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessusTransaction, MGProcessus
from millegrilles.util.Chiffrage import CipherMsg2Chiffrer
from millegrilles.util.JSONMessageEncoders import JSONHelper
from millegrilles.SecuritePKI import EnveloppeCertificat


class TraitementRequetesPubliques(TraitementMessageDomaineRequete):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesForum.REQUETE_FORUMS:
            reponse = self.gestionnaire.get_forums_publics(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_FORUM_POSTS:
            reponse = self.gestionnaire.get_forum_posts(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_POST_COMMENTAIRES:
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

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesForum.REQUETE_FORUMS:
            message_dict['securite'] = Constantes.SECURITE_PRIVE
            reponse = self.gestionnaire.get_forums(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_FORUM_POSTS:
            message_dict['securite'] = Constantes.SECURITE_PRIVE
            reponse = self.gestionnaire.get_forums_posts(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_POST_COMMENTAIRES:
            message_dict['securite'] = Constantes.SECURITE_PRIVE
            reponse = self.gestionnaire.get_posts(message_dict)
            reponse = {'resultats': reponse}
        else:
            reponse = {'err': 'Commande invalide', 'routing_key': routing_key, 'domaine_action': domaine_action}
            self.transmettre_reponse(message_dict, reponse, properties.reply_to, properties.correlation_id)
            raise Exception("Requete publique non supportee " + routing_key)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementRequetesProtegees(TraitementRequetesPrivees):

    def traiter_requete(self, ch, method, properties, body, message_dict, enveloppe_certificat):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesForum.REQUETE_FORUMS:
            message_dict['securite'] = Constantes.SECURITE_PROTEGE
            reponse = self.gestionnaire.get_forums(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_FORUM_POSTS:
            message_dict['securite'] = Constantes.SECURITE_PROTEGE
            reponse = self.gestionnaire.get_forums_posts(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_POST_COMMENTAIRES:
            message_dict['securite'] = Constantes.SECURITE_PROTEGE
            reponse = self.gestionnaire.get_post_commentaires(message_dict)
            reponse = {'resultats': reponse}
        else:
            reponse = super().traiter_requete(ch, method, properties, body, message_dict)

        if reponse:
            self.transmettre_reponse(
                message_dict, reponse, properties.reply_to, properties.correlation_id, ajouter_certificats=True)


class TraitementCommandesPubliques(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        if action == ConstantesForum.COMMANDE_VOTER:
            resultat = self.gestionnaire.ajouter_vote(message_dict)
        elif action == ConstantesForum.COMMANDE_TRANSMETTRE_FORUMS_POSTS:
            message_dict['securite'] = Constantes.SECURITE_PUBLIC
            resultat = self.gestionnaire.transmettre_forums_posts(message_dict, properties)
        elif action == ConstantesForum.COMMANDE_TRANSMETTRE_POSTS_COMMENTAIRES:
            message_dict['securite'] = Constantes.SECURITE_PUBLIC
            resultat = self.gestionnaire.transmettre_posts_commentaires(message_dict, properties)
        else:
            resultat = super().traiter_commande(enveloppe_certificat, ch, method, properties, body, message_dict)

        return resultat


class TraitementCommandesPrivees(TraitementMessageDomaineCommande):

    def traiter_commande(self, enveloppe_certificat, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        action = routing_key.split('.')[-1]

        resultat: dict
        if action == ConstantesForum.COMMANDE_VOTER:
            resultat = self.gestionnaire.ajouter_vote(message_dict)
        elif action == ConstantesForum.COMMANDE_TRANSMETTRE_FORUMS_POSTS:
            message_dict['securite'] = Constantes.SECURITE_PRIVE
            resultat = self.gestionnaire.transmettre_forums_posts(message_dict, properties)
        elif action == ConstantesForum.COMMANDE_TRANSMETTRE_POSTS_COMMENTAIRES:
            message_dict['securite'] = Constantes.SECURITE_PRIVE
            resultat = self.gestionnaire.transmettre_posts_commentaires(message_dict, properties)
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
        elif action == ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS:
            # resultat = self.gestionnaire.generer_forums_posts(message_dict)
            self.gestionnaire.trigger_generer_forums_posts(message_dict, properties.reply_to, properties.correlation_id)
            resultat = None
        elif action == ConstantesForum.COMMANDE_GENERER_POSTS_COMMENTAIRES:
            # resultat = self.gestionnaire.generer_posts_comments(message_dict)
            self.gestionnaire.trigger_generer_posts_comments(message_dict, properties.reply_to, properties.correlation_id)
            resultat = None
        elif action == ConstantesForum.COMMANDE_TRANSMETTRE_FORUMS_POSTS:
            message_dict['securite'] = Constantes.SECURITE_PROTEGE
            resultat = self.gestionnaire.transmettre_forums_posts(message_dict, properties)
        elif action == ConstantesForum.COMMANDE_TRANSMETTRE_POSTS_COMMENTAIRES:
            message_dict['securite'] = Constantes.SECURITE_PROTEGE
            resultat = self.gestionnaire.transmettre_posts_commentaires(message_dict, properties)
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
            Constantes.SECURITE_PUBLIC: TraitementCommandesPubliques(self),
            Constantes.SECURITE_PRIVE: TraitementCommandesPrivees(self),
            Constantes.SECURITE_PROTEGE: TraitementCommandesForumProtegees(self)
        }

    def configurer(self):
        super().configurer()
        self.creer_index()  # Creer index dans MongoDB

    def demarrer(self):
        super().demarrer()

    def creer_index(self):
        collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        collection_forums.create_index([(ConstantesForum.CHAMP_FORUM_ID, 1)], name='ref_id', unique=True)
        collection_forums.create_index([(ConstantesForum.CHAMP_DIRTY_POSTS, 1)], name='dirty_posts')

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        collection_posts.create_index([(ConstantesForum.CHAMP_POST_ID, 1)], name='post_id', unique=True)
        collection_posts.create_index([(ConstantesForum.CHAMP_FORUM_ID, 1)], name='forum_id')
        collection_posts.create_index([(ConstantesForum.CHAMP_DIRTY_COMMENTS, 1)], name='dirty_comments')

        collection_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        collection_commentaires.create_index([(ConstantesForum.CHAMP_COMMENT_ID, 1)], name='comment_id', unique=True)
        collection_commentaires.create_index([(ConstantesForum.CHAMP_POST_ID, 1)], name='post_id')

        collection_forums_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_POSTS_NOM)
        collection_forums_posts.create_index(
            [(ConstantesForum.CHAMP_FORUM_ID, 1), (ConstantesForum.CHAMP_SORT_TYPE, 1)],
            name='forum_sorttype', unique=True
        )

        collection_posts_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_COMMENTAIRES_NOM)
        collection_posts_commentaires.create_index([(ConstantesForum.CHAMP_POST_ID, 1)], name='post_id', unique=True)

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

        minutes = evenement['timestamp']['UTC'][4]
        # if minutes % 15 == 3:
        # self.resoumettre_conversions_manquantes()
        self.trigger_generer_forums_posts(dict())
        self.trigger_generer_posts_comments(dict())

    def identifier_processus(self, domaine_transaction):
        domaine_action = domaine_transaction.split('.').pop()
        if domaine_action == ConstantesForum.TRANSACTION_CREER_FORUM:
            processus = "millegrilles_domaines_Forum:ProcessusTransactionCreationForum"
        elif domaine_action == ConstantesForum.TRANSACTION_MODIFIER_FORUM:
            processus = "millegrilles_domaines_Forum:ProcessusTransactionModifierForum"
        elif domaine_action == ConstantesForum.TRANSACTION_AJOUTER_POST:
            processus = "millegrilles_domaines_Forum:ProcessusTransactionAjouterPost"
        elif domaine_action == ConstantesForum.TRANSACTION_MODIFIER_POST:
            processus = "millegrilles_domaines_Forum:ProcessusTransactionModifierPost"
        elif domaine_action == ConstantesForum.TRANSACTION_AJOUTER_COMMENTAIRE:
            processus = "millegrilles_domaines_Forum:ProcessusTransactionAjouterCommentaire"
        elif domaine_action == ConstantesForum.TRANSACTION_MODIFIER_COMMENTAIRE:
            processus = "millegrilles_domaines_Forum:ProcessusTransactionModifierCommentaire"
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

    def get_post(self, post_id) -> dict:
        filtre = {ConstantesForum.CHAMP_POST_ID: post_id}
        collection_post = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        post = collection_post.find_one(filtre)
        return post

    def get_commentaire(self, commentaire_id) -> dict:
        filtre = {ConstantesForum.CHAMP_COMMENT_ID: commentaire_id}
        collection_comment = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        comment = collection_comment.find_one(filtre)
        return comment

    def get_forums(self, params: dict):
        niveaux_securite = ConstantesSecurite.cascade_public(params['securite']) or Constantes.SECURITE_PUBLIC
        filtre = {
            Constantes.DOCUMENT_INFODOC_SECURITE: {'$in': niveaux_securite}
        }
        collection_site = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        curseur = collection_site.find(filtre)

        forums = list()
        for forum in curseur:
            for key in list(forum.keys()):
                if key.startswith('_'):
                    del forum[key]
            forums.append(forum)

        return forums

    def get_forum(self, forum_id: str):
        collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        filtre = {ConstantesForum.CHAMP_FORUM_ID: forum_id}
        return collection_forums.find_one(filtre)

    def get_forums_posts(self, params: dict):
        forum_id = params[ConstantesForum.CHAMP_FORUM_ID]
        ordre_tri = params[ConstantesForum.CHAMP_SORT_TYPE]
        niveaux_securite = params['securite'] or Constantes.SECURITE_PUBLIC

        forum = self.get_forum(forum_id)
        if forum is None:
            return {'ok': False, 'err': "Forum non trouve"}

        securite_forum = forum[Constantes.DOCUMENT_INFODOC_SECURITE]

        if securite_forum not in ConstantesSecurite.cascade_public(niveaux_securite):
            return {'ok': False, 'err': 'Niveau securite insuffisant'}

        filtre = {
            ConstantesForum.CHAMP_FORUM_ID: forum_id,
            ConstantesForum.CHAMP_SORT_TYPE: ordre_tri,
        }
        collection_forums_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_POSTS_NOM)
        doc_forum_posts = collection_forums_posts.find_one(filtre)

        try:
            del doc_forum_posts['_id']
        except TypeError:
            # Aucun forum post, probablement un nouveau forum
            doc_forum_posts = dict()

        return doc_forum_posts

    def get_post_commentaires(self, params: dict):
        post_id = params[ConstantesForum.CHAMP_POST_ID]
        niveaux_securite = params['securite'] or Constantes.SECURITE_PUBLIC

        filtre = {
            ConstantesForum.CHAMP_POST_ID: post_id,
        }
        collection_post_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_COMMENTAIRES_NOM)
        doc_post_commentaires = collection_post_commentaires.find_one(filtre)

        if doc_post_commentaires is None:
            # Tenter de faire genrer le post, si applicable
            self.trigger_generer_posts_comments({ConstantesForum.CHAMP_POST_IDS: [post_id]})
            return {'ok': False, 'err': "Post id inconnu"}

        del doc_post_commentaires['_id']
        del doc_post_commentaires[Constantes.DOCUMENT_INFODOC_LIBELLE]

        # Verification de securite (acces)
        try:
            forum_id = doc_post_commentaires[ConstantesForum.CHAMP_FORUM_ID]
        except KeyError:
            collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
            post_doc = collection_posts.find_one({ConstantesForum.CHAMP_POST_ID: post_id})
            forum_id = post_doc[ConstantesForum.CHAMP_FORUM_ID]

        forum = self.get_forum(forum_id)
        securite_forum = forum[Constantes.DOCUMENT_INFODOC_SECURITE]

        if securite_forum not in ConstantesSecurite.cascade_public(niveaux_securite):
            return {'ok': False, 'err': 'Niveau securite insuffisant'}

        return doc_post_commentaires

    def creer_forum(self, params: dict):
        uuid_transaction = params['en-tete']['uuid_transaction']
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())
        forum = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_FORUM,
            Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
            Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: date_courante,

            ConstantesForum.CHAMP_FORUM_ID: uuid_transaction,
            'securite': Constantes.SECURITE_PROTEGE,
        }
        collection_site = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)

        resultat = collection_site.insert_one(forum)
        if resultat.acknowledged is not True:
            return {'ok': False, 'err': 'Echec ajout document de forum'}

        # Transmettre transaction pour creer une collection "grosfichiers" pour les fichiers du forum
        domaine_action = ConstantesGrosFichiers.TRANSACTION_NOUVELLE_COLLECTION
        transaction_creer_collection = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: uuid_transaction,
            ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION: uuid_transaction,
            ConstantesGrosFichiers.DOCUMENT_UUID_PARENT: ConstantesGrosFichiers.LIBVAL_UUID_COLLECTION_FORUMS,
            ConstantesGrosFichiers.CHAMP_CREER_PARENT: True,
        }
        self.generateur_transactions.soumettre_transaction(transaction_creer_collection, domaine_action)

        # Trigger creation du forumPosts
        commande = {ConstantesForum.CHAMP_FORUM_IDS: [uuid_transaction]}
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS
        self.generateur_transactions.transmettre_commande(commande, domaine_action)

        # Emettre evenement de modification de forums
        domaine_action = 'Forum.' + ConstantesForum.EVENEMENT_MAJ_FORUMS
        exchanges = ConstantesSecurite.cascade_protege(Constantes.SECURITE_PROTEGE)
        self.generateur_transactions.emettre_message(
            forum, 'evenement.' + domaine_action, domaine_action=domaine_action, exchanges=exchanges)

        return {'ok': True, 'forum': forum}

    def maj_forum(self, params: dict):
        ref_id = params[ConstantesForum.CHAMP_FORUM_ID]

        champs_supportes = [
            ConstantesForum.CHAMP_NOM_FORUM,
            ConstantesForum.CHAMP_LANGUE_FORUM,
            ConstantesForum.CHAMP_DESCRIPTION_FORUM,
            Constantes.DOCUMENT_INFODOC_SECURITE,
        ]

        # Transferer les valeurs a modifier en fonction de la liste de champs supportes
        set_ops = dict()
        for key in params:
            if key in champs_supportes:
                set_ops[key] = params[key]

        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True}
        }

        filtre = {
            ConstantesForum.CHAMP_FORUM_ID: ref_id,
        }

        collection_site = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        doc_forum = collection_site.find_one_and_update(filtre, ops, return_document=ReturnDocument.AFTER)

        if doc_forum is None:
            return {'ok': False, 'err': "Echec mise a jour, document non trouve : %s" % ref_id}

        # Maj de la collection de fichiers associee (securite et nom)
        transaction_maj_collection = {
            ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: ref_id,
            Constantes.DOCUMENT_INFODOC_SECURITE: doc_forum[Constantes.DOCUMENT_INFODOC_SECURITE],
            # ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION: doc_forum[ConstantesForum.CHAMP_NOM_FORUM],
        }
        if doc_forum.get(ConstantesForum.CHAMP_NOM_FORUM):
            transaction_maj_collection[ConstantesGrosFichiers.DOCUMENT_COLLECTION_NOMCOLLECTION] = doc_forum[ConstantesForum.CHAMP_NOM_FORUM]
        self.generateur_transactions.soumettre_transaction(transaction_maj_collection, 'GrosFichiers.' + ConstantesGrosFichiers.TRANSACTION_DECRIRE_COLLECTION)

        # Trigger maj du forumPost
        commande = {ConstantesForum.CHAMP_FORUM_IDS: [ref_id]}
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS
        self.generateur_transactions.transmettre_commande(commande, domaine_action)

        # Emettre evenement de modification de forums
        domaine_action = 'Forum.' + ConstantesForum.EVENEMENT_MAJ_FORUMS
        exchanges = ConstantesSecurite.cascade_protege(Constantes.SECURITE_PROTEGE)
        self.generateur_transactions.emettre_message(
            doc_forum, 'evenement.' + domaine_action, domaine_action=domaine_action, exchanges=exchanges)

        return {'ok': True, 'forum': doc_forum}

    # def creer_post(self, params: dict):
    #     uuid_transaction = params['en-tete']['uuid_transaction']

    def maj_post(self, params: dict):
        version_id = params['en-tete']['uuid_transaction']
        post_id = params.get(ConstantesForum.CHAMP_POST_ID) or version_id
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())
        user_id = params[ConstantesForum.CHAMP_USERID]

        entete = params[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        date_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        date_transaction = datetime.datetime.fromtimestamp(date_transaction, tz=pytz.utc)

        set_ops = {
            ConstantesForum.CHAMP_VERSION_ID: version_id,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_transaction,
        }

        champs_supportes = [
            # ConstantesForum.CHAMP_TYPE_POST, // setOnInsert
            ConstantesForum.CHAMP_TITRE,
            ConstantesForum.CHAMP_CONTENU,
            ConstantesForum.CHAMP_MEDIA_UUID,
            ConstantesForum.CHAMP_MEDIA_FUUID_PREVIEW,
            ConstantesForum.CHAMP_MEDIA_MIMETYPE_PREVIEW,
            ConstantesForum.CHAMP_MEDIA_FUUID_MEDIA,
            ConstantesForum.CHAMP_MEDIA_MIMETYPE_MEDIA,
            ConstantesForum.CHAMP_MEDIA_VIDEO,
            ConstantesForum.CHAMP_MEDIA_SECURITE,
        ]
        for key in params:
            if key in champs_supportes:
                set_ops[key] = params[key]

        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        filtre = {
            ConstantesForum.CHAMP_POST_ID: post_id,
        }

        if post_id == version_id:
            upsert = True
            ops['$setOnInsert'] = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_POST,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                ConstantesForum.CHAMP_POST_ID: version_id,
                ConstantesForum.CHAMP_FORUM_ID: params[ConstantesForum.CHAMP_FORUM_ID],
                ConstantesForum.CHAMP_TYPE_POST: params[ConstantesForum.CHAMP_TYPE_POST],
                ConstantesForum.CHAMP_USERID: params[ConstantesForum.CHAMP_USERID],
                ConstantesForum.CHAMP_DATE_CREATION: date_transaction,
            }
        else:
            # Empecher update d'un post si la transaction est plus vieille que la derniere
            # transaction a modifier le post.
            upsert = False  # Eviter de creer des doublons
            filtre[ConstantesForum.CHAMP_DATE_MODIFICATION] = {'$lt': date_transaction}

            # Valider que l'usager qui modifie le post est le meme qui l'a cree
            filtre[ConstantesForum.CHAMP_USERID] = user_id

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        post = collection_posts.find_one_and_update(
            filtre, ops, upsert=upsert,
            projection={ConstantesForum.CHAMP_FORUM_ID: True},
            return_document=ReturnDocument.AFTER
        )

        if post is None:
            return {'ok': False, 'err': 'Echec ajout post'}

        # Recuperer le forum_id du post - la transaction ne contient pas le forum_id sur update de post
        forum_id = post[ConstantesForum.CHAMP_FORUM_ID]

        # Associer fichier media au post (si applicable)
        if params.get(ConstantesForum.CHAMP_MEDIA_UUID):
            transaction_media_collection = {
                ConstantesGrosFichiers.DOCUMENT_FICHIER_UUID_DOC: forum_id,
                ConstantesGrosFichiers.DOCUMENT_COLLECTION_DOCS_UUIDS: [params[ConstantesForum.CHAMP_MEDIA_UUID]],
            }
            self.generateur_transactions.soumettre_transaction(
                transaction_media_collection,
                ConstantesGrosFichiers.TRANSACTION_AJOUTER_FICHIERS_COLLECTION
            )

        # Flag dirty sur forum
        filtre = {ConstantesForum.CHAMP_FORUM_ID: forum_id}
        ops = {'$set': {ConstantesForum.CHAMP_DIRTY_POSTS: True}}
        collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        collection_forums.update_one(filtre, ops)

        # Commande mise a jour forum posts et post comments
        commande = {ConstantesForum.CHAMP_FORUM_IDS: [forum_id]}
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS
        self.generateur_transactions.transmettre_commande(commande, domaine_action)

        commande = {ConstantesForum.CHAMP_POST_IDS: [post_id]}
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_POSTS_COMMENTAIRES
        self.generateur_transactions.transmettre_commande(commande, domaine_action)

        return {'ok': True}

    def maj_commentaire(self, params: dict):
        version_id = params['en-tete']['uuid_transaction']
        post_id = params.get(ConstantesForum.CHAMP_POST_ID)
        comment_id = params.get(ConstantesForum.CHAMP_COMMENT_ID) or version_id
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())
        user_id = params[ConstantesForum.CHAMP_USERID]

        entete = params[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        date_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        date_transaction = datetime.datetime.fromtimestamp(date_transaction, tz=pytz.utc)

        set_ops = {
            ConstantesForum.CHAMP_VERSION_ID: version_id,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_transaction,
        }

        champs_supportes = [
            ConstantesForum.CHAMP_CONTENU,
        ]
        for key in params:
            if key in champs_supportes:
                set_ops[key] = params[key]

        ops = {
            '$set': set_ops,
            '$currentDate': {Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION: True},
        }

        filtre = {
            ConstantesForum.CHAMP_COMMENT_ID: comment_id,
        }

        if comment_id == version_id:
            upsert = True
            ops['$setOnInsert'] = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_COMMENTAIRE,
                Constantes.DOCUMENT_INFODOC_DATE_CREATION: date_courante,
                ConstantesForum.CHAMP_POST_ID: post_id,
                ConstantesForum.CHAMP_COMMENT_ID: version_id,
                ConstantesForum.CHAMP_USERID: params[ConstantesForum.CHAMP_USERID],
                ConstantesForum.CHAMP_DATE_CREATION: date_transaction,
            }
            parent_id = params.get(ConstantesForum.CHAMP_COMMENT_PARENT_ID)
            if parent_id is not None:
                ops['$setOnInsert'][ConstantesForum.CHAMP_COMMENT_PARENT_ID] = parent_id
        else:
            # Empecher update d'un post si la transaction est plus vieille que la derniere
            # transaction a modifier le commentaire.
            upsert = False  # Eviter de creer des doublons
            filtre[ConstantesForum.CHAMP_DATE_MODIFICATION] = {'$lt': date_transaction}

            # Validation que l'usager qui modifie le commentaire est bien celui qui l'a emis
            filtre[ConstantesForum.CHAMP_USERID] = user_id

        collection_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        comment_doc = collection_commentaires.find_one_and_update(filtre, ops, upsert=upsert, return_document=ReturnDocument.AFTER)

        if comment_doc is None:
            return {'ok': False, 'err': 'Echec ajout post'}

        # Extraire le post id du commentaire (e.g. non fourni dans params sur maj)
        post_id = comment_doc[ConstantesForum.CHAMP_POST_ID]

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        filtre = {ConstantesForum.CHAMP_POST_ID: post_id}
        ops = {'$set': {ConstantesForum.CHAMP_DIRTY_COMMENTS: True}}
        collection_posts.update_one(filtre, ops, upsert=upsert)

        # Transmettre commande pour regenerer post
        commande_generer = {ConstantesForum.CHAMP_POST_IDS: [post_id]}
        domaine_action_generer = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_POSTS_COMMENTAIRES
        self.generateur_transactions.transmettre_commande(commande_generer, domaine_action_generer)

        return {'ok': True}

    def trigger_generer_forums_posts(self, params: dict, reply_to: str = None, correlation_id: str = None):
        params = params.copy()

        # Split les forum_ids, un processus par forum
        try:
            forum_ids = params[ConstantesForum.CHAMP_FORUM_IDS]
            del params[ConstantesForum.CHAMP_FORUM_IDS]
        except KeyError:
            # Faire aller chercher la liste de tous les forums
            collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
            projection = {ConstantesForum.CHAMP_FORUM_ID}
            filtre = {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_FORUM,
                ConstantesForum.CHAMP_DIRTY_POSTS: True,
            }
            curseur = collection_forums.find(filtre, projection=projection)
            forum_ids = [f[ConstantesForum.CHAMP_FORUM_ID] for f in curseur]

        if reply_to:
            params['reply_to'] = reply_to
        if correlation_id:
            params['correlation_id'] = correlation_id
        for forum_id in forum_ids:
            params[ConstantesForum.CHAMP_FORUM_ID] = forum_id
            self.demarrer_processus('millegrilles_domaines_Forum:ProcessusGenererForumsPosts', params)

    def trigger_generer_posts_comments(self, params: dict, reply_to: str = None, correlation_id: str = None):
        params = params.copy()
        try:
            post_ids = params[ConstantesForum.CHAMP_POST_IDS]
            del params[ConstantesForum.CHAMP_POST_IDS]
        except KeyError:
            collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
            projection = {ConstantesForum.CHAMP_POST_ID: True}
            try:
                forum_ids = params[ConstantesForum.CHAMP_FORUM_IDS]
                # Trouver les posts du forum et lancer un processus pour chaque
                filtre = {ConstantesForum.CHAMP_FORUM_ID: {'$in': forum_ids}}
                curseur_posts = collection_posts.find(filtre, projection)
            except KeyError:
                filtre = {ConstantesForum.CHAMP_DIRTY_COMMENTS: True}
                curseur_posts = collection_posts.find(filtre, projection)

            post_ids = [p[ConstantesForum.CHAMP_POST_ID] for p in curseur_posts]

        if reply_to:
            params['reply_to'] = reply_to
        if correlation_id:
            params['correlation_id'] = correlation_id
        for post_id in post_ids:
            params[ConstantesForum.CHAMP_POST_ID] = post_id
            self.demarrer_processus('millegrilles_domaines_Forum:ProcessusGenererPostsCommentaires', params)

    def extraire_usagers_forums_posts(self, params: dict) -> list:
        """
        Extrait tous les user_ids des posts d'un forum.
        :param params:
        :return:
        """
        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        filtre = {ConstantesForum.CHAMP_FORUM_ID: params[ConstantesForum.CHAMP_FORUM_ID]}
        projection = {ConstantesForum.CHAMP_USERID}
        curseur_posts = collection_posts.find(filtre, projection=projection)

        # Parcourir
        userids_set = set()
        for post in curseur_posts:
            user_id = post[ConstantesForum.CHAMP_USERID]
            userids_set.add(user_id)

        return list(userids_set)

    def extraire_usagers_posts_forums(self, params: dict) -> list:
        post_id = params[ConstantesForum.CHAMP_POST_ID]

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        filtre = {ConstantesForum.CHAMP_POST_ID: post_id}
        projection = {ConstantesForum.CHAMP_USERID}

        post = collection_posts.find_one(filtre, projection=projection)

        collection_comments = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        curseur_comments = collection_comments.find(filtre, projection)

        # Parcourir
        userids_set = set()
        userids_set.add(post[ConstantesForum.CHAMP_USERID])
        for comment in curseur_comments:
            user_id = comment[ConstantesForum.CHAMP_USERID]
            userids_set.add(user_id)

        return list(userids_set)

    def generer_forums_posts(self, params: dict, certs_chiffrage: dict = None, usagers: dict = None):
        """
        Generer les documents de metadonnees pour les forums.
        :param params:
        :return:
        """
        enveloppes_rechiffrage = dict()
        if certs_chiffrage is not None:
            # Preparer les certificats avec enveloppe, par fingerprint
            for cert in certs_chiffrage:
                enveloppe = EnveloppeCertificat(certificat_pem=cert)
                fp = enveloppe.fingerprint
                enveloppes_rechiffrage[fp] = enveloppe

        collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_FORUM,
            ConstantesForum.CHAMP_FORUM_ID: params[ConstantesForum.CHAMP_FORUM_ID],
        }

        forum = collection_forums.find_one(filtre)
        rk_evenement = 'evenement.Forum.' + ConstantesForum.EVENEMENT_MAJ_FORUM_POSTS
        securite_forum = forum[Constantes.DOCUMENT_INFODOC_SECURITE]
        exchanges = ConstantesSecurite.cascade_protege(securite_forum)

        document_forum_posts = self.generer_doc_forum(forum, params, enveloppes_rechiffrage, usagers)

        # Emettre document sous forme d'evenement
        del document_forum_posts['_id']
        self.generateur_transactions.emettre_message(
            document_forum_posts, rk_evenement, exchanges=exchanges)

        return {'ok': True}

    def generer_doc_forum(self, forum: dict, params, enveloppes_rechiffrage: dict = None, usagers: dict = None):
        forum_id = forum[ConstantesForum.CHAMP_FORUM_ID]
        nom_forum = forum.get(ConstantesForum.CHAMP_NOM_FORUM) or forum_id
        self.__logger.debug("Traitement posts du forum %s (%s)" % (nom_forum, forum_id))
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
        filtre_forum = {ConstantesForum.CHAMP_FORUM_ID: forum_id}
        form_doc = collection_forums.find_one(filtre_forum)
        securite_forum = form_doc[Constantes.DOCUMENT_INFODOC_SECURITE]

        champs_projection = [
            ConstantesForum.CHAMP_POST_ID,
            ConstantesForum.CHAMP_DATE_CREATION,
            ConstantesForum.CHAMP_DATE_MODIFICATION,
            ConstantesForum.CHAMP_TITRE,
            ConstantesForum.CHAMP_TYPE_POST,
            ConstantesForum.CHAMP_USERID,
            ConstantesForum.CHAMP_VERSION_ID,
            ConstantesForum.CHAMP_CONTENU,
            ConstantesForum.CHAMP_MEDIA_UUID,
            ConstantesForum.CHAMP_MEDIA_FUUID_PREVIEW,
            ConstantesForum.CHAMP_MEDIA_MIMETYPE_PREVIEW,
        ]

        # Genrer doc posts plus recent
        posts_plus_recents = list()
        filtre_forum = {
            ConstantesForum.CHAMP_FORUM_ID: forum[ConstantesForum.CHAMP_FORUM_ID],
        }
        sort = [(ConstantesForum.CHAMP_DATE_CREATION, -1)]
        limit = 500

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        posts = collection_posts.find(filtre_forum, projection=champs_projection, sort=sort, limit=limit)
        fuuids = set()
        for post in posts:
            # Mapper nom usager au user_id
            user_id = post[ConstantesForum.CHAMP_USERID]
            try:
                nom_usager = usagers[user_id][Constantes.ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
            except KeyError:
                nom_usager = user_id

            post_filtre = dict()
            post_filtre[ConstantesForum.CHAMP_USERID] = user_id
            post_filtre[ConstantesForum.CHAMP_NOM_USAGER] = nom_usager

            for key, value in post.items():
                if key in champs_projection:
                    post_filtre[key] = value
            posts_plus_recents.append(post_filtre)

            if post.get(ConstantesForum.CHAMP_MEDIA_FUUID_PREVIEW):
                fuuids.add(post[ConstantesForum.CHAMP_MEDIA_FUUID_PREVIEW])

        if securite_forum in [Constantes.SECURITE_PRIVE, Constantes.SECURITE_PROTEGE]:
            # Compresser (gzip) et chiffrer le contenu
            contenu = {
                ConstantesForum.CHAMP_NOM_FORUM: nom_forum,
                ConstantesForum.CHAMP_POSTS: posts_plus_recents,
            }
            identificateurs_documents = {
                'type': ConstantesForum.LIBVAL_FORUM_POSTS,
                'forum_id': forum_id,
            }
            contenu_chiffre, hachage_bytes = self.chiffrer_contenu(
                contenu, enveloppes_rechiffrage, identificateurs_documents)

            # On ajoute une permission de niveau prive pour tous les medias du forum
            fuuids = list(set(fuuids))  # Dedupe
            if hachage_bytes is not None:
                # Ajouter hachage du forum_post (contenu chiffre)
                fuuids.append(hachage_bytes)
            permission = {
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: fuuids,
                Constantes.DOCUMENT_INFODOC_SECURITE: securite_forum,
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: 10 * 365 * 24 * 60 * 60,  # 10 ans
            }
            permission = self.generateur_transactions.preparer_enveloppe(permission, ConstantesMaitreDesCles.REQUETE_PERMISSION)

        else:
            contenu_chiffre = None
            hachage_bytes = None
            permission = None

        # Signer le document
        document_forum_posts = {
            ConstantesForum.CHAMP_FORUM_ID: forum_id,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_courante,
            ConstantesForum.CHAMP_SORT_TYPE: 'plusRecent',
            Constantes.DOCUMENT_INFODOC_SECURITE: securite_forum,
        }

        unset = dict()
        if contenu_chiffre is not None:
            document_forum_posts['contenu_chiffre'] = contenu_chiffre
            document_forum_posts['hachage_bytes'] = hachage_bytes
            unset[ConstantesForum.CHAMP_NOM_FORUM] = True
            unset[ConstantesForum.CHAMP_POSTS] = True
        else:
            document_forum_posts[ConstantesForum.CHAMP_NOM_FORUM] = nom_forum
            document_forum_posts[ConstantesForum.CHAMP_POSTS] = posts_plus_recents
            unset['contenu_chiffre'] = True
            unset['hachage_bytes'] = True

        if permission is not None:
            document_forum_posts['permission'] = permission
        else:
            unset['permission'] = True

        document_forum_posts = self.generateur_transactions.preparer_enveloppe(
            document_forum_posts,
            domaine='Forum.' + ConstantesForum.LIBVAL_FORUM_POSTS,
            ajouter_certificats=True
        )

        filtre_forum = {
            ConstantesForum.CHAMP_FORUM_ID: forum_id,
            ConstantesForum.CHAMP_SORT_TYPE: ConstantesForum.TRI_PLUSRECENT,
        }
        ops = {
            '$set': document_forum_posts,
            '$unset': unset,
        }

        collection_forums_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_POSTS_NOM)
        forum_posts = collection_forums_posts.find_one_and_update(
            filtre_forum, ops, upsert=True, return_document=ReturnDocument.AFTER)

        # Set flag dirty sur le forum
        ops = {'$set': {ConstantesForum.CHAMP_DIRTY_POSTS: False}}
        collection_forums.update_one(filtre_forum, ops)

        return forum_posts

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

    def generer_posts_comments(self, params: dict, certs_chiffrage: dict = None, usagers: dict = None):
        post_id = params.get(ConstantesForum.CHAMP_POST_ID)

        enveloppes_rechiffrage = dict()
        if certs_chiffrage is not None:
            # Preparer les certificats avec enveloppe, par fingerprint
            for cert in certs_chiffrage:
                enveloppe = EnveloppeCertificat(certificat_pem=cert)
                fp = enveloppe.fingerprint
                enveloppes_rechiffrage[fp] = enveloppe

        # Routing key pour emettre maj d'un post
        rk_evenement = 'evenement.Forum.' + ConstantesForum.EVENEMENT_MAJ_POST_COMMENTS

        # Traitement par posts individuel
        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        post = collection_posts.find_one({ConstantesForum.CHAMP_POST_ID: post_id})

        forum = None
        if post.get(ConstantesForum.CHAMP_FORUM_ID):
            forum = self.get_forum(post[ConstantesForum.CHAMP_FORUM_ID])
        document_post_commentaires = self.generer_doc_post(post, params, enveloppes_rechiffrage, forum=forum, usagers=usagers)

        forum_id = post[ConstantesForum.CHAMP_FORUM_ID]
        if forum is None or forum_id != forum[ConstantesForum.CHAMP_FORUM_ID]:
            # Charger nouveau forum pour trouver le niveau de securite
            forum = self.get_forum(forum_id)

        exchanges = ConstantesSecurite.cascade_protege(forum[Constantes.DOCUMENT_INFODOC_SECURITE])

        # Emettre document sous forme d'evenement
        del document_post_commentaires['_id']
        self.generateur_transactions.emettre_message(
            document_post_commentaires, rk_evenement, exchanges=exchanges)

        return {'ok': True}

    def generer_doc_post(self, post: dict, params: dict, enveloppes_rechiffrage: dict, forum: dict = None, usagers: dict = None):

        post_id = post[ConstantesForum.CHAMP_POST_ID]
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)

        if forum is None:
            # Assumer qu'on a un post existant
            post = collection_posts.find({ConstantesForum.CHAMP_POST_ID: post_id})
            forum = self.get_forum(post[ConstantesForum.CHAMP_FORUM_ID])

        forum_id = forum[ConstantesForum.CHAMP_FORUM_ID]

        securite_forum = forum[Constantes.DOCUMENT_INFODOC_SECURITE]

        champs_post = [
            ConstantesForum.CHAMP_FORUM_ID,
            ConstantesForum.CHAMP_DATE_CREATION,
            # ConstantesForum.CHAMP_DATE_MODIFICATION,
            ConstantesForum.CHAMP_TITRE,
            ConstantesForum.CHAMP_TYPE_POST,
            ConstantesForum.CHAMP_USERID,
            ConstantesForum.CHAMP_VERSION_ID,
            ConstantesForum.CHAMP_CONTENU,
            ConstantesForum.CHAMP_MEDIA_UUID,
            ConstantesForum.CHAMP_MEDIA_FUUID_PREVIEW,
            ConstantesForum.CHAMP_MEDIA_MIMETYPE_PREVIEW,
            ConstantesForum.CHAMP_MEDIA_FUUID_MEDIA,
            ConstantesForum.CHAMP_MEDIA_MIMETYPE_MEDIA,
            ConstantesForum.CHAMP_MEDIA_VIDEO,
        ]

        champs_commentaires = [
            ConstantesForum.CHAMP_DATE_CREATION,
            ConstantesForum.CHAMP_DATE_MODIFICATION,
            ConstantesForum.CHAMP_USERID,
            ConstantesForum.CHAMP_CONTENU,
            ConstantesForum.CHAMP_COMMENT_ID,
        ]

        post_comments = {
            ConstantesForum.CHAMP_POST_ID: post_id,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_courante,
        }
        user_id = post[ConstantesForum.CHAMP_USERID]
        try:
            nom_usager = usagers[user_id][Constantes.ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
        except KeyError:
            nom_usager = user_id
        post_dict = {
            ConstantesForum.CHAMP_NOM_USAGER: nom_usager,
        }
        for key, value in post.items():
            if key in champs_post:
                post_dict[key] = value

        collection_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        filtre = {
            ConstantesForum.CHAMP_POST_ID: post_id,
        }
        ordre = [(ConstantesForum.CHAMP_DATE_CREATION, 1)]
        curseur_commentaires = collection_commentaires.find(filtre, sort=ordre, limit=1000)

        commentaires_par_id = dict()
        top_level_commentaires = list()
        post_dict[ConstantesForum.CHAMP_COMMENTAIRES] = top_level_commentaires

        for commentaire in curseur_commentaires:
            user_id = commentaire[ConstantesForum.CHAMP_USERID]
            try:
                nom_usager = usagers[user_id][Constantes.ConstantesMaitreDesComptes.CHAMP_NOM_USAGER]
            except KeyError:
                nom_usager = user_id

            try:
                # On a un placeholder, on va le remplir avec les valeurs reelles
                comment_dict = commentaires_par_id[commentaire[ConstantesForum.CHAMP_COMMENT_ID]]
            except KeyError:
                comment_dict = dict()
                # Conserver reference au commentaire pour inserer les sous-commentaires (hierarchie)
                commentaires_par_id[commentaire[ConstantesForum.CHAMP_COMMENT_ID]] = comment_dict

            comment_dict[ConstantesForum.CHAMP_NOM_USAGER] = nom_usager
            for key, value in commentaire.items():
                if key in champs_commentaires:
                    comment_dict[key] = value

            parent_id = commentaire.get(ConstantesForum.CHAMP_COMMENT_PARENT_ID)
            if parent_id is None:
                # Ajouter commentaire a la liste directe sous le post (top-level)
                top_level_commentaires.append(comment_dict)
            else:
                try:
                    parent_commentaire = commentaires_par_id[parent_id]
                except KeyError:
                    # Generer un placeholder
                    parent_commentaire = {ConstantesForum.CHAMP_COMMENTAIRES: list()}
                    commentaires_par_id[parent_id] = parent_commentaire

                try:
                    commentaires = parent_commentaire[ConstantesForum.CHAMP_COMMENTAIRES]
                except KeyError:
                    # Creer list sous-commentaires pour le parent
                    commentaires = list()
                    parent_commentaire[ConstantesForum.CHAMP_COMMENTAIRES] = commentaires

                # Inserer commentaire sous le parent
                commentaires.append(comment_dict)

        unset_ops = dict()
        if securite_forum in [Constantes.SECURITE_PROTEGE, Constantes.SECURITE_PRIVE]:
            fuuids = set()
            if post.get(ConstantesForum.CHAMP_MEDIA_FUUID_PREVIEW):
                fuuids.add(post[ConstantesForum.CHAMP_MEDIA_FUUID_PREVIEW])
            if post.get(ConstantesForum.CHAMP_MEDIA_UUID):
                fuuids.add(post[ConstantesForum.CHAMP_MEDIA_FUUID_MEDIA])
            if post.get(ConstantesForum.CHAMP_MEDIA_VIDEO):
                for vid in post[ConstantesForum.CHAMP_MEDIA_VIDEO].values():
                    fuuids.add(vid['fuuid'])

            # Chiffrer contenu post
            identificateurs_documents = {
                'type': ConstantesForum.LIBVAL_POST_COMMENTAIRES,
                'post_id': post_id,
            }
            contenu_chiffre, hachage_bytes = self.chiffrer_contenu(
                post_dict, enveloppes_rechiffrage, identificateurs_documents)

            post_comments['contenu_chiffre'] = contenu_chiffre
            post_comments['hachage_bytes'] = hachage_bytes

            unset_ops[ConstantesForum.CHAMP_COMMENTAIRES] = True
            for champ in champs_post:
                if champ not in [ConstantesForum.CHAMP_FORUM_ID]:
                    unset_ops[champ] = True

            # On ajoute une permission de niveau prive pour tous les medias du forum
            fuuids = list(set(fuuids))  # Dedupe
            if hachage_bytes is not None:
                # Ajouter hachage du forum_post (contenu chiffre)
                fuuids.append(hachage_bytes)
            permission = {
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_LISTE_HACHAGE_BYTES: fuuids,
                Constantes.DOCUMENT_INFODOC_SECURITE: securite_forum,
                ConstantesMaitreDesCles.TRANSACTION_CHAMP_DUREE_PERMISSION: 10 * 365 * 24 * 60 * 60,  # 10 ans
            }
            permission = self.generateur_transactions.preparer_enveloppe(permission, ConstantesMaitreDesCles.REQUETE_PERMISSION)

        else:
            unset_ops['contenu_chiffre'] = True
            unset_ops['hachage_bytes'] = True
            hachage_bytes = None
            permission = None
            post_comments.update(post_dict)
            fuuids = list()

        if permission is not None:
            post_comments['permission'] = permission
        else:
            unset_ops['permission'] = True

        post_comments[ConstantesForum.CHAMP_FORUM_ID] = forum_id

        # Signer le post
        post_comments = self.generateur_transactions.preparer_enveloppe(
            post_comments,
            domaine='Forum.' + ConstantesForum.LIBVAL_POST,
            ajouter_certificats=True
        )
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_POST_COMMENTAIRES,
            ConstantesForum.CHAMP_POST_ID: post_id,
        }

        ops = {
            '$set': post_comments,
            '$unset': unset_ops,
        }

        collection_post_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_COMMENTAIRES_NOM)
        post_commentaires = collection_post_commentaires.find_one_and_update(
            filtre, ops, upsert=True, return_document=ReturnDocument.AFTER)

        filtre = {ConstantesForum.CHAMP_POST_ID: post_id}
        ops = {'$set': {ConstantesForum.CHAMP_DIRTY_COMMENTS: False}}
        collection_posts.update_one(filtre, ops)

        return post_commentaires

    def transmettre_forums_posts(self, params: dict, properties):
        """
        Emet tous les forums posts correspondants aux params vers le demandeur
        au rythme d'un message par forum_posts.
        :param params:
        :param properties:
        :return:
        """
        filtre = {
            # Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_POST_COMMENTAIRES,
        }
        forum_ids = params.get(ConstantesForum.CHAMP_FORUM_IDS)
        if forum_ids is not None:
            filtre[ConstantesForum.CHAMP_FORUM_ID] = {'$in': forum_ids}

        collection_forums_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_POSTS_NOM)
        curseur = collection_forums_posts.find(filtre)

        # Emettre chaque forum_posts dans un message different vers le demandeur
        reply_to = properties.reply_to
        correlation_id = properties.correlation_id

        reponse_transmise = False

        for forum_posts in curseur:
            # Enlever metadata base de donnee
            del forum_posts['_id']
            # del forum_posts[Constantes.DOCUMENT_INFODOC_DATE_CREATION]
            # del forum_posts[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION]

            if reponse_transmise is False:
                # Liberer thread sur client, indiquer que les reponses vont etre emises
                self.generateur_transactions.transmettre_reponse(
                    {'ok': True, 'vide': False}, replying_to=reply_to, correlation_id=correlation_id)
                reponse_transmise = True

            # Emettre le message (il est deja formatte avec entete, _certificat et _signature)
            self.generateur_transactions.transmettre_reponse(
                forum_posts,
                replying_to=reply_to,
                correlation_id=ConstantesForum.LIBVAL_FORUM_POSTS,
                no_format=True
            )

        if reponse_transmise is False:
            # Liberer thread sur client, indiquer qu'on n'a aucun resultat a transmettre
            self.generateur_transactions.transmettre_reponse(
                {'ok': True, 'vide': True}, replying_to=reply_to, correlation_id=correlation_id)

    def transmettre_posts_commentaires(self, params: dict, properties):
        """
        Emet tous les post commentaires correspondants aux params vers le demandeur
        au rythme d'un message par forum_posts.
        :param params:
        :param properties:
        :return:
        """

        filtre = dict()
        forum_id = params.get(ConstantesForum.CHAMP_FORUM_ID)
        forum_ids = params.get(ConstantesForum.CHAMP_FORUM_IDS)
        post_ids = params.get(ConstantesForum.CHAMP_POST_IDS)
        if forum_ids is not None:
            filtre[ConstantesForum.CHAMP_FORUM_ID] = {'$in': forum_ids}
        if forum_id is not None:
            filtre[ConstantesForum.CHAMP_FORUM_ID] = forum_id
        if post_ids is not None:
            filtre[ConstantesForum.CHAMP_POST_ID] = {'$in': post_ids}

        collection_posts_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_COMMENTAIRES_NOM)
        curseur = collection_posts_commentaires.find(filtre)

        # Emettre chaque forum_posts dans un message different vers le demandeur
        reply_to = properties.reply_to
        correlation_id = properties.correlation_id

        reponse_transmise = False

        for post_commentaires in curseur:
            # Enlever metadata base de donnee
            del post_commentaires['_id']
            # del forum_posts[Constantes.DOCUMENT_INFODOC_DATE_CREATION]
            # del forum_posts[Constantes.DOCUMENT_INFODOC_DERNIERE_MODIFICATION]

            if reponse_transmise is False:
                # Liberer thread sur client, indiquer que les reponses vont etre emises
                self.generateur_transactions.transmettre_reponse(
                    {'ok': True, 'vide': False}, replying_to=reply_to, correlation_id=correlation_id)
                reponse_transmise = True

            # Emettre le message (il est deja formatte avec entete, _certificat et _signature)
            self.generateur_transactions.transmettre_reponse(
                post_commentaires,
                replying_to=reply_to,
                correlation_id=ConstantesForum.LIBVAL_POST_COMMENTAIRES,
                no_format=True,
            )

        if reponse_transmise is False:
            # Liberer thread sur client, indiquer qu'on n'a aucun resultat a transmettre
            self.generateur_transactions.transmettre_reponse(
                {'ok': True, 'vide': True}, replying_to=reply_to, correlation_id=correlation_id)


class ProcessusTransactionCreationForum(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def verifier_autorisation(self):
        """
        S'assurer que l'usager a un acces 3.protege
        :param certificat:
        :return:
        """
        certificat = self.certificat
        niveaux_securite = certificat.get_exchanges

        if Constantes.SECURITE_PROTEGE not in niveaux_securite and Constantes.SECURITE_SECURE not in niveaux_securite:
            self.__logger.error("ProcessusTransactionCreationForum: Usager n'a pas le niveau securite 3.protege")
            return False

        return True

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction
        reponse = self.controleur.gestionnaire.creer_forum(transaction)

        self.set_etape_suivante()  # Termine

        return reponse


class ProcessusTransactionModifierForum(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def verifier_autorisation(self):
        """
        S'assurer que l'usager a un acces 3.protege
        :param certificat:
        :return:
        """
        certificat = self.certificat
        niveaux_securite = certificat.get_exchanges

        if Constantes.SECURITE_PROTEGE not in niveaux_securite and Constantes.SECURITE_SECURE not in niveaux_securite:
            self.__logger.error("ProcessusTransactionCreationForum: Usager n'a pas le niveau securite 3.protege")
            return False

        return True

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction
        reponse = self.controleur.gestionnaire.maj_forum(transaction)

        self.set_etape_suivante()  # Termine

        return reponse


class ProcessusTransactionPost(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def verifier_autorisation(self):
        """
        S'assurer que l'usager correspond au userId de la transaction
        :param certificat:
        :return:
        """
        transaction = self.transaction
        certificat = self.certificat

        niveaux_securite = certificat.get_exchanges
        if ConstantesSecurite.verifier_minimum(Constantes.SECURITE_PRIVE, niveaux_securite) is False:
            self.__logger.error("L'usager n'a pas un certificat de niveau prive ou plus secure")
            return False

        if transaction.get(ConstantesForum.CHAMP_POST_ID) is None:
            # La transaction est un nouveau post. Un usager prive peut creer un nouveau post.
            return True
        else:
            # Verifier si l'usager est l'originateur du post
            user_id = certificat.get_user_id

            post_id = transaction[ConstantesForum.CHAMP_POST_ID]
            post = self.controleur.gestionnaire.get_post(post_id)
            post_user_id = post[ConstantesForum.CHAMP_USERID]

            if user_id != post_user_id:
                self.__logger.error("User %s ne correspond pas au user_id dans le post (%s)" % (user_id, post_user_id))
                return False

        return True


class ProcessusTransactionCommentaire(MGProcessusTransaction):

    def __init__(self, controleur, evenement, transaction_mapper=None):
        super().__init__(controleur, evenement, transaction_mapper)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def verifier_autorisation(self):
        """
        S'assurer que l'usager correspond au userId de la transaction
        :param certificat:
        :return:
        """
        transaction = self.transaction
        certificat = self.certificat

        niveaux_securite = certificat.get_exchanges
        if ConstantesSecurite.verifier_minimum(Constantes.SECURITE_PRIVE, niveaux_securite) is False:
            self.__logger.error("L'usager n'a pas un certificat de niveau prive ou plus secure")
            return False

        if transaction.get(ConstantesForum.CHAMP_COMMENT_ID) is None:
            # La transaction est un nouveau post. Un usager prive peut creer un nouveau post.
            return True
        else:
            # Verifier si l'usager est l'originateur du post
            user_id = certificat.get_user_id

            commentaire_id = transaction[ConstantesForum.CHAMP_COMMENT_ID]
            comment = self.controleur.gestionnaire.get_commentaire(commentaire_id)
            comment_user_id = comment.get(ConstantesForum.CHAMP_USERID)

            if comment_user_id is not None and user_id != comment_user_id:
                self.__logger.error("User %s ne correspond pas au user_id dans le commentaire (%s)" % (user_id, comment_user_id))
                return False

        return True


class ProcessusTransactionAjouterPost(ProcessusTransactionPost):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction

        # Injecter userId a partir du certificat
        certificat = self.certificat
        transaction[ConstantesForum.CHAMP_USERID] = certificat.get_user_id

        reponse = self.controleur.gestionnaire.maj_post(transaction)

        if transaction.get(ConstantesForum.CHAMP_MEDIA_UUID) is not None:
            # On a un media - demander publication de la collection de fichiers du forum
            commande_publier_fichiers = {
                ConstantesForum.CHAMP_FORUM_ID: transaction[ConstantesForum.CHAMP_FORUM_ID],
                'fuuids': [transaction[ConstantesForum.CHAMP_MEDIA_FUUID_MEDIA]],
            }

            domaine_action = 'commande.Publication.' + Constantes.ConstantesPublication.COMMANDE_PUBLIER_FICHIERS_FORUM
            self.ajouter_commande_a_transmettre(domaine_action, commande_publier_fichiers, blocking=True)
            self.set_etape_suivante(ProcessusTransactionAjouterPost.attendre_publication.__name__)
        else:
            self.set_etape_suivante()  # Termine

        return reponse

    def attendre_publication(self):

        self.set_etape_suivante()  # Termine
        return {'ok': True, 'publication': True}


class ProcessusTransactionModifierPost(ProcessusTransactionPost):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction

        certificat = self.certificat
        transaction[ConstantesForum.CHAMP_USERID] = certificat.get_user_id

        reponse = self.controleur.gestionnaire.maj_post(transaction)

        self.set_etape_suivante()  # Termine

        return reponse


class ProcessusTransactionAjouterCommentaire(ProcessusTransactionCommentaire):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction

        # Injecter userId a partir du certificat
        certificat = self.certificat
        transaction[ConstantesForum.CHAMP_USERID] = certificat.get_user_id

        reponse = self.controleur.gestionnaire.maj_commentaire(transaction)

        self.set_etape_suivante()  # Termine

        return reponse


class ProcessusTransactionModifierCommentaire(ProcessusTransactionCommentaire):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction

        certificat = self.certificat
        transaction[ConstantesForum.CHAMP_USERID] = certificat.get_user_id

        reponse = self.controleur.gestionnaire.maj_commentaire(transaction)

        self.set_etape_suivante()  # Termine

        return reponse


class ProcessusGenererForumsPosts(MGProcessus):

    def initiale(self):
        # Requete pour maitre des cles
        self.set_requete('MaitreDesCles.' + ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES, dict())
        self.set_etape_suivante(ProcessusGenererForumsPosts.identifier_usagers.__name__)

    def identifier_usagers(self):
        params = self.parametres
        usagers = self.controleur.gestionnaire.extraire_usagers_forums_posts(params)

        # Faire requete pour recuperer nom usagers par user_id
        requete = {
            Constantes.ConstantesMaitreDesComptes.CHAMP_LIST_USERIDS: usagers
        }
        domaine_action = 'MaitreDesComptes.' + Constantes.ConstantesMaitreDesComptes.REQUETE_LISTE_USAGERS
        self.set_requete(domaine_action, requete)

        self.set_etape_suivante(ProcessusGenererForumsPosts.generer_forums_posts.__name__)

    def generer_forums_posts(self):
        params = self.parametres
        reponse_requete_certs = params['reponse'][0]

        # Creer dict usagers par user_id
        usagers = dict()
        for usager in params['reponse'][1]['usagers']:
            user_id = usager[Constantes.ConstantesMaitreDesComptes.CHAMP_USER_ID]
            usagers[user_id] = usager

        certs = [
            reponse_requete_certs['certificat'],
            reponse_requete_certs['certificat_millegrille'],
        ]
        self.controleur.gestionnaire.generer_forums_posts(params, certs, usagers)

        self.set_etape_suivante()  # Termine


class ProcessusGenererPostsCommentaires(MGProcessus):

    def initiale(self):
        # Requete pour maitre des cles
        self.set_requete('MaitreDesCles.' + ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES, dict())
        self.set_etape_suivante(ProcessusGenererPostsCommentaires.identifier_usagers.__name__)

    def identifier_usagers(self):
        params = self.parametres
        usagers = self.controleur.gestionnaire.extraire_usagers_posts_forums(params)

        # Faire requete pour recuperer nom usagers par user_id
        requete = {
            Constantes.ConstantesMaitreDesComptes.CHAMP_LIST_USERIDS: usagers
        }
        domaine_action = 'MaitreDesComptes.' + Constantes.ConstantesMaitreDesComptes.REQUETE_LISTE_USAGERS
        self.set_requete(domaine_action, requete)

        self.set_etape_suivante(ProcessusGenererPostsCommentaires.generer_posts_commentaires.__name__)

    def generer_posts_commentaires(self):
        params = self.parametres
        reponse_requete_certs = params['reponse'][0]

        # Creer dict usagers par user_id
        usagers = dict()
        for usager in params['reponse'][1]['usagers']:
            user_id = usager[Constantes.ConstantesMaitreDesComptes.CHAMP_USER_ID]
            usagers[user_id] = usager

        certs = [
            reponse_requete_certs['certificat'],
            reponse_requete_certs['certificat_millegrille'],
        ]
        self.controleur.gestionnaire.generer_posts_comments(params, certs, usagers)

        self.set_etape_suivante()  # Termine
