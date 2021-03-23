import logging
import datetime
import pytz

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesSecurite, ConstantesForum
from millegrilles.Domaines import GestionnaireDomaineStandard, TraitementMessageDomaineRequete, \
    TraitementMessageDomaineCommande, TraitementCommandesProtegees
from millegrilles.MGProcessus import MGProcessusTransaction


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
            message_dict['securite'] = Constantes.SECURITE_PRIVE
            reponse = self.gestionnaire.get_forums(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_FORUM_POSTS:
            message_dict['securite'] = Constantes.SECURITE_PRIVE
            reponse = self.gestionnaire.get_forums_posts(message_dict)
            reponse = {'resultats': reponse}
        elif domaine_action == ConstantesForum.REQUETE_POSTS:
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

    def traiter_requete(self, ch, method, properties, body, message_dict):
        routing_key = method.routing_key
        domaine_action = routing_key.split('.').pop()

        if domaine_action == ConstantesForum.REQUETE_FORUMS:
            message_dict['securite'] = Constantes.SECURITE_PROTEGE
            reponse = self.gestionnaire.get_forums(message_dict)
            reponse = {'resultats': reponse}
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
        elif action == ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS:
            resultat = self.gestionnaire.generer_forums_posts(message_dict)
        elif action == ConstantesForum.COMMANDE_GENERER_POSTS_COMMENTAIRES:
            resultat = self.gestionnaire.generer_posts_comments(message_dict)
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

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        collection_posts.create_index([(ConstantesForum.CHAMP_POST_ID, 1)], name='post_id', unique=True)
        collection_posts.create_index([(ConstantesForum.CHAMP_FORUM_ID, 1)], name='forum_id')

        collection_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        collection_commentaires.create_index([(ConstantesForum.CHAMP_COMMENT_ID, 1)], name='comment_id', unique=True)
        collection_commentaires.create_index([(ConstantesForum.CHAMP_POST_ID, 1)], name='post_id')

    def traiter_cedule(self, evenement):
        super().traiter_cedule(evenement)

        # minutes = evenement['timestamp']['UTC'][4]
        #
        # if minutes % 15 == 3:
        #     self.resoumettre_conversions_manquantes()

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

        return {'ok': True}

    def maj_forum(self, params: dict):
        ref_id = params[ConstantesForum.CHAMP_FORUM_ID]

        champs_supportes = [
            ConstantesForum.CHAMP_NOM_FORUM,
            ConstantesForum.CHAMP_LANGUE_FORUM,
            ConstantesForum.CHAMP_DESCRIPTION_FORUM,
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
        resultats = collection_site.update_one(filtre, ops)

        if resultats.modified_count != 1:
            return {'ok': False, 'err': "Echec mise a jour, document non trouve"}

        return {'ok': True}

    # def creer_post(self, params: dict):
    #     uuid_transaction = params['en-tete']['uuid_transaction']

    def maj_post(self, params: dict):
        version_id = params['en-tete']['uuid_transaction']
        post_id = params.get(ConstantesForum.CHAMP_POST_ID) or version_id
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        entete = params[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        date_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        date_transaction = datetime.datetime.fromtimestamp(date_transaction, tz=pytz.utc)

        set_ops = {
            ConstantesForum.CHAMP_VERSION_ID: version_id,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_transaction,
            ConstantesForum.CHAMP_DIRTY: True,
        }

        champs_supportes = [
            ConstantesForum.CHAMP_TITRE,
            ConstantesForum.CHAMP_CONTENU,
            ConstantesForum.CHAMP_MEDIA_PREVIEW,
            ConstantesForum.CHAMP_IMG,
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

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        resultat = collection_posts.update_one(filtre, ops, upsert=upsert)

        modified_count = resultat.modified_count
        upserted_id = resultat.upserted_id
        if modified_count == 0 and upserted_id is None:
            return {'ok': False, 'err': 'Echec ajout post'}

        return {'ok': True}

    def maj_commentaire(self, params: dict):
        version_id = params['en-tete']['uuid_transaction']
        comment_id = params.get(ConstantesForum.CHAMP_COMMENT_ID) or version_id
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        entete = params[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE]
        date_transaction = entete[Constantes.TRANSACTION_MESSAGE_LIBELLE_ESTAMPILLE]
        date_transaction = datetime.datetime.fromtimestamp(date_transaction, tz=pytz.utc)

        set_ops = {
            ConstantesForum.CHAMP_VERSION_ID: version_id,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_transaction,
            ConstantesForum.CHAMP_DIRTY: True,
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
                ConstantesForum.CHAMP_POST_ID: params[ConstantesForum.CHAMP_POST_ID],
                ConstantesForum.CHAMP_COMMENT_ID: version_id,
                ConstantesForum.CHAMP_USERID: params[ConstantesForum.CHAMP_USERID],
                ConstantesForum.CHAMP_DATE_CREATION: date_transaction,
            }
        else:
            # Empecher update d'un post si la transaction est plus vieille que la derniere
            # transaction a modifier le commentaire.
            upsert = False  # Eviter de creer des doublons
            filtre[ConstantesForum.CHAMP_DATE_MODIFICATION] = {'$lt': date_transaction}

        collection_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        resultat = collection_commentaires.update_one(filtre, ops, upsert=upsert)

        modified_count = resultat.modified_count
        upserted_id = resultat.upserted_id
        if modified_count == 0 and upserted_id is None:
            return {'ok': False, 'err': 'Echec ajout post'}

        return {'ok': True}

    def generer_forums_posts(self, params: dict):
        """
        Generer les documents de metadonnees pour les forums.
        :param params:
        :return:
        """

        # Si la liste de forum est None, indique qu'on fait tous les forums
        forum_list = params.get('forum_list') or None

        # Si dirty_only==True, on skip les forums qui n'ont pas de posts/comments qui sont dirty
        dirty_only = params.get('dirty_only') or False

        collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)

        curseur_forum = collection_forums.find({Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_FORUM})
        for forum in curseur_forum:
            self.generer_doc_forum(forum, params)

        return {'ok': True}

    def generer_doc_forum(self, forum: dict, params):
        forum_id = forum[ConstantesForum.CHAMP_FORUM_ID]
        nom_forum = forum.get(ConstantesForum.CHAMP_NOM_FORUM) or forum_id
        self.__logger.debug("Traitement posts du forum %s (%s)" % (nom_forum, forum_id))
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        champs_projection = [
            ConstantesForum.CHAMP_POST_ID,
            ConstantesForum.CHAMP_DATE_CREATION,
            ConstantesForum.CHAMP_DATE_MODIFICATION,
            ConstantesForum.CHAMP_TITRE,
            ConstantesForum.CHAMP_TYPE_POST,
            ConstantesForum.CHAMP_USERID,
            ConstantesForum.CHAMP_VERSION_ID,
            ConstantesForum.CHAMP_MEDIA_PREVIEW,
        ]

        # Genrer doc posts plus recent
        posts_plus_recents = list()
        filtre = {
            ConstantesForum.CHAMP_FORUM_ID: forum[ConstantesForum.CHAMP_FORUM_ID],
        }
        sort = [(ConstantesForum.CHAMP_DATE_CREATION, -1)]
        limit = 100

        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)
        posts = collection_posts.find(filtre, projection=champs_projection, sort=sort, limit=limit)
        for post in posts:
            post_filtre = dict()
            for key, value in post.items():
                if key in champs_projection:
                    post_filtre[key] = value
            posts_plus_recents.append(post_filtre)

        # Signer le document
        document_forum_posts = {
            ConstantesForum.CHAMP_FORUM_ID: forum_id,
            ConstantesForum.CHAMP_NOM_FORUM: nom_forum,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_courante,
            ConstantesForum.CHAMP_POSTS: posts_plus_recents,
            ConstantesForum.CHAMP_SORT_TYPE: 'plusRecent',
        }
        document_forum_posts = self.generateur_transactions.preparer_enveloppe(
            document_forum_posts,
            domaine='Forum.' + ConstantesForum.LIBVAL_FORUM_POSTS,
            ajouter_certificats=True
        )

        filtre = {
            ConstantesForum.CHAMP_FORUM_ID: forum_id,
            ConstantesForum.CHAMP_SORT_TYPE: 'plusRecent',
        }
        ops = {
            '$set': document_forum_posts,
        }

        collection_forums_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_POSTS_NOM)
        resultat = collection_forums_posts.update_one(filtre, ops, upsert=True)

        modified_count = resultat.modified_count
        upserted_id = resultat.upserted_id
        if modified_count == 0 and upserted_id is None:
            raise Exception("Erreur creation document forums posts")

    def generer_posts_comments(self, params: dict):
        collection_posts = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_NOM)

        forum_id = params.get(ConstantesForum.CHAMP_FORUM_ID)
        if forum_id is None:
            collection_forums = self.document_dao.get_collection(ConstantesForum.COLLECTION_FORUMS_NOM)
            filtre = {Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_FORUM}
            curseur_forums = collection_forums.find(filtre)
            forum_ids = [forum[ConstantesForum.CHAMP_FORUM_ID] for forum in curseur_forums]
        else:
            forum_ids = [forum_id]

        for forum_id in forum_ids:
            curseur_posts = collection_posts.find({
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_POST,
                ConstantesForum.CHAMP_FORUM_ID: forum_id,
            })
            for post in curseur_posts:
                self.generer_doc_post(post, params)

        return {'ok': True}

    def generer_doc_post(self, post: dict, params: dict):

        post_id = post[ConstantesForum.CHAMP_POST_ID]
        date_courante = pytz.utc.localize(datetime.datetime.utcnow())

        champs_post = [
            ConstantesForum.CHAMP_FORUM_ID,
            ConstantesForum.CHAMP_POST_ID,
            ConstantesForum.CHAMP_DATE_CREATION,
            ConstantesForum.CHAMP_DATE_MODIFICATION,
            ConstantesForum.CHAMP_TITRE,
            ConstantesForum.CHAMP_TYPE_POST,
            ConstantesForum.CHAMP_USERID,
            ConstantesForum.CHAMP_VERSION_ID,
            ConstantesForum.CHAMP_MEDIA_PREVIEW,
            ConstantesForum.CHAMP_CONTENU,
            ConstantesForum.CHAMP_IMG,
        ]

        champs_commentaires = [
            ConstantesForum.CHAMP_DATE_CREATION,
            ConstantesForum.CHAMP_DATE_MODIFICATION,
            ConstantesForum.CHAMP_USERID,
            ConstantesForum.CHAMP_CONTENU,
            ConstantesForum.CHAMP_COMMENT_ID,
        ]

        post_dict = {
            ConstantesForum.CHAMP_POST_ID: post_id,
            ConstantesForum.CHAMP_DATE_MODIFICATION: date_courante,
        }
        for key, value in post.items():
            if key in champs_post:
                post_dict[key] = value

        collection_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_COMMENTAIRES_NOM)
        filtre = {
            ConstantesForum.CHAMP_POST_ID: post_id,
        }
        ordre = [(ConstantesForum.CHAMP_DATE_CREATION, 1)]
        curseur_commentaires = collection_commentaires.find(filtre, sort=ordre)

        commentaires_par_id = dict()
        top_level_commentaires = list()
        post_dict[ConstantesForum.CHAMP_COMMENTAIRES] = top_level_commentaires

        for commentaire in curseur_commentaires:

            comment_dict = dict()
            for key, value in commentaire.items():
                if key in champs_commentaires:
                    comment_dict[key] = value

            # Conserver reference au commentaire pour inserer les sous-commentaires (hierarchie)
            commentaires_par_id[commentaire[ConstantesForum.CHAMP_COMMENT_ID]] = comment_dict

            parent_id = commentaire.get(ConstantesForum.CHAMP_COMMENT_PARENT_ID)
            if parent_id is None:
                # Ajouter commentaire a la liste directe sous le post (top-level)
                top_level_commentaires.append(comment_dict)
            else:
                parent_commentaire = commentaires_par_id[parent_id]

                try:
                    commentaires = parent_commentaire[ConstantesForum.COLLECTION_COMMENTAIRES_NOM]
                except KeyError:
                    # Creer list sous-commentaires pour le parent
                    commentaires = list()
                    parent_commentaire[ConstantesForum.COLLECTION_COMMENTAIRES_NOM] = commentaires

                # Inserer commentaire sous le parent
                commentaires.append(comment_dict)

        # Signer le post
        post_dict = self.generateur_transactions.preparer_enveloppe(
            post_dict,
            domaine='Forum.ConstantesForum.LIBVAL_POST',
            ajouter_certificats=True
        )
        filtre = {
            Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesForum.LIBVAL_POST_COMMENTAIRES,
            ConstantesForum.CHAMP_POST_ID: post_id,
        }

        ops = {
            '$set': post_dict,
        }

        collection_post_commentaires = self.document_dao.get_collection(ConstantesForum.COLLECTION_POSTS_COMMENTAIRES_NOM)
        collection_post_commentaires.update(filtre, ops, upsert=True)


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

        self.set_etape_suivante()  # Termine

        return reponse


class ProcessusTransactionModifierPost(ProcessusTransactionPost):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def initiale(self):
        """
        :return:
        """
        transaction = self.transaction
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
        reponse = self.controleur.gestionnaire.maj_commentaire(transaction)

        self.set_etape_suivante()  # Termine

        return reponse
