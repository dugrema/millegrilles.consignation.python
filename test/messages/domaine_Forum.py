import logging

from millegrilles.util.BaseTestMessages import DomaineTest
from millegrilles.Constantes import ConstantesForum


class TestForum(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.forum_id = '6f34871c-8be0-11eb-80e1-6d0a897f52de'

    def requete_liste_forum(self):
        requete = dict()
        domaine_action = 'requete.Forum.' + ConstantesForum.REQUETE_FORUMS
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def requete_liste_forum_posts(self):
        requete = {
            ConstantesForum.CHAMP_FORUM_ID: '21ad1064-d5e1-42c3-a42e-0fc0c94caa3d',
            ConstantesForum.CHAMP_SORT_TYPE: ConstantesForum.TRI_PLUSRECENT,
        }
        domaine_action = 'requete.Forum.' + ConstantesForum.REQUETE_FORUM_POSTS
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def requete_liste_post_commentaires(self):
        requete = {
            ConstantesForum.CHAMP_POST_ID: 'aeaaf988-8c1e-11eb-80e2-6d0a897f52de',
        }
        domaine_action = 'requete.Forum.' + ConstantesForum.REQUETE_POST_COMMENTAIRES
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def creer_forum(self):
        transaction = {}
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_CREER_FORUM
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def maj_forum(self):
        transaction = {
            ConstantesForum.CHAMP_FORUM_ID: self.forum_id,
            ConstantesForum.CHAMP_NOM_FORUM: 'Forumer de testa',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_MODIFIER_FORUM
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def creer_post(self):
        transaction = {
            ConstantesForum.CHAMP_FORUM_ID: self.forum_id,
            ConstantesForum.CHAMP_TYPE_POST: 'texte',
            ConstantesForum.CHAMP_TITRE: 'Mon post de forumer',
            ConstantesForum.CHAMP_CONTENU: 'Ceci est du contenu',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_AJOUTER_POST
        correlation_id = 'test'

        self.attendre_apres_recu = True  # On attend plusieurs messages
        for i in range(0, 1):
            self.generateur.soumettre_transaction(
                transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def maj_post(self):
        transaction = {
            ConstantesForum.CHAMP_POST_ID: '137d9562-8e1a-11eb-8d53-5dded0196c72',
            ConstantesForum.CHAMP_TITRE: 'Mon post de forumer #3',
            ConstantesForum.CHAMP_CONTENU: 'Ceci est du contenu, maj apres 3',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_MODIFIER_POST
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def creer_commentaire(self):
        transaction = {
            ConstantesForum.CHAMP_POST_ID: '8dae94b6-8b69-11eb-b5ae-0f2c17a0e437',
            ConstantesForum.CHAMP_CONTENU: 'Un commentaire',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_AJOUTER_COMMENTAIRE
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def maj_commentaire(self):
        transaction = {
            ConstantesForum.CHAMP_COMMENT_ID: '6efa08f8-8bf9-11eb-80e1-6d0a897f52de',
            ConstantesForum.CHAMP_CONTENU: 'Commentaire mis a jour',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_MODIFIER_COMMENTAIRE
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def commande_generer_forums_posts(self):
        commande = {
            # ConstantesForum.CHAMP_FORUM_IDS: [self.forum_id],
        }
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_FORUMS_POSTS
        correlation_id = 'test'
        self.generateur.transmettre_commande(
            commande, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def commande_generer_posts_commentaires(self):
        commande = {
            ConstantesForum.CHAMP_FORUM_IDS: ['21ad1064-d5e1-42c3-a42e-0fc0c94caa3d', 'f79a8178-fe9b-4288-b811-ab1490ee8dab'],
            # ConstantesForum.CHAMP_POST_IDS: ['12e5c0c1-e934-4107-b97a-e3cd2120b502']
        }
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_GENERER_POSTS_COMMENTAIRES
        correlation_id = 'test'
        self.generateur.transmettre_commande(
            commande, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def commande_transmettre_forums_posts(self):
        self.attendre_apres_recu = True  # On attend plusieurs messages
        commande = {}
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_TRANSMETTRE_FORUMS_POSTS
        correlation_id = 'test'
        self.generateur.transmettre_commande(
            commande, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def commande_transmettre_posts_commentaires(self):
        self.attendre_apres_recu = True  # On attend plusieurs messages
        commande = {
            # ConstantesForum.CHAMP_FORUM_ID: '93f69900-8be0-11eb-80e1-6d0a897f52de',
        }
        domaine_action = 'commande.Forum.' + ConstantesForum.COMMANDE_TRANSMETTRE_POSTS_COMMENTAIRES
        correlation_id = 'test'
        self.generateur.transmettre_commande(
            commande, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)


    def executer(self):
        self.__logger.debug("Executer")

        # self.requete_liste_forum()
        # self.requete_liste_forum_posts()
        # self.requete_liste_post_commentaires()
        # self.creer_forum()
        # self.maj_forum()
        # self.creer_post()
        # self.maj_post()
        # self.creer_commentaire()
        # self.maj_commentaire()
        # self.commande_generer_forums_posts()
        self.commande_generer_posts_commentaires()
        # self.commande_transmettre_forums_posts()
        # self.commande_transmettre_posts_commentaires()


# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('TestForum').setLevel(logging.DEBUG)
    test = TestForum()
    # TEST

    # FIN TEST
    test.event_recu.wait(5)
    test.deconnecter()
