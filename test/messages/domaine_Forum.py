import logging

from millegrilles.util.BaseTestMessages import DomaineTest
from millegrilles.Constantes import ConstantesForum


class TestForum(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.forum_id = '93f69900-8be0-11eb-80e1-6d0a897f52de'

    def requete_liste_forum(self):
        requete = dict()
        domaine_action = 'requete.Forum.' + ConstantesForum.REQUETE_FORUMS
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
            ConstantesForum.CHAMP_NOM_FORUM: 'Mon forum #2',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_MODIFIER_FORUM
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def creer_post(self):
        transaction = {
            ConstantesForum.CHAMP_FORUM_ID: self.forum_id,
            ConstantesForum.CHAMP_TYPE_POST: 'texte',
            ConstantesForum.CHAMP_TITRE: 'Mon post',
            ConstantesForum.CHAMP_CONTENU: 'Ceci est du contenu',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_AJOUTER_POST
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def maj_post(self):
        transaction = {
            ConstantesForum.CHAMP_POST_ID: 'c24ec2de-8bf7-11eb-80e1-6d0a897f52de',
            ConstantesForum.CHAMP_TITRE: 'Mon post updated 5!',
            ConstantesForum.CHAMP_CONTENU: 'Ceci est du contenu, maj apres 5',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_MODIFIER_POST
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name, ajouter_certificats=True)

    def creer_commentaire(self):
        transaction = {
            ConstantesForum.CHAMP_POST_ID: 'c24ec2de-8bf7-11eb-80e1-6d0a897f52de',
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

    # def maj_site(self):
    #     info_site = {
    #         ConstantesPublication.CHAMP_SITE_ID: '09906262-206c-11eb-88cc-af560af5618f',
    #         ConstantesPublication.CHAMP_NOM_SITE: 'Mon site',
    #         ConstantesPublication.CHAMP_LANGUAGES: ['fr', 'en'],
    #         ConstantesPublication.CHAMP_NOEUDS_URLS: {
    #             self.site_id: ["mg-dev3.maple.maceroc.com"]
    #         },
    #         ConstantesPublication.CHAMP_FICHIERS: {
    #             ConstantesPublication.CHAMP_TOUTES_COLLECTIONS: True
    #         },
    #         ConstantesPublication.CHAMP_ALBUMS: {
    #             ConstantesPublication.CHAMP_TOUTES_COLLECTIONS: True
    #         }
    #     }
    #     domaine_action = 'Publication.' + ConstantesPublication.TRANSACTION_MAJ_SITE
    #     self.generateur.soumettre_transaction(info_site, domaine_action, reply_to=self.queue_name)

    def executer(self):
        self.__logger.debug("Executer")

        # self.requete_liste_forum()
        # self.creer_forum()
        # self.maj_forum()
        # self.creer_post()
        # self.maj_post()
        # self.creer_commentaire()
        self.maj_commentaire()


# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('TestForum').setLevel(logging.DEBUG)
    test = TestForum()
    # TEST

    # FIN TEST
    test.event_recu.wait(10)
    test.deconnecter()
