import logging

from millegrilles.util.BaseTestMessages import DomaineTest
from millegrilles.Constantes import ConstantesForum


class TestForum(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

    def requete_liste_forum(self):
        requete = dict()
        domaine_action = 'requete.Forum.' + ConstantesForum.REQUETE_FORUMS
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def creer_forum(self):
        transaction = {}
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_CREER_FORUM
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def maj_forum(self):
        transaction = {
            ConstantesForum.CHAMP_REF_ID: 'ea8c2736-8b4e-11eb-b5ae-0f2c17a0e437',
            ConstantesForum.CHAMP_NOM_FORUM: 'Mon forum #2',
        }
        domaine_action = 'Forum.' + ConstantesForum.TRANSACTION_MODIFIER_FORUM
        correlation_id = 'test'
        self.generateur.soumettre_transaction(
            transaction, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)


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
        self.maj_forum()


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
