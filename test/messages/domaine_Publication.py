import logging

from uuid import uuid4

from millegrilles.util.BaseTestMessages import DomaineTest
from millegrilles.Constantes import ConstantesPublication


class TestPublication(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.site_id = '09906262-206c-11eb-88cc-af560af5618f'
        self.noeud_id = '639e1d3b-fa5b-4a13-86b2-d3e6148c9d99'

    def requete_liste_sites(self):
        requete = dict()
        domaine_action = 'requete.Publication.' + ConstantesPublication.REQUETE_LISTE_SITES
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def requete_liste_posts(self):
        requete = {'post_ids': ['bf20add7-0355-40e7-86d4-5b0ab1fee873', 'a5e34904-ffdb-4f50-a092-86e3058f9716', '5fce6672-a644-4f1b-94e0-3fa265b4affc']}
        domaine_action = 'requete.Publication.' + ConstantesPublication.REQUETE_POSTS
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def requete_config_site(self):
        requete = {'site_id': self.site_id}
        domaine_action = 'requete.Publication.' + ConstantesPublication.REQUETE_CONFIGURATION_SITE
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def requete_sites_pour_noeud(self):
        requete = {'noeud_id': self.noeud_id}
        domaine_action = 'requete.Publication.' + ConstantesPublication.REQUETE_SITES_POUR_NOEUD
        correlation_id = 'test'
        self.generateur.transmettre_requete(
            requete, domaine_action, correlation_id=correlation_id, reply_to=self.queue_name)

    def maj_site(self):
        info_site = {
            ConstantesPublication.CHAMP_SITE_ID: '09906262-206c-11eb-88cc-af560af5618f',
            ConstantesPublication.CHAMP_NOM_SITE: 'Mon site',
            ConstantesPublication.CHAMP_LANGUAGES: ['fr', 'en'],
            ConstantesPublication.CHAMP_NOEUDS_URLS: {
                self.site_id: ["mg-dev3.maple.maceroc.com"]
            },
            ConstantesPublication.CHAMP_FICHIERS: {
                ConstantesPublication.CHAMP_TOUTES_COLLECTIONS: True
            },
            ConstantesPublication.CHAMP_ALBUMS: {
                ConstantesPublication.CHAMP_TOUTES_COLLECTIONS: True
            }
        }
        domaine_action = 'Publication.' + ConstantesPublication.TRANSACTION_MAJ_SITE
        self.generateur.soumettre_transaction(info_site, domaine_action, reply_to=self.queue_name)

    def maj_post(self):
        info_post = {
            "post_id": "17b2430e-c6bc-4d0b-8dd1-9787e0b5bf2a",
            # "post_id": str(uuid4()),
            "html": {
                "fr": "<h1>Mon post, en francais</h1><p>Un nouveau post</p>",
                "en": "<h1>My post, in English</h1><p>A new post</p>",
            }
        }
        domaine_action = 'Publication.' + ConstantesPublication.TRANSACTION_MAJ_POST
        self.generateur.soumettre_transaction(info_post, domaine_action, reply_to=self.queue_name)

    def executer(self):
        self.__logger.debug("Executer")

        # self.requete_liste_sites()
        # self.requete_liste_posts()
        # self.requete_config_site()
        self.requete_sites_pour_noeud()
        # self.maj_site()
        # self.maj_post()


# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('TestPublication').setLevel(logging.DEBUG)
    test = TestPublication()
    # TEST

    # FIN TEST
    test.event_recu.wait(10)
    test.deconnecter()
