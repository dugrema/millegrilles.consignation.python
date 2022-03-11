import requests
import logging
import json
import gzip

from base64 import b64encode

from millegrilles.util.BaseTestMessages import DomaineTest


class FichiersTest(DomaineTest):

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.url_fichiers = 'https://mg-dev5:3021/fichiers'
        self.certfile = self.configuration.pki_certfile
        self.keyfile = self.configuration.pki_keyfile
        with open(self.configuration.pki_cafile, 'r') as fichier:
            self.capem = fichier.read()

    def head_fichier(self):
        fuuid = 'zSEfXUA9VkhoYq7y9vatRzP1wi1j67BofDzSPUuiL6x4yaCj8F8tqLXARHkJT48vaqVx66kdEw6ahdBxKb4t2ZSBvvkpfU'
        url_fichier = self.url_fichiers + '/' + fuuid

        self.__logger.info("Requete HEAD %s", url_fichier)
        r = requests.head(
            url_fichier,
            verify=False,
            # verify=self._contexte.configuration.pki_cafile,
            cert=(self.certfile, self.keyfile)
        )

        if r.status_code == 429:
            self.__logger.warning("Erreur poster throttle en cours (429)")
        elif r.status_code == 200:
            self.__logger.info("HEAD OK, headers:\n%s" % r.headers)
        else:
            self.__logger.error("Erreur poster (%d)" % (r.status_code))

        return r

    def executer(self):
        self.__logger.debug("Executer")
        try:
            self.head_fichier()
        except:
            self.__logger.exception("Erreur")
        finally:
            self.event_recu.set()

# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('FichiersTest').setLevel(logging.DEBUG)
    # test = PutCommands()
    test = FichiersTest()
    # TEST

    # FIN TEST
    test.event_recu.wait(10)
    test.deconnecter()
