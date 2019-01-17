from millegrilles.SecuritePKI import SignateurTransaction
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles

import json
import logging


class HachageTest:

    def __init__(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser()
        self._signateur = SignateurTransaction(self.contexte.configuration)

        self._logger = logging.getLogger("HachageTest")
        self._logger.setLevel(logging.DEBUG)

    def hacher_fichier(self, path):
        with open(path) as f:
            dict_message = json.loads(f.read())
        hash = self._signateur.hacher_contenu(dict_message)
        self._logger.info("Hachage: %s" % hash)


def test():
    logging.basicConfig(level=logging.INFO)

    hachage = HachageTest()
    hachage.hacher_fichier('/home/mathieu/tmp/sample_msg_1.json')


test()
