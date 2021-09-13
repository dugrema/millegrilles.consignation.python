from millegrilles.SecuritePKI import SignateurTransaction
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.util.Hachage import ErreurHachage

from cryptography.exceptions import InvalidSignature

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

    def verifier_fichier(self, path):
        with open(path) as f:
            dict_message = json.loads(f.read())
        validateur = self.contexte.validateur_message
        try:
            validateur.verifier(dict_message)
            print("Message OK")
        except ErreurHachage as e:
            print("Exception Hachage %s" % str(e))
            del dict_message['en-tete']
            nouveau_message = self.contexte.generateur_transactions.preparer_enveloppe(dict_message)
            print("Hachage incorrect, nouveau message hache \n%s" % json.dumps(nouveau_message, sort_keys=True))
        except InvalidSignature as e:
            print("Signature invalide ou non verifiable %s" % str(e))


def test():
    logging.basicConfig(level=logging.INFO)

    hachage = HachageTest()
    hachage.verifier_fichier('/tmp/test.json')


test()
