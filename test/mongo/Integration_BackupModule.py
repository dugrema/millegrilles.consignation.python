# Script de test pour transmettre une requete MongoDB

import logging
import datetime
import pytz

from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
from millegrilles.util.BackupModule import HandlerBackupDomaine


# class TestCallback(BaseCallback):
#
#     def __init__(self, contexte, classe_requete):
#         super().__init__(contexte)
#         self.classe_requete = classe_requete
#
#     def traiter_message(self, ch, method, properties, body):
#         print("Reponse recue: %s" % body)
#         self.reponse = body


class TestBackupModule:

    def __init__(self, contexte):
        self.contexte = contexte
        self.__logger = logging.getLogger('__main__.' + self.__class__.__name__)

        self.handler = HandlerBackupDomaine(contexte, 'MaitreDesCles', 'MaitreDesCles', 'MaitreDesCles/documents')

    def test_find(self):
        collection = self.contexte.document_dao.get_collection('Principale/documents')
        curseur = collection.find()
        self.__logger.debug("Entrees collection principal")
        for r in curseur:
            self.__logger.debug(r)

    def find_sousdomaines_horaires(self):
        ts = datetime.datetime.now(tz=pytz.UTC)
        curseur = self.handler._effectuer_requete_domaine(ts)
        self.__logger.debug("Sous domaines horaires :")
        for r in curseur:
            self.__logger.debug(r)


# --- MAIN ---
def main():
    logging.basicConfig()
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    contexte = ContexteRessourcesDocumentsMilleGrilles()
    contexte.initialiser(init_document=True)

    test = TestBackupModule(contexte)
    # test.test_find()
    test.find_sousdomaines_horaires()


# TEST
if __name__ == '__main__':
    main()
