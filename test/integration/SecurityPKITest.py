from millegrilles.SecuritePKI import VerificateurCertificats
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles


class TestVerificateurs:

    def __init__(self):
        self._contexte = ContexteRessourcesMilleGrilles()
        self._contexte.initialiser()

        self.securite = VerificateurCertificats(self._contexte)


def test():
    test = TestVerificateurs()


# MAIN
test()