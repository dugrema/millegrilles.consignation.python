import logging

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration


class Hebergement(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.__millegrilles = None

        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def executer(self):
        self.__logging.info("Demarrage hebergement")

        self.__logging.info("Arret hebergement")


class HebergementTransactions(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)


class HebergementDomaines(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)


class HebergementMaitreDesCles(Hebergement):

    def __init__(self):
        super().__init__()
        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)
