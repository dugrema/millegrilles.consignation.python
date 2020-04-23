import logging

from threading import Event

from millegrilles.util.UtilScriptLigneCommandeMessages import ModeleConfiguration


class Hebergement(ModeleConfiguration):

    def __init__(self):
        super().__init__()
        self.__millegrilles = None
        self.__fermeture_event = Event()

        self.__logging = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def deconnecter(self):
        self.__fermeture_event.set()

    def executer(self):
        self.__logging.info("Demarrage hebergement")

        while not self.__fermeture_event.is_set():
            self.__fermeture_event.wait(10)

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
