# Configuration pour traiter les transactions

from millegrilles.SecuritePKI import VerificateurTransaction, VerificateurCertificats
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.DocumentDAO import MongoDAO


class ContexteRessourcesDocumentsMilleGrilles(ContexteRessourcesMilleGrilles):
    """ Classe helper qui permet d'initialiser et de passer les ressources (configuration, DAOs) """

    def __init__(self, configuration=None, message_dao=None, document_dao=None, additionals: list = None):
        """
        Init classe. Fournir les ressources deja initialisee ou utiliser methode initialiser().

        :param configuration: Optionnel, configuration MilleGrilles deja initialisee.
        :param message_dao: Optionnel, message_dao deja initialise.
        :param document_dao: Optionnel, document_dao deja initialise.
        :param additionals: Fichiers de config additionels a combiner
        """
        super().__init__(configuration, message_dao, additionals)
        self._document_dao = document_dao

        self._verificateur_certificats = None
        self._verificateur_transactions = None

    def initialiser(self, init_message=True, init_document=True, connecter=True):
        """
        Initialise/reinitialise le contexte et connecte les DAOs.

        :param init_message: Si True, initialise et connecte PikaDAO
        :param init_document: Si True, initialise et connecte MongoDAO
        :param connecter: Si true, la connexion aux DAOs est ouverte immediatement
        """

        super().initialiser(init_message, connecter)
        self._document_dao = None

        if init_document:
            self._document_dao = MongoDAO(self._configuration)
            self._verificateur_transactions = VerificateurTransaction(self)
            self._verificateur_certificats = VerificateurCertificats(self)
            if connecter:
                self._document_dao.connecter()

    @property
    def document_dao(self) -> MongoDAO:
        """
        Retourne un document_dao.

        :return: Document dao.
        :raises: ValueError si document_dao n'a pas ete defini.
        """

        # if self._document_dao is None:
        #     raise ValueError("DocumentDAO n'est pas initialise")
        return self._document_dao

    @document_dao.setter
    def document_dao(self, document_dao):
        self._document_dao = document_dao

    @property
    def verificateur_transaction(self) -> VerificateurTransaction:
        return self._verificateur_transactions

    @property
    def verificateur_certificats(self) -> VerificateurCertificats:
        return self._verificateur_certificats

