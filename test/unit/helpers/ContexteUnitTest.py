# Module pour les unit tests, inclus un contexte qui fourni des stubs de services MQ et Mongo
# Genere aussi les certificats requis en memoire pour le test, fournissant des certs differents et actifs a chaque test.
import logging

from millegrilles.SecuritePKI import VerificateurCertificats, VerificateurTransaction, SignateurTransaction
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles, TransactionConfiguration
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.ValidateursPki import ValidateurCertificat


class ContexteUnitTest(ContexteRessourcesMilleGrilles):

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        configuration = TransactionConfiguration()
        self._message_dao = None
        super().__init__(configuration, message_dao=None)

        self._signateur_transactions = SignateurTransaction(self)
        self._signateur_transactions.initialiser()
        self._validateur_message = ValidateurMessage()  # Validateur avec cache, sans connexion mq
        self._generateur_transactions = None

    def initialiser(self, init_message=True, connecter=True):
        self.__logger.debug("ContexteUnitTest: Dummy initialiser()")

    def connecter(self):
        self.__logger.debug("ContexteUnitTest: Dummy connecter()")

    def fermer(self):
        self.__logger.debug("ContexteUnitTest: Dummy fermer()")

    @property
    def configuration(self):
        return super().configuration()

    # @property
    # def message_dao(self) -> PikaDAO:
    #     return super().message_dao()
    #
    # @property
    # def generateur_transactions(self) -> GenerateurTransaction:
    #     return super().generateur_transactions
    #
    # @property
    # def signateur_transactions(self) -> SignateurTransaction:
    #     return super().signateur_transactions
    #
    # @property
    # def idmg(self) -> str:
    #     return super().idmg
    #
    # @property
    # def validateur_message(self) -> ValidateurMessage:
    #     return super().validateur_message()
    #
    # @property
    # def validateur_pki(self) -> ValidateurCertificat:
    #     return super().validateur_pki()
    #
