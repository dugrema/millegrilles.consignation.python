# Module pour les unit tests, inclus un contexte qui fourni des stubs de services MQ et Mongo
# Genere aussi les certificats requis en memoire pour le test, fournissant des certs differents et actifs a chaque test.
import logging

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGenerateurCertificat
from millegrilles.SecuritePKI import VerificateurCertificats, VerificateurTransaction, SignateurTransaction
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles, TransactionConfiguration
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.ValidateursPki import ValidateurCertificat
from millegrilles.MGProcessus import StubGenerateurTransactions

from unit.helpers.CertUTHelper import PreparateurCertificats, clecert_1


class ContexteUnitTest(ContexteRessourcesMilleGrilles):

    def __init__(self):
        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)
        configuration = TransactionConfiguration()

        self._message_dao = None
        self._stub_document_dao = DocumentDaoStub()

        super().__init__(configuration, message_dao=None)

        self._generateur_transactions = GenerateurTransactionsStub()

        # Preparer une cle temporaire (avec son cert)
        cle_millegrille = clecert_1
        idmg = cle_millegrille.idmg
        configuration._millegrille_config[Constantes.CONFIG_IDMG] = idmg

        self.preparateur = PreparateurCertificats(cle_millegrille)
        clecert_domaine = self.preparateur.generer_role(ConstantesGenerateurCertificat.ROLE_DOMAINES)
        self.configuration.cle = clecert_domaine

        # Charger le signateur - utilise la cle temporaire
        self._signateur_transactions = SignateurTransaction(self)
        self._signateur_transactions.initialiser()
        self._validateur_message = ValidateurMessage(idmg=idmg)  # Validateur avec cache, sans connexion mq

    def initialiser(self, init_message=True, connecter=True):
        self.__logger.debug("ContexteUnitTest: re-initialiser")

    def connecter(self):
        self.__logger.debug("ContexteUnitTest: Dummy connecter()")

    def fermer(self):
        self.__logger.debug("ContexteUnitTest: Dummy fermer()")

    @property
    def configuration(self):
        return super().configuration

    @property
    def document_dao(self):
        return self._stub_document_dao

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


class GenerateurTransactionsStub(StubGenerateurTransactions):

    def __init__(self):
        super().__init__()
        self.liste_emettre_message = list()

    def emettre_message(self, *args, **kwargs):
        # Capture messages
        self.liste_emettre_message.append({'args': args, 'kwargs': kwargs})

    def preparer_enveloppe(self, *args, **kwargs):
        return args[0]


class DocumentDaoStub:
    """
    Stub document dao - agit aussi comme une collection (get_collection -> self)
    """

    def __init__(self):
        self.calls_aggregate = list()
        self.calls_find = list()
        self.calls_update = list()

        # Placeholders pour retourner des valeurs
        self.valeurs_aggregate = list()
        self.valeurs_find = list()
        self.valeurs_update = list()

    def get_collection(self, nom_collection):
        return self

    def find(self, *args, **kwargs):
        self.calls_find.append({'args': args, 'kwargs': kwargs})
        return self.valeurs_find.pop(0)

    def update(self, *args, **kwargs):
        self.calls_update.append({'args': args, 'kwargs': kwargs})
        return self.valeurs_update.pop(0)

    def aggregate(self, *args, **kwargs):
        self.calls_aggregate.append({'args': args, 'kwargs': kwargs})
        return self.valeurs_aggregate.pop(0)


contexte_instance = ContexteUnitTest()