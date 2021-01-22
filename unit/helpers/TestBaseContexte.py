import logging

from typing import Optional
from unittest import TestCase

from unit.helpers.ContexteUnitTest import ContexteUnitTest, contexte_instance
from millegrilles import Constantes


class TestCaseContexte(TestCase):
    """
    TestCase qui configure automatiquement un Contexte MilleGrilles en memoire avec des certificats temporaires.
    """

    ma_valeur: Optional[int] = None
    logger: Optional[logging.Logger] = None
    contexte = contexte_instance

    @classmethod
    def setUpClass(cls):
        # logging.basicConfig(format=Constantes.LOGGING_FORMAT)
        logging.basicConfig()
        logging.getLogger('unit.helpers').setLevel(logging.DEBUG)
        cls.logger = logging.getLogger('unit.helpers.' + cls.__name__)
        cls.logger.setLevel(logging.DEBUG)
        cls.logger.debug("Set up Class")
        cls.ma_valeur = 1

    @classmethod
    def tearDownClass(cls) -> None:
        cls.logger.debug("Tear Down class")

    def setUp(self) -> None:
        # self.__class__.logger.debug("setUp")
        # self.__class__.logger.debug("Ma valeur = %s" % self.__class__.ma_valeur)
        pass

    def tearDown(self) -> None:
        self.__class__.logger.debug("tear down")
        self.contexte.reset()
