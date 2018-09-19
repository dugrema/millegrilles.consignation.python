#!/usr/bin/python3

from millegrilles import Constantes
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.dao.Configuration import TransactionConfiguration

# Generateur de transaction - peut etre reutilise.
class GenerateurTransaction:

    def __init__(self):
        self._configuration = TransactionConfiguration()
        self._configuration.loadEnvironment()
        self._message_dao = TransactionConfiguration(self._configuration)

    def soumettre_transaction(self):
        pass
