# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles


class BaseMongo:

    def __init__(self):
        self._contexte = ContexteRessourcesMilleGrilles()
        self._contexte.initialiser(init_message=True)
        self.document_dao = self._contexte.document_dao

    def deconnecter(self):
        self.document_dao.deconnecter()

    @property
    def contexte(self):
        return self._contexte
