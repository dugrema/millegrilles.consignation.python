import datetime
import pytz
import logging
import json

from os import path
from certvalidator.errors import PathValidationError
from typing import Dict
from threading import Event
from cryptography.exceptions import InvalidSignature

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGenerateurCertificat
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.X509Certificate import RenouvelleurCertificat, EnveloppeCleCert
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.SecuritePKI import HachageInvalide


class ValiderMessage:

    def __init__(self):
        self.__logger = logging.getLogger('__main__.' + self.__class__.__name__)
        self.contexte = None

    def initialiser_contexte(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser()

    def test_valider_message(self):
        self.__logger.debug("Preparation validateur message")
        validateur = ValidateurMessage(self.contexte)
        validateur.connecter()
        self.__logger.debug("Validateur pret")

        message_signe = self.contexte.generateur_transactions.preparer_enveloppe(
            {'test': True}, domaine='test', ajouter_certificats=True)

        # Tester message de base
        enveloppe_certificat = validateur.verifier(message_signe, utiliser_date_message=True)
        self.__logger.debug("Message valide, certificat %s" % enveloppe_certificat.fingerprint_sha256_b64)

        # Tester validation signature
        try:
            message_signe['en-tete']['allo'] = True
            validateur.verifier(message_signe, utiliser_date_message=True)
        except InvalidSignature:
            self.__logger.debug("Verification signature message - OK, flagge comme invalide")
        else:
            self.__logger.error("ERREUR - Verification signature message, flagge comme valide mais est invalide")

        try:
            message_signe['allo'] = True
            validateur.verifier(message_signe, utiliser_date_message=True)
        except HachageInvalide:
            self.__logger.debug("Verification hachage message - OK, flagge comme invalide")
        else:
            self.__logger.error("ERREUR - Verification hachage message, flagge comme valide mais est invalide")


def main():
    logging.basicConfig(format=Constantes.LOGGING_FORMAT)
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('millegrilles.util.ValidateursPki').setLevel(logging.DEBUG)
    logging.getLogger('millegrilles.util.ValidateurMessage').setLevel(logging.DEBUG)

    test = ValiderMessage()
    test.initialiser_contexte()
    test.test_valider_message()


if __name__ == '__main__':
    main()
