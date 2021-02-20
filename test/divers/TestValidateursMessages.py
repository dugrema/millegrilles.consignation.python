import logging

from cryptography.exceptions import InvalidSignature

from millegrilles import Constantes
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.SecuritePKI import HachageInvalide


class ValiderMessage:

    def __init__(self):
        self.__logger = logging.getLogger('__main__.' + self.__class__.__name__)
        self.contexte = None
        self.validateur = None

    def initialiser_contexte(self):
        # self.contexte = ContexteRessourcesMilleGrilles()
        # self.contexte.initialiser()

        self.__logger.debug("Preparation validateur message")
        self.validateur = ValidateurMessage(idmg="QLA8z7SaLx4ZFTyRbUdPiejojm5hUfqxcPRcwsuiVR8T")
        # self.validateur.connecter()
        self.__logger.debug("Validateur pret")

    def test_valider_message(self):
        message_signe = self.contexte.generateur_transactions.preparer_enveloppe(
            {'test': True}, domaine='test', ajouter_certificats=True)

        # Tester message de base
        enveloppe_certificat = self.validateur.verifier(message_signe, utiliser_date_message=True)
        self.__logger.debug("Message valide, certificat %s" % enveloppe_certificat.fingerprint_sha256_b64)

    def test_valider_message_chargercertificat(self):
        message_signe = self.contexte.generateur_transactions.preparer_enveloppe({'test': True}, domaine='test')

        # Tester message de base
        enveloppe_certificat = self.validateur.verifier(message_signe, utiliser_date_message=True)
        self.__logger.debug("Message valide, certificat %s" % enveloppe_certificat.fingerprint_sha256_b64)

    def test_signature_invalide(self):
        # Tester validation signature
        message_signe = self.contexte.generateur_transactions.preparer_enveloppe(
            {'test': True}, domaine='test', ajouter_certificats=True)
        try:
            message_signe['en-tete']['allo'] = True
            self.validateur.verifier(message_signe, utiliser_date_message=True)
        except InvalidSignature:
            self.__logger.debug("Verification signature message - OK, flagge comme invalide")
        else:
            self.__logger.error("ERREUR - Verification signature message, flagge comme valide mais est invalide")

    def test_hachage_invalide(self):
        message_signe = self.contexte.generateur_transactions.preparer_enveloppe(
            {'test': True}, domaine='test', ajouter_certificats=True)
        try:
            message_signe['allo'] = True
            self.validateur.verifier(message_signe, utiliser_date_message=True)
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

    test.test_valider_message_chargercertificat()
    test.test_valider_message()
    test.test_signature_invalide()
    test.test_hachage_invalide()

    # Verifier le cache de certificat
    test.test_valider_message_chargercertificat()


if __name__ == '__main__':
    main()
