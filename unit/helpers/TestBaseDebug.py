import logging

from unit.helpers.TestBaseContexte import TestCaseContexte


class VerifTest(TestCaseContexte):

    def testSignatureMessage(self):
        self.__class__.logger.debug("Test signature message avec certificat temporaire")
        message = {
            'en-tete': {},
            'allo': True
        }
        message_signe = self.contexte.signateur_transactions.signer(message)
        self.__class__.logger.debug("En-tete: %s\nSignature : %s" % (message_signe['en-tete'], message_signe['_signature']))

    def testAccesCollection(self):
        pass
