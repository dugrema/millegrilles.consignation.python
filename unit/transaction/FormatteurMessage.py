import json

from unit.helpers.TestBaseContexte import TestCaseContexte
from millegrilles.transaction.FormatteurMessage import FormatteurMessageMilleGrilles


IDMG = 'DUMMY'


message_1 = {
    'en-tete': {},
    'allo': True
}


class FormatteurMessageTest(TestCaseContexte):

    def setUp(self) -> None:
        self.formatteur = FormatteurMessageMilleGrilles(IDMG, self.contexte.signateur_transactions)

    def testSignatureMessage(self):
        """
        Test pour s'assurer que le signateur de transactions fonctionne (sanity)
        :return:
        """
        self.__class__.logger.debug("Test signature message avec certificat temporaire")
        message = message_1.copy()
        message_signe = self.contexte.signateur_transactions.signer(message)
        self.__class__.logger.debug("En-tete: %s\nSignature : %s" % (message_signe['en-tete'], message_signe['_signature']))

    def testFormatterMessage(self):
        message = message_1.copy()
        message_signe, uuid_transaction = self.formatteur.signer_message(message, 'Domaine.test', ajouter_chaine_certs=True)
        self.__class__.logger.debug("Message signe\n%s" % json.dumps(message_signe, indent=1))
        self.assertIsNotNone(message_signe['en-tete']['hachage_contenu'])
        self.assertIsNotNone(message_signe['_signature'])
        self.assertIsNotNone(message_signe['_certificat'])
