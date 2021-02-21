import datetime
import json
import logging

from unit.helpers.TestBaseContexte import TestCaseContexte
from millegrilles.transaction.FormatteurMessage import FormatteurMessageMilleGrilles
from millegrilles.util.ValidateursMessages import ValidateurMessage


# Setup logging
logging.basicConfig()
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)
logging.getLogger('millegrilles').setLevel(logging.DEBUG)


IDMG = 'DUMMY'


message_1 = {
    'en-tete': {},
    'allo': True
}

HACHAGE_MESSAGE_2 = 'mEiCTYQUmipCIDGauFwcwtEJW7hJUhrrpqGHUcNZHj3S+oA'
message_2 = {
    'texte': 'Du texte',
    'int': 1234,
    'float': 5678.12,
    'float zero': 1234.0,
    'date': datetime.datetime(year=2021, month=2, day=20, hour=13, minute=00),
    'dict': {'valeur': 'davantage de contenu'},
    'texte_accents': u"ÀÉËÊÈÇÏÎÔÛŨÙàéëèçïîôù",
    'texte_chars': u"¤{}[]¬~`°|/'\"\n\\"
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

    def testFormatterMessage2(self):
        message = message_2.copy()
        message_signe, uuid_transaction = self.formatteur.signer_message(message, 'Domaine.test', ajouter_chaine_certs=True)
        self.__class__.logger.debug("En-tete: %s\nSignature : %s" % (message_signe['en-tete'], message_signe['_signature']))

        self.assertEqual(HACHAGE_MESSAGE_2, message_signe['en-tete']['hachage_contenu'])
        self.assertIsNotNone(message_signe['_signature'])
        self.assertIsNotNone(message_signe['_certificat'])


class ValiderMessageFormatte(TestCaseContexte):

    def setUp(self) -> None:
        idmg = 'z2RACWHAFSqghq8EaTg5HSGKNPBr3uBfpcpLmBTJa9SEK9MmbD6cA2'
        self.formatteur = FormatteurMessageMilleGrilles(idmg, self.contexte.signateur_transactions)
        self.validateur = ValidateurMessage(idmg=idmg)

    def test_valider_message1(self):
        message = message_1.copy()
        message_signe, uuid_transaction = self.formatteur.signer_message(message, 'Domaine.test', ajouter_chaine_certs=True)
        self.validateur.verifier(message_signe, utiliser_date_message=True, utiliser_idmg_message=True)

    def test_valider_message2(self):
        message = message_2.copy()
        message_signe, uuid_transaction = self.formatteur.signer_message(message, 'Domaine.test', ajouter_chaine_certs=True)
        self.validateur.verifier(message_signe, utiliser_date_message=True, utiliser_idmg_message=True)
