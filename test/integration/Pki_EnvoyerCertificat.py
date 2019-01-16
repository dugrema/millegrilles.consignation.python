# Test pour transmettre un certificat au domaine PKI
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import PikaDAO
from millegrilles.domaines.Notifications import NotificationsConstantes
from millegrilles import Constantes
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.domaines.Pki import ConstantesPki
from millegrilles.SecuritePKI import VerificateurCertificats

from cryptography.hazmat.primitives import serialization

import datetime
import logging

FICHIER_CERTIFICAT = '/usr/local/etc/millegrilles/certs/pki.millegrilles.ssl.cert'


class TransmettreCertificatTransactionTest:

    def __init__(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser(init_message=True)

        self._logger = logging.getLogger('test')
        self.generateur_transaction = GenerateurTransaction(self.contexte.configuration, self.contexte.message_dao)

        self.enveloppe_certificat = None

    def charger_certificat(self, fichier):

        verificateur = VerificateurCertificats(self.contexte)
        self.enveloppe_certificat = verificateur.charger_certificat(fichier)
        verificateur.verifier_chaine(self.enveloppe_certificat)

    def transmettre(self):
        certificat = self.enveloppe_certificat.certificat
        self._logger.debug("Certificat a transmettre: %s" % str(certificat))
        certificat_pem = str(certificat.public_bytes(serialization.Encoding.PEM), 'utf-8')
        self._logger.debug("Certificat string: %s" % certificat_pem)

        message = {
            'certificat_pem': certificat_pem,
            'fingerprint': self.enveloppe_certificat.fingerprint_ascii
        }

        domaine = '%s.%s' % (ConstantesPki.DOMAINE_NOM, ConstantesPki.TRANSACTION_EVENEMENT_CERTIFICAT)
        self.generateur_transaction.soumettre_transaction(message, domaine)


def test_transmettre_certificat():
    logging.basicConfig(level=logging.INFO)
    logging.getLogger('test').setLevel(logging.DEBUG)
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)

    transmetteur = TransmettreCertificatTransactionTest()
    transmetteur.charger_certificat(FICHIER_CERTIFICAT)
    transmetteur.transmettre()


test_transmettre_certificat()