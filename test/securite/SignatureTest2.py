import logging
import json

import cryptography.exceptions

from millegrilles import Constantes
from millegrilles.transaction.FormatteurMessage import SignateurTransactionSimple, FormatteurMessageMilleGrilles
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.dao.Configuration import TransactionConfiguration, ContexteRessourcesMilleGrilles
from millegrilles.util.X509Certificate import EnveloppeCleCert
from millegrilles.util.Hachage import ErreurHachage

configuration = TransactionConfiguration()

mq_config = configuration._mq_config
mq_config[Constantes.CONFIG_MQ_KEYFILE] = '/home/mathieu/git/millegrilles.consignation/playground/scripts/leaf.key'
mq_config[Constantes.CONFIG_MQ_CERTFILE] = '/home/mathieu/git/millegrilles.consignation/playground/scripts/leaf.chaine'
mq_config[Constantes.CONFIG_MQ_CA_CERTS] = '/home/mathieu/git/millegrilles.consignation/playground/scripts/ca.cert'

clecert_leaf = EnveloppeCleCert()
clecert_leaf.from_files(mq_config[Constantes.CONFIG_MQ_KEYFILE], mq_config[Constantes.CONFIG_MQ_CERTFILE])
clecert_ca = EnveloppeCleCert()
clecert_ca.from_files(None, mq_config[Constantes.CONFIG_MQ_CA_CERTS])
idmg = clecert_ca.idmg
configuration._millegrille_config['idmg'] = idmg

contexte = ContexteRessourcesMilleGrilles(configuration)
contexte.initialiser(False, False)
signateur = SignateurTransactionSimple(clecert_leaf)
formatteur = FormatteurMessageMilleGrilles(idmg, signateur)

validateur = ValidateurMessage(contexte)

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'
logger = logging.getLogger("SignatureTest2")

def signer_1():
    message = {
        "en-tete": {},
        "valeur": "Mon message"
    }
    # message_signe = signateur.signer(message)
    message_signe, uuid_transaction = formatteur.signer_message(message, ajouter_chaine_certs=True)
    logger.debug("Signature message %s\n%s" % (uuid_transaction, json.dumps(message_signe, indent=2)))

    validateur.verifier(message_signe)
    logger.debug("Hachage et signature du message verifiee OK")

    # Corrompre la signature
    message_signe['en-tete']['corrompu'] = 'oui'
    try:
        validateur.verifier(message_signe)
        logger.debug("ERREUR, signature devrait etre invalide")
    except cryptography.exceptions.InvalidSignature:
        logger.debug("Signature invalide, OK!")

    # Corrompre hachage du contenu
    message_signe['corrompu'] = 'oui'
    try:
        validateur.verifier(message_signe)
        logger.debug("ERREUR, hachage devrait etre invalide")
    except ErreurHachage:
        logger.debug("Hachage invalide, OK!")


def main():
    logging.basicConfig(format=LOGGING_FORMAT, level=logging.WARNING)
    # logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('SignatureTest2').setLevel(logging.DEBUG)

    logger.debug("Generer cles")

    signer_1()


if __name__ == '__main__':
    main()