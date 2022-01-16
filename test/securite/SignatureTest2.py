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
mq_config[Constantes.CONFIG_MQ_KEYFILE] = '/home/mathieu/mgdev/certs/pki.media.key'
mq_config[Constantes.CONFIG_MQ_CERTFILE] = '/home/mathieu/mgdev/certs/pki.media.cert'
mq_config[Constantes.CONFIG_MQ_CA_CERTS] = '/home/mathieu/mgdev/certs/pki.millegrille.cert'

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

MESSAGE_RUST = """
{
"_certificat":["-----BEGIN CERTIFICATE-----\\nMIICFTCCAcegAwIBAgIUDgk2RY9xKdhV9H2sbaRwuV7tSB8wBQYDK2VwMHIxLTAr\\nBgNVBAMTJDI2MmVhZTMzLTI1ZTQtNDRiNy04ZmNkLTQ0NjcxMTdhMmZmZTFBMD8G\\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\\nWHJwMjJiQXR3R203SmYwHhcNMjIwMTE0MTkzODI2WhcNMjIwMjA0MTk0MDI2WjBk\\nMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpGdUhHNzk2ZVN2Q1RXRTRN\\nNDMyaXpYcnAyMmJBdHdHbTdKZjENMAsGA1UECwwEY29yZTEQMA4GA1UEAwwHbWct\\nZGV2NTAqMAUGAytlcAMhAOZNry7yvtjalT4jAc8OpwI+ysCgtS6SaW5SIBYUnP/z\\no30wezAdBgNVHQ4EFgQUzzXqIfw8aogDTo5LZboRMLnasmAwHwYDVR0jBBgwFoAU\\nMkSbvTt6igrEK2uRJ/coCRhLd6kwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBPAw\\nEAYEKgMEAAQINC5zZWN1cmUwDAYEKgMEAQQEY29yZTAFBgMrZXADQQACgFhgYbZI\\na3sgHcgS6fbaxGq4oVj+1CEaI6Lx/CMH6pHKreAKMcfVl8WCRsaYCWPk45R/DY7I\\na4ik+RVCK1sK\\n-----END CERTIFICATE-----\\n","-----BEGIN CERTIFICATE-----\\nMIIBozCCAVWgAwIBAgIKBgaEZ0OASVdwADAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\\nbGVHcmlsbGUwHhcNMjIwMTE0MTk0MDE4WhcNMjMwNzI2MTk0MDE4WjByMS0wKwYD\\nVQQDEyQyNjJlYWUzMy0yNWU0LTQ0YjctOGZjZC00NDY3MTE3YTJmZmUxQTA/BgNV\\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEA6UoxhuJKARsV5XeovcX91+eFFlwxU3CP\\nfZ1+xCvs7GCjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\\nA1UdDgQWBBQyRJu9O3qKCsQra5En9ygJGEt3qTAfBgNVHSMEGDAWgBTTiP/MFw4D\\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQC3BaK5TWjXole4f/TP9Fzsb4lsYyJJi/q+\\nJCQEOXZ1kF5F+NRyI/fYmOoac59S4kna0YXn/eb3qwm8uQ5a6kMO\\n-----END CERTIFICATE-----\\n"],
"_signature":"mAm9bi3NoAgtACIYObvFd1q1vM70opLFO63GvegCIQFie0/3vypvxfbVDUFpZ44cnNgQxyOQSLPhAaPTFOTACdgM",
"allo":"toi",
"en-tete":{"estampille":1642278159,"fingerprint_certificat":"z2i3XjxDSREuw2h9thRXe9kAo1YJWECjDaEVEzmt44HMdBwpgzS","hachage_contenu":"mEiAWCt1Uobj6loESgGj5Zeiiebhp+aSyF8q9uSC3XMBSRg","idmg":"zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf","uuid_transaction":"08e298f8-9599-4f85-b314-e696655abe4d","version":1}
}
"""

MESSAGE_JAVASCRIPT = """
{"valeur":"allo","en-tete":{"domaine":"test","idmg":"zeYncRqEqZ6eTEmUZ8whJFuHG796eSvCTWE4M432izXrp22bAtwGm7Jf","uuid_transaction":"62ace8e0-bb42-4f9d-aaa1-8aac61998c88","estampille":1642291179,"fingerprint_certificat":"z2i3XjxDSREuw2h9thRXe9kAo1YJWECjDaEVEzmt44HMdBwpgzS","hachage_contenu":"m4OQCIOuFICpjef9aij3kieETbn7f986gVSCxmcicP3H5moHY","version":1},"_certificat":["-----BEGIN CERTIFICATE-----\\nMIICFTCCAcegAwIBAgIUDgk2RY9xKdhV9H2sbaRwuV7tSB8wBQYDK2VwMHIxLTAr\\nBgNVBAMTJDI2MmVhZTMzLTI1ZTQtNDRiNy04ZmNkLTQ0NjcxMTdhMmZmZTFBMD8G\\nA1UEChM4emVZbmNScUVxWjZlVEVtVVo4d2hKRnVIRzc5NmVTdkNUV0U0TTQzMml6\\nWHJwMjJiQXR3R203SmYwHhcNMjIwMTE0MTkzODI2WhcNMjIwMjA0MTk0MDI2WjBk\\nMUEwPwYDVQQKDDh6ZVluY1JxRXFaNmVURW1VWjh3aEpGdUhHNzk2ZVN2Q1RXRTRN\\nNDMyaXpYcnAyMmJBdHdHbTdKZjENMAsGA1UECwwEY29yZTEQMA4GA1UEAwwHbWct\\nZGV2NTAqMAUGAytlcAMhAOZNry7yvtjalT4jAc8OpwI+ysCgtS6SaW5SIBYUnP/z\\no30wezAdBgNVHQ4EFgQUzzXqIfw8aogDTo5LZboRMLnasmAwHwYDVR0jBBgwFoAU\\nMkSbvTt6igrEK2uRJ/coCRhLd6kwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBPAw\\nEAYEKgMEAAQINC5zZWN1cmUwDAYEKgMEAQQEY29yZTAFBgMrZXADQQACgFhgYbZI\\na3sgHcgS6fbaxGq4oVj+1CEaI6Lx/CMH6pHKreAKMcfVl8WCRsaYCWPk45R/DY7I\\na4ik+RVCK1sK\\n-----END CERTIFICATE-----","-----BEGIN CERTIFICATE-----\\nMIIBozCCAVWgAwIBAgIKBgaEZ0OASVdwADAFBgMrZXAwFjEUMBIGA1UEAxMLTWls\\nbGVHcmlsbGUwHhcNMjIwMTE0MTk0MDE4WhcNMjMwNzI2MTk0MDE4WjByMS0wKwYD\\nVQQDEyQyNjJlYWUzMy0yNWU0LTQ0YjctOGZjZC00NDY3MTE3YTJmZmUxQTA/BgNV\\nBAoTOHplWW5jUnFFcVo2ZVRFbVVaOHdoSkZ1SEc3OTZlU3ZDVFdFNE00MzJpelhy\\ncDIyYkF0d0dtN0pmMCowBQYDK2VwAyEA6UoxhuJKARsV5XeovcX91+eFFlwxU3CP\\nfZ1+xCvs7GCjYzBhMBIGA1UdEwEB/wQIMAYBAf8CAQAwCwYDVR0PBAQDAgEGMB0G\\nA1UdDgQWBBQyRJu9O3qKCsQra5En9ygJGEt3qTAfBgNVHSMEGDAWgBTTiP/MFw4D\\nDwXqQ/J2LLYPRUkkETAFBgMrZXADQQC3BaK5TWjXole4f/TP9Fzsb4lsYyJJi/q+\\nJCQEOXZ1kF5F+NRyI/fYmOoac59S4kna0YXn/eb3qwm8uQ5a6kMO\\n-----END CERTIFICATE-----"],"_signature":"mAvCjl8gF+8R1T6oCQLYsTj7ixludJ+OdBERIv07pRbQ9J0IvMI7u2fXZ+AkhQ2EMijBQPSXBJs7ql4x/aU4yvA0"}
"""


def signer_1():
    message = {
        "en-tete": {},
        "valeur": "Mon message"
    }
    # message_signe = signateur.signer(message)
    message_signe, uuid_transaction = formatteur.signer_message(message, ajouter_chaine_certs=True)
    logger.debug("Signature message %s\n%s" % (uuid_transaction, json.dumps(message_signe)))

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


def verifier_rust():
    msg = json.loads(MESSAGE_RUST)
    validateur.verifier(msg)
    logger.debug("Hachage et signature du message RUST OK")


def verifier_javascript():
    msg = json.loads(MESSAGE_JAVASCRIPT)
    validateur.verifier(msg)
    logger.debug("Hachage et signature du message JavaScript OK")


def main():
    logging.basicConfig(format=LOGGING_FORMAT, level=logging.WARNING)
    # logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('SignatureTest2').setLevel(logging.DEBUG)

    logger.debug("Generer cles")

    signer_1()
    verifier_rust()
    verifier_javascript()


if __name__ == '__main__':
    main()