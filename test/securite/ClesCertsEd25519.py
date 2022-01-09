# Test de generation, sauvegarde cle privee Ed25519
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding
from millegrilles.util.X509Certificate import GenerateurCertificateParRequest, EnveloppeCleCert

LOGGING_FORMAT = '%(asctime)s %(threadName)s %(levelname)s: %(message)s'
logger = logging.getLogger('ClesCertsEd25519')


def generer_cle():
    #private_key = Ed25519PrivateKey.generate()
    #public_key = private_key.public_key()
    #logger.debug("Private Key %s" % private_key)

    clecert = EnveloppeCleCert()
    clecert.generer_private_key(generer_password=True)
    cle_private_pem = clecert.private_key_bytes
    logger.debug("PEM private bytes password: %s\n%s", clecert.password.decode('utf-8'), cle_private_pem.decode('utf-8'))


def generer_csr():
    generateur = GenerateurCertificateParRequest('abcd1234')
    csr_empty = generateur.preparer_request('dummy')
    logger.debug("CSR dummy :\n%s" % csr_empty.csr_bytes.decode('utf-8'))
    return csr_empty


def signer_csr():
    # Charger cert/cle existants
    password = 'monpassword'.encode('utf-8')
    clecert = EnveloppeCleCert()
    # clecert.from_files('/home/mathieu/mgdev/tmp/ca.key', '/home/mathieu/mgdev/tmp/ca.pem', password)
    clecert.from_files('/home/mathieu/git/millegrilles.consignation/playground/scripts/ca.key', '/home/mathieu/git/millegrilles.consignation/playground/scripts/ca.cert', None)

    clecert_csr = generer_csr()

    dict_ca = dict()
    generateur = GenerateurCertificateParRequest('IDMGDUMMY', dict_ca, clecert)
    cert = generateur.signer(clecert_csr.csr, role='monitor')

    logger.debug("Cert\n%s" % cert.public_bytes(Encoding.PEM).decode('utf-8'))
    return cert


def comparer_cles():
    clecert1 = EnveloppeCleCert()
    clecert1.from_files('/home/mathieu/git/millegrilles.consignation/playground/scripts/ca.key', '/home/mathieu/git/millegrilles.consignation/playground/scripts/ca.cert', None)

    correspondent = clecert1.cle_correspondent()
    logger.debug("Certificat et cle privee correspondent : %s" % correspondent)

    clecert2 = EnveloppeCleCert()
    clecert2.generer_private_key(generer_password=True)


def main():
    logging.basicConfig(format=LOGGING_FORMAT, level=logging.WARNING)
    # logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('ClesCertsEd25519').setLevel(logging.DEBUG)

    logger.debug("Generer cles")
    #generer_cle()
    # generer_csr()
    # signer_csr()
    comparer_cles()


if __name__ == '__main__':
    main()
