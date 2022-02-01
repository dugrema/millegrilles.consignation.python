# Test de generation, sauvegarde cle privee Ed25519
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
from millegrilles.util.X509Certificate import GenerateurCertificateParRequest, EnveloppeCleCert
from nacl.signing import SigningKey, VerifyKey

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


def convertir_ed25519_x25519():
    clecert1 = EnveloppeCleCert()
    clecert2 = EnveloppeCleCert()
    clecert1.generer_private_key()
    clecert2.generer_private_key()

    # cle1_private_bytes = clecert1.private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    # cle1_public_bytes = clecert1.private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    # cle2_private_bytes = clecert2.private_key.private_bytes(encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption())
    # cle2_public_bytes = clecert2.private_key.public_key().public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
    #
    # # Charger cle format nacl
    # cle1_nacl_signingkey = SigningKey(cle1_private_bytes)
    # cle2_nacl_signingkey = SigningKey(cle2_private_bytes)
    # cle1_nacl_verifykey = VerifyKey(cle1_public_bytes)
    # cle2_nacl_verifykey = VerifyKey(cle2_public_bytes)
    #
    # cle1_x25519_public = cle1_nacl_verifykey.to_curve25519_public_key().encode()
    # cle2_x25519_public = cle2_nacl_verifykey.to_curve25519_public_key().encode()
    # cle1_x25519_prive = cle1_nacl_signingkey.to_curve25519_private_key().encode()
    # cle2_x25519_prive = cle2_nacl_signingkey.to_curve25519_private_key().encode()
    #
    # # Convertir cles privees, publiques en x25519
    # cle1_privee = X25519PrivateKey.from_private_bytes(cle1_x25519_prive)
    # cle1_publique = X25519PublicKey.from_public_bytes(cle1_x25519_public)
    # cle2_privee = X25519PrivateKey.from_private_bytes(cle2_x25519_prive)
    # cle2_publique = X25519PublicKey.from_public_bytes(cle2_x25519_public)

    cle1_publique = clecert1.get_public_x25519()
    cle2_publique = clecert2.get_public_x25519()
    cle1_privee = clecert1.get_private_x25519()
    cle2_privee = clecert2.get_private_x25519()

    # Faire les 2 key exchanges
    cle_handshake_a = cle1_privee.exchange(cle2_publique)
    cle_handshake_b = cle2_privee.exchange(cle1_publique)

    if cle_handshake_a == cle_handshake_b:
        print("Cle derivee asymmetrique A == B, OK!")
    else:
        raise Exception("Erreur comparaison cles A et B")


def main():
    logging.basicConfig(format=LOGGING_FORMAT, level=logging.WARNING)
    # logging.getLogger().setLevel(logging.WARNING)
    logging.getLogger('ClesCertsEd25519').setLevel(logging.DEBUG)

    logger.debug("Generer cles")
    #generer_cle()
    # generer_csr()
    # signer_csr()
    # comparer_cles()
    convertir_ed25519_x25519()


if __name__ == '__main__':
    main()
