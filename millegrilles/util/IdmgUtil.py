# Utilitaire d'encodage, decodage du IDMG et verification de certificat associe
import base58
import math
import struct
import multibase
import multihash

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from multihash.constants import HASH_CODES
from typing import Union

from millegrilles.util.Hachage import map_code_to_hashes


class IdmgUtil:
    """
    Classe utilitaire pour generer et verifier un IDMG.
    """

    # Version courante de IDMG
    VERSION_ACTIVE = 2
    VERSION_PACK = {
        1: '=B28sI',
        2: {'header': '=BI'}
    }

    ENCODING = 'base58btc'
    HASH_FUNCTION = 'sha2-256'

    def __init__(self):
        pass

    def encoder_idmg(self, certificat_pem: str, version=VERSION_ACTIVE):
        return encoder_idmg(certificat_pem, version)

    def encoder_idmg_cert(self, cert_x509: x509, version=VERSION_ACTIVE):
        return encoder_idmg_cert(cert_x509, version)

    def verifier_idmg(self, idmg: str, certificat_pem: str):
        return verifier_idmg(idmg, certificat_pem)


def encoder_idmg(certificat_pem: str, version=IdmgUtil.VERSION_ACTIVE, hashing_code: Union[int, str] = 'sha2-256'):
    cert_x509 = x509.load_pem_x509_certificate(certificat_pem.encode('utf-8'), default_backend())
    return encoder_idmg_cert(cert_x509, version, hashing_code)


def encoder_idmg_cert(cert_x509: x509, version=IdmgUtil.VERSION_ACTIVE, hashing_code: Union[int, str] = 'sha2-256'):
    if isinstance(hashing_code, str):
        hashing_code = HASH_CODES[hashing_code]
    hashing_function = map_code_to_hashes(hashing_code)
    digest_fingerprint = cert_x509.fingerprint(hashing_function)

    # Encoder hachage dans un multihash
    mh = multihash.encode(digest_fingerprint, hashing_code)

    date_exp = cert_x509.not_valid_after
    date_exp_int = int(math.ceil(float(date_exp.timestamp()) / 1000.0))

    version_info = IdmgUtil.VERSION_PACK[version]
    header_struct = version_info['header']

    valeur_combinee = struct.pack(header_struct, version, date_exp_int)
    valeur_combinee = valeur_combinee + mh

    mb = multibase.encode(IdmgUtil.ENCODING, valeur_combinee)

    return mb.decode('utf-8')


def verifier_idmg(idmg: str, certificat_pem: str):
    """
    Verifie la correspondance du idmg avec un certificat
    :param idmg: IDMG a verifier
    :param certificat_pem: Certificat qui devrait correspondre au IDMG
    :return:
    :raises: IdmgInvalide si le Idmg ne correspond pas au certificat
    """
    # Extraire la version
    # valeur = base58.b58decode(idmg)
    try:
        valeur = multibase.decode(idmg)
    except ValueError:
        # Probablement version 1 sans multibase
        # Tenter d'extraire directement en base58
        valeur = base58.b58decode(idmg)

    version = int(valeur[0])

    version_info = IdmgUtil.VERSION_PACK[version]

    if version == 1:
        # Version 1 - 33 bytes en base58, hachage SHA512_224
        (version, digest_recu, date_exp_int_recu) = struct.unpack(version_info, valeur)
        hashing_function = hashes.SHA512_224()
    elif version == 2:
        # Version 2 - encodage multibase, 5 bytes header + multihash
        header_struct = version_info['header']
        header_size = struct.Struct(header_struct).size
        (version, date_exp_int_recu) = struct.unpack(header_struct, valeur[0:header_size])
        mh_bytes = valeur[header_size:]
        mh = multihash.decode(mh_bytes)
        hashing_code = mh.code
        hashing_function = map_code_to_hashes(hashing_code)
        digest_recu = mh.digest
    else:
        raise IdmgInvalide("Version non supportee : %d" % version)

    cert_x509 = x509.load_pem_x509_certificate(certificat_pem.encode('utf-8'), default_backend())
    digest_fingerprint_calcule = cert_x509.fingerprint(hashing_function)
    if digest_recu != digest_fingerprint_calcule:
        raise IdmgInvalide("IDMG ne correspond pas au certificat")

    date_exp = cert_x509.not_valid_after
    date_exp_int = int(math.ceil(float(date_exp.timestamp()) / 1000.0))
    if date_exp_int_recu != date_exp_int:
        raise IdmgInvalide("IDMG fourni en parametre est invalide - date expiration mismatch")


class IdmgInvalide(BaseException):
    pass
