# Utilitaire d'encodage, decodage du IDMG et verification de certificat associe
import base58
import math
import struct
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class IdmgUtil:
    """
    Classe utilitaire pour generer et verifier un IDMG.
    """

    # Version courante de IDMG
    VERSION_ACTIVE = 1
    VERSION_PACK = {1: '=B28sI'}

    def __init__(self):
        pass

    def encoder_idmg(self, certificat_pem: str, version=VERSION_ACTIVE):
        cert_x509 = x509.load_pem_x509_certificate(certificat_pem.encode('utf-8'), default_backend())
        return self.encoder_idmg_cert(cert_x509, version)

    def encoder_idmg_cert(self, cert_x509: x509, version=VERSION_ACTIVE):
        date_exp = cert_x509.not_valid_after
        date_exp_int = math.ceil(float(date_exp.timestamp()) / 1000.0)
        valeur = cert_x509.fingerprint(hashes.SHA512_224())

        valeur_combinee = struct.pack(IdmgUtil.VERSION_PACK[version], version, valeur, date_exp_int)
        valeur_base58 = base58.b58encode(valeur_combinee).decode('utf-8')

        return valeur_base58

    def verifier_idmg(self, idmg: str, certificat_pem: str):
        """
        Verifie la correspondance du idmg avec un certificat
        :param idmg: IDMG a verifier
        :param certificat_pem: Certificat qui devrait correspondre au IDMG
        :return:
        :raises: IdmgInvalide si le Idmg ne correspond pas au certificat
        """
        # Extraire la version
        valeur = base58.b58decode(idmg)
        version = valeur[0]

        # Generer le IDMG pour cette version
        try:
            idmg_calcule = self.encoder_idmg(certificat_pem, version)
        except KeyError:
            raise IdmgInvalide("IDMG fourni en parametre est invalide pour version %d" % version)

        if idmg_calcule != idmg:
            raise IdmgInvalide("IDMG ne correspond pas au certificat")


class IdmgInvalide(BaseException):
    pass
