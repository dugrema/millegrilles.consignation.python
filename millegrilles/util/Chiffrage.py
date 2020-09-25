import secrets

from typing import Optional
from cryptography.hazmat.primitives import serialization, asymmetric, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

from millegrilles.Constantes import ConstantesSecurityPki


class CipherMgs1:
    """
    Cipher de chiffrage symmetrique avec les parametres de MilleGrilles, format mgs1
    """

    def __init__(self):
        self.__skip_iv = False

        self._iv: Optional[bytes] = None
        self._password: Optional[bytes] = None

        self._cipher: Optional[Cipher] = None

        self._context: Optional[CipherContext] = None

    def _ouvrir_cipher(self):
        backend = default_backend()
        self._cipher = Cipher(algorithms.AES(self._password), modes.CBC(self._iv), backend=backend)


class CipherMsg1Chiffrer(CipherMgs1):
    """
    Helper pour chiffrer en mode MilleGrilles (mgs1)
    Instructions: 1. utiliser start_encrypt() et recuperer debut chiffrage (iv)
                  2. update(data)
                  3. finalize()
    Helper method : chiffrer_motdepasse pour chiffrer le secret avec la cle publique (cert)
    """

    def __init__(self):
        super().__init__()
        self.__padder: Optional[padding.PaddingContext] = None
        self.__generer()
        self._ouvrir_cipher()

    def __generer(self):
        self._password = secrets.token_bytes(32)  # AES-256 = 32 bytes
        self._iv = secrets.token_bytes(16)

    def start_encrypt(self):
        self._context = self._cipher.encryptor()
        self.__padder = padding.PKCS7(ConstantesSecurityPki.SYMETRIC_PADDING).padder()
        return self._context.update(self.__padder.update(self._iv))

    def update(self, data: bytes):
        data = self._context.update(self.__padder.update(data))
        return data

    def finalize(self):
        data = self._context.update(self.__padder.finalize())
        return data + self._context.finalize()

    def chiffrer_motdepasse_enveloppe(self, enveloppe):
        public_key = enveloppe.certificat.public_key()
        return self.chiffrer_motdepasse(public_key)

    def chiffrer_motdepasse(self, public_key):
        password_chiffre = public_key.encrypt(
            self._password,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return password_chiffre

    @property
    def iv(self):
        return self._iv

    @property
    def password(self):
        return self._password


class CipherMsg1Dechiffrer(CipherMgs1):
    """
    Helper pour dechiffrer en format MilleGrilles (mgs1)
    """

    def __init__(self, iv: bytes, password: bytes):
        super().__init__()
        self.__skip_iv = True
        self.__unpadder = padding.PKCS7(ConstantesSecurityPki.SYMETRIC_PADDING).unpadder()

        self._iv = iv
        self._password = password
        self._ouvrir_cipher()
        self.__start_decrypt()

    def __start_decrypt(self):
        self._context = self._cipher.decryptor()
        self.__skip_iv = True

    def update(self, data: bytes):
        data = self.__unpadder.update(self._context.update(data))
        if self.__skip_iv:
            self.__skip_iv = False
            data = data[16:]
        return data

    def finalize(self):
        data = self.__unpadder.update(self._context.finalize())
        data = data + self.__unpadder.finalize()
        return data

    @staticmethod
    def dechiffrer_cle(cle_privee, cle_chiffree):
        """
        Utilise la cle privee dans l'enveloppe pour dechiffrer la cle secrete chiffree
        """
        contenu_bytes = b64decode(cle_chiffree)

        contenu_dechiffre = cle_privee.decrypt(
            contenu_bytes,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return contenu_dechiffre
