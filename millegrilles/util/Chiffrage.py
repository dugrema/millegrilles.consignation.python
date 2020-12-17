import secrets

from io import RawIOBase
from base64 import b64encode

from typing import Optional
from cryptography.hazmat.primitives import serialization, asymmetric, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

from millegrilles.Constantes import ConstantesSecurityPki


class CipherMgs1(RawIOBase):
    """
    Cipher de chiffrage symmetrique avec les parametres de MilleGrilles, format mgs1
    Implemente RawIOBase - permet d'utiliser le cipher comme fileobj (stream)
    """

    def __init__(self):
        self.__skip_iv = False

        self._iv: Optional[bytes] = None
        self._password: Optional[bytes] = None

        self._cipher: Optional[Cipher] = None

        self._context: Optional[CipherContext] = None

        self._digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        self._digest_result: Optional[str] = None

    def _ouvrir_cipher(self):
        backend = default_backend()
        self._cipher = Cipher(algorithms.AES(self._password), modes.CBC(self._iv), backend=backend)

    @property
    def digest(self):
        """
        Digest calcule sur le resultat chiffre
        :return:
        """
        return 'sha512_b64:' + b64encode(self._digest_result).decode('utf-8')


class CipherMsg1Chiffrer(CipherMgs1):
    """
    Helper pour chiffrer en mode MilleGrilles (mgs1)
    Instructions: 1. utiliser start_encrypt() et recuperer debut chiffrage (iv)
                  2. update(data)
                  3. finalize()
    Helper method : chiffrer_motdepasse pour chiffrer le secret avec la cle publique (cert)
    """

    def __init__(self, output_stream=None):
        """
        :param output_stream: Optionnel - permet d'utiliser le cipher comme stream (fileobj)
        """
        super().__init__()
        self.__output_stream = output_stream
        self.__padder: Optional[padding.PaddingContext] = None
        self.__generer()
        self._ouvrir_cipher()

        if output_stream:
            self.start_encrypt()

    def __generer(self):
        self._password = secrets.token_bytes(32)  # AES-256 = 32 bytes
        self._iv = secrets.token_bytes(16)

    def start_encrypt(self):
        self._context = self._cipher.encryptor()
        self.__padder = padding.PKCS7(ConstantesSecurityPki.SYMETRIC_PADDING).padder()

        data = self._context.update(self.__padder.update(self._iv))
        self._digest.update(data)

        if self.__output_stream is not None:
            self.__output_stream.write(data)

        return data

    def update(self, data: bytes):
        data = self._context.update(self.__padder.update(data))
        self._digest.update(data)

        return data

    def finalize(self):
        data = self._context.update(self.__padder.finalize())
        data_final = data + self._context.finalize()

        if data_final is not None:
            self._digest.update(data_final)
        self._digest_result = self._digest.finalize()

        return data_final

    def write(self, __b) -> Optional[int]:
        """
        Methode de RawIOBase.
        :param __b:
        :return:
        """
        data = self.update(__b)
        return self.__output_stream.write(data)

    def close(self):
        """
        Methode de RawIOBase, finalize le cipher et ferme l'output stream.
        :return:
        """
        data_final = self.finalize()
        self.__output_stream.write(data_final)

        self.__output_stream.close()

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
        # if self.__skip_iv:
        #     self.__skip_iv = False
        #     data = data[16:]
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


class DigestStream(RawIOBase):

    def __init__(self, file_object):
        super().__init__()
        self.__file_object = file_object

        self.__digest = hashes.Hash(hashes.SHA512(), backend=default_backend())

        self.__digest_result: Optional[str] = None

    def read(self, *args, **kwargs):  # real signature unknown
        data = self.__file_object.read()

        # Calculer digest
        self.__digest.update(data)

        return data

    def digest(self):
        digest_result = self.__digest.finalize()
        return 'sha512_b64:' + b64encode(digest_result).decode('utf-8')


class DecipherStream(DigestStream):

    def __init__(self, decipher: CipherMsg1Dechiffrer, file_object):
        super().__init__(file_object)
        self.__decipher = decipher

    def read(self, *args, **kwargs):  # real signature unknown
        data = super().read(args, kwargs)

        # Dechiffrer
        if data is None:
            return self.__decipher.finalize()
        else:
            return self.__decipher.update(data)
