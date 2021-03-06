import secrets
import json
import multibase

from uuid import uuid4
from io import RawIOBase
from base64 import b64encode
from typing import Optional, Union
from cryptography.hazmat.primitives import asymmetric, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, CipherContext
from cryptography.hazmat.backends import default_backend
from base64 import b64decode

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesSecurityPki
from millegrilles.SecuritePKI import EnveloppeCertificat
from millegrilles.util.Hachage import Hacheur


class CipherMgs1(RawIOBase):
    """
    Cipher de chiffrage symmetrique avec les parametres de MilleGrilles, format mgs1
    Implemente RawIOBase - permet d'utiliser le cipher comme fileobj (stream)
    """

    def __init__(self, password: bytes = None, encoding_digest='base64'):
        self.__skip_iv = False

        self._iv: Optional[bytes] = None
        self._password: Optional[bytes] = password

        self._cipher: Optional[Cipher] = None

        self._context: Optional[CipherContext] = None

        self._hacheur = Hacheur(hashing_code='sha2-512', encoding=encoding_digest)
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
        return self._digest_result

    def get_meta(self):
        meta_info = {
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_IV: multibase.encode('base64', self._iv).decode('utf-8'),
            Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_HACHAGE_BYTES: self.digest,
        }
        return meta_info


class CipherMsg1Chiffrer(CipherMgs1):
    """
    Helper pour chiffrer en mode MilleGrilles (mgs1)
    Instructions: 1. utiliser start_encrypt() et recuperer debut chiffrage (iv)
                  2. update(data)
                  3. finalize()
    Helper method : chiffrer_motdepasse pour chiffrer le secret avec la cle publique (cert)
    """

    def __init__(self, output_stream=None, password: bytes = None, padding=True, encoding_digest='base64'):
        """
        :param output_stream: Optionnel - permet d'utiliser le cipher comme stream (fileobj)
        """
        super().__init__(password=password, encoding_digest=encoding_digest)
        self.__output_stream = output_stream
        self.__padder: Optional[padding.PaddingContext] = None
        self._generer()
        self.__padding = padding
        self._ouvrir_cipher()

        if output_stream:
            self.start_encrypt()

    def _generer(self):
        if self._password is None:
            self._password = secrets.token_bytes(32)  # AES-256 = 32 bytes
        self._iv = secrets.token_bytes(16)

    def start_encrypt(self):
        if self._context is not None:
            raise Exception('Contexte cipher deja initialise')

        self._context = self._cipher.encryptor()
        if self.__padding is True:
            # On assume mode CBC avec padding, IV requis
            self.__padder = padding.PKCS7(ConstantesSecurityPki.SYMETRIC_PADDING).padder()
            data = self._context.update(self.__padder.update(self._iv))
            # data = bytes()
        else:
            # Le IV n'est pas nessaire dans un mode sans padding (e.g. GCM)
            data = bytes()

        self._hacheur.update(data)

        if self.__output_stream is not None:
            self.__output_stream.write(data)

        return data

    def update(self, data: bytes):
        if self.__padder is not None:
            data = self.__padder.update(data)

        data = self._context.update(data)
        self._hacheur.update(data)

        return data

    def finalize(self):
        if self.__padder is not None:
            data = self._context.update(self.__padder.finalize())
        else:
            data = bytes()

        data_final = data + self._context.finalize()

        if data_final:
            self._hacheur.update(data_final)

        self._digest_result = self._hacheur.finalize()

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

    def __init__(self, iv: bytes, password: bytes, padding=True):
        super().__init__()
        if padding:
            self.__unpadder = padding.PKCS7(ConstantesSecurityPki.SYMETRIC_PADDING).unpadder()
        else:
            self.__unpadder = None

        self._iv = iv
        self._password = password
        self._ouvrir_cipher()
        self.__start_decrypt()

    def __start_decrypt(self):
        self._context = self._cipher.decryptor()
        if self.__unpadder is not None:
            self.__skip_iv = True
        else:
            # On assume mode sans besoin de prepend IV (e.g. GCM)
            self.__skip_iv = False

    def update(self, data: bytes):
        data = self._context.update(data)
        if self.__unpadder:
            data = self.__unpadder.update(data)
        if self.__skip_iv:
            self.__skip_iv = False
            iv_dechiffre = data[:16]
            if iv_dechiffre != self._iv:
                raise Exception("Erreur dechiffrage, IV ne correspond pas")
            return data[16:]
        return data

    def finalize(self):
        data = self._context.finalize()
        if self.__unpadder is not None:
            data = self.__unpadder.update(data)
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


class CipherMsg2Chiffrer(CipherMsg1Chiffrer):
    """
    Chiffrage avec GCM, tag de 128 bits
    """

    def __init__(self, output_stream=None, password: bytes = None, encoding_digest='base64'):
        super().__init__(output_stream, password, padding=False, encoding_digest=encoding_digest)

    def _generer(self):
        if self._password is None:
            self._password = secrets.token_bytes(32)  # AES-256 = 32 bytes
        self._iv = secrets.token_bytes(12)        # GCM 96 bits = 12 bytes

    def _ouvrir_cipher(self):
        backend = default_backend()
        self._cipher = Cipher(algorithms.AES(self._password), modes.GCM(self._iv), backend=backend)

    @property
    def tag(self):
        """
        :return: Compute tag necessaire pour verifier le dechiffrage
        """
        return self._context.tag

    def get_meta(self):
        meta_info = super().get_meta()
        meta_info[Constantes.ConstantesMaitreDesCles.TRANSACTION_CHAMP_TAG] = multibase.encode('base64', self.tag).decode('utf-8')
        return meta_info


class CipherMsg2Dechiffrer(CipherMsg1Dechiffrer):
    """
    Dechiffrage avec GCM, tag de 128 bits
    """

    def __init__(self, iv: Union[str, bytes], password: bytes, compute_tag: Union[str, bytes]):
        if isinstance(iv, str):
            iv = multibase.decode(iv.encode('utf-8'))

        if isinstance(compute_tag, str):
            compute_tag = multibase.decode(compute_tag.encode('utf-8'))

        self._compute_tag = compute_tag
        super().__init__(iv, password, padding=False)

    def _ouvrir_cipher(self):
        backend = default_backend()
        self._cipher = Cipher(algorithms.AES(self._password), modes.GCM(self._iv, self._compute_tag), backend=backend)


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


class ChiffrerChampDict:

    def __init__(self, contexte):
        self.__contexte = contexte

    def chiffrer(self, cert_maitrecles: dict, domaine: str, identificateurs_document: dict, valeur):

        env_maitrecles = EnveloppeCertificat(certificat_pem=cert_maitrecles['certificat'][0])
        env_millegrille = EnveloppeCertificat(certificat_pem=cert_maitrecles['certificat_millegrille'])

        if isinstance(valeur, dict):
            valeur = json.dumps(valeur)
        elif not isinstance(valeur, str):
            raise TypeError('Valeur doit etre : dict ou str')

        valeur_bytes = valeur.encode('utf-8')

        cipher = CipherMsg1Chiffrer()
        valeur_chiffree = cipher.start_encrypt() + cipher.update(valeur_bytes) + cipher.finalize()
        cle_secrete = cipher.password

        domaine_action_requete = Constantes.ConstantesMaitreDesCles.DOMAINE_NOM + '.' + Constantes.ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        # cert_maitrecles = self.__message_handler.requete(domaine_action_requete)

        cles = dict()
        envs = [env_maitrecles, env_millegrille]
        for env in envs:
            cles[env.fingerprint_b64] = b64encode(env.chiffrage_asymmetrique(cle_secrete)[0]).decode('utf-8')

        msg_maitredescles = {
            'identificateurs_document': identificateurs_document,
            'domaine': domaine,
            'version': str(uuid4()),
            "iv": b64encode(cipher.iv).decode('utf-8'),
            "cles": cles,
        }

        msg_maitrecles_signe = self.__contexte.generateur_transactions.preparer_enveloppe(
            msg_maitredescles, Constantes.ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_DOCUMENT)

        contenu = {
            'chiffrement': 'mgs1',
            'uuid_transaction': msg_maitrecles_signe[Constantes.TRANSACTION_MESSAGE_LIBELLE_EN_TETE][Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID],
            'identificateurs_document': identificateurs_document,
            'secret_chiffre': b64encode(valeur_chiffree).decode('utf-8'),
        }

        return {
            'maitrecles': msg_maitrecles_signe,
            'contenu': contenu,
        }


class DechiffrerChampDict:

    def __init__(self, contexte):
        self.__contexte = contexte

    def dechiffrer(self, contenu_chiffre: dict, iv_base64: str, cle_bytes: bytes) -> str:
        iv_bytes = b64decode(iv_base64.encode('utf-8'))
        decipher = CipherMsg1Dechiffrer(iv_bytes, cle_bytes)
        contenu_bytes = b64decode(contenu_chiffre['secret_chiffre'].encode('utf-8'))

        valeur = decipher.update(contenu_bytes) + decipher.finalize()

        return valeur
