"""
Module avec les fonctions de hachage utilisees dans MilleGrilles.

Inclus les conversions avec multihash et multibase
"""
import multibase
import multihash

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from multihash.constants import HASH_CODES
from typing import Union, Optional


class Hacheur:

    def __init__(self, hashing_code: Union[int, str] = 'sha2-512', encoding: str = 'base58btc'):
        self.__encoding = encoding

        if isinstance(hashing_code, str):
            hashing_code = HASH_CODES[hashing_code]
        self.__hashing_code = hashing_code

        hashing_function = map_code_to_hashes(hashing_code)
        self.__hashing_context = hashes.Hash(hashing_function, backend=default_backend())

        self.__digest: Optional[bytes] = None

    def update(self, data: Union[str, bytes]):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.__hashing_context.update(data)

    def digest(self):
        if self.__digest is None:
            self.__digest = self.__hashing_context.finalize()
            self.__hashing_context = None
        return self.__digest

    def finalize(self):
        digest = self.digest()
        mh = multihash.encode(digest, self.__hashing_code)
        mb = multibase.encode(self.__encoding, mh)
        return mb.decode('utf-8')


class VerificateurHachage:

    def __init__(self, hachage_multibase: str):
        self.__hachage_multibase = hachage_multibase

        mb = multibase.decode(hachage_multibase)
        mh = multihash.decode(mb)
        self.__hachage_recu = mh.digest
        self.__hashing_code = mh.code

        hashing_function = map_code_to_hashes(self.__hashing_code)
        self.__hashing_context = hashes.Hash(hashing_function, backend=default_backend())

        self.__hachage_calcule: Optional[bytes] = None

    def update(self, data: Union[str, bytes]):
        if isinstance(data, str):
            data = data.encode('utf-8')
        self.__hashing_context.update(data)

    def digest(self) -> bytes:
        if self.__hachage_calcule is None:
            self.__hachage_calcule = self.__hashing_context.finalize()
            self.__hashing_context = None
        return self.__hachage_calcule

    def verify(self) -> bool:
        hachage_calcule = self.digest()
        if hachage_calcule != self.__hachage_recu:
            raise ErreurHachage("Hachage different")

        return True


def hacher_to_digest(valeur: Union[bytes, str], hashing_code: Union[int, str] = 'sha2-512') -> bytes:
    if isinstance(hashing_code, str):
        hashing_code = HASH_CODES[hashing_code]

    hashing_function = map_code_to_hashes(hashing_code)
    context = hashes.Hash(hashing_function, backend=default_backend())

    if isinstance(valeur, str):
        valeur = valeur.encode('utf-8')
    elif isinstance(valeur, dict):
        # Serializer avec json
        pass

    context.update(valeur)
    digest = context.finalize()

    return digest


def hacher(valeur: Union[bytes, str], hash_name: str = 'sha2-512', encoding: str = 'base58btc') -> str:
    digest = hacher_to_digest(valeur, hash_name)
    hashing_code = HASH_CODES[hash_name]
    mh = multihash.encode(digest, hashing_code)
    mb = multibase.encode(encoding, mh)
    return mb.decode('utf-8')


def verifier_hachage(hachage_multibase: str, valeur: Union[bytes, str]) -> bool:
    mb = multibase.decode(hachage_multibase)
    mh = multihash.decode(mb)
    hachage_recu = mh.digest
    code = mh.code

    # Verifier hachage
    hachage_calcule = hacher_to_digest(valeur, code)
    if hachage_recu != hachage_calcule:
        raise ErreurHachage("Hachage different")

    return True


def map_code_to_hashes(code: int) -> hashes.HashAlgorithm:
    if code == 0x12:
        return hashes.SHA256()
    if code == 0x13:
        return hashes.SHA512()
    if code == 0xb240:
        return hashes.BLAKE2b(64)
    if code == 0xb260:
        return hashes.BLAKE2s(32)
    raise ValueError("Hachage non supporte : %d", code)


class ErreurHachage(Exception):
    pass
