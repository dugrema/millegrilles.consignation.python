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

    def __init__(self, hash_name: str = 'sha2-512', encoding: str = 'base58btc'):
        self.__hash_name = hash_name
        self.__encoding = encoding

        hashing_code = HASH_CODES[hash_name]
        hashing_function = map_code_to_hashes(hashing_code)
        self.__hashing_context = hashes.Hash(hashing_function, backend=default_backend())

        self.__digest: Optional[bytes] = None

    def update(self, data: bytes):
        self.__hashing_context.update(data)

    def digest(self):
        if self.__digest is None:
            self.__digest = self.__hashing_context.finalize()
            self.__hashing_context = None
        return self.__digest


def hacher_to_digest(valeur: Union[bytes, str, dict], hashing_code: Union[int, str] = 'sha2-512') -> bytes:
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


def hacher(valeur: Union[bytes, str, dict], hash_name: str = 'sha2-512', encoding: str = 'base58btc') -> str:
    digest = hacher_to_digest(valeur, hash_name)
    hashing_code = HASH_CODES[hash_name]
    mh = multihash.encode(digest, hashing_code)
    mb = multibase.encode(encoding, mh)
    return mb.decode('utf-8')


def verifier_hachage(hachage_multibase: str, valeur: Union[bytes, str, dict]) -> bool:
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
