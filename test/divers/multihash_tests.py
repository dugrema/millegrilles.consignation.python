import multihash
import multibase

from multihash.constants import HASH_CODES

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class MultihashTest:

    def hacher(self, valeur: bytes, code=HASH_CODES['sha2-256']) -> bytes:
        algo = self.map_code_to_hashes(code)
        hachage = algo
        digest = hashes.Hash(hachage, backend=default_backend())
        digest.update(valeur)
        resultat_digest = digest.finalize()
        return resultat_digest

    def map_code_to_hashes(self, code: int):
        # code_hashes = multihash.multihash.constants.CODE_HASHES
        if code == 0x12:
            return hashes.SHA256()
        if code == 0x13:
            return hashes.SHA512()
        if code == 0xb240:
            return hashes.BLAKE2b(64)
        if code == 0xb260:
            return hashes.BLAKE2s(32)
        raise ValueError("Hachage non supporte : %d", code)

    def encoder_multihash(self, valeur: bytes) -> str:
        hachage_untest = self.hacher(valeur)
        mh = multihash.encode(hachage_untest, 'sha2-256')
        resultat = multihash.to_b58_string(mh)
        return resultat

    def encoder_multihash_multibase(self, valeur: bytes, encodage=HASH_CODES['sha2-256']) -> str:
        hachage_untest = self.hacher(valeur, encodage)
        mh = multihash.encode(hachage_untest, encodage)

        mb = multibase.encode('base58btc', mh)

        return mb

    def verifier_multihash(self, hachage: str, valeur: bytes):
        bytes_hash = multihash.from_b58_string(hachage)
        mh = multihash.decode(bytes_hash)
        print(mh)
        digest = mh.digest
        code = mh.code

        # Verifier hachage
        hachage = self.hacher(valeur, code)
        if digest != hachage:
            print("Erreur, hachage different")
        else:
            print("OK, hachage valeur %s match le multibase %s" % (valeur, hachage))

    def verifier_multibase(self, multibase_input: str, valeur: bytes):
        mb = multibase.decode(multibase_input)
        mh = multihash.decode(mb)
        print(mh)
        digest = mh.digest
        code = mh.code

        # Verifier hachage
        hachage = self.hacher(valeur, code)
        if digest != hachage:
            print("Erreur, hachage different")
        else:
            print("OK, hachage valeur %s match le multibase %s" % (valeur, multibase_input))

    def map_multibase_to_hash(self, multibase_input: str):
        mb = multibase.decode(multibase_input)
        mh = multihash.decode(mb)
        code = mh.code
        hash_func = self.map_code_to_hashes(code)

        return hash_func

    def executer(self):
        encodage = self.encoder_multihash(b'un test')
        self.verifier_multihash(encodage, b'un test')
        print("Encodage = %s" % encodage)

        encodage_multibase = self.encoder_multihash_multibase(b'Ceci est un test dadada')
        encodage_multibase_sha512 = self.encoder_multihash_multibase(b'Ceci est un test dadada', HASH_CODES['sha2-512'])
        encodage_multibase_blake2s = self.encoder_multihash_multibase(b'un test', HASH_CODES['blake2s-256'])
        encodage_multibase_blake2b = self.encoder_multihash_multibase(b'un test', HASH_CODES['blake2b-512'])

        print("Encodage multibase\nSHA2-256: %s\nSHA2-512: %s\nBLAKE2s: %s\nBLAKE2b: %s" % (
            encodage_multibase, encodage_multibase_sha512, encodage_multibase_blake2s, encodage_multibase_blake2b))

        self.verifier_multibase(encodage_multibase, b'un test')
        self.verifier_multibase(encodage_multibase_sha512, b'un test')
        self.verifier_multibase(encodage_multibase_sha512, b'un test')
        self.verifier_multibase(encodage_multibase_blake2b, b'un test')

        hashing_blake2b = self.map_multibase_to_hash(encodage_multibase_blake2b)
        print("Algo BLAKE2b: %s" % hashing_blake2b)


def main():
    test = MultihashTest()
    test.executer()


if __name__ == '__main__':
    main()
