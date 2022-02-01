from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import poly1305
import multibase
import os

message_1 = b"un message secret"
key_1 = b"m7o6Oy11rqROwiWk/UgE1zq+UifXeMYdwecDhDZkjENo"
nonce_1 = b"mwbQUFbYMUR1f3eu5"
cyphertext_1 = b"mTkvJw79bU02T7aVAMa2APm8xUs5Ao/9YX+n1gEqbXwfa"


def chiffrer_chacha20poly1305():
    key = multibase.decode(key_1)
    nonce = multibase.decode(nonce_1)

    chacha = ChaCha20Poly1305(key)
    cyphertext = chacha.encrypt(nonce, message_1, None)

    cyphertext_str = multibase.encode("base64", cyphertext)
    print("Cyphertext : %s" % cyphertext_str)


def dechiffrer_chacha20poly1305():
    key = multibase.decode(key_1)
    nonce = multibase.decode(nonce_1)

    chacha = ChaCha20Poly1305(key)
    message_str = chacha.decrypt(nonce, cyphertext_1, None)

    print("Message dechiffre : %s" % message_str)


def chiffrer_avec_update():
    key = multibase.decode(key_1)
    nonce = multibase.decode(nonce_1)
    nonce = nonce + bytes([0, 0, 0, 1])

    algorithm = algorithms.ChaCha20(key, nonce)
    p = poly1305.Poly1305(key)
    cipher = Cipher(algorithm, mode=None)
    encryptor = cipher.encryptor()

    cypher1 = encryptor.update(message_1)
    p.update(message_1)

    tag = p.finalize()
    cypher_complet = cypher1 + tag

    cypher_str = multibase.encode('base64', cypher_complet)
    print("Message chiffre : %s" % cypher_str)


def generer_cle():
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)

    key_str = multibase.encode('base64', key)
    nonce_str = multibase.encode('base64', nonce)

    print("Key: %s\nNonce: %s" % (key_str, nonce_str))


def main():
    # generer_cle()
    # chiffrer_chacha20poly1305()
    # dechiffrer_chacha20poly1305()
    chiffrer_avec_update()


if __name__ == '__main__':
    main()
