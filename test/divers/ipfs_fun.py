import base58
import multihash
import binascii

import ipfshttpclient

from base64 import b64encode
from cid import make_cid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def test_cid():
    cid_example = make_cid('QmUW9wCkk1uPQE6Acpy1tJ8MhKC2hpYvz6zvKmunLPHcJc')
    print('CID V0 : %s' % cid_example)
    print('CID V1 : %s' % cid_example.to_v1())
    mh = multihash.decode(cid_example.multihash)
    print('Multihash : %s\n%s\n' % (b64encode(cid_example.multihash), mh))


def test_ipfs_api():
    client = ipfshttpclient.connect()
    client.add_bytes()

def test_fichier():
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    cid_fichier_input = 'QmP3MWVkdYUfPigW1V2FV44RDXx7STpp6vuJVFSSyuPphc'
    cid_inst = make_cid(cid_fichier_input)
    multihash_fichier = cid_inst.multihash
    multihash_inst = multihash.decode(multihash_fichier)

    path_fichier = '/home/mathieu/' + cid_fichier_input
    print("Chargement fichier %s" % cid_fichier_input)
    with open(path_fichier, 'rb') as fichier:
        digest.update(fichier.read())
        resultat_digest = digest.finalize()

    resultat_digest_binascii = binascii.hexlify(resultat_digest).decode('utf-8')
    multihash_digest_binascii = binascii.hexlify(multihash_inst.digest).decode('utf-8')

    if resultat_digest_binascii != multihash_digest_binascii:
        print("Resultats/multihash: \n%s\n%s\n" % (resultat_digest_binascii, multihash_digest_binascii))
        raise ValueError("Mauvais digest de multihash")

    print("Resultat digest : %s" % b64encode(resultat_digest))
    encoded_multihash = multihash.encode(resultat_digest, 'sha2-256')

    print('Fichier resultat : %s', encoded_multihash)
    mh = multihash.decode(encoded_multihash)
    print("Multihash %s" % str(mh))
    cid_fichier = make_cid(0, 'dag-pb', encoded_multihash)

    print('Fichier CID : %s' % cid_fichier)
    if cid_fichier.encode() != cid_fichier_input.encode('utf-8'):
        raise ValueError("CID mal calcule")


# def test1():
#     resultat = multihash.digest(b'test', 'sha2_256')
#     print(resultat)
#     print(resultat.encode('base64'))
#
#
# def test2():
#     with open('/home/mathieu/QmUW9wCkk1uPQE6Acpy1tJ8MhKC2hpYvz6zvKmunLPHcJc', 'rb') as fichier:
#         resultat = multihash.digest(fichier.read(), 'sha2_256')
#
#     print(resultat)
#     print(resultat.encode('base64'))
#
#     digest = resultat.digest
#     print("Base 58: %s" % base58.b58encode(digest))


if __name__ == '__main__':
    test_cid()
    test_ipfs_api()
    # test_fichier()
    # test2()
