import json
import lzma

from base64 import b64encode, b64decode
from os import path

from millegrilles.util.Chiffrage import CipherMsg1Chiffrer, CipherMsg1Dechiffrer
from millegrilles.SecuritePKI import EnveloppeCertificat
from millegrilles.util.X509Certificate import EnveloppeCleCert


class TestChiffrage:

    def __init__(self):
        with open('/home/mathieu/mgdev/certs/pki.fichiers.cert', 'r') as fichier:
            certificat_pem = fichier.read()
        self._enveloppe = EnveloppeCertificat(certificat_pem=certificat_pem)

    def chiffrer(self) -> (bytes, bytes, bytes):
        chiffreur = CipherMsg1Chiffrer()

        contenu = 'abcdefghijklmnopqrstuvwxyz0123456789'.encode('utf-8')
        data = chiffreur.start_encrypt()
        data = data + chiffreur.update(contenu)
        data = data + chiffreur.finalize()

        print("Data chiffree : %s" % data)

        print("Mot de passe chiffre " + b64encode(chiffreur.chiffrer_motdepasse_enveloppe(self._enveloppe)).decode('utf-8'))

        return data, chiffreur.iv, chiffreur.password

    def dechiffrer(self, data_chiffree: bytes, iv: bytes, password: bytes) -> bytes:
        dechiffreur = CipherMsg1Dechiffrer(iv, password)

        # print("Data init : %s" % data)
        data = dechiffreur.update(data_chiffree)
        data = data + dechiffreur.finalize()

        print("Data dechiffree : %s" % data)

        return data


class TestFichier:

    def chiffrer(self, path_src: str, path_dst: str):
        chiffreur = CipherMsg1Chiffrer()

        with open(path_src, 'rb') as fichier_in:
            with open(path_dst, 'wb') as fichier_out:
                fichier_out.write(chiffreur.start_encrypt())
                fichier_out.write(chiffreur.update(fichier_in.read()))
                fichier_out.write(chiffreur.finalize())

        iv_b64 = b64encode(chiffreur.iv)
        pwd_b64 = b64encode(chiffreur.password)
        print("IV = %s , password = %s" % (iv_b64.decode('utf-8'), pwd_b64.decode('utf-8')))

    def dechiffrer(self, path_src: str, path_dst: str, iv: str, password: str):
        iv_bytes = b64decode(iv)
        password_bytes = b64decode(password)
        dechiffreur = CipherMsg1Dechiffrer(iv_bytes, password_bytes)

        with open(path_src, 'rb') as fichier_in:
            with open(path_dst, 'wb') as fichier_out:
                fichier_out.write(dechiffreur.update(fichier_in.read()))
                fichier_out.write(dechiffreur.finalize())

    def dechiffrer_asymmetrique(self, path_src: str, path_dst: str, iv: str, password: str, enveloppe):
        password_dechiffre = CipherMsg1Dechiffrer.dechiffrer_cle(enveloppe.private_key, password)
        password_dechiffre_b64 = b64encode(password_dechiffre)
        return self.dechiffrer(path_src, path_dst, iv, password_dechiffre_b64)

def chiffrer_fichier():
    src_cat = '/tmp/mgbackup/test.txt'
    dst_cat = '/tmp/mgbackup/test.txt.msg1'
    test_fichier = TestFichier()
    test_fichier.chiffrer(src_cat, dst_cat)


def dechiffrer_fichier():
    iv = 'Mo0a5RMJG4f8zjM2rQuq/g=='
    password = 'SFwNzzIPbKi4BzByfGBhJA4JZ6XWn+6xm6MW5RbrUrA='
    src = '/tmp/mgbackup/MaitreDesCles_transactions_2020092412_3.protege.json.xz'
    dst = '/tmp/mgbackup/MaitreDesCles_transactions_2020092412_3.protege.json.out.xz'

    test_fichier = TestFichier()
    test_fichier.dechiffrer(src, dst, iv, password)


def dechiffrer_backup(path_catalogue):
    with lzma.open(path_catalogue, 'rb') as fichier:
        catalogue = json.load(fichier)

    path_archives = path.dirname(path_catalogue)
    path_transactions = path.abspath(path.join(path_archives, '..', 'transactions'))

    nom_transaction = catalogue['transactions_nomfichier']
    path_fichier_transactions = path.join(path_transactions, nom_transaction)
    path_output = path_fichier_transactions.replace('.mgs1', '')

    iv = catalogue['iv']
    password = catalogue['cle']

    # Dechiffrer cle secrete avec cle de millegrille
    with open('/home/mathieu/mgdev/cle_mg/cle.pem', 'r') as fichier:
        private_key = fichier.read()
    with open('/home/mathieu/mgdev/cle_mg/password.txt', 'r') as fichier:
        pwd_cle_privee = fichier.read()
    pwd_cle_privee = pwd_cle_privee.strip().encode('utf-8')

    clecert_millegrille = EnveloppeCleCert()
    clecert_millegrille.key_from_pem_bytes(private_key.encode('utf-8'), pwd_cle_privee)

    test_fichier = TestFichier()

    test_fichier.dechiffrer_asymmetrique(path_fichier_transactions, path_output, iv, password, clecert_millegrille)


def run_test():
    # test = TestChiffrage()
    # data, iv, password = test.chiffrer()
    # test.dechiffrer(data, iv, password)

    # chiffrer_fichier()
    # dechiffrer_fichier()

    dechiffrer_backup('/var/opt/millegrilles/consignation/JPtGcNcFSkfSdw49YsDpQHKxqTHMitpbPZW17a2JC54T/backup/horaire/2020/09/24/12/catalogues/MaitreDesCles_catalogue_2020092412_3.protege.json.xz')



# --------- MAIN -------------
if __name__ == '__main__':
    run_test()
