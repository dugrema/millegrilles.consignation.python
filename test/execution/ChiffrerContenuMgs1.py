from base64 import b64encode, b64decode

from millegrilles.util.Chiffrage import CipherMsg1Chiffrer, CipherMsg1Dechiffrer
from millegrilles.SecuritePKI import EnveloppeCertificat


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


def run_test():
    # test = TestChiffrage()
    # data, iv, password = test.chiffrer()
    # test.dechiffrer(data, iv, password)

    # chiffrer_fichier()
    dechiffrer_fichier()



# --------- MAIN -------------
if __name__ == '__main__':
    run_test()
