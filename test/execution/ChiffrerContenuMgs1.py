from base64 import b64encode

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


def run_test():
    test = TestChiffrage()
    data, iv, password = test.chiffrer()
    test.dechiffrer(data, iv, password)


# --------- MAIN -------------
if __name__ == '__main__':
    run_test()
