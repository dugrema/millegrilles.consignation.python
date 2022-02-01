# Test chiffrage et dechiffrage JSON
import logging
import json
import binascii
import multibase

from base64 import b64encode, b64decode

# from millegrilles.util.BaseTestMessages import DomaineTest
# from millegrilles.SecuritePKI import SignateurTransaction
from millegrilles.util.Chiffrage import CipherMsg2Chiffrer, CipherMsg2Dechiffrer, CipherMgs3Chiffrer, CipherMgs3Dechiffrer, chiffrer_cle_ed25519, dechiffrer_cle_ed25519
from millegrilles.util.X509Certificate import EnveloppeCleCert

# cle_secrete = secrets.token_bytes(32)
# cle_secrete_b64 = base64.b64encode(cle_secrete).decode('utf-8')
# print('Cle secrete : %s' % cle_secrete_b64)

# Note speciale sur la cle secrete (password) :
#   -> Le format est binhex (01234567890abcdef) encode en UTF-8, re-encode en base64
#   Le format de base en mode asymmetrique est str binhex, ici on fait juste simuler ce format.


class TestChiffrage:

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.contenu_original = {
            'secret': 'message secret a chiffrer',
            'public': 'Tout le monde peut voir ca',
        }

        self.contenu = None

        self.contenu = {
            "contenu_chiffre": "is3XXgbDgigKA1HZwJc=",
            "iv": "zkLhAjKVG/Tq+h25ku8ftw==",
            "cle_secrete": "ZjBkOTFjN2NmODg5YzdkODMyMjE3Zjg1ZmRjMmYxZmIxNTgwYzhjNDFhNGMwMDM2NzA1MDU5YTRiMDU3NmVmMA==",
            "compute_tag": "EuAIcvP8yFDfHsZfy6kUTQ==",
        }

        self.contenu_dechiffre = None

    def chiffrer_contenu(self):
        cipher = CipherMsg2Chiffrer()
        valeur_init = cipher.start_encrypt()
        contenu_chiffre = valeur_init + cipher.update(self.contenu_original['secret'].encode('utf-8')) + cipher.finalize()
        compute_tag = cipher.tag

        self.contenu = {
            "contenu_chiffre": b64encode(contenu_chiffre).decode('utf-8'),
            "iv": b64encode(cipher.iv).decode('utf-8'),
            "cle_secrete": b64encode(binascii.hexlify(cipher.password)).decode('utf-8'),
            "compute_tag": b64encode(compute_tag).decode('utf-8'),
        }

        print('Contenu chiffre : %s' % json.dumps(self.contenu, indent=2))

    def dechiffrer_contenu(self):

        iv = b64decode(self.contenu['iv'].encode('utf-8'))
        compute_tag = b64decode(self.contenu['compute_tag'].encode('utf-8'))

        cle_secrete = b64decode(self.contenu['cle_secrete'].encode('utf-8'))
        # Unhexlify
        try:
            cle_secrete = binascii.unhexlify(cle_secrete)
        except Exception:
            self.__logger.info("Cle pas en format hex")

        decipher = CipherMsg2Dechiffrer(iv, cle_secrete, compute_tag)
        contenu = decipher.update(b64decode(self.contenu['contenu_chiffre'].encode('utf-8'))) + decipher.finalize()

        # iv_dechiffre = contenu[0:16]
        # print("IV dechiffre : %s" % b64encode(iv_dechiffre))
        #if iv_dechiffre != iv:
        #    raise Exception("IV!")
        self.contenu_dechiffre = contenu.decode('utf-8')

        print("Contenu dechiffre : %s" % self.contenu_dechiffre)

    def executer(self):
        self.__logger.debug("Executer")
        self.chiffrer_contenu()
        self.dechiffrer_contenu()


class TestChiffrageMgs3:

    def __init__(self):
        super().__init__()
        self.__logger = logging.getLogger(self.__class__.__name__)

        self.clecert_ca = EnveloppeCleCert()
        self.clecert_ca.generer_private_key()

        self.contenu_original = {
            'secret': 'message secret a chiffrer',
            'public': 'Tout le monde peut voir ca',
        }

        self.contenu = None

        self.contenu_dechiffre = None

    def chiffrer_contenu(self):
        cle_x25519 = self.clecert_ca.get_public_x25519()
        cipher = CipherMgs3Chiffrer(cle_x25519)
        valeur_init = cipher.start_encrypt()
        contenu_chiffre = valeur_init
        contenu_chiffre = contenu_chiffre + cipher.update(self.contenu_original['secret'].encode('utf-8'))
        contenu_chiffre = contenu_chiffre + cipher.finalize()
        compute_tag = cipher.tag

        meta_info = cipher.get_meta()

        self.contenu = {
            "contenu_chiffre": multibase.encode('base64', contenu_chiffre).decode('utf-8'),
            # "iv": b64encode(cipher.iv).decode('utf-8'),
            # "cle_secrete": b64encode(binascii.hexlify(cipher.password)).decode('utf-8'),
            # "compute_tag": b64encode(compute_tag).decode('utf-8'),
        }
        self.contenu.update(meta_info)

        print('Contenu chiffre : %s' % json.dumps(self.contenu, indent=2))

    def dechiffrer_contenu(self):

        iv = self.contenu['iv']
        compute_tag = self.contenu['tag']

        cle_secrete = CipherMgs3Dechiffrer.dechiffrer_cle(self.clecert_ca, self.contenu['cle_chiffree'])
        # S'assurer que la cle secrete correspond
        cle_secrete_originale = multibase.decode(self.contenu['cle_secrete'].encode('utf-8'))
        if cle_secrete_originale != cle_secrete:
            raise Exception("Erreur preparer cle secrete, mismatch")

        decipher = CipherMgs3Dechiffrer(iv, cle_secrete_originale, compute_tag)
        contenu_chiffre = multibase.decode(self.contenu['contenu_chiffre'].encode('utf-8'))

        contenu_dechiffre = decipher.update(contenu_chiffre)
        decipher.finalize()

        # iv_dechiffre = contenu[0:16]
        # print("IV dechiffre : %s" % b64encode(iv_dechiffre))
        #if iv_dechiffre != iv:
        #    raise Exception("IV!")
        self.contenu_dechiffre = contenu_dechiffre.decode('utf-8')

        print("Contenu dechiffre : %s" % self.contenu_dechiffre)

    def executer(self):
        self.__logger.debug("Executer")
        self.chiffrer_contenu()
        self.dechiffrer_contenu()


class TestChiffrageEd25519:

    def __init__(self):
        self.cle_secrete = bytearray(32)

    def cycle_chiffrage(self):
        enveloppe = EnveloppeCleCert()
        enveloppe.generer_private_key()
        cle_chiffree = chiffrer_cle_ed25519(enveloppe, bytes(self.cle_secrete))
        print("Cle secrete chiffree 80 bytes : %s" % cle_chiffree)

        cle_dechiffree = dechiffrer_cle_ed25519(enveloppe, cle_chiffree)

        if cle_dechiffree == self.cle_secrete:
            print("OK, cle dechiffree via Ed25519 correspond")
        else:
            raise Exception("Erreur, cle dechiffree via Ed25519 ne correspond pas")


# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('TestChiffrage').setLevel(logging.DEBUG)

    # test = TestChiffrage()
    # test.executer()

    test3 = TestChiffrageMgs3()
    test3.executer()

    #test_ed25519 = TestChiffrageEd25519()
    #test_ed25519.cycle_chiffrage()

    pass
    # TEST


## Code JavaScript
## import {CryptageSymetrique, str2ab, bufferToBase64, ab2hex} from '@dugrema/millegrilles.common/lib/cryptoSubtle'
#
# chiffrer = async event => {
#   console.debug("Chiffrer")
#   const cryptageSymetrique = new CryptageSymetrique()
#   const contenuAb = new TextEncoder("utf-8").encode(this.state.contenuOriginal)
#   const resultatChiffrage = await cryptageSymetrique.crypterContenu(contenuAb)
#   console.debug("Contenu chiffre : %O", resultatChiffrage)
#   this.setState({
#     contenuChiffre: bufferToBase64(resultatChiffrage.bufferCrypte),
#     ivBase64: resultatChiffrage.ivString,
#     passwordBase64: bufferToBase64(str2ab(ab2hex(resultatChiffrage.cleSecreteExportee))),
#   }, _=>{
#     console.debug("State apres chiffrage : %O", this.state)
#   })
#
#   // Test dechiffrer inline
#   const contenuDechiffre = await cryptageSymetrique.decrypterContenu(
#     resultatChiffrage.bufferCrypte, resultatChiffrage.cleSecrete, resultatChiffrage.iv)
#   var contenuDechiffreString = new TextDecoder().decode(contenuDechiffre)
#   console.debug("Contenu dechiffre inline : %O", contenuDechiffreString)
# }
#
# dechiffrer = async event => {
#   console.debug("Dechiffrer")
#   const cryptageSymetrique = new CryptageSymetrique()
#   const cleIv = await cryptageSymetrique.chargerCleSecrete(this.state.passwordBase64, this.state.ivBase64)
#   const contenuChiffreBinary = atob(this.state.contenuChiffre)
#   const contenuChiffreAb = str2ab(contenuChiffreBinary)
#
#   console.debug("Cle dechiffrage : %O\nContenu chiffre: %O", cleIv, contenuChiffreAb.buffer)
#
#   try {
#     const contenuDechiffreAb = await cryptageSymetrique.decrypterContenu(contenuChiffreAb.buffer, cleIv.cleSecrete, cleIv.iv)
#     var contenuDechiffre = new TextDecoder().decode(contenuDechiffreAb)
#     console.debug("Contenu dechiffre : %O", contenuDechiffre)
#     this.setState({contenuDechiffre})
#   } catch(err) {
#     console.error("Erreur dechiffrage : %O", err)
#   }
# }