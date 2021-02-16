# Test chiffrage et dechiffrage JSON
import logging
import secrets
import binascii
from base64 import b64encode, b64decode

# from millegrilles.util.BaseTestMessages import DomaineTest
# from millegrilles.SecuritePKI import SignateurTransaction
from millegrilles.util.Chiffrage import CipherMsg1Chiffrer, CipherMsg2Dechiffrer

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
            "contenu_chiffre": "AWfkRhmWpd72QSPDv3Hs9fkr4ja4NA4DE0cC4KUracovDBCrOiqf4KhsZ5nKJMrPv2kwoavFQJBR",
            "iv": "SeAwHmHq+Ai4g6Mqkpf1gg==",
            "cle_secrete": "NDUyMDcwNjA1YTRiZmRmYTE5ZDIwNDllNWEzNjk0MTg4YjBlZTQ3YjMwNmFiNDI3ZGIyYzI1ODc1ODZiNDNjNQ==",
            "compute_tag": "1qixY0o+GF+XdF92pSEArQ==",
        }

        self.contenu_dechiffre = None

    def chiffrer_contenu(self):
        cipher = CipherMsg1Chiffrer()
        valeur_init = cipher.start_encrypt()
        contenu_chiffre = valeur_init + cipher.update(self.contenu_original['secret'].encode('utf-8')) + cipher.finalize()

        self.contenu = {
            "contenu_chiffre": b64encode(contenu_chiffre).decode('utf-8'),
            "iv": b64encode(cipher.iv).decode('utf-8'),
            "cle_secrete": b64encode(binascii.hexlify(cipher.password)).decode('utf-8'),
        }

        print('Contenu chiffre : %s' % str(self.contenu))

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
        # self.chiffrer_contenu()
        self.dechiffrer_contenu()


# --- MAIN ---
if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('millegrilles').setLevel(logging.DEBUG)
    logging.getLogger('TestChiffrage').setLevel(logging.DEBUG)
    test = TestChiffrage()
    test.executer()
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