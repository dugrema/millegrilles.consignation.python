from millegrilles import Constantes
from millegrilles.Constantes import ConstantesMessagerie
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles.util.Chiffrage import ChiffrerChampDict
from millegrilles.SecuritePKI import EnveloppeCertificat
from threading import Event
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

import json
import datetime
import uuid
import logging
import multibase

logging.basicConfig(level=logging.ERROR)
logging.getLogger('millegrilles').setLevel(logging.INFO)
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)

        self.queue_name = None
        self.channel = None
        self.event_recu = Event()

        with open('/home/mathieu/mgdev/certs/pki.maitrecles.cert', 'r') as fichier:
            cert_maitrecles = fichier.read()
            cert_enveloppe = EnveloppeCertificat(certificat_pem=cert_maitrecles)
            self.cert_maitrecles = cert_enveloppe.chaine_pem()

        with open(self.contexte.configuration.mq_cafile, 'r') as fichier:
            self.cacert = fichier.read()

        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        logger.debug("Channel open %s" % channel)
        channel.queue_declare('', durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        logger.debug("Queue open: %s" % str(self.queue_name))

        self.channel.basic_consume(self.queue_name, self.callbackAvecAck, auto_ack=False)

        logger.debug("Demarrer execution")
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        message = json.loads(str(body, 'utf-8'))
        print(json.dumps(message, indent=4))

    def poster_message(self):
        to = ['@proprietaire/mg-dev5.maple.maceroc.com', '@p/mg-dev5.maple.maceroc.com']
        cc = ['@buzzah/mg-dev5.maple.maceroc.com']
        attachments = []
        attachments_inline = [{'content': 'mEFGH5678', 'nom_fichier': 'monfichier.jpg', 'mimetype': 'image/jpeg'}]
        message = {
            'to': to,
            'cc': cc,
            'from': '@mathieu/mg-dev5.maple.maceroc.com',
            'reply_to': '@mathieu/mg-dev5.maple.maceroc.com',
            'subject': 'Ca commence a faire des messages',
            'content': 'Pas pire, y''a des messages qui arrivent.',
            'attachments': attachments,
            'attachments_inline': attachments_inline,
        }
        message_signe = self.generateur.preparer_enveloppe(message, version=1)
        logger.debug("Message signe\n%s" % json.dumps(message_signe, indent=2))

        header = {
            'from': '@mathieu/mg-dev5.maple.maceroc.com',
            'subject': 'Mon 4e message de test',
        }
        header_signe = self.generateur.preparer_enveloppe(header, version=1)
        logger.debug("Header signe\n%s" % json.dumps(header_signe, indent=2))

        dests = to.copy()
        dests.extend(cc)

        cert_maitrecles = {
            'certificat': self.cert_maitrecles,
            'certificat_millegrille': self.cacert,
        }

        # Chiffrer message
        chiffreur = ChiffrerChampDict(contexte)
        message_chiffre_info = chiffreur.chiffrer(cert_maitrecles, ConstantesMessagerie.DOMAINE_NOM, {"message": 'true'}, message_signe)
        message_maitredescles = message_chiffre_info['maitrecles']
        logger.debug("Emettre message maitre des cles %s" % json.dumps(message_maitredescles, indent=2))

        del message_maitredescles['en-tete']
        del message_maitredescles['_signature']
        message_chiffre = message_chiffre_info['secret_chiffre']
        partition = message_chiffre_info['partition']

        # Valider chiffrage (pour test/debug)
        chacha = ChaCha20Poly1305(message_chiffre_info['cle_secrete'])
        message_chiffre_tag = multibase.decode(message_chiffre) + multibase.decode(message_maitredescles['tag'])
        iv_bytes = multibase.decode(message_maitredescles['iv'])
        message_str = chacha.decrypt(iv_bytes, message_chiffre_tag, None)
        logger.debug("Message dechiffre (**TEST**)\n%s" % message_str)

        # Chiffrer en-tete - reutiliser la cle secrete (password)
        chiffreur_entete = ChiffrerChampDict(contexte, password=message_chiffre_info['cle_secrete'])
        entete_chiffre_info = chiffreur_entete.chiffrer(cert_maitrecles, ConstantesMessagerie.DOMAINE_NOM, {"header": 'true'}, header_signe)
        logger.debug("Entete chiffree info : %s" % entete_chiffre_info)
        entete_maitredescles = message_chiffre_info['maitrecles']
        entete_iv = entete_maitredescles['iv']
        entete_tag = entete_maitredescles['tag']

        header = {'iv': entete_iv, 'tag': entete_tag, 'content': multibase.encode('base64', entete_chiffre_info['secret_chiffre']).decode('utf-8')}

        self.generateur.transmettre_commande(
            message_maitredescles,
            domaine=Constantes.ConstantesMaitreDesCles.DOMAINE_NOM,
            action=Constantes.ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE,
            partition=partition,
            exchange=Constantes.SECURITE_PRIVE,
            correlation_id='abcd-1234', reply_to=self.queue_name,
            ajouter_certificats=True,
        )

        commande = {
            # 'header': header,
            'message_chiffre': message_chiffre,
            'hachage_bytes': message_maitredescles['hachage_bytes'],
            'attachments': attachments,
            'to': dests,
            'bcc': ['@mathieu/mg-dev5.maple.maceroc.com'],
            'fingerprint_certificat': message_signe['en-tete']['fingerprint_certificat'],
        }
        domaine = ConstantesMessagerie.DOMAINE_NOM
        action = 'poster'
        logger.debug("Emettre message chiffre %s" % json.dumps(commande, indent=2))
        enveloppe = self.generateur.transmettre_commande(
            commande,
            domaine=domaine, action=action, exchange=Constantes.SECURITE_PRIVE,
            correlation_id='abcd-1234', reply_to=self.queue_name,
            ajouter_certificats=True,
        )

        logger.debug("Envoi : %s" % enveloppe)
        return enveloppe

    def get_liste_messages(self):
        requete = {}
        domaine = ConstantesMessagerie.DOMAINE_NOM
        action = 'getMessages'
        self.generateur.transmettre_requete(
            requete,
            domaine=domaine, action=action, securite=Constantes.SECURITE_PRIVE,
            correlation_id='abcd-1234', reply_to=self.queue_name,
            ajouter_certificats=True,
        )

    def executer(self):
        event = Event()
        event.wait(2)

        try:
            self.poster_message()
            # self.get_liste_messages()
        except:
            logger.exception("Erreur execution")


# --- MAIN ---
sample = MessagesSample()

# TEST

# FIN TEST
sample.event_recu.wait(60)
sample.deconnecter()


