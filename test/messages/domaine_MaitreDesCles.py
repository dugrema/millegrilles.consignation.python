# Script de test pour transmettre message de transaction

import datetime, time
import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.MaitreDesCles import ConstantesMaitreDesCles
from millegrilles.domaines.Parametres import ConstantesParametres
from millegrilles.util.X509Certificate import EnveloppeCleCert

from threading import Event, Thread
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat import primitives
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode
from uuid import uuid4


contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.channel = None
        self.event_recu = Event()
        # self.thread_ioloop = Thread(target=self.run_ioloop)

        self.certificat_maitredescles = None
        self.cert_maitredescles_recu = Event()

        self.mot_de_passe = 'sjdpo-1824-JWAZ'

        # Charger cert MaitreDesCles pour pouvoir crypter contenu a transmettre
        with open('/home/mathieu/mgdev/certs/pki.maitrecles.cert', 'rb') as certificat_pem:
            self.certificat_courant_pem = certificat_pem.read()
            self.clecert = EnveloppeCleCert()
            self.clecert.set_chaine_str(self.certificat_courant_pem.decode('utf-8'))
            self.clecert.cert_from_pem_bytes(self.certificat_courant_pem)
            # cert = x509.load_pem_x509_certificate(
            #     certificat_courant_pem,
            #     backend=default_backend()
            # )
            self.certificat_courant = self.clecert.cert
            self.certificat_courant_pem = self.certificat_courant_pem.decode('utf8')

        with open('/home/mathieu/mgdev/certs/pki.millegrille.cert', 'rb') as certificat_pem:
            self.certificat_millegrille_pem = certificat_pem.read()
            self.clecert_millegrille = EnveloppeCleCert()
            self.clecert_millegrille.set_chaine_str(self.certificat_millegrille_pem.decode('utf-8'))
            self.clecert_millegrille.cert_from_pem_bytes(self.certificat_millegrille_pem)
            # cert = x509.load_pem_x509_certificate(
            #     certificat_courant_pem,
            #     backend=default_backend()
            # )
            self.cert_millegrille = self.clecert_millegrille.cert
            self.cert_millegrille_pem = self.certificat_millegrille_pem.decode('utf8')

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        # self.event_recu.set()
        self.executer()

    # def run_ioloop(self):
    #     self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)

        message_dict = json.loads(body)
        certificat_pem = message_dict.get('certificat')
        if certificat_pem is not None:
            cert = EnveloppeCleCert()
            try:
                cert.cert_from_pem_bytes(certificat_pem.encode('utf-8'))
                self.certificat_maitredescles = cert
            except:
                print("Erreur traitement certificat_pem")
            self.cert_maitredescles_recu.set()
        else:
            self.event_recu.set()
            if message_dict.get('certificats_pem'):
                for cert in message_dict.get('certificats_pem'):
                    print(cert)

        print(json.dumps(message_dict, indent=4))

    def requete_cert_maitredescles(self):
        requete_cert_maitredescles = {
            # Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_trousseau_hebergement(self):
        requete = {
            'idmg': ['2aMvfBTqyfeQsMgSsYbtJuMeqUJ5TZV2iNiy2ES']
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete,
            'millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_TROUSSEAU_HEBERGEMENT,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_decryptage_cle_fuuid(self):
        requete_cert_maitredescles = {
            'fuuid': "ddb0d8f0-f7b4-11ea-89ec-13126005a8b0"
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_cle_document(self):
        fingerprint = self.clecert.fingerprint

        requete_cert_maitredescles = {
            'fingerprint': fingerprint,
            'certificat': self.certificat_courant_pem,
            'domaine': 'MaitreDesComptes',
            'identificateurs_document': {
                "libelle": "proprietaire",
                "champ": "totp"
            }
        }

        print(requete_cert_maitredescles)

        self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_DOCUMENT,
            'abcd-1234',
            self.queue_name
        )

    def requete_decryptage_cle_fuuid_avecfingerprint(self):
        requete_cert_maitredescles = {
            'fuuid': "b4ecca10-1c2b-11ea-904a-7b4d1a2d4432",
            'fingerprint': '74fd5742aec60dd37f99c75df423008a10149018'
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_cle_racine(self):
        # Attendre le certificat de maitre des cles pour chiffrer la cle
        self.cert_maitredescles_recu.wait(5)

        mot_de_passe_chiffre, fingerprint = self.certificat_maitredescles.chiffrage_asymmetrique(self.mot_de_passe.encode('utf-8'))

        requete_cle_racine = {
            'fingerprint': '',
            'mot_de_passe_chiffre': str(b64encode(mot_de_passe_chiffre), 'utf-8'),
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cle_racine,
            'millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_CLE_RACINE,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def commande_signer_cle_backup(self):
        with open ('/home/mathieu/mgdev/certs/pki.connecteur.key', 'rb') as fichier:
            key_bytes = fichier.read()

        enveloppe = EnveloppeCleCert()
        enveloppe.key_from_pem_bytes(key_bytes, None)
        public_bytes = enveloppe.public_bytes

        requete_cle_racine = {
            'cle_publique': public_bytes.decode('utf-8'),
        }
        enveloppe_requete = self.generateur.transmettre_commande(
            requete_cle_racine,
            'commande.millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.COMMANDE_SIGNER_CLE_BACKUP,
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def commande_restaurer_backup_cle(self):
        with open ('/home/mathieu/mgdev/certs/pki.connecteur.key', 'rb') as fichier:
            key_bytes = fichier.read()

        clecert = EnveloppeCleCert()
        clecert.key_from_pem_bytes(key_bytes, None)
        clecert.password = self.mot_de_passe.encode('utf-8')
        key_chiffree_bytes = clecert.private_key_bytes

        self.cert_maitredescles_recu.wait(5)
        mot_de_passe_chiffre, fingerprint = self.certificat_maitredescles.chiffrage_asymmetrique(self.mot_de_passe.encode('utf-8'))

        enveloppe = EnveloppeCleCert()
        enveloppe.key_from_pem_bytes(key_bytes, None)

        requete_cle_racine = {
            'cle_privee': key_chiffree_bytes.decode('utf-8'),
            'mot_de_passe_chiffre': str(b64encode(mot_de_passe_chiffre), 'utf-8'),
            # 'fingerprint_base64': 'Ut/UQ5aKomoGzXB7mpUduPk4Xzg=',
        }
        enveloppe_requete = self.generateur.transmettre_commande(
            requete_cle_racine,
            'commande.millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.COMMANDE_RESTAURER_BACKUP_CLES,
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def commande_creer_cles_millegrille_hebergee(self):
        enveloppe_requete = self.generateur.transmettre_commande(
            dict(),
            'commande.millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.COMMANDE_CREER_CLES_MILLEGRILLE_HEBERGEE,
            correlation_id='abcd-1234',
            reply_to=self.queue_name,
            exchange=Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE
        )

        print("Envoi commande: %s" % enveloppe_requete)
        return enveloppe_requete

    def nouvelle_cle_grosfichiers(self):

        cle_secrete = 'Mon mot de passe secret'
        clecert_chiffrage = self.clecert_millegrille
        # cert_chiffrage = self.certificat_courant
        cert_chiffrage = clecert_chiffrage.cert
        fingerprint_b64 = clecert_chiffrage.fingerprint_b64
        cle_secrete_encryptee = cert_chiffrage.public_key().encrypt(
            cle_secrete.encode('utf8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cle_secrete_encryptee_base64 = b64encode(cle_secrete_encryptee).decode('utf8')

        nouvelle_cle = {
            "domaine": "GrosFichiers",
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                "fuuid": str(uuid4()),
            },
            "cles": {fingerprint_b64: cle_secrete_encryptee_base64},
            "iv": "gA8cRaiJE+8aN2c6/N1vTg==",
            "sujet": ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_GROSFICHIERS,
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            nouvelle_cle,
            ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_GROSFICHIER,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def nouvelle_cle_document(self):

        fingerprint_b64 = self.clecert.fingerprint_b64
        cle_secrete = 'Mon mot de passe secret'
        cle_secrete_encryptee = self.certificat_courant.public_key().encrypt(
            cle_secrete.encode('utf8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        cle_secrete_encryptee_mime64 = b64encode(cle_secrete_encryptee).decode('utf8')

        nouvelle_cle = {
            "domaine": "MaitreDesComptes",
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                "_mg-libelle": "proprietaire",
                "champ": "totp",
            },
            "cles": {fingerprint_b64: cle_secrete_encryptee_mime64},
            "iv": "gA8cRaiJE+8aN2c6/N1vTg==",
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            nouvelle_cle,
            ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_DOCUMENT,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_declasser_grosfichier(self):

        transaction = {
            'fuuid': '3830311b-145f-4ab2-850e-f4defdb70767'
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            transaction,
            ConstantesMaitreDesCles.TRANSACTION_DECLASSER_CLE_GROSFICHIER,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_signer_certificat_navigateur(self):

        public_key_str = """
-----BEGIN CERTIFICATE REQUEST-----
MIICfTCCAWUCAQAwODESMBAGA1UEAxMJbm9tVXNhZ2VyMRMwEQYDVQQLEwpOYXZp
Z2F0ZXVyMQ0wCwYDVQQKEwRpZG1nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAwDlWi2KJsccrDJKHq8xLYjCqndu+Oh4GNsbRypPctuu+oU6PNkwwjSIN
xNuJret+ZVr2mw2MNbt9JYANriltYwvFWkF63NTIGXstaegNCkj6vqa4KdtXK7uu
NREtMLEhEu+ZWYcR2hWzVEN9GyIPwEgPNYQwUjjjLADUnaZ73t9Bk+fivgll0JbJ
reSw8DHqvdcmB28AnXltch6Wh34EGiYPbJqDm+NnCHHZ2EumbPRkN5/bqZTmpUDw
qqt+6cTcgAtdIuzYm3sPQt/Zf3EJwDT9dBxVrdbBnNFG4js3lauy49hog78zwwNP
/i3DZU3VDDCDeT4POKfEHXtwxTLF4QIDAQABoAAwDQYJKoZIhvcNAQENBQADggEB
AKBdiHJamlXfevloSBhehrf5g7lRbISGEsyY5HOXvVMLbip75QcGMcz8jnEJxYFk
8mDPuxlR3VOkyDiPGpLloN9hOgk50igwtRmFXcGCENbaJX2FZdho0yyx/yS03WXR
HXkje/v1Z6x1gitAxACbvvywo4qtIQoBSwP08D0JIGtD2GWPvzd1+PSgsdqQsmxz
EMkpLW0RZ2y1fCZyXbXPfAI4rnCL5Lb3CW7e4sbdH2XkcV4fBPEDGo03TE8648XV
6PCY9G7vw3iPiAhicMp1nI9bx+N/IapZvWmqR8vOURfFHYB1ilnli7S3MNXpDC9Q
BMz4ginADdtNs9ARr3DcwG4=
-----END CERTIFICATE REQUEST-----
        """

        commande = {
            'est_proprietaire': True,
            'csr': public_key_str,
        }

        enveloppe_val = self.generateur.transmettre_commande(
            commande,
            'commande.MaitreDesCles.' + ConstantesMaitreDesCles.COMMANDE_SIGNER_NAVIGATEUR_CSR,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_demande_inscription_tierce(self):
        transaction = {
            'idmg': '33KRMhqcWCKvMHyY5xymMCUEbT53Kg1NqUb9AU6'
        }
        domaine = ConstantesMaitreDesCles.TRANSACTION_GENERER_DEMANDE_INSCRIPTION

        enveloppe_val = self.generateur.soumettre_transaction(
            transaction,
            domaine,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_signature_inscription_tierce(self):
        with open('/home/mathieu/PycharmProjects/MilleGrilles.consignation.python/test/messages/demande_connexion.json') as fichier:
            transaction = json.load(fichier)
        domaine = ConstantesMaitreDesCles.TRANSACTION_GENERER_CERTIFICAT_POUR_TIERS

        enveloppe_val = self.generateur.soumettre_transaction(
            transaction,
            domaine,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_supprimer_trousseau_hebergement(self):
        domaine = ConstantesMaitreDesCles.TRANSACTION_HEBERGEMENT_SUPPRIMER

        enveloppe_val = self.generateur.soumettre_transaction(
            {'idmg': '3M87pZxVVWbT1dVLeRarQnge1mvADTs4trG7Caa'},
            domaine,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def commande_signer_csr(self):
        clecert = EnveloppeCleCert()
        clecert.generer_private_key(generer_password=True, keysize=4096)

        public_key = clecert.private_key.public_key()
        builder = x509.CertificateSigningRequestBuilder()
        name = x509.Name([
            x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, '3aeGLdmMbA1BrmRYwpPgNAZKH2WGWmSedBjKSxw'),
            x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, 'domaines'),
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, 'test')
        ])
        builder = builder.subject_name(name)
        request = builder.sign(
            clecert.private_key, hashes.SHA256(), default_backend()
        )
        request_pem = request.public_bytes(primitives.serialization.Encoding.PEM)

        commande = {
            'liste_csr': [request_pem.decode('utf-8')],
        }
        enveloppe_requete = self.generateur.transmettre_commande(
            commande,
            'commande.millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.COMMANDE_SIGNER_CSR,
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def commande_signer_csr_noeud_prive(self):
        clecert = EnveloppeCleCert()
        clecert.generer_private_key(keysize=2048)

        public_key = clecert.private_key.public_key()
        builder = x509.CertificateSigningRequestBuilder()
        name = x509.Name([
            # x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, '3aeGLdmMbA1BrmRYwpPgNAZKH2WGWmSedBjKSxw'),
            x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, 'intermediaire'),
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, str(uuid4()))
        ])
        builder = builder.subject_name(name)
        request = builder.sign(
            clecert.private_key, hashes.SHA256(), default_backend()
        )
        request_pem = request.public_bytes(primitives.serialization.Encoding.PEM)

        commande = {
            'liste_csr': [request_pem.decode('utf-8')],
            'role': 'prive'
        }
        enveloppe_requete = self.generateur.transmettre_commande(
            commande,
            'commande.MaitreDesCles.%s' % ConstantesMaitreDesCles.COMMANDE_SIGNER_CSR,
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_cles_non_dechiffrables(self):
        requete_cle_racine = {
            'taille': 2
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cle_racine,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_CLES_NON_DECHIFFRABLES,
            'abcd-1234',
            self.queue_name
        )
        return enveloppe_requete

    def executer(self):
        # self.event_recu.wait(5)
        # self.event_recu.clear()

        # enveloppe = self.requete_cert_maitredescles()
        # self.requete_trousseau_hebergement()

        for i in range(0, 200):
            enveloppe = self.nouvelle_cle_grosfichiers()
        # enveloppe = self.nouvelle_cle_document()
        # enveloppe = self.transaction_declasser_grosfichier()
        # enveloppe = self.transaction_signer_certificat_navigateur()
        # enveloppe = self.requete_decryptage_cle_fuuid()
        # enveloppe = self.requete_decryptage_cle_fuuid_avecfingerprint()
        # self.transaction_demande_inscription_tierce()
        # self.transaction_signature_inscription_tierce()
        # self.transaction_supprimer_trousseau_hebergement()
        # self.requete_cle_document()

        # self.requete_cle_racine()
        # self.commande_signer_cle_backup()
        # self.commande_restaurer_backup_cle()
        # self.commande_creer_cles_millegrille_hebergee()
        # self.commande_signer_csr()
        # self.commande_signer_csr_noeud_prive()

        # self.requete_cles_non_dechiffrables()


# --- MAIN ---
sample = MessagesSample()

# TEST
# sample.executer()

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()
