# Script de test pour transmettre message de transaction

import datetime, time

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.MaitreDesCles import ConstantesMaitreDesCles
from millegrilles.domaines.Parametres import ConstantesParametres

from threading import Event, Thread
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser(init_document=False)

class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.channel = None
        self.event_recu = Event()
        # self.thread_ioloop = Thread(target=self.run_ioloop)

        # Charger cert MaitreDesCles pour pouvoir crypter contenu a transmettre
        with open('/home/mathieu/mgdev/certs/pki.maitrecles.cert', 'rb') as certificat_pem:
            certificat_courant_pem = certificat_pem.read()
            cert = x509.load_pem_x509_certificate(
                certificat_courant_pem,
                backend=default_backend()
            )
            self.certificat_courant = cert
            self.certificat_courant_pem = certificat_courant_pem.decode('utf8')

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare(durable=True, exclusive=True, callback=self.queue_open)

    def queue_open(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))

        self.channel.basic_consume(self.callbackAvecAck, queue=self.queue_name, no_ack=False)
        self.executer()

    # def run_ioloop(self):
    #     self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(body)
        self.event_recu.set()

    def requete_cert_maitredescles(self):
        requete_cert_maitredescles = {
            Constantes.TRANSACTION_MESSAGE_LIBELLE_EVENEMENT: ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_CERT_MAITREDESCLES,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_decryptage_cle_fuuid(self):
        requete_cert_maitredescles = {
            'fuuid': "b4ecca10-1c2b-11ea-904a-7b4d1a2d4432"
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'millegrilles.domaines.MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECRYPTAGE_GROSFICHIER,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

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

    def nouvelle_cle_grosfichiers(self):

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
            "domaine": "millegrilles.domaines.GrosFichiers",
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: "39c1e1b0-b6ee-11e9-b0cd-d30e8faa841c",
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                "fuuid": "39c1e1b0-b6ee-11e9-b0cd-d30e8faa851a",
            },
            "fingerprint": "abcd",
            "cle": cle_secrete_encryptee_mime64,
            "iv": "gA8cRaiJE+8aN2c6/N1vTg==",
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
            "domaine": "millegrilles.domaines.Parametres",
            Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID: "39c1e1b0-b6ee-11e9-b0cd-d30e8faa841c",
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                Constantes.DOCUMENT_INFODOC_LIBELLE: ConstantesParametres.LIBVAL_EMAIL_SMTP,
            },
            "fingerprint": "abcd",
            "cle": cle_secrete_encryptee_mime64,
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

        public_key_str = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYE8pRzlFVwAgc2uB3ot6Ffd8pPpG4Sb8btFdjArvYcbuWvsRntBUgm/w6c831GpEoOrDr/EoEPRgTjJ81zxa1tkFprsmw9t8HJ0IOV9WF6p1X8gvf4FZaeLW6wTcA6LGhk1lRoN0jIr0VhNBejX4Xl7m7B1hR+pgmafG9Qm9acAZx2+opi9cYkG0lcl33R/106x8nnaF3jwjhBjFEazH5roHN9W253Y1subRXYC0Uq6SIlzN2HDPLn0oHLujAmf0NP6PrqHmDxfrnWc+KKuSJD2Dyf8w07AjJwJgpmWa9JrcqvYjR/BViI06/CqrtJpSAHpCguSQB3QbidSzbFF3wIDAQAB'

        transaction = {
            'sujet': 'test-domaine_MaitreDescLes',
            'cle_publique': public_key_str,
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            transaction,
            ConstantesMaitreDesCles.TRANSACTION_GENERER_CERTIFICAT_NAVIGATEUR,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def transaction_demande_inscription_tierce(self):
        transaction = {
            'idmg': 'jFMV6jSR9e1oNKJi3CqwL1QGywr'
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
        transaction = {
            'idmg_sollicite': 'Mouahahah',
            'csr_correlation': 'Corrollaire',
            'csr': '-----BEGIN CERTIFICATE REQUEST-----\nMIICkTCCAXkCAQAwOzEkMCIGA1UECgwbakZNVjZqU1I5ZTFvTktKaTNDcXdMMVFH\neXdyMRMwEQYDVQQDDApDb25uZWN0ZXVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEA3Dbb7b98K8F67t9tSeW+CWt/IcHQbYcrL/w5jkfVgmtQVykD5cLf\nPd0EF+0K5u+l3IiS8Wb7cHXdvCsN8LlIaeui7Ce6F9AfnJ8CzARHeErrC+tyY2D3\nL3GIQY4nmADpBjoIj2Afr5cm+gTLEYmpIrBsMxkPI80W9zP0WxNHXNm+F47ROgPy\nJmCUHnojTfMgnQGdb44eR/yXvM7Jl00X7bTQlBlRL0Msoihzqk/74JkbevTB9IT3\nauOk9JWHVum0eCk49UfRY7BE4EZKXUuiRnLDtdoe2eTRU6Q9y1n2r+lPgnPy29Fi\nN2o6ZqvNLbGnWxLoqBdlrLJJFYpNRhLHSwIDAQABoBEwDwYJKoZIhvcNAQkOMQIw\nADANBgkqhkiG9w0BAQsFAAOCAQEA1MjxG261aFWO0ZJdGFpePnC34in/eHjN2u4n\nW5DkXp/bXEibjPN3tOk05LIDzYfiGy0C7zRbxDSqAkJ0sT92pk6a0EYqo7lmQZm8\nsZHH9xGYY6cETvtc231+RTkK//Xl8OaHfQB3Qn/zRfAUZBnjy3ScP+zKwNiH1aZq\nz82LSiQ4ZUNUj+wgdz7Ucv0D0sRr9f9FA3xR7xU1o9nK2RGLjjRxrYAWZjmlXTDT\nVi/HuAPAIdWRvQHw8IqPRAoVIk9y6c7/OrUFtMN8mSt3Te8hvnPGuAZtWs8Q+URj\nn+kd8f1d7muFZSTCjLNoRGzqGr5533hhs+cgPBFnT+jI2BUZ7g==\n-----END CERTIFICATE REQUEST-----\n'
        }
        domaine = ConstantesMaitreDesCles.TRANSACTION_GENERER_CERTIFICAT_POUR_TIERS

        enveloppe_val = self.generateur.soumettre_transaction(
            transaction,
            domaine,
            reply_to=self.queue_name,
            correlation_id='efgh'
        )

        print("Sent: %s" % enveloppe_val)
        return enveloppe_val

    def executer(self):
        # enveloppe = self.requete_cert_maitredescles()
        # enveloppe = self.nouvelle_cle_grosfichiers()
        # enveloppe = self.nouvelle_cle_document()
        # enveloppe = self.transaction_declasser_grosfichier()
        # enveloppe = self.transaction_signer_certificat_navigateur()
        # enveloppe = self.requete_decryptage_cle_fuuid()
        # enveloppe = self.requete_decryptage_cle_fuuid_avecfingerprint()
        # self.transaction_demande_inscription_tierce()
        self.transaction_signature_inscription_tierce()


# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()
