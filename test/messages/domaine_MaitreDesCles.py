# Script de test pour transmettre message de transaction

import datetime, time
import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.ConfigurationDocument import ContexteRessourcesDocumentsMilleGrilles
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
from binascii import hexlify


contexte = ContexteRessourcesDocumentsMilleGrilles()
contexte.initialiser()


class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)
        self.channel = None
        self.queue_name = None
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
        # self.requete_cert_maitredescles()
        thread_executer = Thread(name="exec", target=self.executer)
        thread_executer.start()

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
                cert.cert_from_pem_bytes(certificat_pem[0].encode('utf-8'))
                self.certificat_maitredescles = cert
                print("Recu certificat %s" % cert.fingerprint_b64)
            except:
                print("Erreur traitement certificat_pem")
            self.cert_maitredescles_recu.set()
        else:
            if message_dict.get('certificats_pem'):
                for cert in message_dict.get('certificats_pem'):
                    print(cert)

            if message_dict.get('cles'):
                # Tenter de dechiffrer la cle
                clecert = self.configuration.cle
                for cle in message_dict['cles'].values():
                    try:
                        cle_dechiffree = clecert.dechiffrage_asymmetrique(cle['cle'])
                        print("Cle secrete dechiffree : %s" % cle_dechiffree.decode('utf-8'))
                    except KeyError:
                        pass

            self.event_recu.set()


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

    def requete_dechiffrage_cle(self, hachage: list):
        requete_cert_maitredescles = {
            "liste_hachage_bytes": hachage,
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_dechiffrage_cle_permission(self, hachage: list):
        requete_cert_maitredescles = {
            "liste_hachage_bytes": hachage,
            "permission": {
                "_certificat": [
                    "-----BEGIN CERTIFICATE-----\nMIID/zCCAuegAwIBAgIUdPegLK9iH2dwn2/XxWvdA4PPf4EwDQYJKoZIhvcNAQEL\nBQAwgYgxLTArBgNVBAMTJDQ4NzViNjU1LTk0ODMtNDIwOC1iMzUxLWI1NDgwYWYz\nYWNjMTEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5\nZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMB4X\nDTIxMDUyNTE2NTgyN1oXDTIxMDYyNDE3MDAyN1owZjE/MD0GA1UECgw2ejJXMkVD\nblA5ZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdz\nMREwDwYDVQQLDAhkb21haW5lczEQMA4GA1UEAwwHbWctZGV2NDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBALbMEXrc/JRFZg4uRWTlxRZ46lLKVfMIHoiG\nbdg9YWccVHpLUIeSrKq9d0A4fk9uoidGnd5y/5rPR8yIIWpLjPUpQws3JJ0OFERm\nXAMzP/DwYPlPilv4zZzAKIXQhQynVRSaoCGC1nkKqcw0Hx5bpCx905XmlqP1r+7Z\nMCHmSXBYCrUszwBi+oRKBfMki4J2orGSLu6Xuk7teB2Q31vk5MqED2aTl1CONvve\nPGLUtTCjA9BhrrWXy6gWukag3OjTgQxW74KNTSqhkAREFW3BD8GCuDShP4/txF13\nQ1OlPOu143RMNQ2CsgFwi6OGA/Vp5Svfc6JZB7YDB20dQt825rECAwEAAaOBgTB/\nMB0GA1UdDgQWBBSCBC/VZ7m//WZUPWrCiXfBgl4qYDAfBgNVHSMEGDAWgBQ03Pfp\nC+YWm5vfqidQ7JKSlOvVbTAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIE8DAQBgQq\nAwQABAg0LnNlY3VyZTAQBgQqAwQBBAhkb21haW5lczANBgkqhkiG9w0BAQsFAAOC\nAQEAu5rUoczNKYsUa6gJpsxHGi5RvcHHRVuOwbdJnEu9qgYbNfxGXaxY+kdboHR0\nR81le5hLrSELd6TlO7uPoKUzn9uiXZpnsu1zVtcAEi9OwxE9csQt6zhnhjI5gtzn\numcI8NlGgrphNh+R7W+1MrjNqdQyN+E4rb0nSWF0kjV7qAaNjIUarvGQf2n8lThX\nFkRq6yBAwJlRorz4hlATTx9lewgjamml4CjPQ94Z5UrGY13rZn19nXs76Oe1SC7O\nW3l15sl75PkAOXw5kmrGauttdMIo3eltXShLqAWscq+0jmf29jKPdA7alLsP/RMl\np0Qmi5YZUz/HxC1C7qkCHH9TUA==\n-----END CERTIFICATE-----",
                    "-----BEGIN CERTIFICATE-----\nMIID+DCCAmCgAwIBAgIJV4ljiVFZUHcAMA0GCSqGSIb3DQEBDQUAMBYxFDASBgNV\nBAMTC01pbGxlR3JpbGxlMB4XDTIxMDUyNDIwMDkwNloXDTI0MDUyNjIwMDkwNlow\ngYgxLTArBgNVBAMTJDQ4NzViNjU1LTk0ODMtNDIwOC1iMzUxLWI1NDgwYWYzYWNj\nMTEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5ZWF1\nTlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyDFf51VF78Hr+MMRAyiHwu/MxDLQ\njAVWa4UcgjGIN0OvfsCe1wTV16tTWgl89uF+cyAiayNDtvu/WNLkamvAViSOvt2T\nYmH6GPHBms4MDd65IUe43Es0Qlxc5BXCyibrIaEls8M9NZfUT0PUDq8f1JQEj8R6\nHYSm8CmTj3YNQiob4ORNVhyy9/NfazfXdGYaSnnDX8PwrR/wZVY4Yee7HNJgghpD\nlfk16dTKbEn2jDf47+bW60SkV6Q2fKyZ7eT2+odtq0jHHNFZrUGrFRccVFZX4Z6F\nZ3hf0H7MSZoGgSMzO4bEfWWp/MOrivbW6kWbtE9nZA9hKP8ewVSL95yIlwIDAQAB\no1YwVDASBgNVHRMBAf8ECDAGAQH/AgEEMB0GA1UdDgQWBBQ03PfpC+YWm5vfqidQ\n7JKSlOvVbTAfBgNVHSMEGDAWgBQasUCD0J+bwB2Yk8olJGvr057k7jANBgkqhkiG\n9w0BAQ0FAAOCAYEAYNvvFhE5zHp7lIh4AWeeD8G4AZYtfH/y8HCGcsF3MW29EbTX\nj+jNmajIbV0LdPiWvjM2dV7idBSPAnvT8wr9mD9ssDPuuisXlyb4fgvgsEk/B7bC\n+5CIrvGU3oW4immJ98kM6BdsreQazwckj1lE2GIeu24hKzJ47p6y1TG9OOJhCPaa\n+dDKt/BPcBLYZjFpyneXufxXnxJTjSg3vxnspiD7xKoBpWe4eaVCTBlb7sS1ldTD\ny5I96Z+xb4fKqkg4PINsYILfw2CftP5DYd7wFt5YOIHJclZ/RGAfh+TbuTHSi1TK\n0SAtGf7yfHWj81IRP4GK6lzsZWx7F3mFU0LNSdKmr/yLCGMpVNawEQRJXKMKwX5P\nP62FmWgTWLP8Pe1H6m4jT23ZIm6jQWuKU/BlTcjoeF9X9fmo4DwJfSHeMr5JV8MW\n9pw0vVb1bZhHgtOlO5y4E6E/rqlQmQeBhTtzq8EoYeKFtIG44OYq8okibj7VKg+o\nqi9zMJBfsJpi8aJR\n-----END CERTIFICATE-----",
                    "-----BEGIN CERTIFICATE-----\nMIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa\nMBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\nMIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6\npg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau\nbJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q\nTYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+\njTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2\n1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z\nXPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM\neFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq\nLsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE\nFBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk\na+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh\n2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O\nEYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3\nNK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk\n6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr\no/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG\nerI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda\nyGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ\nqn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=\n-----END CERTIFICATE-----"
                ],
                "_signature": "mAWyQqNYOFuZyWUBxpVnlRSNHdewozq07DEXTGcKdg8YibQAAElUT71QRTbSYSvWZUY60VUILXM/Ynb7nQw/Oz0SLK4qZVXgRJYaHS8SZO5EWGdLMKB4AalJn+VGbZ0IwSgE7H18qa2XPAuCbYOCT/vriwrXCmVGwSOypdtnQ+/mBOJzySVlUY6r/bC7zm4RpA05c3NJV9Tgoy7q04B6AnulrNci7zpnMrjXkAK87sYSWTKU6/EZLXddFs1VuSZTojsbc33PliwBUUAoUb2dALibE7YamM0O7IS1HWIVs+tzMHXe/0F7fPceucVWwKRMpIlVs1Hqp4H4oUtyjSEGzzl0",
                "domaine": "Publication",
                "duree": 43200,
                "en-tete": {
                    "estampille": 1622414755,
                    "fingerprint_certificat": "zQmRUBsMvwQ72274KozPmdGeKtEnz5ZUsAdhDU51g94Ey4m",
                    "hachage_contenu": "mEiDVfBHNba0i4nyIY1F6v7VQ8Yma1TPucmRy14G+xZHTRA",
                    "idmg": "z2W2ECnP9eauNXD628aaiURj6tJfSYiygTaffC1bTbCNHCtomhoR7s",
                    "uuid_transaction": "cb43e3cb-c198-11eb-bc2f-d951270ecae2",
                    "version": 6
                },
                "identificateurs_document": {
                    "securite": "2.prive"
                },
                "roles_permis": [
                    "Publication"
                ]
            }
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE,
            'abcd-1234',
            self.queue_name
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_verifier_preuve(self, hachage: list):
        requete_cert_maitredescles = {
            "preuve": {
                "zSEfXUEbDxbPeBxLMRChRmESn4qx26s9dWm4HSoPURfw3JrY76U5QBm4QFVG8fU78wyVX2hFvCjFjbxTu2rv8tTQVsUQfZ": "mcv9Y+kSipXenqFzLbOPGXElreTjLrjPPJwQOB4bQDjPdb7KXHCR5tj0Ob5HPkTQzRS3ItGxLUbZXLN0YZFX/CJJKiuYCwYOmW/xtWErjVas"
            },
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_VERIFIER_PREUVE,
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

    def requete_cle_backup(self):
        requete_cert_maitredescles = {
            'certificat': self.certificat_courant_pem,
            'domaine': 'Topologie',
            'identificateurs_document': {
                'transactions_nomfichier': 'Topologie_transactions_2020100323_3.protege.jsonl.xz.mgs1',
            },
            "cles": {
                "cGrSTYhEB19QGjiipURder6/IRc=Z": "aVA+CkgvSqP496IBrDbFa2SVP11f+BKq8oc3vJ2+8g4Ypo4u2c5ZnYvNPTFEnoAGcggGRDDQY2wkCNUGOjh2gTMnItUOdWJNq5vmjs0XNTOpiEkJpq7U5ZzPTssn2m6V1JbG0TmTu5/f24K1HAhae2lz95mlVdwufm+kQolwL5rzULOzGGV+mX8PGuaQkCHPdcletVj9IUwgkwrwYAgjYHt9qPjGUHO7Bcyiw1t7dWTUTbvt59uh41J53IB79hRqwx8BMeY7rMsWoY5ffVIWBorV//XxcsnEqiXgEOUJoC/LmQfI21FxPNV6mBIzs4hakvOgET5D2yGoAlYX4wJnxg==",
                "OaUo6vkTDQ26S9hbdFqeKYS3NyI=": "jYYDIgn4ShniCGkBgfJ1tIzOARRl1wBAps/SQwKBDMZnL+uH3MAhsieg6XW5vtdZyC/hh+hZ2q++2GGsgSUHAKbJlTn8YWS4WuRpUQssg4agpfCVPndkRoN1qf7QaQiN27HZJhMawqif0KDx7ZU0MsJoHF1l0X0E+frNuVg+WY+8DpHRxxc15CeHcLToSYn1V15WDiCTbrfvZ0zONEF2btie7eQ/B81prcTnUNrJe5xoHraEaQOcD4NOW1gCV0D8YfGcKZ2/by9zad3aJL5iUvGW4AeftewOaaKu4tM5bjdqSeICoeaI0fXwk7L/q2bBR2FOMM/P4so3JbabOaShHA=="
            },
            "iv": "16ldjBWXospiToJEKEIWGw==",
        }

        print(requete_cert_maitredescles)

        self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE_BACKUP,
            'abcd-1234',
            self.queue_name
        )

    def requete_cle_backup_application(self):
        requete_cert_maitredescles = {
            'certificat': self.certificat_courant_pem,
            'identificateurs_document': {
                'archive_nomfichier': 'application_mariadb_redmine_client_archive_202010101721.tar.xz.mgs1'
            },
        }

        print(requete_cert_maitredescles)

        self.generateur.transmettre_requete(
            requete_cert_maitredescles,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_DECHIFFRAGE_BACKUP,
            'abcd-1234',
            self.queue_name
        )

    def commande_sauvegarder_cle(self):
        commande = {
            'domaine': 'Topologie',
            'identificateurs_document': {
                'transactions_nomfichier': 'Topologie_transactions_2020100325_3.protege.jsonl.xz.mgs1',
            },
            'hachage_bytes': 'HAHAHOHO',
            "cles": {
                # "cGrSTYhEB19QGjiipURder6/IRc=Z": "aVA+CkgvSqP496IBrDbFa2SVP11f+BKq8oc3vJ2+8g4Ypo4u2c5ZnYvNPTFEnoAGcggGRDDQY2wkCNUGOjh2gTMnItUOdWJNq5vmjs0XNTOpiEkJpq7U5ZzPTssn2m6V1JbG0TmTu5/f24K1HAhae2lz95mlVdwufm+kQolwL5rzULOzGGV+mX8PGuaQkCHPdcletVj9IUwgkwrwYAgjYHt9qPjGUHO7Bcyiw1t7dWTUTbvt59uh41J53IB79hRqwx8BMeY7rMsWoY5ffVIWBorV//XxcsnEqiXgEOUJoC/LmQfI21FxPNV6mBIzs4hakvOgET5D2yGoAlYX4wJnxg==",
                "sha256_b64:OaUo6vkTDQ26S9hbdFqeKYS3NyI=": "jYYDIgn4ShniCGkBgfJ1tIzOARRl1wBAps/SQwKBDMZnL+uH3MAhsieg6XW5vtdZyC/hh+hZ2q++2GGsgSUHAKbJlTn8YWS4WuRpUQssg4agpfCVPndkRoN1qf7QaQiN27HZJhMawqif0KDx7ZU0MsJoHF1l0X0E+frNuVg+WY+8DpHRxxc15CeHcLToSYn1V15WDiCTbrfvZ0zONEF2btie7eQ/B81prcTnUNrJe5xoHraEaQOcD4NOW1gCV0D8YfGcKZ2/by9zad3aJL5iUvGW4AeftewOaaKu4tM5bjdqSeICoeaI0fXwk7L/q2bBR2FOMM/P4so3JbabOaShHA=="
            },
            "iv": "16ldjBWXospiToJEKEIWGw==",
        }

        self.generateur.transmettre_commande(
            commande,
            'commande.MaitreDesCles.%s' % ConstantesMaitreDesCles.COMMANDE_SAUVEGARDER_CLE,
            exchange=Constantes.SECURITE_PROTEGE,
            correlation_id='abcd-1234',
            reply_to=self.queue_name
        )

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
                "champ": 'dummy' + str(uuid4()),
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

    def nouvelle_cle_backup(self):
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

        date_str = datetime.datetime.utcnow().strftime('%y%m%d%h%m')

        nouvelle_cle = {
            "domaine": "Topologie",
            ConstantesMaitreDesCles.TRANSACTION_CHAMP_IDENTIFICATEURS_DOCUMENTS: {
                "transactions_nomfichier": "Topologie_transactions_%s_3.protege.jsonl.xz.mgs1" % date_str,
            },
            "cles": {fingerprint_b64: cle_secrete_encryptee_base64},
            "iv": "gA8cRaiJE+8aN2c6/N1vTg==",
            "sujet": ConstantesMaitreDesCles.DOCUMENT_LIBVAL_CLES_BACKUPTRANSACTIONS,
        }

        enveloppe_val = self.generateur.soumettre_transaction(
            nouvelle_cle,
            ConstantesMaitreDesCles.TRANSACTION_NOUVELLE_CLE_BACKUPTRANSACTIONS,
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

    def requete_cles_non_dechiffrables_verifmaitrecles(self):
        self.cert_maitredescles_recu.wait(5)  # Attendre reception cert maitredescles

        # Prendre le fingerprint du cert maitre des cles - devrait retourner 0 cles non chiffrees
        fingerprint_maitrecles = self.certificat_maitredescles.fingerprint_b64

        requete_cle_racine = {
            'taille': 2,
            'fingerprints_actifs': [fingerprint_maitrecles],
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cle_racine,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_CLES_NON_DECHIFFRABLES,
            'abcd-1234',
            self.queue_name
        )
        return enveloppe_requete

    def requete_cles_non_dechiffrables_verifcledummy(self):
        self.cert_maitredescles_recu.wait(5)  # Attendre reception cert maitredescles

        # Prendre le fingerprint du cert maitre des cles - devrait retourner 0 cles non chiffrees
        fingerprint_maitrecles = self.certificat_maitredescles.fingerprint_b64

        requete_cle_racine = {
            'taille': 2,
            'fingerprints_actifs': ['DUMMY'],
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cle_racine,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_CLES_NON_DECHIFFRABLES,
            'abcd-1234',
            self.queue_name
        )
        return enveloppe_requete

    def requete_compter_cles_non_dechiffrables_verifcledummy(self):
        self.cert_maitredescles_recu.wait(5)  # Attendre reception cert maitredescles

        # Prendre le fingerprint du cert maitre des cles - devrait retourner 0 cles non chiffrees
        fingerprint_maitrecles = self.certificat_maitredescles.fingerprint_b64

        requete_cle_racine = {
            # 'fingerprints_actifs': ['DUMMY'],
        }
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cle_racine,
            'MaitreDesCles.%s' % ConstantesMaitreDesCles.REQUETE_COMPTER_CLES_NON_DECHIFFRABLES,
            'abcd-1234',
            self.queue_name
        )
        return enveloppe_requete

    def executer(self):
        # self.event_recu.wait(5)
        # self.event_recu.clear()

        # enveloppe = self.requete_cert_maitredescles()
        # self.requete_trousseau_hebergement()

        # for i in range(0, 2):
        #     self.nouvelle_cle_grosfichiers()
        #     self.nouvelle_cle_document()
        #     self.nouvelle_cle_backup()

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
        # self.requete_cles_non_dechiffrables_verifmaitrecles()
        # self.requete_cles_non_dechiffrables_verifcledummy()
        # self.requete_compter_cles_non_dechiffrables_verifcledummy()
        # self.requete_cle_backup()
        # self.requete_cle_backup_application()
        # self.commande_sauvegarder_cle()
        self.requete_verifier_preuve()

        # self.requete_dechiffrage_cle([
        #     "sha512_b64:aBUX0NsH2scbs+dCqAFsd2FCRO1L6aXsvxMpqVrE94vxam45dN9J1sxhrzTh8xKvy17vZDuHW5DmqnOKAij5DQ==",
        #     "sha512_b64:ys1vTtaKjCXnqt6i2G1GbHvN9vvMoiDt2IuV6/WatDVrN6pm670KO9iiL4N/tu6U60Jhsad+W3ZJky5iUGI1Hg==",
        # ])

        # self.requete_dechiffrage_cle_permission([
        #     'z8VtAgm7BYshU7J9ZJRJKg8ZcZF783aAJuGgyR8dLNrvAEFEWhDi8zw8oicBD7NMqYnhNzRYQ8cJTydgWyFhtsjNyWX',
        # ])


def reset_docs_cles():
    collection_docs = contexte.document_dao.get_collection('MaitreDesCles/documents')
    fingerprint = '/kUFlugeL7ezzdoT/rHc9yGIo4Y='
    filtre = {
        '_mg-libelle': 'cles.grosFichiers',
        'cles.%s' % fingerprint: {'$exists': True}
    }
    ops = {
        '$unset': {'cles.%s' % fingerprint: True}
    }
    collection_docs.update_many(filtre, ops)

# reset_docs_cles()

# --- MAIN ---
sample = MessagesSample()

# TEST
sample.executer()

# FIN TEST
sample.event_recu.wait(10)
sample.deconnecter()
