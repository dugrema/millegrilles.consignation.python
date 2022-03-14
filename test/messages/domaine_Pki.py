# Script de test pour transmettre message de transaction

import json

from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles
from millegrilles.dao.MessageDAO import BaseCallback
from millegrilles.transaction.GenerateurTransaction import GenerateurTransaction
from millegrilles import Constantes
from millegrilles.domaines.Pki import ConstantesPki

from threading import Event, Thread

contexte = ContexteRessourcesMilleGrilles()
contexte.initialiser()

class MessagesSample(BaseCallback):

    def __init__(self):
        super().__init__(contexte)
        self.contexte.message_dao.register_channel_listener(self)
        self.generateur = GenerateurTransaction(self.contexte)

        self.fichier_fuuid = "39c1e1b0-b6ee-11e9-b0cd-d30e8fab842j"

        self.channel = None
        self.event_recu = Event()

    def on_channel_open(self, channel):
        # Enregistrer la reply-to queue
        self.channel = channel
        channel.queue_declare('', durable=True, exclusive=True, callback=self.queue_open_local)

    def queue_open_local(self, queue):
        self.queue_name = queue.method.queue
        print("Queue: %s" % str(self.queue_name))
        self.channel.basic_consume(self.queue_name, self.callbackAvecAck, auto_ack=False)
        self.executer()

    def run_ioloop(self):
        self.contexte.message_dao.run_ioloop()

    def deconnecter(self):
        self.contexte.message_dao.deconnecter()

    def traiter_message(self, ch, method, properties, body):
        print("Message recu, correlationId: %s" % properties.correlation_id)
        print(json.dumps(json.loads(body.decode('utf-8')), indent=4))
        print("Channel : " + str(ch))
        print("Method : " + str(method))
        print("Properties : " + str(properties))
        print("Channel virtual host : " + str(ch.connection.params.virtual_host))

    def requete_cert_fingerprint(self):
        fingerprint = 'idpQSrDt2h+CE0XSJZZNPEakd3Wha+EhcD9v4VKUXSk='
        # requete_cert = {
        #     'fingerprint': fingerprint
        # }
        enveloppe_requete = self.generateur.transmettre_requete(
            dict(),
            ConstantesPki.REQUETE_CERTIFICAT_DEMANDE + '.' + fingerprint,
            'abcd-1234',
            self.queue_name,
            securite=Constantes.SECURITE_PROTEGE,
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_cert_pk(self):
        fingerprint = 'mEiBvEkcpY4CKAfjhjoR0VVM74JCW7TrOqsY8daSbGNQKGA'
        enveloppe_requete = self.generateur.transmettre_requete(
            {Constantes.ConstantesSecurityPki.LIBELLE_FINGERPRINT_CLE_PUBLIQUE: fingerprint},
            'requete.Pki.' + ConstantesPki.REQUETE_CERTIFICAT_PAR_PK,
            'abcd-1234',
            self.queue_name,
            securite=Constantes.SECURITE_PROTEGE,
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_cert_backup(self):
        requete_cert = {}
        enveloppe_requete = self.generateur.transmettre_requete(
            requete_cert,
            '%s.%s' % (ConstantesPki.DOMAINE_NOM, ConstantesPki.REQUETE_CERTIFICAT_BACKUP),
            'abcd-1234',
            self.queue_name,
            securite=Constantes.SECURITE_PROTEGE,
        )

        print("Envoi requete: %s" % enveloppe_requete)
        return enveloppe_requete

    def requete_certificat(self):
        # fingerprint = 'zQmTSwmX9UVsEpaeGT2JprmGbSW2S9CYyMXKQShoercJbcg'
        requete = {
            'fingerprint': 'z2i3XjxE6XABbojEjpxaYeznA8Hn8hL4brun8kDDodrc7hxVSEx'
        }
        # domaine_action = 'requete.certificat.' + fingerprint
        self.generateur.transmettre_requete(
            requete,
            'CorePki',
            action='infoCertificat',
            correlation_id='abcd',
            reply_to=self.queue_name
        )

    def commande_sauvegarder_certificat(self):
        commande = {
            "chaine_pem": [
                "-----BEGIN CERTIFICATE-----\nMIID/zCCAuegAwIBAgIUOhOPjxIYcu/2KtUKOfVf9gjtRWswDQYJKoZIhvcNAQEL\nBQAwgYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRj\nYjFhYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5\nZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMB4X\nDTIxMDgxMDExMzkzOFoXDTIxMDkwOTExNDEzOFowZjE/MD0GA1UECgw2ejJXMkVD\nblA5ZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdz\nMREwDwYDVQQLDAhkb21haW5lczEQMA4GA1UEAwwHbWctZGV2NDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBANQpo8awOOHgdRO56fwZ3/eQbAsqJSS8LNR/\nJHf/1ExHY0AbqH88w+X9Rhh2uU92ECQA1usueJHSMDsKeOSTAuw/7yZNxs5Pv/uu\nfgH4Yq1JnM0r1SqT2zeiLxpKyYuB06XgD1jA5+rz0nD593ARTpGP6bx1HQO7F5sj\nc1+N1Ujf/XHDA9SDptREbpsmwzgmgBgVlbTVm4VQrl99B1LZhQPjDX6nLomQ2jmc\n42CXJRzgihIh7Ym6wggKDgVqlOIevlIRuK4oxITaFRMgtzeBbhj7bw1nMZ8BjxYw\nUpvangdvT3W5s9zTg0C4LgRdihCtFMHIXZOR86J27x1DqhLvH7sCAwEAAaOBgTB/\nMB0GA1UdDgQWBBQhkD483zW0QLedR2BlAZcR0glN6zAfBgNVHSMEGDAWgBT170DQ\ne1NxyrKp2GduPOZ6P9b5iDAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIE8DAQBgQq\nAwQABAg0LnNlY3VyZTAQBgQqAwQBBAhkb21haW5lczANBgkqhkiG9w0BAQsFAAOC\nAQEAPLe/7wTifOq24aGzbuB/BXcAbKm53CcnUQH7CbrnFh7VaHEM8WssZmKX5nYw\nKAts+ORk10xoLMddO9mEFtuKQD4QTjMFQe5EXnOuEuxzF51c3Gv2cY+b0Q/GcAcX\nu/UDN5Cw1SoRYd1SfYkvK8+8Deo7ds1Zib1gYehWmTYPA9ZD+bBIISd1pvgif6cz\nHl12aMusZ2F2m6Qhnot31vB90NPNa/hZ9cOAz+WnjwvcYXUXhCKV/wwuHtNWVNOS\nAphmpcYYJxAjqj1ok/EJF9L5/Z83NvTyz6omZbdptxa0ak4Qchql87rM1B6tGEVD\nkA1HOXEzYkfgtP4gGZZsKQhcxA==\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIID+DCCAmCgAwIBAgIJJ0USglmGk0UAMA0GCSqGSIb3DQEBDQUAMBYxFDASBgNV\nBAMTC01pbGxlR3JpbGxlMB4XDTIxMDcyMDEzNTc0MFoXDTI0MDcyMjEzNTc0MFow\ngYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRjYjFh\nYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5ZWF1\nTlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCNK7g/7AzTTRT3SX7vTzQIKhXvZ\nTkjphiJ38SoL4jZnv4tEyTV2j2a6v8UgluG/zab6W38n0YpLr1/J2+xVNOKO5P4t\ni//Qiygjkbl/2HGSjttorwdnybFIUdDqMQAHHZMfuvgZOgzXOG4xRxAD/uoTh1+B\ndj55uLKIwITtAY7e/Zxwia8cH9qPLRUETdp2/3rIGHSSkj1GDucnipGJHqrD2wF5\nylgy1kLLzV87wF55g7+nHYFpWXl19h8pAfxrQM1wMIY/rqAKwYoitePRaaLPfTKR\nTrzP4Ei4lStzuR4MocO2wZRSKKNuJw5GFML7PQf+ZV43KOGlpq8GmyNZxQIDAQAB\no1YwVDASBgNVHRMBAf8ECDAGAQH/AgEEMB0GA1UdDgQWBBT170DQe1NxyrKp2Gdu\nPOZ6P9b5iDAfBgNVHSMEGDAWgBQasUCD0J+bwB2Yk8olJGvr057k7jANBgkqhkiG\n9w0BAQ0FAAOCAYEAcH0Qbyeap2+uCTXyua+z8JpPAgW25GefOAkyzsaEgaSrOp7U\nic16YmZQz6QXZSkq0+agZ0dVue+9J5iPniujJjkACdClWsMl98eFcen0gb35humU\n20QDgvTDdmNpb2psfVfLMn50B1FxcYTVV3J2jjgBQa0/Q69+DPAbagKF/TJgMERY\nm8vBiHLruFWx7iuO5l9zI9/TCfMdZ1c0i+caUEEf4urCmxp7BjdWfDp+HshcJqok\nQN8PMVu4GfexJOD9gdHBaIA2VAuTCElL9K1Iy5kUcklu0qFxBKDi1N0mKOUeaGnq\nxbVEt7CZD3fF0xKnyNXAZzoCvqvkXtUORdkiZIH7k3EPgpgmLKvx2WNyXgFKs7y0\nMsucRkCixTRCdoju5h410hh7hpfR6eT+kHicJMSH1MKDJ/72MeFNeiOatKq8x72L\nzgGYVkuDlfXjPr5zPalw3BVNToikhVAgvVENiEaRzBKDJIkq1MnwK6VAzLMC60Cm\nSLqr6N7dHrSBO27B\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa\nMBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\nMIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6\npg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau\nbJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q\nTYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+\njTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2\n1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z\nXPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM\neFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq\nLsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE\nFBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk\na+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh\n2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O\nEYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3\nNK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk\n6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr\no/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG\nerI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda\nyGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ\nqn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=\n-----END CERTIFICATE-----\n"
            ],
        }
        domaine_action = 'commande.Pki.' + ConstantesPki.COMMANDE_SAUVEGADER_CERTIFICAT
        self.generateur.transmettre_commande(commande, domaine_action, correlation_id='abcd', reply_to=self.queue_name)

    def transaction_sauvegarder_certificat(self):
        transaction = {
            "pem": "-----BEGIN CERTIFICATE-----\nMIID+DCCAmCgAwIBAgIJJ0USglmGk0UAMA0GCSqGSIb3DQEBDQUAMBYxFDASBgNV\nBAMTC01pbGxlR3JpbGxlMB4XDTIxMDcyMDEzNTc0MFoXDTI0MDcyMjEzNTc0MFow\ngYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRjYjFh\nYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5ZWF1\nTlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMIIBIjAN\nBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqCNK7g/7AzTTRT3SX7vTzQIKhXvZ\nTkjphiJ38SoL4jZnv4tEyTV2j2a6v8UgluG/zab6W38n0YpLr1/J2+xVNOKO5P4t\ni//Qiygjkbl/2HGSjttorwdnybFIUdDqMQAHHZMfuvgZOgzXOG4xRxAD/uoTh1+B\ndj55uLKIwITtAY7e/Zxwia8cH9qPLRUETdp2/3rIGHSSkj1GDucnipGJHqrD2wF5\nylgy1kLLzV87wF55g7+nHYFpWXl19h8pAfxrQM1wMIY/rqAKwYoitePRaaLPfTKR\nTrzP4Ei4lStzuR4MocO2wZRSKKNuJw5GFML7PQf+ZV43KOGlpq8GmyNZxQIDAQAB\no1YwVDASBgNVHRMBAf8ECDAGAQH/AgEEMB0GA1UdDgQWBBT170DQe1NxyrKp2Gdu\nPOZ6P9b5iDAfBgNVHSMEGDAWgBQasUCD0J+bwB2Yk8olJGvr057k7jANBgkqhkiG\n9w0BAQ0FAAOCAYEAcH0Qbyeap2+uCTXyua+z8JpPAgW25GefOAkyzsaEgaSrOp7U\nic16YmZQz6QXZSkq0+agZ0dVue+9J5iPniujJjkACdClWsMl98eFcen0gb35humU\n20QDgvTDdmNpb2psfVfLMn50B1FxcYTVV3J2jjgBQa0/Q69+DPAbagKF/TJgMERY\nm8vBiHLruFWx7iuO5l9zI9/TCfMdZ1c0i+caUEEf4urCmxp7BjdWfDp+HshcJqok\nQN8PMVu4GfexJOD9gdHBaIA2VAuTCElL9K1Iy5kUcklu0qFxBKDi1N0mKOUeaGnq\nxbVEt7CZD3fF0xKnyNXAZzoCvqvkXtUORdkiZIH7k3EPgpgmLKvx2WNyXgFKs7y0\nMsucRkCixTRCdoju5h410hh7hpfR6eT+kHicJMSH1MKDJ/72MeFNeiOatKq8x72L\nzgGYVkuDlfXjPr5zPalw3BVNToikhVAgvVENiEaRzBKDJIkq1MnwK6VAzLMC60Cm\nSLqr6N7dHrSBO27B\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD\nVQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa\nMBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A\nMIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6\npg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau\nbJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q\nTYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+\njTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2\n1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z\nXPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM\neFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq\nLsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE\nFBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk\na+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh\n2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O\nEYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3\nNK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk\n6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr\no/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG\nerI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda\nyGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ\nqn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIETzCCAzegAwIBAgIUJ41+cgTa6A36iwoi/X5y/V3F0vQwDQYJKoZIhvcNAQEL\nBQAwgYgxLTArBgNVBAMTJGJiM2I5MzE2LWI0YzctNGJiYS05ODU4LTdlMGU0MTRj\nYjFhYjEWMBQGA1UECxMNaW50ZXJtZWRpYWlyZTE/MD0GA1UEChM2ejJXMkVDblA5\nZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdzMB4X\nDTIxMDcyMDEzNTYwN1oXDTIxMDgxOTEzNTgwN1owZjE/MD0GA1UECgw2ejJXMkVD\nblA5ZWF1TlhENjI4YWFpVVJqNnRKZlNZaXlnVGFmZkMxYlRiQ05IQ3RvbWhvUjdz\nMREwDwYDVQQLDAhmaWNoaWVyczEQMA4GA1UEAwwHbWctZGV2NDCCASIwDQYJKoZI\nhvcNAQEBBQADggEPADCCAQoCggEBAMsRR2Ei5f+EBlEbK8ElNpv7WCLSFR3a51tp\n/Z9NTIoJKXPF00RYVY7qWgxrDbPRRnjtMgaXMHbp2lVb18WY/acKCwQ8U3KLoyop\nWL97dDu+HfjKnAlW5470J9+GVdulDNiYoUwML1kMX1hNBnjWMRPhKkEUlSh/3hT2\nLzSHvr9Tp5JuDXTo4Mq7J5cn2L4Vl76cnmgMdcKL10AR2UJyGtxNp+1Hog6PJqNN\nlvJkMv3M6t+uHNsQCwjfCFhXRpchJCYB5T5VzYKf1Ksv4N0mY2SkOmhu3qJSt+bo\n3bCn2MGS30Kbt0DvhQALXSd5bhyJ+aSGnU0DqnePDnrKHLdOY9MCAwEAAaOB0TCB\nzjAdBgNVHQ4EFgQUpxmmxAAwybpsWefKBwzdrEYGmGQwHwYDVR0jBBgwFoAU9e9A\n0HtTccqyqdhnbjzmej/W+YgwDAYDVR0TAQH/BAIwADALBgNVHQ8EBAMCBPAwEQYE\nKgMEAAQJMy5wcm90ZWdlMB0GBCoDBAEEFWZpY2hpZXJzLEdyb3NGaWNoaWVyczA/\nBgNVHREEODA2gghmaWNoaWVyc4IHbWctZGV2NIIJbG9jYWxob3N0hwR/AAABhxAA\nAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUAA4IBAQBeS6WXugAWRXhN/MWf\nu/rR+Srt8RQ0HH55d+f3qHywCDZEwBXWFziyyCtxc15hrzuMZxk4tW7F3goYEMCL\nceHlrWV8b2zIsySfsJ0srMIb1RBRfr5mggXBfTZQm9MSWh2x9hG/6w+s8xp/bxrj\nG0+MSe92qwyQbDXcucYC3qKd7edyosVMZou5uEmRa9zWu0i7e/zZFZgKgvZPceHU\n+XZwNFRFFbkIdoPAp8LngF3xzQbBJ1jH0xDLVmucYDG2t71qGMjE+9uocYTNub+w\n0kF2ugKTK4QtwnShKqlmRR+jd9QIR0MGWwmKCshQvyktkyJpClJB5U90mYO+aZvo\nRVJ5\n-----END CERTIFICATE-----",
        }
        domaine_action = 'Pki.nouveauCertificat'
        self.generateur.soumettre_transaction(transaction, domaine_action, correlation_id='abcd', reply_to=self.queue_name, ajouter_certificats=True)

    def commande_signer_csr(self):
        commande = {
            'csr': SAMPLE_CSR,
            'role': Constantes.ConstantesGenerateurCertificat.ROLE_MESSAGERIE_WEB
        }
        domaine_action = 'commande.CorePki.' + ConstantesPki.COMMANDE_SIGNER_CSR
        self.generateur.transmettre_commande(commande, domaine_action, correlation_id='abcd', reply_to=self.queue_name, ajouter_certificats=True)

    def executer(self):
        # for i in range(0, 5000):

        # self.requete_cert_backup()
        # self.requete_cert_noeuds()
        # self.requete_certificat()
        # self.requete_cert_pk()
        # self.commande_sauvegarder_certificat()
        # self.transaction_sauvegarder_certificat()
        self.commande_signer_csr()


SAMPLE_CSR = """
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

# --- MAIN ---
sample = MessagesSample()

# TEST
# FIN TEST
sample.event_recu.wait(20)
sample.deconnecter()
