import datetime
import pytz
import logging
import OpenSSL

from os import path
from certvalidator.errors import PathValidationError
from typing import Dict
from threading import Event

from millegrilles import Constantes
from millegrilles.Constantes import ConstantesGenerateurCertificat
from millegrilles.util.ValidateursPki import ValidateurCertificat, ValidateurCertificatCache, ValidateurCertificatRequete
from millegrilles.util.X509Certificate import RenouvelleurCertificat, EnveloppeCleCert
from millegrilles.dao.Configuration import ContexteRessourcesMilleGrilles

mgdev_certs = '/home/mathieu/mgdev/certs'
idmg = 'z2oPZ96cRaFJYqUXcMtmap1KKaNtLXGwakfWcqBnj4HFrjdEbZeqgB'


cert_millegrille = b"""
-----BEGIN CERTIFICATE-----
MIIBUzCCAQWgAwIBAgIUbl3363S2J56H0agwMXf0a94C9RgwBQYDK2VwMBcxFTAT
BgNVBAMMDG1pbGxlZ3JpbGxlczAeFw0yMjAxMDkxMTM1NTVaFw00MjAxMDQxMTM1
NTVaMBcxFTATBgNVBAMMDG1pbGxlZ3JpbGxlczAqMAUGAytlcAMhAGQZ8QkmNIZQ
tqJS2Tcu0g7rIpprCOKz5gZUvzFVjsI4o2MwYTAPBgNVHRMBAf8EBTADAQH/MB0G
A1UdDgQWBBQJRu4NOqtYiAxQbbZNpgNQZ2vvczAfBgNVHSMEGDAWgBQJRu4NOqtY
iAxQbbZNpgNQZ2vvczAOBgNVHQ8BAf8EBAMCAaYwBQYDK2VwA0EA8yDLg6Mlx+L1
e/v99BfqbVQEqaNJpBCc9Eueoj45cFf1gVuM9h3FWFUb9TiP1+P0lQY4u+j8HnWE
72+IybWLBw==
-----END CERTIFICATE-----
"""

cert_1_intermediaire = """
-----BEGIN CERTIFICATE-----
MIIBODCB66ADAgECAgEFMAUGAytlcDAXMRUwEwYDVQQDDAxtaWxsZWdyaWxsZXMw
HhcNMjIwMTA5MTgxMzIxWhcNMjIwMjA4MTgxMzIxWjAQMQ4wDAYDVQQDDAVpbnRl
cjAqMAUGAytlcAMhAIL23KJlKrzb+fO+aUajBS7026rLt+yZVUymRTLa3hT2o2Mw
YTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBQvytsPp0ay7OvPJL1W/tv8+v0z
3TAfBgNVHSMEGDAWgBQJRu4NOqtYiAxQbbZNpgNQZ2vvczAOBgNVHQ8BAf8EBAMC
AaYwBQYDK2VwA0EAdR/R2/tooeE3CEANxWWt+tpZW4ksBJBexG2BixgmueGGnrCG
KqmSTfUlewWAxFcDau05GOR6Hwj3tp9/IVQAAw==
-----END CERTIFICATE-----
"""

cert_1_valide = """
-----BEGIN CERTIFICATE-----
MIIBrDCCAV6gAwIBAgIBAjAFBgMrZXAwEDEOMAwGA1UEAwwFaW50ZXIwHhcNMjIw
MTA5MTgxMzI1WhcNMjIwMjA4MTgxMzI1WjAPMQ0wCwYDVQQDDARsZWFmMCowBQYD
K2VwAyEAp2DEptlRhoIFY3v6mGtPvpRLcABaUQflvPZDLoxdDqejgd0wgdowCQYD
VR0TBAIwADALBgNVHQ8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUF
BwMCMGEGA1UdEQRaMFiHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAGHBMCoAsOCGW1n
LWRldjUubWFwbGUubWFjZXJvYy5jb22CBW1vbmdvgglsb2NhbGhvc3SCB21nLWRl
djWCAm1xMB0GA1UdDgQWBBTRQCkQ9Qq/FzVBFQIz6hI6yQhjaDAfBgNVHSMEGDAW
gBQvytsPp0ay7OvPJL1W/tv8+v0z3TAFBgMrZXADQQCRylN4qsuBNyx6PINYizcL
wfnQvWJeyVYTR7UIXQIT4SOaAssxF8zXbEJ1uAXjVxYiZRv71cUuU2UqUqdz3uoN
-----END CERTIFICATE-----
"""

cert_1_expire = """
-----BEGIN CERTIFICATE-----
MIIEYTCCA0mgAwIBAgIUcKt2m+TJ/BaUBTK7RoSpwLLOjVMwDQYJKoZIhvcNAQEL
BQAwfjEtMCsGA1UEAxMkMmRkYjJiNDktMTZhNS00MmMyLTg3NzItYzJiZTRhNDdm
N2M1MRYwFAYDVQQLEw1pbnRlcm1lZGlhaXJlMTUwMwYDVQQKEyxRTUU4U2poYUNG
eVNEOXFCdDFBaWtRMVU3V3hpZUpZMnhEZzJKQ01jekpTVDAeFw0yMTAxMDkxOTU2
MzhaFw0yMTAxMDkyMDU4MzhaMHgxNTAzBgNVBAoMLFFNRThTamhhQ0Z5U0Q5cUJ0
MUFpa1ExVTdXeGllSlkyeERnMkpDTWN6SlNUMRAwDgYDVQQLDAdtb25pdG9yMS0w
KwYDVQQDDCQyZGRiMmI0OS0xNmE1LTQyYzItODc3Mi1jMmJlNGE0N2Y3YzUwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCu9BTZ7SC+A0VcoP14a+C0Ij1i
z7s8AhQNTqpMcadMGyJqF9vGkHwesOnPx72ZEimIPwQKguFRR8CV456zRlw91Qa3
P86nGJMFfgWkaT+CQHqXcV2DCM28TbvcT1em+yzNBzsSrI203wmJzHGiI0+so1oe
IysAxXIRWaX5xoWwXs/tOYN2tHpVxDa2vdkrLidgnqPsYBsmBXtl+sqBtDLZ1FuS
iH+Oa8hFIDLRSGAI3F5/uKQ165ZkBvfaSekKNyXhAwUo4AnTUuGuvstN1E4FNSMG
A+fPPYBiTPg7j0b92sla0Yad/jLs9gCDkUNdlT/iPXgBNARne1b+RW0M7d8hAgMB
AAGjgdwwgdkwHQYDVR0OBBYEFBCelZdfmMGrNBbhkj4/BduX/lO5MB8GA1UdIwQY
MBaAFBwYQZ07AwHZclv/FhnFOErfi7S6MAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQD
AgTwMCIGBCoDBAAEGjQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlMA8GBCoDBAEE
B21vbml0b3IwRwYDVR0RBEAwPoIkMmRkYjJiNDktMTZhNS00MmMyLTg3NzItYzJi
ZTRhNDdmN2M1hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMA0GCSqGSIb3DQEBCwUA
A4IBAQAutCBqJvencnOkznhm0CvsZQVZCPaeGMz6ESfkgVlTaiHSiJDu79rmKNdF
9HX8Lzae7pAD4ZIyGeVznq8j+HxG6WXWoHrxahN707jOSmDdVoRDhjcq/Oo9VThv
lDesB0sX4SQpt6cyRcLz8Pw0xT364VwLhitXF/XrS03jgHusCDBtq3ZnXUYhnwnX
U/ho5SogCwjFmuH6u5qM5S+d6m77o2hYqi3jBKeM1dJVJ9RX0lRO2UQ6v49VYYdT
z3E0T3HtHJYXdC+ExxQWGYoQcXRjL01PG0CcOAfRdzAbqimca/fudl2NgkqW7Os3
vtYumyCsL6Qb/m3DW8OmFmiElePC
-----END CERTIFICATE-----
"""

dict_ca = dict()


def generer_certificat_valide() -> EnveloppeCleCert:
    ca_autorite = EnveloppeCleCert()
    ca_autorite.cert_from_pem_bytes(cert_millegrille.encode('utf-8'))

    with open(path.join(mgdev_certs, 'pki.intermediaire.key'), 'rb') as fichiers:
        inter_key = fichiers.read()
    with open(path.join(mgdev_certs, 'pki.intermediaire.passwd'), 'rb') as fichiers:
        inter_passwd = fichiers.read()
    with open(path.join(mgdev_certs, 'pki.intermediaire.cert'), 'rb') as fichiers:
        inter_cert = fichiers.read()

    clecert_intermediaire = EnveloppeCleCert()
    clecert_intermediaire.from_pem_bytes(inter_key, inter_cert, inter_passwd)

    renouvelleur = RenouvelleurCertificat(idmg, dict_ca, clecert_intermediaire, ca_autorite)
    cert_enveloppe = renouvelleur.renouveller_par_role(ConstantesGenerateurCertificat.ROLE_DOMAINES, 'test', duree=7)

    return cert_enveloppe


class ValiderCertificat:

    def __init__(self, ca_pem, certs_pems: list):
        self.ca_pem = ca_pem
        self.certs_pems = certs_pems
        self.__logger = logging.getLogger('__main__.ValiderCertificat')

        self.contexte = None
        self.validateur = None

    def test_valider_1(self):
        validateur = ValidateurCertificat(idmg=idmg, certificat_millegrille=self.ca_pem)

        enveloppe1 = EnveloppeCleCert()
        enveloppe1.cert_from_pem_bytes('\n'.join(self.certs_pems).encode('utf-8'))
        validateur.valider(enveloppe1.chaine)

        date_reference = datetime.datetime(year=2010, month=1, day=1, hour=0, minute=0, tzinfo=pytz.UTC)
        try:
            validateur.valider(enveloppe1.chaine, date_reference=date_reference)
        except OpenSSL.crypto.X509StoreContextError as ce:
            self.__logger.debug(" ** OK ** -> Message validation avec validateur implicite : %s" % ce)
        else:
            raise Exception("Erreur de validation, date n'a pas ete flaggee comme invalide")

    def test_valider_cache(self):
        # Tester chargement precedent du cert de millegrille (implicitement)
        validateur_cache = ValidateurCertificatCache(idmg=idmg)

        enveloppe1 = self.certs['1']
        validateur_cache.valider(enveloppe1.chaine)

        enveloppe_cache = validateur_cache.get_enveloppe(enveloppe1.fingerprint_sha256_b64)
        if enveloppe_cache.fingerprint_sha256_b64 != enveloppe1.fingerprint_sha256_b64 is None:
            raise ValueError("Certificat pas conserve dans le cache")

        self.__logger.debug("Certificat conserve dans le cache et valide : %s" % enveloppe_cache.est_verifie)

        enveloppe_millegrille_cache = validateur_cache.get_enveloppe('XE1aGDnW9LmXg9svOFQXy0LSiWojyp0ipHBPlt5SirA=')
        self.__logger.debug("Certificat millegrille conserve dans le cache et valide : %s" % enveloppe_millegrille_cache.est_verifie)

        validateur_cache.entretien()

    def initialiser_contexte(self):
        self.contexte = ContexteRessourcesMilleGrilles()
        self.contexte.initialiser()

        self.__logger.debug("Preparation validateur")
        self.validateur = ValidateurCertificatRequete(self.contexte, idmg=idmg)
        self.validateur.connecter()
        self.__logger.debug("Validateur pret")

    def test_valider_mq(self):

        # Tester certs de base
        enveloppe1 = self.certs['1']
        cert_ref_enveloppe = self.validateur.valider(enveloppe1.chaine)
        self.__logger.debug("Cert de reference valide : %s" % cert_ref_enveloppe.est_verifie)

        fingerprints = [
            'sha256_b64:bD0hnLqS35LmOpVtn4mn4u5A2B9y1l3hOqpKX6XNfZI=',
            'sha256_b64:naUCE5RY8Vk0f5Cz7gPDPuSDdDNBoLxhnl7DiWK0EFU=',
        ]

        self.__logger.debug("Attente demarrage processing")
        Event().wait(2)
        self.__logger.debug("Demarrage processing")
        for fp in fingerprints:
            try:
                # enveloppe_recue = validateur.get_enveloppe(fp)
                enveloppe_recue = self.validateur.valider_fingerprint(fp)
                self.__logger.info("Enveloppe chargee est valide : %s" % enveloppe_recue.est_verifie)
            except AttributeError:
                self.__logger.debug("Certificat non recu")

        self.__logger.debug("Validation avec cache")
        for fp in fingerprints:
            try:
                enveloppe_recue = self.validateur.valider_fingerprint(fp)
                self.__logger.info("Enveloppe chargee est valide : %s" % enveloppe_recue.est_verifie)
            except AttributeError:
                self.__logger.debug("Certificat non recu")

    def verification_conditionnelle(self):

        # Valider un certificat contiditonnelement
        date_validation = datetime.datetime(year=2021, month=1, day=8, hour=21, tzinfo=pytz.UTC)
        self.__logger.debug("Verifier certificat expire avec une date valide : %s" % date_validation)
        fp_conditionnel = 'sha256_b64:QLyRx1zpJemuUwkKfu38QZqgspo4XODy/047fz8sKko='
        enveloppe_conditionnelle = self.validateur.valider_fingerprint(fp_conditionnel, date_reference=date_validation)
        self.__logger.info("Enveloppe chargee est verifie %s (devrait etre False), expiration %s" % (enveloppe_conditionnelle.est_verifie, enveloppe_conditionnelle.not_valid_after))

        self.__logger.debug("Verifier cache cert 'non-verifie'")
        enveloppe_conditionnelle = self.validateur.valider_fingerprint(fp_conditionnel, date_reference=date_validation)
        self.__logger.info("Enveloppe chargee est verifie (devrait etre False) : %s" % enveloppe_conditionnelle.est_verifie)

        date_validation = datetime.datetime.now(tz=pytz.UTC)
        self.__logger.debug("Verifier cache cert expire avec date courante %s" % date_validation)
        try:
            enveloppe_conditionnelle = self.validateur.valider_fingerprint(fp_conditionnel, date_reference=date_validation)
        except PathValidationError:
            self.__logger.info("Enveloppe chargee est invalide pour la date (OK) : expiration = %s" % enveloppe_conditionnelle.not_valid_after)
        else:
            raise Exception("Erreur validation date avec certificat, devrait etre invalide")

    def test_recherche_cert_absent(self):

        # Tester certs de base
        enveloppe1 = self.certs['1']
        cert_ref_enveloppe = self.validateur.valider(enveloppe1.chaine)
        self.__logger.debug("Cert de reference valide : %s" % cert_ref_enveloppe.est_verifie)

        fingerprints = [
            'sha256_b64:DUMMY_EXISTE_PAS',
        ]

        self.__logger.debug("Attente demarrage processing")
        Event().wait(2)
        self.__logger.debug("Demarrage processing")
        for fp in fingerprints:
            try:
                # enveloppe_recue = validateur.get_enveloppe(fp)
                enveloppe_recue = self.validateur.valider_fingerprint(fp)
                self.__logger.info("Enveloppe chargee est valide : %s" % enveloppe_recue.est_verifie)
            except AttributeError:
                self.__logger.debug("OK - Certificat non recu")
            else:
                self.__logger.error("ERREUR - Certificat recu, ne devrait pas exister")


def main():
    logging.basicConfig(format=Constantes.LOGGING_FORMAT)
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('millegrilles.util.ValidateursPki').setLevel(logging.DEBUG)

    test = ValiderCertificat(cert_millegrille, [cert_1_valide, cert_1_intermediaire])
    test.test_valider_1()
    # test.test_valider_cache()

    #test.initialiser_contexte()
    #test.test_valider_mq()
    # test.test_recherche_cert_absent()

    # Event().wait(120)


if __name__ == '__main__':
    main()
