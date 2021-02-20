import logging

from unittest import TestCase
from unit.helpers.TestBaseContexte import TestCaseContexte

from millegrilles.util.Hachage import verifier_hachage
from millegrilles.SecuritePKI import EnveloppeCertificat


# Setup logging
logging.basicConfig()
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)
logging.getLogger('millegrilles').setLevel(logging.DEBUG)


FINGERPRINT_CERT_1 = 'zQmSXwuJRPjRxBnRmozcGPcvq8ufVFXz54VujvYBpE3tGJQ'
IDMG_CERT_1 = 'z2MFCe7c6DfeMwTYpSJBGRPhiyt3peu1ucycDGDReGJQTpidp4ABPi'
SAMPLE_CERT_1 = """
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgIJh4hTAQFkKTIAMA0GCSqGSIb3DQEBDQUAMCcxDzANBgNV
BAMTBlJhY2luZTEUMBIGA1UEChMLTWlsbGVHcmlsbGUwHhcNMjAxMDE1MTczNjQx
WhcNMjExMDE1MTczNjQxWjAnMQ8wDQYDVQQDEwZSYWNpbmUxFDASBgNVBAoTC01p
bGxlR3JpbGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoEQE8xzF
4BeTqnui0ri3F8wKGmF75xLKBUWklpc/FSnyIb6R/IfjoxT+tgI9Gr38lA9ITvdB
ykNAeS4HbKv4K7g+vIWJixGWXBspd0Fs7FKMwZgN/c1wpBZw4rPjujk8u385/Aiu
6WkCK0+QIPl5bmKWLIzs/wpcWt+g7vlFYSM7qKdvlxJ6LToqcZKrKVemPfokIJ+X
QNe6vWTSVKqTCETe9ltPxnftI2eELuHpSyigYwkEIjkQPRbShpm/GdO7MJJwfo0i
XJqAZabEAgJnCt1o0FNySRa8o5VThpiUDlbaAS77v0E/cgM8Q8+vbwZN3mAjzbn9
xBYdSC2KMT5MFQIDAQABo1YwVDASBgNVHRMBAf8ECDAGAQH/AgEFMB0GA1UdDgQW
BBQuZbJB1pbMNRIsl6wwUbkW+wIXVzAfBgNVHSMEGDAWgBQuZbJB1pbMNRIsl6ww
UbkW+wIXVzANBgkqhkiG9w0BAQ0FAAOCAQEAOML4p+SwPU+VeTikYrH4tPQsTXnC
Dt4VqI71MsTD4zOdKUN+voRaKQWO0RE3zcTfIcY784cDxvSrzpDWIkQ1OkAu9VvR
MX1f9dlX3J7jEywnpHnEZ6uphew0PIApumXVsumGsztw+X8RAL8tX9a4V/xSzHwM
Gls59U8FYZbvfIeo+IYxjbiK2tY44qU76tETdhJkUqbYwZKLveRv8UIjmaFAoybA
CbpFuvHsuGMpL1Eg+nqDyn7z4GjAsjxu5UrCTlzXkUXyvGUcZ87zWFJo7ftG4EyM
1D5hhfH0whmeLRxOs/BkYThHe3q+uis8K9R6qbdvXXmuw/nVUQU7QmL0mA==
-----END CERTIFICATE-----
    """


class EnveloppeCertificatTest(TestCase):

    def test_fingerprint(self):
        enveloppe = EnveloppeCertificat(certificat_pem=SAMPLE_CERT_1)
        cert = enveloppe.certificat
        fingerprint = EnveloppeCertificat.calculer_fingerprint(cert)
        fingerprint_pre_calcule = enveloppe.fingerprint
        logger.debug("Fingperprint certificat : %s" % fingerprint)
        self.assertEqual(FINGERPRINT_CERT_1, fingerprint)
        self.assertEqual(FINGERPRINT_CERT_1, fingerprint_pre_calcule)

    def test_idmg(self):
        enveloppe = EnveloppeCertificat(certificat_pem=SAMPLE_CERT_1)
        idmg = enveloppe.idmg
        logger.debug("idmg : %s" % idmg)
        self.assertEqual(IDMG_CERT_1, idmg)

