import logging

from unittest import TestCase

from millegrilles.util.X509Certificate import EnveloppeCleCert


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

FINGERPRINT_CERT_2 = 'zQmT8L1ctRhSV6QAVXWm7bGs9uR14K9whuUnAKanC4Pz84T'
SAMPLE_CERT_2 = """
-----BEGIN CERTIFICATE-----
MIIEbDCCA1SgAwIBAgIUd8jlVh+5i4blQjkMSEbOAx42Xh4wDQYJKoZIhvcNAQEL
BQAwfjEtMCsGA1UEAxMkYjBlN2UxNmItNTMyMC00OTc0LTgxZDAtYmZkMTIyMzVh
N2E1MRYwFAYDVQQLEw1pbnRlcm1lZGlhaXJlMTUwMwYDVQQKEyxRTEE4ejdTYUx4
NFpGVHlSYlVkUGllam9qbTVoVWZxeGNQUmN3c3VpVlI4VDAeFw0yMTAyMTUyMDAz
NDNaFw0yMTAzMTcyMDA1NDNaMHgxNTAzBgNVBAoMLFFMQTh6N1NhTHg0WkZUeVJi
VWRQaWVqb2ptNWhVZnF4Y1BSY3dzdWlWUjhUMRAwDgYDVQQLDAdtb25pdG9yMS0w
KwYDVQQDDCRiMGU3ZTE2Yi01MzIwLTQ5NzQtODFkMC1iZmQxMjIzNWE3YTUwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDl/fpKc+Wu+LcatADxy3ViBX54
n3EK1LEWZJWC6AQR8hGGkaxxtgiyoasMJiblrqnZommcjk399D60Ix2GeMNoCEfu
TWpoxDz7VXFfTQFiUExDwPWqKAdQSeK0B9JUQMyh/0IKH9ARWqnUg9c6Q3DUpHCO
iIqEc3YN9yi+wFplTFnrzemBLYhsql+gNwq5YseqX/ZaV7iM+MoLkYdYERJPlGIA
aYiSD10BZ9K5XXzdXyz8UBwfzJC2haP5fCKjWalusz0d7FLAqVQtLSOf+EANJiQ5
xlbo8HZyqKc9zOChukQDiO4mGNIm0O8aghl9ypAybyX3gJxKJj0UEJTkwEHtAgMB
AAGjgecwgeQwHQYDVR0OBBYEFJfXeAZw7qYc+XASOU6CcUVbfsm6MB8GA1UdIwQY
MBaAFB87VTm4RcNiLLIQTLZ7KIEEu6chMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQD
AgTwMCIGBCoDBAAEGjQuc2VjdXJlLDMucHJvdGVnZSwyLnByaXZlMA8GBCoDBAEE
B21vbml0b3IwUgYDVR0RBEswSYIkYjBlN2UxNmItNTMyMC00OTc0LTgxZDAtYmZk
MTIyMzVhN2E1gglsb2NhbGhvc3SHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAEwDQYJ
KoZIhvcNAQELBQADggEBAAlPk0Efd4kpagvwRTyX5X5W//xnMZ1w47ITc0sGeT4e
uFJh5hBjzCoM56TCb1pQ7s7oM212HzEBvxS7HEcvejbihHFVxr7BFicEl640lFgC
7Za9w+CcJ8a9XoiXxj0n1eIEtP2+M3C+3989bo7Pu7XU3cTRg2MKQ4siMbF8eC5p
HGUcpspZKUewZYWd/jp2vQaUqe9PP/hLHLSQRySo8GVUIITyvbhDZMCaKcTSjbB3
SJhmTaxLKFP0ZMwHnanxpYUVCTgnhL/rjnVcphCyauevJfnz/F9jkQfqSiAnekXR
Mp0ZzHARNeA6hsAjgnIliyUkhw8/A6mH/PDyl+RSl/w=
-----END CERTIFICATE-----
"""

class EnveloppeCleCertTest(TestCase):

    def setUp(self) -> None:
        self.clecert_1 = EnveloppeCleCert()
        self.clecert_1.cert_from_pem_bytes(SAMPLE_CERT_1.encode('utf-8'))
        self.clecert_2 = EnveloppeCleCert()
        self.clecert_2.cert_from_pem_bytes(SAMPLE_CERT_2.encode('utf-8'))

    def test_fingerprint_cert1(self):
        fingerprint = self.clecert_1.fingerprint

        logger.debug("Fingerprint %s" % fingerprint)
        self.assertEqual(FINGERPRINT_CERT_1, fingerprint)

    def test_idmg_cert1(self):
        idmg = self.clecert_1.idmg

        logger.debug("IDMG %s" % idmg)
        self.assertEqual(IDMG_CERT_1, idmg)

    def test_fingerprint_cert2(self):
        fingerprint = self.clecert_2.fingerprint

        logger.debug("Fingerprint %s" % fingerprint)
        self.assertEqual(FINGERPRINT_CERT_2, fingerprint)

    def test_idmg_cert2(self):
        idmg = self.clecert_2.idmg

        logger.debug("IDMG %s" % idmg)
        self.assertEqual(IDMG_CERT_1, idmg)

