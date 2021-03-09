import base64
import logging
import multibase

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

SAMPLE_KEY_1 = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPQmW19+jjbAmY
TISTJJ8p6lE4IKwwVs4fLD2T0WWu2dtCaSHqf7Fti2v9+fQqpTRE86u08ETWHGAh
5CdzlJubSKp1+cBHQetZHttpPC8rgYI5MqdVJOlacVcU5U1WTrLOXOBd7ySFpg3c
IX5P1o7EQgoaUHmuDC6K1w6yKuHzTiPwbDGPo0rhiSkIB55Ehe51dQeE0BvlFKxm
FVBkVykx3LyO92XdSB+T9W4vP4/MKsrN4CQZ4uzn8l8EzkmiUj2WPNzQqZcsTcCA
4b4fkpJK2bVEtwB14DlCM8Xj053EVG6EBlN1uFUBl+B5L1ppzuE2Xr2THrtFGUZD
uND5MFYbAgMBAAECggEBALvFrP56lx0LsXmwwV/KCwVfi6vtNfMpgd8OJs+4I4aR
S6tUMm0QuT/E09cq0IKeX8ekd8ka8VKGLLYnzXJSjdPWttDhr8kfOMjqQuCJrTae
Q8vsT1u9cEkHbFy7DiEGdcqurHuOAKmw8tef5J8ShQ/bwOlsRYFg+f3Br0fNwB27
6T6vnBk1VraRFV1n7kHvZrELI4xQsA7SWGgiLOOiK/MGRn0GFyJT6xXdZkD3VWFn
5nGEKsMqgdMF7mjLjx61cb24gcGB5s69vu8DVuU7FpmMjf17vCuJAMmmim5ts1vd
2DdeBsMM7JFbVIApP03A4j4y3x97IVvaa1/9VM6eKfECgYEA6MOqz4Wo51ubpJcZ
yej+E8b66MhxKuSqq6EzSANY1G5LcCtxUTl1ncErvUVZCNNWHADODbRAgTwsAg8m
vYGeP1RbL9HMCCIA9ArLFxzsWcPyyNuFLMUy5R5ijJv+nuViXziIycKSSmGfl3q6
yKSdz0DbiTu1jnPY1ZB6yKB0sIMCgYEA4/LyRdv52IkWzQ8W4sWQABqo2uMJPRGQ
VPsTtNJBC8SfeP/XhF0z5TF7IRhWhffw/2MRXt1V7c0APWm2tQ5w7c/xVDzCeNiE
IFKRiplRR3SIt6vorIFeovuhx15qXemyn4VF6v+17d2NdkoPWmRxf4L3X88sJ2tb
bOiVBh4koIkCgYBzGvfoQefB6ZpxbUuSfsbOzvKblSvpk0UXNNNgRE90Vcq2gLU7
/pc8WR+hLJ8X7zLBDGDZhA72GeSFbCqzQlsYZEXnwu8MAozIImJGXsY+qdjxHSWh
ey9tAHappCbpOvRHtHRomfCwGdDLHyUpPcbQi/lExyNEe+N50UX22up5swKBgD1y
BcCzFVw7R/wqrx6d5r1Acnfeb2UY0PE3ZQ5/Bq2naN1zCaNShGSpu+kl6FzggwQ0
rkAGJd2ePwxO7MNNiz9vqDvuzPVKWANmfnj/7xr13My1+FhX3yzL68YUO1PpZQ7/
G+PG3kGqUTGrsQvKu5WFti0LaXmOxOxMna8yfOkRAoGBALe4GqADsOsrTCt/pAdz
idy5n/BMzN3rYszGfBo/Kk6+J/+ZMakEX5AJCo/FVB6+GwZXNXbSOwS8YeH7Ua3a
R/l0sX1fFVaL6Ivvhe4h5fO+wnnTcwRQxdbpHUQMWfE7Jx5K0xv+EbWK/kum+zFN
kdy1sUwsQF60ZfujqbMQ49Y4
-----END PRIVATE KEY-----
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
        """ Tester extraction du IDMG a partir de l'organization (champ O) """
        idmg = self.clecert_2.idmg

        logger.debug("IDMG %s" % idmg)
        self.assertEqual('QLA8z7SaLx4ZFTyRbUdPiejojm5hUfqxcPRcwsuiVR8T', idmg)

    def test_fingerprint_cle_publique(self):
        fp = self.clecert_1.fingerprint_cle_publique
        logger.debug("Fingerprint cle publique : %s" % fp)

        # pem = fp['pem'].decode('utf-8')
        # der = fp['der']
        #
        # der_b64 = base64.b64encode(der)
        #
        # logger.debug("Fingerprint cle publique PEM:\n%s\nDER:\n%s" % (pem, der_b64))




PASSWORD_1 = "mh4P1n8aD/byx5+iEt9NU1JEV7JUT7n19lowKrwerkm3cQwLu3e//cZBdcya+2wdEIuYyMW/xlzL2l16o/OZGOzZzA6ZsTWM/9EhuMW+0GO6pwM53vWcooTBcc4HkEX5/6ZkbGUMFn+b/ii34QsrWi7u8NW39UtgcKy5+cS3M0s118yYXDOguJ3UXn8jgpxNYgM3deoFb2KlCRt+rgODTckQweSaOL0xGhsO7g8z4flKvoLfKZN2D5QmDAJK2T1OlUcya+EAnNSN7hT05s7AAQOy2MLS2IGQG1QDp02qlLVbxZWX8bLI9OlDTZ12voK4LcCreqzWqqhNpWDzhiXXc0w"
PASSWORD_1_DECHIFFRE = 'mOBMFwIz7F9bgQvcrQ9xtAxAKBHpozGNQZt6AfYIVdFM'


class EnveloppeCleKeyTest(TestCase):

    def setUp(self) -> None:
        self.clecert_1 = EnveloppeCleCert()
        self.clecert_1.key_from_pem_bytes(SAMPLE_KEY_1.encode('utf-8'))

    def test_dechiffrer_password1(self):
        password1_chiffre_bytes = multibase.decode(PASSWORD_1.encode('utf-8'))
        password_dechiffre = self.clecert_1.dechiffrage_asymmetrique(password1_chiffre_bytes)
        pwd_dechiffre_str = multibase.encode('base64', password_dechiffre).decode('utf-8')
        logger.debug("Password dechiffre : %s" % pwd_dechiffre_str)

        self.assertEqual(PASSWORD_1_DECHIFFRE, pwd_dechiffre_str)

