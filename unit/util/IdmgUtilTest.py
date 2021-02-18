import logging

from unittest import TestCase

from millegrilles.util.IdmgUtil import IdmgInvalide, encoder_idmg, verifier_idmg


# Setup logging
logging.basicConfig()
logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)
logging.getLogger('millegrilles').setLevel(logging.DEBUG)


class IdmgUtilTest(TestCase):

    SAMPLE_VIEUX_IDMG = "QLA8z7SaLx4ZFTyRbUdPiejojm5hUfqxcPRcwsuiVR8T"
    SAMPLE_IDMG_1 = "z2MFCe7c6DfeMwTYpSJBGRPhiyt3peu1ucycDGDReGJQTpidp4ABPi"
    SAMPLE_IDMG_1_BLAKE2s = "zTHLGoJhFmyaCaqeMN16oZw3VY6YyhZpX3B65yPTPFfvStfyKmbY4eNQ"
    SAMPLE_IDMG_1_BLAKE2b = "z8opdm3zQFJzU1FtdXL9RTP5JzXXVYeNSME4XVH2FPh8kYwyMzW8eCNgF6EsSPtBsJWT1zKWPcWAV4qTdR3V3ArHWYb5zP2M3bi1"
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

    def test_generer_idmg(self):
        idmg = encoder_idmg(IdmgUtilTest.SAMPLE_CERT_1)
        logger.debug("IDMG calcule sur PEM : %s" % idmg)
        self.assertEqual(idmg, IdmgUtilTest.SAMPLE_IDMG_1)

    def test_generer_blake2s(self):
        idmg = encoder_idmg(IdmgUtilTest.SAMPLE_CERT_1, hashing_code='blake2s-256')
        logger.debug("IDMG calcule sur PEM : %s" % idmg)
        self.assertEqual(idmg, IdmgUtilTest.SAMPLE_IDMG_1_BLAKE2s)

    def test_generer_blake2b(self):
        idmg = encoder_idmg(IdmgUtilTest.SAMPLE_CERT_1, hashing_code='blake2b-512')
        logger.debug("IDMG calcule sur PEM : %s" % idmg)
        self.assertEqual(idmg, IdmgUtilTest.SAMPLE_IDMG_1_BLAKE2b)

    def test_verifier_idmg(self):
        verifier_idmg(IdmgUtilTest.SAMPLE_IDMG_1, IdmgUtilTest.SAMPLE_CERT_1)

    def test_verifier_idmg_blake2s(self):
        verifier_idmg(IdmgUtilTest.SAMPLE_IDMG_1_BLAKE2s, IdmgUtilTest.SAMPLE_CERT_1)

    def test_verifier_idmg_blake2b(self):
        verifier_idmg(IdmgUtilTest.SAMPLE_IDMG_1_BLAKE2b, IdmgUtilTest.SAMPLE_CERT_1)

    def test_generer_verifier_idmg(self):
        idmg = encoder_idmg(IdmgUtilTest.SAMPLE_CERT_1)
        logger.debug("IDMG calcule sur PEM : %s" % idmg)
        verifier_idmg(idmg, IdmgUtilTest.SAMPLE_CERT_1)

    def test_verifier_idmg_mismatch(self):
        self.assertRaises(ValueError, verifier_idmg, 'IDMG dummy', IdmgUtilTest.SAMPLE_CERT_1)

    def test_verifier_format_1(self):
        verifier_idmg(IdmgUtilTest.SAMPLE_VIEUX_IDMG, IdmgUtilTest.SAMPLE_CERT_1)

