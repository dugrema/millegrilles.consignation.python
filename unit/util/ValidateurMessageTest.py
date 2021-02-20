import json

from cryptography.exceptions import InvalidSignature

from unit.helpers.TestBaseContexte import TestCaseContexte
from millegrilles.util.ValidateursMessages import ValidateurMessage
from millegrilles.util.Hachage import ErreurHachage
from millegrilles.dao.MessageDAO import CertificatInconnu


IDMG = 'z2RACWHAFSqghq8EaTg5HSGKNPBr3uBfpcpLmBTJa9SEK9MmbD6cA2'

MESSAGE_1 = {
 "allo": True,
 "en-tete": {
  "idmg": "DUMMY",
  "uuid_transaction": "d6b436ca-730e-11eb-8224-5bc084acf719",
  "estampille": 1613779313,
  "version": 6,
  "domaine": "Domaine.test",
  "hachage_contenu": "mEiAcD18IXkmUeneUYOVwRvGBKt+foKqzudR0qdN/QNT7YQ",
  "fingerprint_certificat": "zQmfM5VwCxqroqLfLyyATdeDEDu6V7kQ7i3A6ERcMJ6gGzA"
 },
 "_signature": "iLqYQCCccRqwKeCN0v2+tAvxlDLtA8ZO22YxHW9rycBbUlvCI3h6ikMp8SAawVSzR9MRu+uXDPC+S+0631Be07DfDz0rYLM7G0S7T22/h/fZuVFV3T/htrD7d1PprynKxA45RKQAYcrb9teie1WPEezjtsdVx0YjE+lLJzu3jKR+nAiTyIdpz21RgSi9+Au5UxS+jJRLUlCo783kYOW4Qbr3TPM9BTIfMoGXcFHE8WT2LeCm/UjoTp28ZF81LX521oyGeLKbrQTFbLWxUJLUXvUQGTkSdkSwkUgIEh8kvypx+4BszdHbzgm27+dH9O2Oa1zmA4QAyc59WXFiFHOlNQ==",
 "_certificat": [
  "-----BEGIN CERTIFICATE-----\nMIIEEzCCAvugAwIBAgIUCr3RXMBLNHYgk7tqX2Uy+3sTEB8wDQYJKoZIhvcNAQEL\nBQAwgZoxPzA9BgNVBAoMNnoyUkFDV0hBRlNxZ2hxOEVhVGc1SFNHS05QQnIzdUJm\ncGNwTG1CVEphOVNFSzlNbWJENmNBMjEWMBQGA1UECwwNSW50ZXJtZWRpYWlyZTE/\nMD0GA1UEAww2ejJSQUNXSEFGU3FnaHE4RWFUZzVIU0dLTlBCcjN1QmZwY3BMbUJU\nSmE5U0VLOU1tYkQ2Y0EyMB4XDTIxMDIxOTIzNTk1M1oXDTIxMDMyMzAwMDE1M1ow\naDE/MD0GA1UECgw2ejJSQUNXSEFGU3FnaHE4RWFUZzVIU0dLTlBCcjN1QmZwY3BM\nbUJUSmE5U0VLOU1tYkQ2Y0EyMREwDwYDVQQLDAhkb21haW5lczESMBAGA1UEAwwJ\ndW5pdF90ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq8UTmllF\nd3YwGagzlPVs8GwE27kNfRZirW6yrCFCqA0PnhBhtkSQgreUJw7fXNlYGjAy2O/Z\nlIkc7/AGHz5yEXj5ExQBi5nTlEVD4FcMCstheJeeJi1JYQ7Gb2ITfermkkE31tFF\nszEJRRPS90RXfkVceIQ246wLAegCp4GtnLC+K4QKHsmo8BKduV3R9I3Ika9qNKOr\nn/dDXqPQxIzSGs2WseYNpBR2b66uOiW54Lm6ORF5CVE/CTu2YdAhwDY5oSv32YFd\ntjf1dn5nEgxdY+GXr7vZnBSDLlvGn2rjz0Otqnlips6KH9R5GQwJJY16+ASeaag/\nQWRLqL62IvErFwIDAQABo4GBMH8wHQYDVR0OBBYEFMXfG0hE+KLfQt1/RFWjzjM8\nznJ4MB8GA1UdIwQYMBaAFFfgrrkwnA+tpUNNdhrlGNbvRknsMAwGA1UdEwEB/wQC\nMAAwCwYDVR0PBAQDAgTwMBAGBCoDBAAECDQuc2VjdXJlMBAGBCoDBAEECGRvbWFp\nbmVzMA0GCSqGSIb3DQEBCwUAA4IBAQAZxAiiWJyQLz94dAiJBEgzNiovm2JpU08q\nxRx0kI253a7Qh/9+0aMpNfAG+KkwaIYGSyw0MsvrrfIEI/EzzRQmbdSqmtoU7np0\n1cYHSAnTnl3DSwTvO2TYnXnAYiO/2/li8b1LWIMA5oe5C8TXhmDihTlvcu9ju4yX\n3bKqCFyidSVv+34yVVv1Tv+gon5nnmaJJmIDc5L18F8S8FdLkenoa6B758Hs1dwu\nHHy4VG7wzADiQKUtLwKnWLvy6hFyquxmzylRfW+JcbJw9l117xHmspmbtjyeo1ox\nke+yhFwpGdk1gAKbMlYZEUQXzFCE+i7q03a5Ox+Una7s1me0RpCw\n-----END CERTIFICATE-----\n",
  "-----BEGIN CERTIFICATE-----\nMIIEszCCApugAwIBAgIUJBW6xXLtjWq0xk7o/TAZKcPjOQ0wDQYJKoZIhvcNAQEL\nBQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y\nMTAyMTkyMzU5NTNaFw0yMTAzMjMwMDAxNTNaMIGaMT8wPQYDVQQKDDZ6MlJBQ1dI\nQUZTcWdocThFYVRnNUhTR0tOUEJyM3VCZnBjcExtQlRKYTlTRUs5TW1iRDZjQTIx\nFjAUBgNVBAsMDUludGVybWVkaWFpcmUxPzA9BgNVBAMMNnoyUkFDV0hBRlNxZ2hx\nOEVhVGc1SFNHS05QQnIzdUJmcGNwTG1CVEphOVNFSzlNbWJENmNBMjCCASIwDQYJ\nKoZIhvcNAQEBBQADggEPADCCAQoCggEBALUAsdgVo2dauCuimfFMl9r3OrBmtifh\n/mVyPenST/vZieTr1BgZgSMAacY4b9LvZMSUDAfbQSpAmr35eZ5wiXw/k/MXanit\n2sSKKmfdG0j5ytHTJHtRzdmVVmHjsCcK+JYRVGMQ9jWxOlhnq5n9qMFLo+ONnN5v\nkWLl9TcuVSGlMQzOh1hZUjlAcvMoBrMAwobe6cEw+BxtCGBu2E0FANYa5jrktz12\n1Cv0FCY3yjU11DCMOs48TYsZBa29JkHCYceOixjgcr/wMdBvdTPiWQwiUztR7jJ5\nxi/1hrtErto/cLFvbMTFZzhkvD+XHUmMZiI1zVKi7q+QlFN76yqXMkUCAwEAAaNj\nMGEwHQYDVR0OBBYEFFfgrrkwnA+tpUNNdhrlGNbvRknsMB8GA1UdIwQYMBaAFE44\nJLSB/bvYgljhsEwESKiQtYq3MBIGA1UdEwEB/wQIMAYBAf8CAQQwCwYDVR0PBAQD\nAgL8MA0GCSqGSIb3DQEBCwUAA4ICAQCPsWw/o3p524DnQ0y4ZaC9upw8z3yAIrNr\nWYO3PhKip38Y9r4MU0fA1F9Fg2G8OrP+etvv652OJwVd3tqqArugqWRJ2PIfIEz+\nngvLnwxKoY0DeWuiDJjyPS0z1QASCMDC7aT+EUSw2XW6fVN1AoqLJTd62ox3RMfo\nrMPRMmWeJCdG/rgxnOzqNw4t+MC89eHIkRGuyMwCM+v4Ip+o/U01faKUouUcql7g\nEsM1prMf1vujgpGLWaD/5Dd9Bz1AbbMj+9ErimdjJeGsZTmL8XAVSwRSdhcv8PbI\n/3WEDC/DpCNAySQmyEolUImqcmcp5AyOkqCB1I7+fKoDtDyaiqGdw3XMFELYV+mn\ndAVlOPhCyPqMMUn4GDdME2Iie9xglEDU5fMPDIYDFjxhYvcCQMbUBH6UB0dfj2Tk\nJTxqz1YUHjKI9IbcNzjNPoE7DCL9jwxtHmcLgrlANSjSBXDa1NWG7P1WMagsZlho\nnMywVLZqS2W91ZR+P89ZfQGlEZjwLRzhCLWR4svCPfn0UHRbdfskiUcIQO2zulzr\ntWg5NiI4ZpfhpZbR5ohDMwevlYAjxqAicaCIkbsk95uh9eH37oLHOe8DwWaoiLa1\njZ3QvXgFEMNNq8EPIA+EtjVyKSmJZnOFsyJyOik6I75TUJKa8JuQ+77b6dmOUnrj\nagjsSz+AAA==\n-----END CERTIFICATE-----\n",
  "-----BEGIN CERTIFICATE-----\nMIIFMjCCAxqgAwIBAgIUZt8j6LG+nsSb1wsrxjmWmSn5lzUwDQYJKoZIhvcNAQEN\nBQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y\nMTAxMTQxODU3NTZaFw0zMTAxMTcxODU5NTZaMCcxFDASBgNVBAoMC01pbGxlR3Jp\nbGxlMQ8wDQYDVQQDDAZSYWNpbmUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\nAoICAQDu4dTDbd9Wz3elIVisJdBedhmhtxdmgxefKEg5uu415TfICVI4c8ay7Qav\nn22S1C6LyVgB0aK1VD5NS+0fPp2sFmDQ7kP+s7QIjHkNCT6CL/n3SdLRN5gexyc1\ntDd52sDAmVuXqBReQ6xDaHWc94QTbMC3eqrAhtMUjG9XMcoyW0u9LT9d7w3AElYT\nzlkAcTSMmshqg893PQPzbOxjnSiLzsAUWuBrYYXx83jmMKaj6WPJ7tTFRZgZnfId\nuso7rl3UpnjoFBLN9AdhKWFPmt7jnVxxaN0JwG+7elxhR007lJD2RylLtHhcPSCx\nWiMZlFLTG+U+tFZgXRh5DeO1v5/vEj97JU6GX7tZG+0K0UdUa8MDvsToooFq33DV\nG5Al6odx+KLATGhBm/l1HIr9LVrj+5tVklXZpaB0P8SAlic8sEF+YpLjRQLueND3\nsi+TpKCg6S83fMJRdp0bTXNe3oeukB8DQxaH7OqksHzMvYZnLpqjSrTrg2kmtS3z\nwm6KOLXxHzE7r85m5o60SOO++C5gDxAAzwKFABZ0UhhzycMekEMTcqB+h23OQYJK\nFVtdhK95A0nMQGeQqthOyIeAAmEzmCZX2SrDhF3mK1N5PDaHdv6bGPJNHzm5wMQc\nnJcVTJCK9+jmFAVnEZfzphjOHcWtd95XqOYb6kkUAWxca6zGOwIDAQABo1YwVDAd\nBgNVHQ4EFgQUTjgktIH9u9iCWOGwTARIqJC1ircwEgYDVR0TAQH/BAgwBgEB/wIB\nBTAfBgNVHSMEGDAWgBROOCS0gf272IJY4bBMBEiokLWKtzANBgkqhkiG9w0BAQ0F\nAAOCAgEAd/8X18Yt8p6L+ox7Hm23BokcVY6AfZOJajDECuVPlVqUvqu6puP2u+uk\nyg1NPPmPTA981L9EQXGmW8fuwcvlJqiUueIszPqk1Zo2Zg6EvcSHJ93d3SPcDo+W\nzTxrfNFDhVxnlp6RdiaYuhJzAZKICA4EJFi7rogKMdcxrzDk7yNAguoU9pkRM3oP\nnKyCqe34madILHHYTir25wcaV3WsSrY+BmjSTgJkoAUWnuSWKa6fvbcocYmELSIu\nnNcpavckTMPEYwLBA7xxVUppSKdXN4vOCRJVAh6NOx+NW4XhN/rb+ltSFFO87oIG\n3+YihVbIith5Xj0GzUswyOX3gn2SJlXjk+B5UIiOh8cd3U4HarquArnn3cf4P5Ev\n3d6J8i6oq0RQzguu6ER6JcwWkWI9psDag0GTxYUG1oQ99hSsxYavdlonJAao/hS8\ni6vDK150gjFv4+mxanmuGxxgr3f5Kzu+NxwSsCVJGZ3ckyRK/SQlnGHe7K6YncTW\nuEeeBOTeRYnf25D+2lr/MpCtkz5i3DHc3eI9FfeAbmDUI6O5NxYz5pBytb4zQ8Sz\neIdNRGmLNchR/uWo9Wnenvz7DAmqteUWm9Lo+5EStaYesIyHeuirUsKDSJVyS+s6\nZE4ROy5y+dG0q3rgtYWkRh5Jseo1fwtVE2IQ/WhPpi9jdFX4DRw=\n-----END CERTIFICATE-----\n"
 ]
}


class ValidateurMessageTest(TestCaseContexte):

    def setUp(self) -> None:
        self.validateur = ValidateurMessage(idmg=IDMG)

    def testValiderMessage1(self):
        self.validateur.verifier(MESSAGE_1)

    def testValiderMessage1_hachage_mismatch(self):
        message = MESSAGE_1.copy()
        message['dummy_valeur'] = 1
        self.assertRaises(ErreurHachage, self.validateur.verifier, message)

    def testValiderMessage1_signature_mismatch(self):
        message = MESSAGE_1.copy()
        message['_signature'] = 'ZLqYQCCccRqwKeCN0v2+tAvxlDLtA8ZO22YxHW9rycBbUlvCI3h6ikMp8SAawVSzR9MRu+uXDPC+S+0631Be07DfDz0rYLM7G0S7T22/h/fZuVFV3T/htrD7d1PprynKxA45RKQAYcrb9teie1WPEezjtsdVx0YjE+lLJzu3jKR+nAiTyIdpz21RgSi9+Au5UxS+jJRLUlCo783kYOW4Qbr3TPM9BTIfMoGXcFHE8WT2LeCm/UjoTp28ZF81LX521oyGeLKbrQTFbLWxUJLUXvUQGTkSdkSwkUgIEh8kvypx+4BszdHbzgm27+dH9O2Oa1zmA4QAyc59WXFiFHOlNQ=='
        self.assertRaises(InvalidSignature, self.validateur.verifier, message)

    def testValiderMessage1_entete_modifiee(self):
        message = MESSAGE_1.copy()
        message['en-tete'] = message['en-tete'].copy()
        message['en-tete']['dummy'] = 1
        self.assertRaises(InvalidSignature, self.validateur.verifier, message)

    def testValiderMessage1_fingerprint_modifie(self):
        message = MESSAGE_1.copy()
        message['en-tete'] = message['en-tete'].copy()
        message['en-tete']['fingerprint_certificat'] = 'DUMMY'
        self.assertRaises(CertificatInconnu, self.validateur.verifier, message)
