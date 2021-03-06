#!/usr/bin/python3

import datetime
import pytz
from cryptography.hazmat.backends import default_backend
from cryptography import x509

CERT_MILLEGRILLE = b"""
-----BEGIN CERTIFICATE-----
MIIEBjCCAm6gAwIBAgIKCSg3VilRiEQQADANBgkqhkiG9w0BAQ0FADAWMRQwEgYD
VQQDEwtNaWxsZUdyaWxsZTAeFw0yMTAyMjgyMzM4NDRaFw00MTAyMjgyMzM4NDRa
MBYxFDASBgNVBAMTC01pbGxlR3JpbGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8A
MIIBigKCAYEAo7LsB6GKr+aKqzmF7jxa3GDzu7PPeOBtUL/5Q6OlZMfMKLdqTGd6
pg12GT2esBh2KWUTt6MwOz3NDgA2Yk+WU9huqmtsz2n7vqIgookhhLaQt/OoPeau
bJyhm3BSd+Fpf56H1Ya/qZl1Bow/h8r8SjImm8ol1sG9j+bTnaA5xWF4X2Jj7k2q
TYrJJYLTU+tEnL9jH2quaHyiuEnSOfMmSLeiaC+nyY/MuX2Qdr3LkTTTrF+uOji+
jTBFdZKxK1qGKSJ517jz9/gkDCe7tDnlTOS4qxQlIGPqVP6hcBPaeXjiQ6h1KTl2
1B5THx0yh0G9ixg90XUuDTHXgIw3vX5876ShxNXZ2ahdxbg38m4QlFMag1RfHh9Z
XPEPUOjEnAEUp10JgQcd70gXDet27BF5l9rXygxsNz6dqlP7oo2yI8XvdtMcFiYM
eFM1FF+KadV49cXTePqKMpir0mBtGLwtaPNAUZNGCcZCuxF/mt9XOYoBTUEIv1cq
LsLVaM53fUFFAgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQUwHQYDVR0OBBYE
FBqxQIPQn5vAHZiTyiUka+vTnuTuMB8GA1UdIwQYMBaAFBqxQIPQn5vAHZiTyiUk
a+vTnuTuMA0GCSqGSIb3DQEBDQUAA4IBgQBLjk2y9nDW2MlP+AYSZlArX9XewMCh
2xAjU63+nBG/1nFe5u3YdciLsJyiFBlOY2O+ZGliBcQ6EhFx7SoPRDB7v7YKv8+O
EYZOSyule+SlSk2Dv89eYdmgqess/3YyuJN8XDyEbIbP7UD2KtklxhwkpiWcVSC3
NK3ALaXwB/5dniuhxhgcoDhztvR7JiCD3fi1Gwi8zUR4BiZOgDQbn2O3NlgFNjDk
6eRNicWDJ19XjNRxuCKn4/8GlEdLPwlf4CoqKb+O31Bll4aWkWRb9U5lpk/Ia0Kr
o/PtNHZNEcxOrpmmiCIN1n5+Fpk5dIEKqSepWWLGpe1Omg2KPSBjFPGvciluoqfG
erI92ipS7xJLW1dkpwRGM2H42yD/RLLocPh5ZuW369snbw+axbcvHdST4LGU0Cda
yGZTCkka1NZqVTise4N+AV//BQjPsxdXyabarqD9ycrd5EFGOQQAFadIdQy+qZvJ
qn8fGEjvtcCyXhnbCjCO8gykHrRTXO2icrQ=
-----END CERTIFICATE-----
"""


class EpochalypseTest:

    def charger_date(self):
        date_avant = datetime.datetime(year=2038, month=1, day=19)
        print("Date avant %s" % date_avant)

        date_apres = datetime.datetime(year=2038, month=1, day=20)
        print("Date apres %s" % date_apres)

    def charger_certificat(self):
        certificat = x509.load_pem_x509_certificate(CERT_MILLEGRILLE, backend=default_backend())
        print("Information certificat")
        print(certificat)

        # date_expiration = certificat.not_valid_after
        date_expiration = pytz.utc.localize(certificat.not_valid_after)
        print("Expiration : %s" % date_expiration)
        try:
            timestamp_expiration = date_expiration.timestamp()

        except OverflowError as oe:
            print("!!!OVERFLOW!!! ==> %s" % oe)
            date_string = str(date_expiration) + ' +0000'
            print("Date string : %s" % date_string)
            date_expiration = datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S %z")
            print("Datetime importee : %s" % date_expiration)

        print("Expiration timestamp : %d" % date_expiration.timestamp())

    def executer(self):
        self.charger_date()
        self.charger_certificat()


def main():
    test = EpochalypseTest()
    test.executer()


if __name__ == '__main__':
    main()
