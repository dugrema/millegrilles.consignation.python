from millegrilles.util.IdmgUtil import IdmgUtil, IdmgInvalide


CERT_1 = """
-----BEGIN CERTIFICATE-----
MIIFMjCCAxqgAwIBAgIUeDNwCr5MOx56jRjb3daq3PBT1QMwDQYJKoZIhvcNAQEN
BQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y
MDA2MDUxNTI2MDZaFw0zMDA2MDkxNTI2MDZaMCcxFDASBgNVBAoMC01pbGxlR3Jp
bGxlMQ8wDQYDVQQDDAZSYWNpbmUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQDY+yHbFWCeY7lwlLOH2LF7eSAZBi/FTe4gjrlS1sor2eXpx/0QlvhwUxsh
W7LpV52yua0Knbt4ifwfvqUNP5RQ4QzfNJFSd1K3lgGWLt7ML5W3Pl3Ji2//WJt1
gRfP9EmQQTpo4jIbc1SJ47LSiBkvsZOi90bTk0qW8gUXyrcMXSQUYZ05G/DroEmO
1oX9qaG3lp7L3NHdv/96kARKZ0r3jJ+KQv1hJPR3Ad3Vaq8YGdzOEyNn0z0Ycj85
LuB4dwhteEnQGMm/8eNy7kwStpTx+5loivEU36NcvtWwP/nJkBrZOklCQSEskMwc
FdEFwDoOS21rHnazbUkcKyYx7HBP0Ju8koX8DcwnPe1g9IwtSS1xYHjPwYSe18PW
YnRCK70K2OTIxc3NpjCFEmdaK0Wh4xRFP2s8/rjjqm4/XcjJrlc7necJ3pkB84ug
VPHuIAJZxzzxdtxFniw2K/vl23qF4fvGg6lxSPDUaCyvigJ8iMrvdyCD2bQzao35
fipl8Vz24o5+pF9CZVjMZAvStGQK8rjnk/VdawY/1FIzG+EwH8XwbLM/r5aZsPlz
w1mVP6BBYsJ18wqTuvxJyfACOY3zffxoW7RSvjGMtu+R+v2tOGvIyOxOzZaRhRLq
3PWy0TgIaYt8/TBYR9T3lga4fQCkZ1dO0Frm2f+6U8VFxePJGwIDAQABo1YwVDAd
BgNVHQ4EFgQUd8XlD/lNWcXckDR5ft3fzhXjrycwEgYDVR0TAQH/BAgwBgEB/wIB
BTAfBgNVHSMEGDAWgBR3xeUP+U1ZxdyQNHl+3d/OFeOvJzANBgkqhkiG9w0BAQ0F
AAOCAgEASd+pbw7bewxs2kB61XiTvy36bMTqeuZXCWIdhwnOkCR/7Jwmof3pNg9c
QnhFd2pGZEk1Vfc/O5PQAYyl/P1glrr61vKrjJ8jKy2Zwg32oIc62N5KqNIObuqL
Z18yxbmLafXG6iMY4cb7Hsu7m63peANdscIZlq9cYKAAUQSZ8shDkndO6Ec+ZYuY
nJl09Xwcw8YRGKtqVMS3vCFgFbMdyAXJBNCBQcsnmbTm0bobidHtHPsh+4aA86iT
i/MRK0Q/BP4Ji//Nk036cNURXLLIBawpcnXoebCxCDiuk0p5lRPC5pjAcjkGW+a+
nYRlhxk+OGYW4In9cqQeHlHCGC4sX4MOOkThnuj1Lvy3gJmNjukMT8Wj2883pc89
X9copmyb54cRNU/wQnmqho8Qotz1z+yEc6FLh39Af423ITVCo32qhhGfKYE7QyF2
7HeLulNbl97pKBJrMx6h1SOQOOUDa5vIel0Qjnyp8m72hB1NJx9g40sSxvos9t0C
d2cqud3HlRDt6WU3TBZF+lPe9LMyWYFB5MxMOldHF1qh578R5E3s6Ad/iKO6xcq2
z393rTa6h2h/mFIWtNaJOqUZujn/pUs4PfbxIFDESOKfBzbdSkp/6zMAQPVVx0gq
8B1xCXbGv8WDFXxdS9oToOJN1VDYHnnsJucdss5i/OAx/QU0dQs=
-----END CERTIFICATE-----
"""

CERT_2 = """
-----BEGIN CERTIFICATE-----
MIID4TCCAsmgAwIBAgIUH7Bk4+/vb2AtGJ9yPLBaf3n4mv4wDQYJKoZIhvcNAQEL
BQAwejEwMC4GA1UECgwnMjl5SGFKVlhWWjVlQ0VzYjdySzNpTnJydURtWU5oOVoy
aFd6TnR6MRQwEgYDVQQLDAtNaWxsZUdyaWxsZTEwMC4GA1UEAwwnMjl5SGFKVlhW
WjVlQ0VzYjdySzNpTnJydURtWU5oOVoyaFd6TnR6MB4XDTIwMDYwNTE1MjYxMFoX
DTIxMDYwNzE1MjYxMFowVzEwMC4GA1UECgwnMjl5SGFKVlhWWjVlQ0VzYjdySzNp
TnJydURtWU5oOVoyaFd6TnR6MREwDwYDVQQLDAhkb21haW5lczEQMA4GA1UEAwwH
bWctZGV2NDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALgxaQJuZWTn
b7ml07OYMcv/NvzLfnqI6vK13QRyfzI1e4Atm9eygOY//X9Pt03/C/vdncyeNi3Y
982GZMUod+ngJkIsRIy4xSQoMNKYCLlS6JLO7PavK6Ldy4SDNGdjchRCGksMOcPN
YvDqrMI7lVZ7qkyz6pHm8lfFmJDTE+m9kXAPNsBaHQbV2LcjR3YvqAxFAD4mlK97
lUDU+BfnljqdVbRqX3VaNtiLHRt9Hyy3yZesANZv4NudNBobHeTQFFzj7kMgxvVM
AW95cCvTCG/nBhKYNXtjN205aPXzSn0Z79c+MuzIWdtJ2rbnSFYVIm9ilhklaEdj
wGU3+JHVbWkCAwEAAaOBgTB/MB0GA1UdDgQWBBTJjE2N046TztFdXIcspmDSiSyN
pTAfBgNVHSMEGDAWgBTbfQTBMZqYCkXRI9JThJqxP6YKrjAMBgNVHRMBAf8EAjAA
MAsGA1UdDwQEAwIE8DAQBgQqAwQABAg0LnNlY3VyZTAQBgQqAwQBBAhkb21haW5l
czANBgkqhkiG9w0BAQsFAAOCAQEAf0FxqKylEdKvzEzmRPNuX9qT/FPNeN1inPOU
WFuo0O6Xk8bby9u83/2OYzq4FnamGWYZ9HF9o93UM5sc7ZFSYoPE7RSZHTrMfVGD
Lul8PgpR58RXuekLAZHgCIF7ZElCQbOWZz6mDsxPRhXQCyW+kFtCpBh8KnfjY1co
9nNuK5Pwz8DuJQrEOCn2FEhGs0C8ptKdg/kNy50N9Tb5iaIUlio+yYLva3SdLhtI
owiadWMOElqSdX3+v92HIBEAjFRjYwOnua7UBRo7Zm3RSLDm32LJXJUBC+yNTdRX
4F+tr67YEluMPA+A78EcJ7dGAcn/5Qf+FgX+EUcGC/Vcunzm3w==
-----END CERTIFICATE-----
"""


class TestIdmgUtil:

    def __init__(self):
        self.idmg = None
        self.util = IdmgUtil()

    def encoder_cert1(self):
        self.idmg = self.util.encoder_idmg(CERT_1)
        print('IDMG Cert 1 : %s' % self.idmg)

    def decoder_cert1(self):
        self.util.verifier_idmg(self.idmg, CERT_1)
        print("Verification OK")

    def decoder_cert2_invalide(self):
        try:
            self.util.verifier_idmg(self.idmg, CERT_2)
            raise Exception("Test invalide, n'aurait pas du se rendre ici")
        except IdmgInvalide:
            print("OK : verification IDMG/Cert invalide lance une exception")


def main():
    test = TestIdmgUtil()
    test.encoder_cert1()
    test.decoder_cert1()
    test.decoder_cert2_invalide()


if __name__ == '__main__':
    main()
