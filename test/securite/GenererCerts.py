from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.name import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

class GenerateurCertificat:

    def __init__(self):
        pass

    def generer_cert_self_signed(self, nom_fichier):
        one_day = datetime.timedelta(1, 0, 0)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(u'cryptography.io')]
            ),
            critical=False
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        certificate = builder.sign(
            private_key=private_key,
            algorithm = hashes.SHA256(),
            backend=default_backend()
        )

        with open('%s.cert.pem' % nom_fichier, 'wb') as fichier:
            fichier.write(certificate.public_bytes(serialization.Encoding.PEM))

        with open('%s.key.pem' % nom_fichier, 'wb') as fichier:
            fichier.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))

    def generer_csr(self, nom_fichier):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )

        request = builder.sign(
            private_key, hashes.SHA256(), default_backend()
        )

        with open('%s.csr.pem' % nom_fichier, 'wb') as fichier:
            fichier.write(request.public_bytes(serialization.Encoding.PEM))

        with open('%s.key.pem' % nom_fichier, 'wb') as fichier:
            fichier.write(private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            ))


if __name__ == '__main__':
    generateur = GenerateurCertificat()
    generateur.generer_cert_self_signed('/home/mathieu/tmp/certs/self-signed')
    generateur.generer_csr('/home/mathieu/tmp/certs/cert')

