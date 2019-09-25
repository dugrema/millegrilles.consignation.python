from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.name import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime


class GenerateurCertificat:

    def __init__(self):
        self.__nom_millegrille = u'mg-test'

        self.__public_exponent = 65537
        self.__noeud_keysize = 2048
        self.__ca_keysize = 4096

        self.__duree_cert_ca = datetime.timedelta(days=3655)
        self.__one_day = datetime.timedelta(1, 0, 0)

    def generer_cert_self_signed(self, nom_fichier):
        private_key = rsa.generate_private_key(
            public_exponent=self.__public_exponent,
            key_size=self.__ca_keysize,
            backend=default_backend()
        )

        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.__nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'MilleGrille'),
            x509.NameAttribute(NameOID.COMMON_NAME, self.__nom_millegrille),
        ]))
        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.__nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'MilleGrille'),
            x509.NameAttribute(NameOID.COMMON_NAME, self.__nom_millegrille),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - self.__one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + self.__duree_cert_ca)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=5),
            critical=True,
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
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
            key_size=self.__noeud_keysize,
            backend=default_backend()
        )

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ]))
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

    def signer_csr(self, nom_fichier_csr, nom_signataire):
        with open('%s.key.pem' % nom_signataire, 'rb') as fichier:
            private_bytes = fichier.read()
            signing_key = serialization.load_pem_private_key(private_bytes, password=None, backend=default_backend())
        with open('%s.cert.pem' % nom_signataire, 'rb') as fichier:
            public_bytes = fichier.read()
            signing_cert = x509.load_pem_x509_certificate(public_bytes, backend=default_backend())
        with open('%s.csr.pem' % nom_fichier_csr, 'rb') as fichier:
            public_bytes = fichier.read()
            fichier_csr = x509.load_pem_x509_csr(public_bytes, backend=default_backend())

        one_day = datetime.timedelta(1, 0, 0)

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(fichier_csr.subject)
        builder = builder.issuer_name(signing_cert.subject)
        builder = builder.not_valid_before(datetime.datetime.today() - one_day)
        builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(fichier_csr.public_key())
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(u'mon_serveur.ca')]
            ),
            critical=False
        )

        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(fichier_csr.public_key()),
            critical=False
        )

        ski = signing_cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.value.digest,
                None,
                None
            ),
            critical=False
        )

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        )

        certificate = builder.sign(
            private_key=signing_key,
            algorithm = hashes.SHA512(),
            backend=default_backend()
        )
        with open('%s.cert.pem' % nom_fichier_csr, 'wb') as fichier:
            fichier.write(certificate.public_bytes(serialization.Encoding.PEM))


if __name__ == '__main__':
    generateur = GenerateurCertificat()
    generateur.generer_cert_self_signed('/home/mathieu/tmp/certs/self-signed')
    generateur.generer_csr('/home/mathieu/tmp/certs/cert')
    generateur.signer_csr('/home/mathieu/tmp/certs/cert', '/home/mathieu/tmp/certs/self-signed')
