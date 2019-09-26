from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.name import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import secrets
import base64

from millegrilles.SecuritePKI import EnveloppeCertificat


class ConstantesGenerateurCertificat:

    DUREE_CERT_ROOT = datetime.timedelta(days=3655)
    DUREE_CERT_MILLEGRILLE = datetime.timedelta(days=730)
    DUREE_CERT_NOEUD = datetime.timedelta(days=366)
    ONE_DAY = datetime.timedelta(1, 0, 0)


class GenerateurCertificat:

    def __init__(self, nom_millegrille):
        self._nom_millegrille = nom_millegrille
        self.__public_exponent = 65537
        self.__keysize = 2048

    @staticmethod
    def split_chaine(chaine: str) -> list:
        """ Split une liste de certificats en liste """
        pass

    def generer(self):
        raise NotImplementedError("Pas implemente")

    def _generer_self_signed(self) -> dict:
        private_key, private_bytes, password = self._generer_cle(generer_password=True)
        builder = self.__preparer_builder(private_key, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_ROOT)

        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSRoot'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'SSRoot'),
        ])
        builder = builder.subject_name(name)
        builder = builder.issuer_name(name)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=5),
            critical=True,
        )

        certificate = builder.sign(
            private_key=private_key,
            algorithm = hashes.SHA256(),
            backend=default_backend()
        )

        self_signed = {
            'cle': private_key,
            'cle_bytes': private_bytes,
            'cle_password': password,
            'cert': certificate,
            'password': password,
        }

        return self_signed

    def _generer_cle(self, generer_password=False):
        private_key = rsa.generate_private_key(
            public_exponent=self.__public_exponent,
            key_size=self.__keysize,
            backend=default_backend()
        )

        if generer_password:
            password = base64.b64encode(secrets.token_bytes(16))
            private_bytes = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(password)
            )
        else:
            password = None
            private_bytes = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )

        return private_key, private_bytes, password

    def _preparer_builder_from_csr(
            self, csr_request, autorite_cert, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD):

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr_request.subject)
        builder = builder.issuer_name(autorite_cert.subject)
        builder = builder.not_valid_before(datetime.datetime.today() - ConstantesGenerateurCertificat.ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.today() + duree_cert)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr_request.public_key())

        return builder

    def __preparer_builder(self, private_key, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD):
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.not_valid_before(datetime.datetime.today() - ConstantesGenerateurCertificat.ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.today() + duree_cert)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        return builder

    def _preparer_key_request(self, unit_name, common_name, generer_password=False):
        private_key, private_bytes, password = self._generer_cle(generer_password)

        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(name)
        request = builder.sign(
            private_key, hashes.SHA256(), default_backend()
        )

        request_bytes = request.public_bytes(serialization.Encoding.PEM)

        nouveau_keycert = {
            'csr': request,
            'csr_bytes': request_bytes,
            'cle': private_key,
            'cle_bytes': private_bytes,
        }
        if generer_password:
            nouveau_keycert['password'] = password

        return nouveau_keycert


class GenerateurCertificatMilleGrille(GenerateurCertificat):

    def __init__(self, nom_millegrille, dict_ca: dict = None, autorite: dict = None):
        super().__init__(nom_millegrille)
        self.__dict_ca = dict_ca
        self.__autorite = autorite

    def generer_certs_initial(self):
        """
        Sert a generer une chaine initiale de cles et certs CA pour une millegrille
        :return:
        """

        self.__autorite = self._generer_self_signed()
        ss_cert = self.__autorite['cert']
        ss_fingerprint = EnveloppeCertificat.calculer_fingerprint(ss_cert)
        self.__dict_ca = {ss_fingerprint, self.__autorite['cert']}
        millegrille = self.generer()

        chaine = {
            'self_signed': self.__autorite,
            'millegrille': millegrille,
        }

        return chaine

    def generer(self) -> dict:
        """
        Sert a renouveller un certificat de millegrille. Conserve tous les autres certs de MilleGrille valides
        jusqu'a echeance.
        :return:
        """
        # Preparer une nouvelle cle et CSR pour la millegrille
        key_csr = super()._preparer_key_request(
            unit_name='MilleGrille',
            common_name=self._nom_millegrille,
            generer_password=True
        )

        # Signer avec l'autorite pour obtenir le certificat de MilleGrille
        csr_millegrille = key_csr['csr']
        cert_autorite = self.__autorite['cert']
        builder = self._preparer_builder_from_csr(csr_millegrille, cert_autorite, ConstantesGenerateurCertificat.DUREE_CERT_MILLEGRILLE)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=4),
            critical=True,
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr_millegrille.public_key()),
            critical=False
        )

        cert_autorite = self.__autorite['cert']
        ski = cert_autorite.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.value.digest,
                None,
                None
            ),
            critical=False
        )

        cle_autorite = self.__autorite['cle']
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
            private_key=cle_autorite,
            algorithm=hashes.SHA512(),
            backend=default_backend()
        )
        certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

        key_cert = {
            'cle': key_csr['cle'],
            'cle_bytes': key_csr['cle_bytes'],
            'password': key_csr['password'],
            'cert': certificate,
            'cert_bytes': certificate_bytes,
        }

        return key_cert
