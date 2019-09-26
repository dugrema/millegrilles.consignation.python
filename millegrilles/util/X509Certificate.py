from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.name import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import secrets
import base64


class ConstantesGenerateurCertificat:

    DUREE_CERT_ROOT = datetime.timedelta(days=3655)
    DUREE_CERT_MILLEGRILLE = datetime.timedelta(days=730)
    DUREE_CERT_NOEUD = datetime.timedelta(days=366)
    ONE_DAY = datetime.timedelta(1, 0, 0)


class GenerateurCertificat:

    def __init__(self, nom_millegrille):
        self.__nom_millegrille = nom_millegrille
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
        builder = self._preparer_builder(private_key, unit_name='SSRoot', common_name='SSRoot', duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_ROOT)

        builder = builder.issuer_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.__nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'SSRoot'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'SSRoot'),
        ]))
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=5),
            critical=True,
        )

        certificate = builder.sign(
            private_key=private_key,
            algorithm = hashes.SHA256(),
            backend=default_backend()
        )

        public_bytes = certificate.public_bytes(serialization.Encoding.PEM)

        self_signed = {
            'cle': private_key,
            'cle_bytes': private_bytes,
            'cle_password': password,
            'cert': certificate,
            'cert_bytes': public_bytes,
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

    def _preparer_builder(self, private_key, unit_name, common_name, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD):
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.__nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]))
        builder = builder.not_valid_before(datetime.datetime.today() - ConstantesGenerateurCertificat.ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.today() + duree_cert)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        return builder


class GenerateurCertificatMilleGrille(GenerateurCertificat):

    def __init__(self, nom_millegrille, chaine_ca: list = None, autorite: dict = None):
        super().__init__(nom_millegrille)
        self.__chaine_ca = chaine_ca
        self.__autorite = autorite

    def generer_chaine_initiale(self):
        """
        Sert a generer une chaine initiale de cles et certs CA pour une millegrille
        :return:
        """

        self.__autorite = self.__generer_self_signed()
        self.__chaine_ca = [self.__autorite['cert']]
        millegrille = self.renouveller()

        chaine = {
            'self_signed': self.__autorite,
            'millegrille': millegrille,
            'chaine_ca': self.__chaine_ca,
        }

        return chaine

    def generer(self) -> dict:
        """
        Sert a renouveller un certificat de millegrille. Conserve tous les autres certs de MilleGrille valides
        jusqu'a echeance.
        :return:
        """
        pass

    def _preparer_builder(self, private_key, unit_name, common_name, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD):
        super()._preparer_builder(
            private_key=private_key,
            unit_name=unit_name,
            common_name=common_name,
            duree_cert=duree_cert
        )
