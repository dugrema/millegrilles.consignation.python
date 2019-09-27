from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.name import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import secrets
import base64
from millegrilles import Constantes


class ConstantesGenerateurCertificat:

    DUREE_CERT_ROOT = datetime.timedelta(days=3655)
    DUREE_CERT_MILLEGRILLE = datetime.timedelta(days=730)
    DUREE_CERT_NOEUD = datetime.timedelta(days=366)
    ONE_DAY = datetime.timedelta(1, 0, 0)

    # Custom OIDs

    # Composant avec acces interne.
    # Liste des exchanges: millegrilles.middleware,millegrilles.noeud,etc.
    MQ_EXCHANGES_OID = x509.ObjectIdentifier('1.2.3.4.0')

    # Liste de roles internes speciaux: transaction,deployeur,maitredescles
    MQ_ROLES_OID = x509.ObjectIdentifier('1.2.3.4.1')

    # Liste des domaines: SenseursPassifs,GrosFichiers,MaitreDesCles,etc.
    MQ_DOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.2')


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

    @staticmethod
    def get_authority_identifier(certificat):
        authorityKeyIdentifier = certificat.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
        key_id = bytes.hex(authorityKeyIdentifier.value.key_identifier)
        return key_id

    @staticmethod
    def get_subject_identifier(certificat):
        subjectKeyIdentifier = certificat.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        key_id = bytes.hex(subjectKeyIdentifier.value.digest)
        return key_id


class GenerateurCertificateParRequest(GenerateurCertificat):

    def __init__(self, nom_millegrille, dict_ca: dict = None, autorite: dict = None):
        super().__init__(nom_millegrille)
        self._dict_ca = dict_ca
        self._autorite = autorite

    def _get_keyusage(self, builder):
        # custom_oid_permis = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        # builder = builder.add_extension(
        #     x509.UnrecognizedExtension(custom_oid_permis, b'SenseursPassifs,Parametres'),
        #     critical=False
        # )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        )

        return builder


    def aligner_chaine(self, certificat):
        """
        Genere la chaine PEM str avec le certificat et les certificats intermediares. Exclue root.
        :param certificat:
        :return:
        """
        chaine = [certificat]

        akid_autorite = GenerateurCertificat.get_authority_identifier(certificat)
        idx = 0
        for idx in range(0, 100):
            cert_autorite = self._dict_ca.get(akid_autorite)

            if cert_autorite is None:
                raise Exception("Erreur, autorite introuvable")
            akid_autorite_suivante = GenerateurCertificat.get_authority_identifier(cert_autorite)
            if akid_autorite == akid_autorite_suivante:
                # On est rendu au root, on ne l'inclue pas
                break
            else:
                chaine.append(cert_autorite)
                akid_autorite = akid_autorite_suivante

        if idx == 100:
            raise Exception("Depasse limite profondeur")

        # Generer la chaine de certificats avec les intermediaires
        fichier_cert_str = ''
        for cert in chaine:
            fichier_cert_str = '%s\n%s' % (fichier_cert_str, cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

        return fichier_cert_str


class GenerateurCertificatMilleGrille(GenerateurCertificateParRequest):

    def __init__(self, nom_millegrille, dict_ca: dict = None, autorite: dict = None):
        super().__init__(nom_millegrille, dict_ca, autorite)

    def generer(self) -> dict:
        """
        Sert a renouveller un certificat de millegrille. Conserve tous les autres certs de MilleGrille valides
        jusqu'a echeance.
        :return:
        """
        # Preparer une nouvelle cle et CSR pour la millegrille
        key_csr = super()._preparer_key_request(
            unit_name=u'MilleGrille',
            common_name=self._nom_millegrille,
            generer_password=True
        )

        # Signer avec l'autorite pour obtenir le certificat de MilleGrille
        csr_millegrille = key_csr['csr']
        cert_autorite = self._autorite['cert']
        builder = self._preparer_builder_from_csr(csr_millegrille, cert_autorite, ConstantesGenerateurCertificat.DUREE_CERT_MILLEGRILLE)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=4),
            critical=True,
        )

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr_millegrille.public_key()),
            critical=False
        )

        ski = cert_autorite.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.value.digest,
                None,
                None
            ),
            critical=False
        )

        cle_autorite = self._autorite['cle']
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=True,
                key_cert_sign=True,
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
        chaine = self.aligner_chaine(certificate)

        key_cert = {
            'cle': key_csr['cle'],
            'cle_bytes': key_csr['cle_bytes'],
            'password': key_csr['password'],
            'cert': certificate,
            'cert_bytes': certificate_bytes,
            'chaine': chaine
        }

        return key_cert


class GenerateurInitial(GenerateurCertificatMilleGrille):

    def __init__(self, nom_millegrille):
        super().__init__(nom_millegrille, None, None)

    def generer(self):
        """
        Sert a generer une chaine initiale de cles et certs CA pour une millegrille
        :return:
        """

        self._autorite = self._generer_self_signed()
        ss_cert = self._autorite['cert']
        ss_skid = GenerateurCertificat.get_subject_identifier(ss_cert)
        self._dict_ca = {ss_skid: ss_cert}

        millegrille = super().generer()
        millegrille_skid = GenerateurCertificat.get_subject_identifier(ss_cert)
        self._dict_ca[millegrille_skid] = millegrille

        chaine = {
            'self_signed': self._autorite,
            'millegrille': millegrille,
        }

        return chaine

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

    def _generer_self_signed(self) -> dict:
        private_key, private_bytes, password = self._generer_cle(generer_password=True)
        builder = self.__preparer_builder(private_key, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_ROOT)

        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'SSRoot'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'SSRoot'),
        ])
        builder = builder.subject_name(name)
        builder = builder.issuer_name(name)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=5),
            critical=True,
        )

        ski = x509.SubjectKeyIdentifier.from_public_key(private_key.public_key())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.digest,
                None,
                None
            ),
            critical=False
        )

        certificate = builder.sign(
            private_key=private_key,
            algorithm = hashes.SHA512(),
            backend=default_backend()
        )

        certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

        self_signed = {
            'cle': private_key,
            'cle_bytes': private_bytes,
            'cle_password': password,
            'cert': certificate,
            'cert_bytes': certificate_bytes,
            'password': password,
        }

        return self_signed


class GenerateurNoeud(GenerateurCertificateParRequest):

    def __init__(self, nom_millegrille, organization_nom, common_name, dict_ca: dict, autorite: dict):
        super().__init__(nom_millegrille, dict_ca, autorite)
        self._organization_name = organization_nom
        self._common_name = common_name

    def generer(self):
        # Preparer une nouvelle cle et CSR pour la millegrille
        key_csr = super()._preparer_key_request(
            unit_name=self._organization_name,
            common_name=self._common_name
        )

        # Signer avec l'autorite pour obtenir le certificat de MilleGrille
        csr_millegrille = key_csr['csr']
        cert_autorite = self._autorite['cert']
        builder = self._preparer_builder_from_csr(
            csr_millegrille, cert_autorite, ConstantesGenerateurCertificat.DUREE_CERT_NOEUD)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr_millegrille.public_key()),
            critical=False
        )

        ski = cert_autorite.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.value.digest,
                None,
                None
            ),
            critical=False
        )

        # Ajouter les acces specifiques a ce type de cert
        builder = self._get_keyusage(builder)

        cle_autorite = self._autorite['cle']
        certificate = builder.sign(
            private_key=cle_autorite,
            algorithm=hashes.SHA512(),
            backend=default_backend()
        )
        certificate_bytes = certificate.public_bytes(serialization.Encoding.PEM)

        chaine = self.aligner_chaine(certificate)

        key_cert = {
            'cle': key_csr['cle'],
            'cle_bytes': key_csr['cle_bytes'],
            'cert': certificate,
            'cert_bytes': certificate_bytes,
            'chaine': chaine
        }

        return key_cert


class GenererDeployeur(GenerateurNoeud):
    """
    Deployeur de MilleGrilles
    """

    def _get_keyusage(self, builder):

        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        )

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % Constantes.ROLE_DEPLOYEUR).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, roles),
            critical=False
        )

        return builder
