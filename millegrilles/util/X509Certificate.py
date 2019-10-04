from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.name import NameOID
from cryptography.hazmat.primitives import asymmetric


import datetime
import secrets
import base64
from millegrilles import Constantes


class ConstantesGenerateurCertificat:

    DUREE_CERT_ROOT = datetime.timedelta(days=3655)
    DUREE_CERT_MILLEGRILLE = datetime.timedelta(days=730)
    DUREE_CERT_NOEUD = datetime.timedelta(days=366)
    ONE_DAY = datetime.timedelta(1, 0, 0)

    ROLE_MQ = 'mq'
    ROLE_MONGO = 'mongo'
    ROLE_DEPLOYEUR = 'deployeur'
    ROLE_MAITREDESCLES = 'maitredescles'
    ROLE_TRANSACTIONS = 'transaction'
    ROLE_CEDULEUR = 'ceduleur'
    ROLE_DOMAINES = 'domaines'
    ROLE_COUPDOEIL = 'coupdoeil'
    ROLE_FICHIERS = 'fichiers'
    ROLE_VITRINE = 'vitrine'
    ROLE_PUBLICATEUR = 'publicateur'
    ROLE_MONGOEXPRESS = 'mongoexpress'
    ROLE_NGINX = 'nginx'

    ROLES_ACCES_MONGO = [
        ROLE_MONGO,
        ROLE_TRANSACTIONS,
        ROLE_DOMAINES,
        ROLE_MONGOEXPRESS,
        ROLE_MAITREDESCLES,
    ]

    # Custom OIDs

    # Composant avec acces interne.
    # Liste des exchanges: millegrilles.middleware,millegrilles.noeud,etc.
    MQ_EXCHANGES_OID = x509.ObjectIdentifier('1.2.3.4.0')

    # Liste de roles internes speciaux: transaction,deployeur,maitredescles
    MQ_ROLES_OID = x509.ObjectIdentifier('1.2.3.4.1')

    # Liste des domaines: SenseursPassifs,GrosFichiers,MaitreDesCles,etc.
    MQ_DOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.2')


class EnveloppeCleCert:

    def __init__(self, private_key=None, cert=None, password=None):
        self.private_key = private_key
        self.cert = cert
        self.password = password
        self.csr = None
        self.chaine = None

    def set_cert(self, cert):
        self.cert = cert

    def set_csr(self, csr):
        self.csr = csr

    def set_chaine(self, chaine: list):
        self.chaine = chaine

    def set_chaine_str(self, chaine: str):
        chaine_list = chaine.split('-----END PRIVATE KEY-----')
        self.chaine = list()
        for cert in chaine_list:
            cert = cert + '-----END PRIVATE KEY-----'
            self.chaine.append(cert)

    def from_pem_bytes(self, private_key_bytes, cert_bytes, password_bytes=None):
        self.private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=password_bytes,
            backend=default_backend()
        )

        self.cert_from_pem_bytes(cert_bytes)

    def cert_from_pem_bytes(self, cert_bytes):
        self.cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

    def cle_correspondent(self):
        if self.private_key is not None and self.cert is not None:
            # Verifier que le cert et la cle privee correspondent
            public1 = self.private_key.public_key().public_numbers()
            public2 = self.cert.public_key().public_numbers()

            n1 = public1.n
            n2 = public2.n

            return n1 == n2

        return False

    def key_from_pem_bytes(self, key_bytes, password_bytes=None):
        self.private_key = serialization.load_pem_private_key(
            key_bytes,
            password=password_bytes,
            backend=default_backend()
        )

    def from_files(self, private_key, cert, password_bytes=None):
        with open(cert, 'rb') as fichier:
            self.cert = x509.load_pem_x509_certificate(fichier.read(), default_backend())

        with open(private_key, 'rb') as fichier:
            self.key_from_pem_bytes(fichier.read(), password_bytes)

    @property
    def cert_bytes(self):
        return self.cert.public_bytes(serialization.Encoding.PEM)

    @property
    def csr_bytes(self):
        return self.csr.public_bytes(serialization.Encoding.PEM)

    @property
    def akid(self):
        return EnveloppeCleCert.get_authority_identifier(self.cert)

    @property
    def skid(self):
        return EnveloppeCleCert.get_subject_identifier(self.cert)

    @property
    def fingerprint(self):
        return bytes.hex(self.cert.fingerprint(hashes.SHA1()))

    @property
    def not_valid_before(self):
        return self.cert.not_valid_before

    @property
    def not_valid_after(self):
        return self.cert.not_valid_after

    @property
    def private_key_bytes(self):
        if self.password is not None:
            cle_privee_bytes = self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.BestAvailableEncryption(self.password)
            )
        else:
            cle_privee_bytes = self.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()
            )

        return cle_privee_bytes

    def generer_private_key(self, generer_password=False, keysize=2048, public_exponent=65537):
        if generer_password:
            self.password = base64.b64encode(secrets.token_bytes(16))

        self.private_key = asymmetric.rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=keysize,
            backend=default_backend()
        )

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

    def formatter_subject(self):
        sujet_dict = {}

        sujet = self.cert.subject
        for elem in sujet:
            sujet_dict[elem.oid._name] = elem.value

        return sujet_dict

class GenerateurCertificat:

    def __init__(self, nom_millegrille):
        self._nom_millegrille = nom_millegrille
        self.__public_exponent = 65537
        self.__keysize = 2048

    @staticmethod
    def split_chaine(chaine: str) -> list:
        """ Split une liste de certificats en liste """
        pass

    def generer(self) -> EnveloppeCleCert:
        raise NotImplementedError("Pas implemente")

    def signer(self, csr) -> x509.Certificate:
        raise NotImplementedError("Pas implemente")

    def _get_keyusage(self, builder):
        raise NotImplementedError("Pas implemente")

    def _preparer_builder_from_csr(self, csr_request, autorite_cert,
                                   duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD) -> x509.CertificateBuilder:

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr_request.subject)
        builder = builder.issuer_name(autorite_cert.subject)
        builder = builder.not_valid_before(datetime.datetime.today() - ConstantesGenerateurCertificat.ONE_DAY)
        builder = builder.not_valid_after(datetime.datetime.today() + duree_cert)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr_request.public_key())

        return builder

    def preparer_key_request(self, unit_name, common_name, generer_password=False) -> EnveloppeCleCert:
        clecert = EnveloppeCleCert()
        clecert.generer_private_key(generer_password=generer_password)

        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, self._nom_millegrille),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, unit_name),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(name)
        request = builder.sign(
            clecert.private_key, hashes.SHA256(), default_backend()
        )
        clecert.set_csr(request)

        return clecert


class GenerateurCertificateParRequest(GenerateurCertificat):

    def __init__(self, nom_millegrille, dict_ca: dict = None, autorite: EnveloppeCleCert = None):
        super().__init__(nom_millegrille)
        self._dict_ca = dict_ca
        self._autorite = autorite

    def _get_keyusage(self, builder):
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )

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

    def signer(self, csr) -> x509.Certificate:
        cert_autorite = self._autorite.cert
        builder = self._preparer_builder_from_csr(
            csr, cert_autorite, ConstantesGenerateurCertificat.DUREE_CERT_NOEUD)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
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

        cle_autorite = self._autorite.private_key
        certificate = builder.sign(
            private_key=cle_autorite,
            algorithm=hashes.SHA512(),
            backend=default_backend()
        )
        return certificate

    def aligner_chaine(self, certificat: x509.Certificate):
        """
        Genere la chaine PEM str avec le certificat et les certificats intermediares. Exclue root.
        :param certificat:
        :return:
        """
        chaine = [certificat]

        akid_autorite = EnveloppeCleCert.get_authority_identifier(certificat)
        idx = 0
        for idx in range(0, 100):
            cert_autorite = self._dict_ca.get(akid_autorite)

            if cert_autorite is None:
                raise Exception("Erreur, autorite introuvable")

            chaine.append(cert_autorite)
            akid_autorite_suivante = EnveloppeCleCert.get_authority_identifier(cert_autorite)

            if akid_autorite == akid_autorite_suivante:
                # On est rendu au root
                break

            akid_autorite = akid_autorite_suivante

        if idx == 100:
            raise Exception("Depasse limite profondeur")

        # Generer la chaine de certificats avec les intermediaires
        return [c.public_bytes(serialization.Encoding.PEM).decode('utf-8') for c in chaine]


class GenerateurCertificatMilleGrille(GenerateurCertificateParRequest):

    def __init__(self, nom_millegrille, dict_ca: dict = None, autorite: EnveloppeCleCert = None):
        super().__init__(nom_millegrille, dict_ca, autorite)

    def generer(self) -> EnveloppeCleCert:
        """
        Sert a renouveller un certificat de millegrille. Conserve tous les autres certs de MilleGrille valides
        jusqu'a echeance.
        :return:
        """
        # Preparer une nouvelle cle et CSR pour la millegrille
        clecert = super().preparer_key_request(
            unit_name=u'MilleGrille',
            common_name=self._nom_millegrille,
            generer_password=True
        )

        # Signer avec l'autorite pour obtenir le certificat de MilleGrille
        csr_millegrille = clecert.csr
        certificate = self.signer(csr_millegrille)
        clecert.set_cert(certificate)

        chaine = self.aligner_chaine(certificate)
        clecert.set_chaine(chaine)

        return clecert

    def _get_keyusage(self, builder):
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=4),
            critical=True,
        )

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

        return builder


class GenerateurInitial(GenerateurCertificatMilleGrille):

    def __init__(self, nom_millegrille):
        super().__init__(nom_millegrille, None, None)

    def generer(self) -> EnveloppeCleCert:
        """
        Sert a generer une chaine initiale de cles et certs CA pour une millegrille
        :return:
        """

        self._autorite = self._generer_self_signed()
        ss_cert = self._autorite.cert
        ss_skid = self._autorite.skid
        self._dict_ca = {ss_skid: ss_cert}

        millegrille = super().generer()
        millegrille_skid = EnveloppeCleCert.get_subject_identifier(ss_cert)
        self._dict_ca[millegrille_skid] = millegrille

        return millegrille

    def __preparer_builder(self, private_key, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD) -> x509.CertificateBuilder:
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

    def _generer_self_signed(self) -> EnveloppeCleCert:
        clecert = EnveloppeCleCert()
        clecert.generer_private_key(generer_password=True)
        builder = self.__preparer_builder(clecert.private_key, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_ROOT)

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

        ski = x509.SubjectKeyIdentifier.from_public_key(clecert.private_key.public_key())
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.digest,
                None,
                None
            ),
            critical=False
        )

        certificate = builder.sign(
            private_key=clecert.private_key,
            algorithm = hashes.SHA512(),
            backend=default_backend()
        )

        clecert.set_cert(certificate)

        return clecert

    @property
    def autorite(self):
        return self._autorite


class GenerateurNoeud(GenerateurCertificateParRequest):

    def __init__(self, nom_millegrille, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None, domaines_publics: list = None):
        super().__init__(nom_millegrille, dict_ca, autorite)
        self._organization_name = organization_nom
        self._common_name = common_name
        self._domaines_publics = domaines_publics

    def generer(self) -> EnveloppeCleCert:
        # Preparer une nouvelle cle et CSR pour la millegrille
        clecert = super().preparer_key_request(
            unit_name=self._organization_name,
            common_name=self._common_name,
            generer_password=self.generer_password
        )

        # Signer avec l'autorite pour obtenir le certificat de MilleGrille
        csr_millegrille = clecert.csr
        certificate = self.signer(csr_millegrille)
        clecert.set_cert(certificate)

        chaine = self.aligner_chaine(certificate)
        clecert.set_chaine(chaine)

        return clecert

    @property
    def generer_password(self):
        return False


class GenererDeployeur(GenerateurNoeud):
    """
    Deployeur de MilleGrilles
    """

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_DEPLOYEUR).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererCeduleur(GenerateurNoeud):
    """
    Ceduleur de MilleGrilles
    """

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID

        exchanges_supportes = [
            Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE,
            Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            Constantes.DEFAUT_MQ_EXCHANGE_INTER,
            Constantes.DEFAUT_MQ_EXCHANGE_PUBLIC,
        ]

        exchanges = (','.join(exchanges_supportes)).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_CEDULEUR).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererPublicateur(GenerateurNoeud):
    """
    Publicateur de MilleGrilles
    """

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID

        exchanges_supportes = [
            Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            Constantes.DEFAUT_MQ_EXCHANGE_PUBLIC,
        ]

        exchanges = (','.join(exchanges_supportes)).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_PUBLICATEUR).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererMaitredescles(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MAITREDESCLES).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererMaitredesclesCryptage(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MAITREDESCLES).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder

    @property
    def generer_password(self):
        return True


class GenererTransactions(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_TRANSACTIONS).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererDomaines(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_DOMAINES).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererMQ(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MQ).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'mq'),
            x509.DNSName(u'mq-%s.local' % self._nom_millegrille),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'%s.local' % self._common_name),
        ]

        # Si le CN == mg-NOM_MILLEGRILLE, on n'a pas besoin d'ajouter cette combinaison (identique)
        if self._common_name != 'mg-%s' % self._nom_millegrille:
            liste_dns.append(x509.DNSName(u'mg-%s' % self._nom_millegrille))
            liste_dns.append(x509.DNSName(u'mg-%s.local' % self._nom_millegrille))

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))
                liste_dns.append(x509.DNSName(u'mq.%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererMongo(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MONGO).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'mongo'),
            x509.DNSName(u'mongo-%s.local' % self._nom_millegrille),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'%s.local' % self._common_name),
        ]

        # Si le CN == mg-NOM_MILLEGRILLE, on n'a pas besoin d'ajouter cette combinaison (identique)
        if self._common_name != 'mg-%s' % self._nom_millegrille:
            liste_dns.append(x509.DNSName(u'mg-%s' % self._nom_millegrille))
            liste_dns.append(x509.DNSName(u'mg-%s.local' % self._nom_millegrille))

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))
                liste_dns.append(x509.DNSName(u'mq.%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererCoupdoeil(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_COUPDOEIL).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererFichiers(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_FICHIERS).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererVitrine(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.DEFAUT_MQ_EXCHANGE_PUBLIC).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_VITRINE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererMongoexpress(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'mongoexpress'),
            x509.DNSName(u'mongoexpress-%s.local' % self._nom_millegrille),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'%s.local' % self._common_name),
        ]

        # Si le CN == mg-NOM_MILLEGRILLE, on n'a pas besoin d'ajouter cette combinaison (identique)
        if self._common_name != 'mg-%s' % self._nom_millegrille:
            liste_dns.append(x509.DNSName(u'mg-%s' % self._nom_millegrille))
            liste_dns.append(x509.DNSName(u'mg-%s.local' % self._nom_millegrille))

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererNginx(GenerateurNoeud):

    def _get_keyusage(self, builder):
        builder = super()._get_keyusage(builder)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_NGINX).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'www'),
            x509.DNSName(u'www-%s.local' % self._nom_millegrille),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'%s.local' % self._common_name),
        ]

        # Si le CN == mg-NOM_MILLEGRILLE, on n'a pas besoin d'ajouter cette combinaison (identique)
        if self._common_name != 'mg-%s' % self._nom_millegrille:
            liste_dns.append(x509.DNSName(u'mg-%s' % self._nom_millegrille))
            liste_dns.append(x509.DNSName(u'mg-%s.local' % self._nom_millegrille))

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))
                liste_dns.append(x509.DNSName(u'www.%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class RenouvelleurCertificat:

    def __init__(self, nom_millegrille, dict_ca: dict, millegrille: EnveloppeCleCert, ca_autorite: EnveloppeCleCert = None):
        self.__nom_millegrille = nom_millegrille
        self.__dict_ca = dict_ca
        self.__millegrille = millegrille
        self.__generateurs_par_role = {
            ConstantesGenerateurCertificat.ROLE_FICHIERS: GenererFichiers,
            ConstantesGenerateurCertificat.ROLE_COUPDOEIL: GenererCoupdoeil,
            ConstantesGenerateurCertificat.ROLE_MQ: GenererMQ,
            ConstantesGenerateurCertificat.ROLE_MONGO: GenererMongo,
            ConstantesGenerateurCertificat.ROLE_DOMAINES: GenererDomaines,
            ConstantesGenerateurCertificat.ROLE_TRANSACTIONS: GenererTransactions,
            ConstantesGenerateurCertificat.ROLE_MAITREDESCLES: GenererMaitredescles,
            ConstantesGenerateurCertificat.ROLE_VITRINE: GenererVitrine,
            ConstantesGenerateurCertificat.ROLE_DEPLOYEUR: GenererDeployeur,
            ConstantesGenerateurCertificat.ROLE_CEDULEUR: GenererCeduleur,
            ConstantesGenerateurCertificat.ROLE_PUBLICATEUR: GenererPublicateur,
            ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS: GenererMongoexpress,
            ConstantesGenerateurCertificat.ROLE_NGINX: GenererNginx,
        }

        self.__generateur_millegrille = None
        if ca_autorite is not None:
            self.__generateur_millegrille = GenerateurCertificatMilleGrille(nom_millegrille, dict_ca, ca_autorite)

        # Permettre de conserver le nouveau cert millegrille en attendant confirmation de l'activation
        self.__clecert_millegrille_nouveau = None

    def renouveller_cert_millegrille(self) -> EnveloppeCleCert:
        if self.__generateur_millegrille is None:
            raise Exception("L'autorite n'est pas disponible pour generer un nouveau cert millegrille")

        clecert = self.__generateur_millegrille.generer()

        # Ajouter a la liste de CAs
        self.__dict_ca[clecert.akid] = clecert.cert

        # Conserver le cert en memoire en attendant confirmation d'activation par le deployeur
        # Permet d'eviter un redemarrage pour charger les nouveaux secrets dans Docker
        self.__clecert_millegrille_nouveau = clecert

        return clecert

    def renouveller_avec_csr(self, role, node_name, csr_bytes: bytes):
        generateur = self.__generateurs_par_role[role]
        generateur_instance = generateur(
            self.__nom_millegrille, role, node_name, self.__dict_ca, self.__millegrille)

        csr = x509.load_pem_x509_csr(csr_bytes, backend=default_backend())

        certificat = generateur_instance.signer(csr)
        chaine = generateur_instance.aligner_chaine(certificat)

        clecert = EnveloppeCleCert(cert=certificat)
        clecert.chaine = chaine

        return clecert

    def renouveller_par_role(self, role, common_name):
        generateur = self.__generateurs_par_role[role]
        generateur_instance = generateur(
            self.__nom_millegrille, role, common_name, self.__dict_ca, self.__millegrille)

        cert_dict = generateur_instance.generer()
        return cert_dict


class DecryptionHelper:

    def __init__(self, clecert: EnveloppeCleCert):
        self.__clecert = clecert

    def decrypter_asymmetrique(self, contenu: str):
        """
        Utilise la cle privee en memoire pour decrypter le contenu.
        :param contenu:
        :return:
        """
        contenu_bytes = base64.b64decode(contenu)

        contenu_decrypte = self.__clecert.private_key.decrypt(
            contenu_bytes,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return contenu_decrypte

    def decrypter_symmetrique(self, cle_secrete: bytes, iv: bytes, contenu_crypte: bytes):
        backend = default_backend()

        cipher = Cipher(algorithms.AES(cle_secrete), modes.CBC(iv), backend=backend)
        unpadder = padding.PKCS7(256).unpadder()
        decryptor = cipher.decryptor()

        contenu_decrypte = decryptor.update(contenu_crypte) + decryptor.finalize()
        contenu_unpadde = unpadder.update(contenu_decrypte) + unpadder.finalize()

        return contenu_unpadde[16:]  # Enleve 16 premiers bytes, c'est l'IV

