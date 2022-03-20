from cryptography.hazmat.backends import default_backend
from cryptography.hazmat import primitives
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.hazmat.primitives import asymmetric
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ipaddress import IPv4Address, IPv6Address
from typing import Union
from multihash.constants import HASH_CODES
from nacl.signing import SigningKey, VerifyKey

import datetime
import secrets
import base64
import logging
import multihash
import multibase
import pytz

from millegrilles import Constantes
from millegrilles.util.IdmgUtil import encoder_idmg_cert
from millegrilles.SecuritePKI import ConstantesSecurityPki
from millegrilles.util.Hachage import map_code_to_hashes, hacher
from millegrilles.util.Ed25519 import chiffrer_cle_ed25519, dechiffrer_cle_ed25519


class ConstantesGenerateurCertificat(Constantes.ConstantesGenerateurCertificat):

    DELTA_INITIAL = datetime.timedelta(seconds=20)  # Initialiser a 2 minutes avant temps courant
    ONE_DAY = datetime.timedelta(hours=2)

    DUREE_CERT_ROOT = datetime.timedelta(days=3655)
    DUREE_CERT_BACKUP = datetime.timedelta(hours=3)
    DUREE_CERT_MILLEGRILLE = datetime.timedelta(hours=3)
    DUREE_CERT_NOEUD = datetime.timedelta(hours=3)
    DUREE_CERT_NAVIGATEUR = datetime.timedelta(hours=3)
    DUREE_CERT_TIERS = datetime.timedelta(hours=3)
    DUREE_CERT_HERBERGEMENT_XS = datetime.timedelta(hours=3)
    DUREE_CERT_INSTALLATION = datetime.timedelta(hours=3)

    # DUREE_CERT_ROOT = datetime.timedelta(days=3655)
    # DUREE_CERT_BACKUP = datetime.timedelta(days=3655)
    # DUREE_CERT_MILLEGRILLE = datetime.timedelta(days=730)
    # DUREE_CERT_NOEUD = datetime.timedelta(days=366)
    # DUREE_CERT_NAVIGATEUR = datetime.timedelta(weeks=6)
    # DUREE_CERT_TIERS = datetime.timedelta(weeks=4)
    # DUREE_CERT_HERBERGEMENT_XS = datetime.timedelta(days=90)
    # DUREE_CERT_INSTALLATION = datetime.timedelta(days=1)
    # ONE_DAY = datetime.timedelta(1, 0, 0)

    # ROLES_ACCES_MONGO = [
    #     Constantes.ConstantesGenerateurCertificat.ROLE_MONGO,
    #     Constantes.ConstantesGenerateurCertificat.ROLE_DOMAINES,
    #     Constantes.ConstantesGenerateurCertificat.ROLE_CORE,
    #     Constantes.ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS,
    #     Constantes.ConstantesGenerateurCertificat.ROLE_MAITREDESCLES,
    # ]

    # Custom OIDs

    # Composant avec acces interne.
    # Liste des exchanges: millegrilles.middleware,millegrilles.noeud,etc.
    MQ_EXCHANGES_OID = x509.ObjectIdentifier('1.2.3.4.0')

    # Liste de roles internes speciaux: transaction,deployeur,maitredescles
    MQ_ROLES_OID = x509.ObjectIdentifier('1.2.3.4.1')

    # Liste des domaines: SenseursPassifs,GrosFichiers,MaitreDesCles,etc.
    MQ_DOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.2')

    # userId: ID unique de l'usager (ne pas confondre avec nomUsager dans CN)
    MQ_USERID_OID = x509.ObjectIdentifier('1.2.3.4.3')

    # Role usager 'administrateur' qui s'applique a toute la MilleGrille.
    # Valeurs: proprietaire, delegue
    MQ_DELEGATION_GLOBALE_OID = x509.ObjectIdentifier('1.2.3.4.4')

    # Liste des domaines auxquels l'usager a un acces total (niveau 3.protege)
    # Exemple : GrosFichiers,CoupDoeil,Publication
    MQ_DELEGATION_DOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.5')

    # Liste des sous-domaines auxquels l'usager a un acces total (niveau 3.protege)
    # Exemple : Publication:forum_id=abc1234,GrosFichiers:uuid_collection=abcd1234;uuid_collection=abcd1235
    MQ_DELEGATIONS_SOUSDOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.6')


class EnveloppeCleCert:

    # HASH_FINGERPRINT = 'sha2-256'
    HASH_FINGERPRINT = 'blake2s-256'
    ENCODING_FINGERPRINT = 'base58btc'

    def __init__(self, private_key=None, cert: x509.Certificate = None, password=None):
        self.private_key = private_key
        self.cert = cert
        self.password = password
        self.csr = None
        self.chaine = None
        self.__fingerprint = None
        self.__idmg = None

        self._sign_hash_function = hashes.SHA512
        self._contenu_hash_function = hashes.SHA256

    def set_cert(self, cert):
        self.cert = cert

    def set_csr(self, csr):
        self.csr = csr

    def set_chaine(self, chaine: list):
        self.chaine = chaine

    def set_chaine_str(self, chaine: str):
        END_MARKER = '-----END CERTIFICATE-----'
        chaine_list = chaine.split(END_MARKER)
        self.chaine = list()
        for cert in chaine_list:
            cert = cert + END_MARKER
            cert = cert.strip()
            self.chaine.append(cert)

        # Cleanup dernier element au besoin
        if self.chaine[-1] == END_MARKER:
            self.chaine = self.chaine[:-1]

    def from_pem_bytes(self, private_key_bytes: bytes, cert_bytes: bytes, password_bytes: bytes = None):
        self.private_key = primitives.serialization.load_pem_private_key(
            private_key_bytes,
            password=password_bytes,
            backend=default_backend()
        )

        self.password = password_bytes

        self.cert_from_pem_bytes(cert_bytes)

    def cert_from_pem_bytes(self, cert_bytes: Union[str, bytes]):
        if isinstance(cert_bytes, str):
            pem_string = cert_bytes
            cert_bytes = cert_bytes.encode('utf-8')
        else:
            pem_string = cert_bytes.decode('utf-8')

        self.cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())

        self.set_chaine_str(pem_string)
        if len(self.chaine) < 2:
            self.chaine = None  # On n'a pas de chaine

    def cle_correspondent(self):
        if self.private_key is not None and self.cert is not None:
            # Verifier que le cert et la cle privee correspondent
            # public1 = self.private_key.public_key().public_numbers()
            # public2 = self.cert.public_key().public_numbers()
            #
            # n1 = public1.n
            # n2 = public2.n
            #
            # return n1 == n2

            public1_bytes = self.private_key.public_key().public_bytes(
                primitives.serialization.Encoding.Raw, primitives.serialization.PublicFormat.Raw)
            public2_bytes = self.cert.public_key().public_bytes(
                primitives.serialization.Encoding.Raw, primitives.serialization.PublicFormat.Raw)

            return public1_bytes == public2_bytes

        return False

    def csr_cert_correspondent(self):
        if self.csr is not None and self.cert is not None:
            # Verifier que le cert et la cle privee correspondent
            public1 = self.csr.public_key().public_numbers()
            public2 = self.cert.public_key().public_numbers()

            n1 = public1.n
            n2 = public2.n

            return n1 == n2

        return False

    def key_from_pem_bytes(self, key_bytes: bytes, password_bytes: bytes = None):
        self.private_key = primitives.serialization.load_pem_private_key(
            key_bytes,
            password=password_bytes,
            backend=default_backend()
        )

    def from_files(self, private_key, cert, password_bytes=None):
        with open(cert, 'rb') as fichier:
            contenu_pem = fichier.read()
            self.cert = x509.load_pem_x509_certificate(contenu_pem, default_backend())
            self.set_chaine_str(contenu_pem.decode('utf-8'))

        if private_key is not None:
            with open(private_key, 'rb') as fichier:
                self.key_from_pem_bytes(fichier.read(), password_bytes)

    def chiffrage_asymmetrique(self, cle_secrete):
        # public_key = self.cert.public_key()
        # cle_secrete_backup = public_key.encrypt(
        #     cle_secrete,
        #     asymmetric.padding.OAEP(
        #         mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )
        cle_secrete_backup = chiffrer_cle_ed25519(self, cle_secrete)
        fingerprint = self.fingerprint
        return cle_secrete_backup, fingerprint

    def dechiffrage_asymmetrique(self, contenu: Union[bytes, str]) -> bytes:
        """
        Utilise la cle privee en memoire pour dechiffrer le contenu.
        :param contenu:
        :return:
        """
        if isinstance(contenu, str):
            contenu_bytes = base64.b64decode(contenu)
        elif isinstance(contenu, bytes):
            contenu_bytes = contenu
        else:
            raise TypeError("Mauvais type contenu pour dechiffrage")

        contenu_dechiffre = self.private_key.decrypt(
            contenu_bytes,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return contenu_dechiffre

    def signer(self, message_bytes: bytes):
        signature = self.private_key.sign(
            message_bytes,
            # asymmetric.padding.PSS(
            #     mgf=asymmetric.padding.MGF1(self._sign_hash_function()),
            #     # salt_length=asymmetric.padding.PSS.MAX_LENGTH
            #     salt_length=64   # Maximum supporte sur iPhone
            # ),
            # self._sign_hash_function()
        )

        return signature

    @property
    def get_roles(self):
        extensions = self.cert.extensions
        oid_attribute = extensions.get_extension_for_oid(ConstantesGenerateurCertificat.MQ_ROLES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_exchanges(self):
        MQ_EXCHANGES_OID = x509.ObjectIdentifier('1.2.3.4.0')
        extensions = self.cert.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_EXCHANGES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_domaines(self):
        MQ_DOMAINES_OID = x509.ObjectIdentifier('1.2.3.4.2')
        extensions = self.cert.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DOMAINES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        attribute_values = oid_value.split(',')
        return attribute_values

    @property
    def get_user_id(self):
        MQ_DOMAINES_OID = ConstantesGenerateurCertificat.MQ_USERID_OID
        extensions = self.cert.extensions
        oid_attribute = extensions.get_extension_for_oid(MQ_DOMAINES_OID)
        oid_value = oid_attribute.value
        oid_value = oid_value.value.decode('utf-8')
        return oid_value

    @property
    def cert_bytes(self):
        return self.cert.public_bytes(primitives.serialization.Encoding.PEM)

    @property
    def public_bytes(self):
        if self.cert:
            return self.cert_bytes
        elif self.private_key:
            return self.private_key.public_key().public_bytes(primitives.serialization.Encoding.PEM, primitives.serialization.PublicFormat.SubjectPublicKeyInfo)

        return None

    @property
    def csr_bytes(self):
        return self.csr.public_bytes(primitives.serialization.Encoding.PEM)

    @property
    def akid(self):
        return EnveloppeCleCert.get_authority_identifier(self.cert)

    @property
    def skid(self):
        return EnveloppeCleCert.get_subject_identifier(self.cert)

    @property
    def fingerprint(self) -> str:
        if self.__fingerprint is None:
            hashing_code = HASH_CODES[EnveloppeCleCert.HASH_FINGERPRINT]
            hash_method = map_code_to_hashes(hashing_code)
            digest = self.cert.fingerprint(hash_method)
            mh = multihash.encode(digest, EnveloppeCleCert.HASH_FINGERPRINT)
            mb = multibase.encode(EnveloppeCleCert.ENCODING_FINGERPRINT, mh)
            self.__fingerprint = mb.decode('utf-8')

        return self.__fingerprint

    # @fingerprint.setter
    # def fingerprint(self, fingerprint: str):
    #     """
    #     Set le fingerprint multibase base58btc, multihash BLAKE2s-256
    #     :param fingerprint:
    #     :return:
    #     """
    #     self.__fingerprint = fingerprint

    @property
    def fingerprint_cle_publique(self) -> str:
        pk = self.cert.public_key()
        pem = pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        pem_bytes = ''.join(pem.strip().decode('utf-8').split('\n')[1:-1]).encode('utf-8')
        pk_bytes = base64.b64decode(pem_bytes)
        return hacher(pk_bytes, hashing_code='blake2s-256', encoding='base64')

    @property
    def idmg(self) -> str:
        """
        Retourne le idmg du certificat.
        Si c'est un certificat CA, calcule le IDMG. Sinon utilise la valeur du champ Organization (O)
        """
        if self.__idmg is None:
            if self.akid == self.skid:
                self.__idmg = encoder_idmg_cert(self.cert)
            else:
                subject = self.formatter_subject()
                self.__idmg = subject['organizationName']

        return self.__idmg

    @property
    def not_valid_before(self) -> datetime.datetime:
        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        return pytz.utc.localize(self.cert.not_valid_before)

    @property
    def not_valid_after(self) -> datetime.datetime:
        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        return pytz.utc.localize(self.cert.not_valid_after)

    @property
    def private_key_bytes(self):
        if self.password is not None:
            cle_privee_bytes = self.private_key.private_bytes(
                primitives.serialization.Encoding.PEM,
                primitives.serialization.PrivateFormat.PKCS8,
                primitives.serialization.BestAvailableEncryption(self.password)
            )
        else:
            cle_privee_bytes = self.private_key.private_bytes(
                primitives.serialization.Encoding.PEM,
                primitives.serialization.PrivateFormat.PKCS8,
                primitives.serialization.NoEncryption()
            )

        return cle_privee_bytes

    def generer_private_key(self, generer_password=False, keysize=None, public_exponent=65537):
        if generer_password:
            self.password = base64.b64encode(secrets.token_bytes(16))

        if keysize is None:
            self.private_key = Ed25519PrivateKey.generate()
        else:
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

    def formatter_issuer(self):
        sujet_dict = {}

        sujet = self.cert.issuer
        for elem in sujet:
            sujet_dict[elem.oid._name] = elem.value

        return sujet_dict

    def subject_rfc4514_string(self):
        return self.cert.subject.rfc4514_string()

    def subject_rfc4514_string_mq(self):
        """
        Subject avec ordre inverse pour RabbitMQ EXTERNAL
        :return:
        """
        subject = self.subject_rfc4514_string()
        subject_list = subject.split(',')
        # subject_list.reverse()  # Plus necessaire depuis upgrade deps
        return ','.join(subject_list)

    @property
    def is_valid_at_current_time(self):
        now = pytz.utc.localize(datetime.datetime.utcnow())

        # Note : utilisation de pytz pour transformer la date vers le format datetime python3
        #        cryptography utilise un format susceptible a epochalypse sur .timestamp()
        #        https://en.wikipedia.org/wiki/Year_2038_problem
        is_valid_from = (now > pytz.utc.localize(self.cert.not_valid_before))
        is_valid_to = (now < pytz.utc.localize(self.cert.not_valid_after))

        return is_valid_from and is_valid_to

    def get_public_x25519(self) -> X25519PublicKey:
        if self.cert is not None:
            public_key = self.cert.public_key()
        elif self.private_key is not None:
            public_key = self.private_key.public_key()
        else:
            raise Exception("Cle publique non disponible")

        cle_public_bytes = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        cle_nacl_verifykey = VerifyKey(cle_public_bytes).to_curve25519_public_key()
        x25519_public_key = X25519PublicKey.from_public_bytes(cle_nacl_verifykey.encode())

        return x25519_public_key

    def get_private_x25519(self) -> X25519PrivateKey:
        if self.private_key is not None:
            private_key = self.private_key
        else:
            raise Exception("Cle privee non disponible")

        cle_private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        cle_nacl_signingkey = SigningKey(cle_private_bytes)
        cle_x25519_prive = cle_nacl_signingkey.to_curve25519_private_key()
        x25519_private_key = X25519PrivateKey.from_private_bytes(cle_x25519_prive.encode())

        return x25519_private_key


class GenerateurCertificat:

    def __init__(self, idmg):
        self._idmg = idmg
        self.__public_exponent = 65537
        self.__keysize = 2048
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    @staticmethod
    def split_chaine(chaine: str) -> list:
        """ Split une liste de certificats en liste """
        pass

    def generer(self) -> EnveloppeCleCert:
        raise NotImplementedError("Pas implemente")

    def signer(self, csr) -> x509.Certificate:
        raise NotImplementedError("Pas implemente")

    def _get_keyusage(self, builder, **kwargs):
        raise NotImplementedError("Pas implemente")

    def _preparer_builder_from_csr(self, csr_request, autorite_cert,
                                   duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD,
                                   role: str = None,
                                   **kwargs) -> x509.CertificateBuilder:

        builder = x509.CertificateBuilder()

        subject = csr_request.subject
        idmg_certificat = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        if idmg_certificat and idmg_certificat[0].value != 'idmg':
            idmg_certificat = idmg_certificat[0].value
        else:
            idmg_certificat = self._idmg

        if role:
            role_csr = role
        else:
            role_csr = subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value

        cn = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        subject = x509.Name([
            x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, idmg_certificat),
            x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, role_csr),
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, cn)
        ])

        now = datetime.datetime.utcnow()

        builder = builder.subject_name(subject)
        builder = builder.issuer_name(autorite_cert.subject)
        builder = builder.not_valid_before(now - ConstantesGenerateurCertificat.DELTA_INITIAL)
        builder = builder.not_valid_after(now + duree_cert)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(csr_request.public_key())

        return builder

    def preparer_empty_request(self) -> EnveloppeCleCert:
        clecert = EnveloppeCleCert()
        clecert.generer_private_key()

        builder = x509.CertificateSigningRequestBuilder()
        # request = builder.sign(clecert.private_key, hashes.SHA256(), default_backend())
        request = builder.sign(clecert.private_key, None, default_backend())
        clecert.set_csr(request)

        return clecert

    def preparer_request(self, common_name, unit_name=None, alt_names: list = None) -> EnveloppeCleCert:
        clecert = EnveloppeCleCert()
        clecert.generer_private_key()

        builder = x509.CertificateSigningRequestBuilder()

        # Batir subject
        name_list = [x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, self._idmg)]
        if unit_name is not None:
            name_list.append(x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, unit_name))
        name_list.append(x509.NameAttribute(x509.name.NameOID.COMMON_NAME, common_name))
        name = x509.Name(name_list)
        builder = builder.subject_name(name)

        if alt_names is not None:
            self.__logger.debug("Preparer requete %s avec urls publics: %s" % (common_name, str(alt_names)))
            liste_names = list()
            for alt_name in alt_names:
                liste_names.append(x509.DNSName(alt_name))
            # Ajouter noms DNS valides pour MQ
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_names), critical=False)

        # request = builder.sign(clecert.private_key, hashes.SHA256(), default_backend())
        request = builder.sign(clecert.private_key, None, default_backend())
        clecert.set_csr(request)

        return clecert

    def preparer_key_request(self, unit_name, common_name, generer_password=False, alt_names: list = None) -> EnveloppeCleCert:
        clecert = EnveloppeCleCert()
        clecert.generer_private_key(generer_password=generer_password)

        builder = x509.CertificateSigningRequestBuilder()
        name = x509.Name([
            x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, self._idmg),
            x509.NameAttribute(x509.name.NameOID.ORGANIZATIONAL_UNIT_NAME, unit_name),
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, common_name),
        ])
        builder = builder.subject_name(name)

        if alt_names is not None:
            self.__logger.debug("Preparer requete %s avec urls publics: %s" % (common_name, str(alt_names)))
            liste_names = list()
            for alt_name in alt_names:
                liste_names.append(x509.DNSName(alt_name))
            # Ajouter noms DNS valides pour MQ
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_names), critical=False)

        # request = builder.sign(clecert.private_key, hashes.SHA256(), default_backend())
        request = builder.sign(clecert.private_key, None, default_backend())
        clecert.set_csr(request)

        return clecert


class GenerateurCertificateParClePublique(GenerateurCertificat):

    def __init__(self, idmg, dict_ca: dict = None, autorite: EnveloppeCleCert = None, domaines_publics: list = None):
        super().__init__(idmg)
        self._dict_ca = dict_ca
        self._autorite = autorite
        self.__domaines_publics = domaines_publics
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def _get_keyusage(self, builder, **kwargs):
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

    def preparer_builder(self, cle_publique_pem: str,
                         duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NAVIGATEUR,
                         **kwargs) -> x509.CertificateBuilder:

        builder = x509.CertificateBuilder()

        sujet = kwargs.get('sujet')

        name = x509.Name([
            x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, self._idmg),
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, sujet),
        ])
        builder = builder.subject_name(name)

        builder = builder.issuer_name(self._autorite.cert.subject)
        builder = builder.not_valid_before(datetime.datetime.utcnow() - ConstantesGenerateurCertificat.DELTA_INITIAL)
        builder = builder.not_valid_after(datetime.datetime.utcnow() + duree_cert)
        builder = builder.serial_number(x509.random_serial_number())

        pem_bytes = cle_publique_pem.encode('utf-8')

        public_key = primitives.serialization.load_pem_public_key(
            pem_bytes,
            backend=default_backend()
        )

        builder = builder.public_key(public_key)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        ski = self._autorite.cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(
                ski.value.digest,
                None,
                None
            ),
            critical=False
        )

        # Ajouter les acces specifiques a ce type de cert
        builder = self._get_keyusage(builder, **kwargs)

        return builder

    def signer(self, builder) -> x509.Certificate:

        cle_autorite = self._autorite.private_key
        # certificate = builder.sign(
        #     private_key=cle_autorite,
        #     algorithm=hashes.SHA256(),
        #     backend=default_backend()
        # )
        certificate = builder.sign(
            private_key=cle_autorite,
            algorithm=None,
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
        return [c.public_bytes(primitives.serialization.Encoding.PEM).decode('utf-8') for c in chaine]


class GenerateurCertificateParRequest(GenerateurCertificat):

    def __init__(self, idmg, dict_ca: dict = None, autorite: EnveloppeCleCert = None, domaines_publics: list = None):
        super().__init__(idmg)
        self._dict_ca = dict_ca
        self._autorite = autorite
        self.__domaines_publics = domaines_publics
        self.__logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

    def _get_keyusage(self, builder, **kwargs):
        """
        Genere builder de certificat
        :param builder:
        :param kwargs: Parametres optionnels
                       - csr: x509.CertificateSigningRequest
                       - altnames=False : empeche le traitement automatique des altnames du csr
        :return: Builder
        """
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

        csr = kwargs.get('csr')
        if csr:
            traiter_alternames = kwargs.get('altnames')
            # if not traiter_alternames and traiter_alternames is not False:
            #     altnames = self.extraire_altnames(csr)
            #     if altnames:
            #         liste_dnsnames = [x509.DNSName(domaine) for domaine in altnames]
            #         builder = builder.add_extension(x509.SubjectAlternativeName(liste_dnsnames), critical=False)

        return builder

    def extraire_altnames(self, csr: x509.CertificateSigningRequest):
        # Extraire les extensions pour alt names
        # Copier les extensions fournies dans la requete (exemple subject alt names)
        domaines_publics = None
        try:
            subject_alt_names = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            domaines_publics = [d.value for d in subject_alt_names.value]
        except x509.extensions.ExtensionNotFound:
            pass

        return domaines_publics

    def signer(self, csr: x509.CertificateSigningRequest, role: str = None, **kwargs) -> x509.Certificate:
        cert_autorite = self._autorite.cert
        duree = kwargs.get('duree') or datetime.timedelta(days=3)
        builder = self._preparer_builder_from_csr(
            csr, cert_autorite, duree, role=role, **kwargs)

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
        builder = self._get_keyusage(builder, csr=csr, **kwargs)

        cle_autorite = self._autorite.private_key
        certificate = builder.sign(
            private_key=cle_autorite,
            # algorithm=hashes.SHA256(),
            algorithm=None,
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
        for idx in range(0, 5):
            cert_autorite = self._dict_ca.get(akid_autorite)

            if cert_autorite is None:
                raise Exception("Erreur, autorite %s introuvable" % akid_autorite)

            chaine.append(cert_autorite)
            akid_autorite_suivante = EnveloppeCleCert.get_authority_identifier(cert_autorite)

            if akid_autorite == akid_autorite_suivante:
                # On est rendu au root
                # chaine.pop()
                break

            akid_autorite = akid_autorite_suivante

        if idx == 5:
            raise Exception("Depasse limite profondeur")

        # Generer la chaine de certificats avec les intermediaires
        return [c.public_bytes(primitives.serialization.Encoding.PEM).decode('utf-8') for c in chaine]


class GenerateurCertificatNginxSelfsigned:
    """
    Genere un certificat self-signed pour Nginx pour l'installation d'un nouveau noeud.
    """

    def generer(self, server_name: str, rsa=False):
        clecert = EnveloppeCleCert()
        if rsa is True:
            clecert.generer_private_key(generer_password=False, keysize=2048)
        else:
            # Va utilise type par defaut (EdDSA25519)
            clecert.generer_private_key(generer_password=False)

        public_key = clecert.private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.not_valid_before(datetime.datetime.utcnow() - ConstantesGenerateurCertificat.DELTA_INITIAL)
        builder = builder.not_valid_after(datetime.datetime.utcnow() + ConstantesGenerateurCertificat.DUREE_CERT_INSTALLATION)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        name = x509.Name([
            x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, u'MilleGrille'),
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, server_name),
        ])
        builder = builder.subject_name(name)
        builder = builder.issuer_name(name)

        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
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

        if rsa is True:
            certificate = builder.sign(
                private_key=clecert.private_key,
                algorithm=hashes.SHA512(),
                backend=default_backend()
            )
        else:
            certificate = builder.sign(
                private_key=clecert.private_key,
                algorithm=None,
                backend=default_backend()
            )

        clecert.set_cert(certificate)

        return clecert


class GenerateurCertificatMilleGrille(GenerateurCertificateParRequest):

    def __init__(self, idmg, dict_ca: dict = None, autorite: EnveloppeCleCert = None):
        super().__init__(idmg, dict_ca, autorite)

    def generer(self) -> EnveloppeCleCert:
        """
        Sert a renouveller un certificat de millegrille. Conserve tous les autres certs de MilleGrille valides
        jusqu'a echeance.
        :return:
        """
        # Preparer une nouvelle cle et CSR pour la millegrille
        clecert = super().preparer_key_request(
            unit_name=u'MilleGrille',
            common_name=self._idmg,
            generer_password=True
        )

        # Signer avec l'autorite pour obtenir le certificat de MilleGrille
        csr_millegrille = clecert.csr
        certificate = self.signer(csr_millegrille)
        clecert.set_cert(certificate)

        chaine = self.aligner_chaine(certificate)
        clecert.set_chaine(chaine)

        return clecert

    def _get_keyusage(self, builder, **kwargs):
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
    """
    Sert a generer une chaine initiale de cles et certs CA pour une millegrille.
    """

    def __init__(self, idmg, autorite: EnveloppeCleCert = None):
        super().__init__(idmg, None, None)
        self._autorite = autorite

    def generer(self) -> EnveloppeCleCert:
        """
        :return:
        """
        if self.autorite is None:
            # Le certificat d'autorite n'a pas encore ete generer, on s'en occupe
            self._autorite = self._generer_self_signed()

        ss_cert = self.autorite.cert
        ss_skid = self.autorite.skid
        self._dict_ca = {ss_skid: ss_cert}

        # Calculer idmg de la nouvelle MilleGrille
        self._idmg = self.autorite.idmg

        millegrille = super().generer()
        millegrille_skid = EnveloppeCleCert.get_subject_identifier(ss_cert)
        self._dict_ca[millegrille_skid] = millegrille

        return millegrille

    def __preparer_builder(self, private_key, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_NOEUD) -> x509.CertificateBuilder:
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder()
        builder = builder.not_valid_before(datetime.datetime.utcnow() - ConstantesGenerateurCertificat.DELTA_INITIAL)
        builder = builder.not_valid_after(datetime.datetime.utcnow() + duree_cert)
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.public_key(public_key)

        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False
        )

        return builder

    def _generer_self_signed(self) -> EnveloppeCleCert:
        clecert = EnveloppeCleCert()
        clecert.generer_private_key(generer_password=True, keysize=4096)
        private_key = clecert.private_key
        builder = self.__preparer_builder(private_key, duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_ROOT)

        name = x509.Name([
            x509.NameAttribute(x509.name.NameOID.ORGANIZATION_NAME, u'MilleGrille'),
            x509.NameAttribute(x509.name.NameOID.COMMON_NAME, u'Racine'),
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
            private_key=clecert.private_key,
            # algorithm=hashes.SHA512(),
            algorithm=None,
            backend=default_backend()
        )

        clecert.set_cert(certificate)

        return clecert

    @property
    def autorite(self):
        return self._autorite


class GenerateurNoeud(GenerateurCertificateParRequest):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, dict_ca, autorite, domaines_publics)
        self._organization_name = organization_nom
        self._common_name = common_name
        self._domaines_publics = domaines_publics
        self._generer_password = generer_password
        self._duree = datetime.timedelta(days=duree, hours=duree_heures)

    def generer(self) -> EnveloppeCleCert:
        # Preparer une nouvelle cle et CSR pour la millegrille
        clecert = super().preparer_key_request(
            unit_name=self._organization_name,
            common_name=self._common_name,
            generer_password=self.generer_password
        )

        # Signer avec l'autorite pour obtenir le certificat de MilleGrille
        csr_millegrille = clecert.csr

        certificate = self.signer(csr_millegrille, duree=self._duree)
        clecert.set_cert(certificate)

        chaine = self.aligner_chaine(certificate)
        clecert.set_chaine(chaine)

        return clecert

    @property
    def generer_password(self):
        return self._generer_password


class GenererDeployeur(GenerateurNoeud):
    """
    Deployeur de MilleGrilles
    """

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

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


class GenererMaitredescles(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([
            Constantes.SECURITE_SECURE,
            Constantes.SECURITE_PROTEGE,
            Constantes.SECURITE_PRIVE,
            Constantes.SECURITE_PUBLIC,
        ]).encode('utf-8')
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

        custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        domaines = ','.join([
            Constantes.ConstantesMaitreDesCles.DOMAINE_NOM,
        ]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_domaines, domaines),
            critical=False
        )

        return builder


class GenererMaitredesclesCryptage(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

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


class GenererCore(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([
            Constantes.SECURITE_SECURE,
            Constantes.SECURITE_PROTEGE,
            Constantes.SECURITE_PRIVE,
            Constantes.SECURITE_PUBLIC,
        ]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ','.join([ConstantesGenerateurCertificat.ROLE_CORE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        domaines = ','.join([
            Constantes.ConstantesBackup.DOMAINE_NOM,
            Constantes.ConstantesCatalogueApplications.DOMAINE_NOM,
            Constantes.ConstantesMaitreDesComptes.DOMAINE_NOM,
            Constantes.ConstantesPki.DOMAINE_NOM,
            Constantes.ConstantesTopologie.DOMAINE_NOM,
        ]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_domaines, domaines),
            critical=False
        )

        return builder


class GenererConnecteur(GenerateurNoeud):
    """
    Generateur de certificats pour le connecteur inter-MilleGrilles
    """

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s,%s' % (Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS, Constantes.DEFAUT_MQ_EXCHANGE_PRIVE)).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_CONNECTEUR).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererMonitor(GenerateurNoeud):
    """
    Generateur de certificats pour le monitor de noeud protege principal
    """

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID

        exchanges = ','.join([
            # Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE,
            Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            Constantes.DEFAUT_MQ_EXCHANGE_PRIVE,
            Constantes.DEFAUT_MQ_EXCHANGE_PUBLIC
        ]).encode('utf-8')

        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_MONITOR.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]
        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererMonitorDependant(GenerateurNoeud):
    """
    Generateur de certificats pour le monitor de services
    """

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID

        exchanges = ','.join([
            Constantes.DEFAUT_MQ_EXCHANGE_MIDDLEWARE,
            Constantes.DEFAUT_MQ_EXCHANGE_NOEUDS,
            Constantes.DEFAUT_MQ_EXCHANGE_PRIVE
        ]).encode('utf-8')

        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererRedis(GenerateurNoeud):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, organization_nom, common_name, dict_ca, autorite, domaines_publics, generer_password, duree, duree_heures)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_REDIS).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'redis'),
            x509.DNSName(u'%s' % self._common_name),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter la liste des domaines publics recus du CSR
        if self._domaines_publics is not None:
            liste_dns.extend([x509.DNSName(d) for d in self._domaines_publics])

        # Ajouter noms DNS valides
        try:
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)
        except ValueError:
            self.__logger.exception("Erreur ajout extension SubjectAlternativeName")

        return builder


class GenererMQ(GenerateurNoeud):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, organization_nom, common_name, dict_ca, autorite, domaines_publics, generer_password, duree, duree_heures)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MQ).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'mq'),
            x509.DNSName(u'%s' % self._common_name),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter la liste des domaines publics recus du CSR
        if self._domaines_publics is not None:
            liste_dns.extend([x509.DNSName(d) for d in self._domaines_publics])

        # Si le CN == mg-IDMG, on n'a pas besoin d'ajouter cette combinaison (identique)
        if self._common_name != 'mg-%s' % self._idmg:
            liste_dns.append(x509.DNSName(u'mg-%s' % self._idmg))

        # Ajouter noms DNS valides pour MQ
        try:
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)
        except ValueError:
            self.__logger.exception("Erreur ajout extension SubjectAlternativeName")

        return builder


class GenererMongo(GenerateurNoeud):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, organization_nom, common_name, dict_ca, autorite, domaines_publics, generer_password, duree, duree_heures)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MONGO).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'mongo'),
            x509.DNSName(u'%s' % self._common_name),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Si le CN == mg-IDMG, on n'a pas besoin d'ajouter cette combinaison (identique)
        if self._common_name != 'mg-%s' % self._idmg:
            liste_dns.append(x509.DNSName(u'mg-%s' % self._idmg))

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))
                liste_dns.append(x509.DNSName(u'mq.%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        try:
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)
        except ValueError:
            self.__logger.exception("Erreur ajout extension SubjectAlternativeName")

        return builder


class GenererMaitreComptes(GenerateurNoeud):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, organization_nom, common_name, dict_ca, autorite, domaines_publics, generer_password, duree, duree_heures)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.DEFAUT_MQ_EXCHANGE_PRIVE, Constantes.DEFAUT_MQ_EXCHANGE_PUBLIC]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID

        liste_roles = [
            ConstantesGenerateurCertificat.ROLE_MAITRE_COMPTES,
            Constantes.ConstantesMaitreDesComptes.DOMAINE_NOM,
        ]

        roles = ','.join(liste_roles).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'maitrecomptes'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1'))
        ]

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        try:
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)
        except ValueError:
            self.__logger.exception("Erreur ajout extension SubjectAlternativeName")

        return builder


class GenererWebPrive(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = Constantes.SECURITE_PRIVE.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MAITRE_COMPTES).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'www'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'coupdoeil-%s' % self._idmg),
        ]

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))

        # Ajouter noms DNS valides pour CoupDoeil
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererCoupdoeil(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PROTEGE, Constantes.SECURITE_PRIVE, Constantes.SECURITE_PUBLIC]).encode('utf-8')
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

        liste_dns = [
            x509.DNSName(u'www'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'coupdoeil'),
        ]

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))

        # Ajouter noms DNS valides pour CoupDoeil
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererFichiers(GenerateurNoeud):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, organization_nom, common_name, dict_ca, autorite, domaines_publics, generer_password, duree, duree_heures)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([('%s' % e) for e in [Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s,%s' % (ConstantesGenerateurCertificat.ROLE_FICHIERS, ConstantesGenerateurCertificat.ROLE_BACKUP)).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'fichiers'),
            x509.DNSName(u'backup'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        if self._domaines_publics is not None:
            liste_dns.extend([x509.DNSName(d) for d in self._domaines_publics])

        # Ajouter noms DNS valides pour MQ
        try:
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)
        except ValueError:
            self.__logger.exception("Erreur ajout extension SubjectAlternativeName")

        return builder


class GenererSenseursPassifs(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE, Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_SENSEURSPASSIFS.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        domaines = ','.join([
            'SenseursPassifs',
        ]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_domaines, domaines),
            critical=False
        )

        return builder


class GenererSenseursPassifsWeb(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_SENSEURSPASSIFS.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        domaines = ','.join([
            'SenseursPassifs',
        ]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_domaines, domaines),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'senseurspassifs'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererGrosFichiers(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE, Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_GROS_FICHIERS.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        domaines = ','.join([Constantes.ConstantesGrosFichiers.DOMAINE_NOM]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_domaines, domaines),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'grosfichiers'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererCollections(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_COLLECTIONS.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'collections'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererMessagerie(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE, Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_MESSAGERIE.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        domaines = ','.join(['Messagerie']).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_domaines, domaines),
            critical=False
        )

        liste_dns = [
            # x509.DNSName(u'messagerie'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererPostmaster(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_POSTMASTER.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        # custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        # domaines = ','.join(['Messagerie']).encode('utf-8')
        # builder = builder.add_extension(
        #     x509.UnrecognizedExtension(custom_oid_domaines, domaines),
        #     critical=False
        # )

        liste_dns = [
            # x509.DNSName(u'messagerie'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererMessagerieWeb(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_MESSAGERIE.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'messagerie'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter noms DNS valides
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererMedia(GenerateurNoeud):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, organization_nom, common_name, dict_ca, autorite, domaines_publics, generer_password, duree, duree_heures)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE, Constantes.SECURITE_PROTEGE, Constantes.SECURITE_SECURE]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ','.join([ConstantesGenerateurCertificat.ROLE_MEDIA, ConstantesGenerateurCertificat.ROLE_FICHIERS]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        custom_oid_domaines = ConstantesGenerateurCertificat.MQ_DOMAINES_OID
        domaines = ','.join([Constantes.ConstantesGrosFichiers.DOMAINE_NOM]).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_domaines, domaines),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'media'),
            x509.DNSName(u'%s' % self._common_name),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Ajouter noms DNS valides pour MQ
        try:
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)
        except ValueError:
            self.__logger.exception("Erreur ajout extension SubjectAlternativeName")

        return builder


class GenererMongoexpress(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'mongoxp'),
            x509.DNSName(u'%s' % self._common_name),
        ]

        # # Si le CN == mg-IDMG, on n'a pas besoin d'ajouter cette combinaison (identique)
        # if self._common_name != 'mg-%s' % self._idmg:
        #     liste_dns.append(x509.DNSName(u'mg-%s' % self._idmg))
        #     liste_dns.append(x509.DNSName(u'mg-%s.local' % self._idmg))

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererNginx(GenerateurNoeud):

    def __init__(self, idmg, organization_nom, common_name, dict_ca: dict, autorite: EnveloppeCleCert = None,
                 domaines_publics: list = None, generer_password=False, duree=0, duree_heures=3):
        super().__init__(idmg, organization_nom, common_name, dict_ca, autorite, domaines_publics, generer_password, duree, duree_heures)

        self.__logger = logging.getLogger(__name__ + '.' + self.__class__.__name__)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_NGINX).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'www'),
            x509.DNSName(u'%s' % self._common_name),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        # Si le CN == mg-idmg, on n'a pas besoin d'ajouter cette combinaison (identique)
        if self._common_name != 'mg-%s' % self._idmg:
            liste_dns.append(x509.DNSName(u'mg-%s' % self._idmg))

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))
                liste_dns.append(x509.DNSName(u'www.%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        try:
            builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)
        except ValueError:
            self.__logger.exception("Erreur ajout extension SubjectAlternativeName")

        return builder


class GenererVitrine(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

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

        liste_dns = [
            x509.DNSName(u'www'),
            x509.DNSName(u'vitrine'),
            x509.DNSName(u'localhost'),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))
                liste_dns.append(x509.DNSName(u'www.%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenererNoeudPrive(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_exchanges = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = (','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]).encode('utf-8'))
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_exchanges, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererNoeudPublic(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_exchanges = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = (','.join([Constantes.SECURITE_PUBLIC]).encode('utf-8'))
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_exchanges, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererApplicationPrivee(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_exchanges = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = (','.join([Constantes.SECURITE_PUBLIC, Constantes.SECURITE_PRIVE]).encode('utf-8'))
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_exchanges, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        liste_dns = [
            x509.DNSName(u'%s' % self._common_name),
            x509.IPAddress(IPv4Address('127.0.0.1')),
            x509.IPAddress(IPv6Address('::1')),
        ]

        if self._domaines_publics is not None:
            for domaine in self._domaines_publics:
                liste_dns.append(x509.DNSName(u'%s' % domaine))

        # Ajouter noms DNS valides pour MQ
        builder = builder.add_extension(x509.SubjectAlternativeName(liste_dns), critical=False)

        return builder


class GenerateurCertificateNoeud(GenerateurCertificateParRequest):

    def __init__(self, idmg, domaines: list, dict_ca: dict = None, autorite: EnveloppeCleCert = None):
        super().__init__(idmg, dict_ca, autorite)
        self.__domaines = domaines

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ','.join(self.__domaines).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenerateurCertificateNavigateur(GenerateurCertificateParRequest):

    def __init__(self, idmg, dict_ca: dict = None, autorite: EnveloppeCleCert = None):
        super().__init__(idmg, dict_ca, autorite)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        roles = [
            ConstantesGenerateurCertificat.ROLE_NAVIGATEUR,
        ]

        if kwargs.get('compte_prive') is True:
            roles.append(ConstantesGenerateurCertificat.ROLE_COMPTE_PRIVE)

        csr = kwargs.get('csr')
        sujet_dict = dict()
        for elem in csr.subject:
            sujet_dict[elem.oid._name] = elem.value
        common_name = sujet_dict['commonName']
        nom_usager: str = kwargs['nom_usager']
        if common_name != nom_usager:
            raise Exception("Nom usager du CSR (%s) ne correspond par a celui de la commande (%s)" % (common_name, nom_usager))

        # On doit recuperer le user_id en parametres
        user_id: str = kwargs['user_id']

        # if kwargs.get('est_proprietaire'):
        #     roles.append('proprietaire')
        #     exchange_list.append(Constantes.SECURITE_PROTEGE)
        # elif kwargs.get('securite') == Constantes.SECURITE_PROTEGE:
        #     exchange_list.append(Constantes.SECURITE_PROTEGE)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ','.join(roles).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        custom_oid_user_id = ConstantesGenerateurCertificat.MQ_USERID_OID
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_user_id, user_id.encode('utf-8')),
            critical=False
        )

        try:
            delegation_globale = kwargs['delegation_globale']
            custom_oid_delegation_globale = ConstantesGenerateurCertificat.MQ_DELEGATION_GLOBALE_OID
            builder = builder.add_extension(
                x509.UnrecognizedExtension(custom_oid_delegation_globale, delegation_globale.encode('utf-8')),
                critical=False
            )
        except (AttributeError, KeyError):
            pass  # OK

        try:
            delegations_domaines = kwargs['delegations_domaines']
            custom_oid_delegation_domaines = ConstantesGenerateurCertificat.MQ_DELEGATION_DOMAINES_OID
            builder = builder.add_extension(
                x509.UnrecognizedExtension(custom_oid_delegation_domaines, delegations_domaines.encode('utf-8')),
                critical=False
            )
        except (AttributeError, KeyError):
            pass  # OK

        try:
            delegations_sousdomaines = kwargs['delegations_sousdomaines']
            custom_oid_delegation_sousdomaines = ConstantesGenerateurCertificat.MQ_DELEGATIONS_SOUSDOMAINES_OID
            builder = builder.add_extension(
                x509.UnrecognizedExtension(custom_oid_delegation_sousdomaines, delegations_sousdomaines.encode('utf-8')),
                critical=False
            )
        except (AttributeError, KeyError):
            pass  # OK

        return builder


class GenerateurCertificatBackup(GenerateurCertificateParClePublique):

    def __init__(self, idmg, dict_ca: dict = None, autorite: EnveloppeCleCert = None):
        super().__init__(idmg, dict_ca, autorite)

    def preparer_builder(self, cle_publique_pem: str,
                         duree_cert=ConstantesGenerateurCertificat.DUREE_CERT_BACKUP,
                         **kwargs) -> x509.CertificateBuilder:
        return super().preparer_builder(cle_publique_pem, duree_cert, **kwargs)

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ConstantesGenerateurCertificat.ROLE_BACKUP.encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class GenererAgentBackup(GenerateurNoeud):

    def _get_keyusage(self, builder, **kwargs):
        builder = super()._get_keyusage(builder, **kwargs)

        custom_oid_permis = ConstantesGenerateurCertificat.MQ_EXCHANGES_OID
        exchanges = ('%s' % Constantes.SECURITE_SECURE).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_permis, exchanges),
            critical=False
        )

        custom_oid_roles = ConstantesGenerateurCertificat.MQ_ROLES_OID
        roles = ('%s' % ConstantesGenerateurCertificat.ROLE_BACKUP).encode('utf-8')
        builder = builder.add_extension(
            x509.UnrecognizedExtension(custom_oid_roles, roles),
            critical=False
        )

        return builder


class RenouvelleurCertificat:

    def __init__(self, idmg, dict_ca: dict, clecert_intermediaire: EnveloppeCleCert = None, ca_autorite: EnveloppeCleCert = None, generer_password=False):
        self.__idmg = idmg
        self.__dict_ca = dict_ca
        self.__clecert_intermediaire = clecert_intermediaire
        self.__generer_password = generer_password
        self.__niveau_securite_par_role = {
            # Note : le role de securite par defaut est Protege, il n'est pas necessaire de le lister

            # Roles 4.secure
            ConstantesGenerateurCertificat.ROLE_MONGO: Constantes.SECURITE_SECURE,
            ConstantesGenerateurCertificat.ROLE_MAITREDESCLES: Constantes.SECURITE_SECURE,
            ConstantesGenerateurCertificat.ROLE_MEDIA: Constantes.SECURITE_SECURE,
            ConstantesGenerateurCertificat.ROLE_SENSEURSPASSIFS: Constantes.SECURITE_SECURE,

            # Roles 2.prive
            ConstantesGenerateurCertificat.ROLE_MAITRE_COMPTES: Constantes.SECURITE_PRIVE,
            ConstantesGenerateurCertificat.ROLE_SENSEURSPASSIFS_WEB: Constantes.SECURITE_PRIVE,
            ConstantesGenerateurCertificat.ROLE_COLLECTIONS: Constantes.SECURITE_PRIVE,
            ConstantesGenerateurCertificat.ROLE_MESSAGERIE_WEB: Constantes.SECURITE_PRIVE,

            # Roles 1.public
            ConstantesGenerateurCertificat.ROLE_POSTMASTER: Constantes.SECURITE_PUBLIC,
            ConstantesGenerateurCertificat.ROLE_NGINX: Constantes.SECURITE_PUBLIC,
        }
        self.__generateurs_par_role = {
            ConstantesGenerateurCertificat.ROLE_FICHIERS: GenererFichiers,
            ConstantesGenerateurCertificat.ROLE_MQ: GenererMQ,
            ConstantesGenerateurCertificat.ROLE_MONGO: GenererMongo,
            ConstantesGenerateurCertificat.ROLE_CORE: GenererCore,
            ConstantesGenerateurCertificat.ROLE_MAITREDESCLES: GenererMaitredescles,
            ConstantesGenerateurCertificat.ROLE_MAITRE_COMPTES: GenererMaitreComptes,
            ConstantesGenerateurCertificat.ROLE_COUPDOEIL: GenererCoupdoeil,
            ConstantesGenerateurCertificat.ROLE_DEPLOYEUR: GenererDeployeur,
            ConstantesGenerateurCertificat.ROLE_MONGOEXPRESS: GenererMongoexpress,
            ConstantesGenerateurCertificat.ROLE_NGINX: GenererNginx,
            ConstantesGenerateurCertificat.ROLE_CONNECTEUR: GenererConnecteur,
            ConstantesGenerateurCertificat.ROLE_VITRINE: GenererVitrine,
            ConstantesGenerateurCertificat.ROLE_BACKUP: GenererAgentBackup,
            ConstantesGenerateurCertificat.ROLE_REDIS: GenererRedis,

            # Monitors de service pour noeuds middleware
            ConstantesGenerateurCertificat.ROLE_MONITOR: GenererMonitor,
            ConstantesGenerateurCertificat.ROLE_MONITOR_DEPENDANT: GenererMonitorDependant,
            ConstantesGenerateurCertificat.ROLE_NOEUD_PRIVE: GenererNoeudPrive,
            ConstantesGenerateurCertificat.ROLE_NOEUD_PUBLIC: GenererNoeudPublic,
            ConstantesGenerateurCertificat.ROLE_APPLICATION_PRIVEE: GenererApplicationPrivee,

            ConstantesGenerateurCertificat.ROLE_SENSEURSPASSIFS: GenererSenseursPassifs,
            ConstantesGenerateurCertificat.ROLE_SENSEURSPASSIFS_WEB: GenererSenseursPassifsWeb,
            ConstantesGenerateurCertificat.ROLE_GROS_FICHIERS: GenererGrosFichiers,
            ConstantesGenerateurCertificat.ROLE_MEDIA: GenererMedia,
            ConstantesGenerateurCertificat.ROLE_COLLECTIONS: GenererCollections,
            ConstantesGenerateurCertificat.ROLE_MESSAGERIE: GenererMessagerie,
            ConstantesGenerateurCertificat.ROLE_MESSAGERIE_WEB: GenererMessagerieWeb,
            ConstantesGenerateurCertificat.ROLE_POSTMASTER: GenererPostmaster,
        }

        # S'assurer que le dict contient reference aux CAs
        if clecert_intermediaire is not None:
            self.__dict_ca[clecert_intermediaire.skid] = clecert_intermediaire.cert
            if ca_autorite:
                self.__dict_ca[ca_autorite.skid] = ca_autorite.cert

        self.__generateur_par_csr = GenerateurCertificateParRequest

        self.__generateur_millegrille = None
        if ca_autorite is not None:
            self.__generateur_millegrille = GenerateurCertificatMilleGrille(idmg, dict_ca, ca_autorite)

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

    def signer_csr(self, csr_bytes: bytes, role: str = None, duree: datetime.timedelta = None):
        csr = x509.load_pem_x509_csr(csr_bytes, backend=default_backend())
        sujet_dict = dict()
        for elem in csr.subject:
            sujet_dict[elem.oid._name] = elem.value

        # Le role demande dans le CSR peut etre modifie par le parametre role dans la commande
        role = role or sujet_dict.get('organizationalUnitName')
        common_name = sujet_dict['commonName']

        return self.renouveller_avec_csr(role, common_name, csr_bytes, duree=duree)

    def renouveller_avec_csr(self, role, node_name, csr_bytes: bytes, duree: datetime.timedelta = None, liste_dns: list = None):
        csr = x509.load_pem_x509_csr(csr_bytes, backend=default_backend())

        # Extraire les extensions pour alt names
        # Copier les extensions fournies dans la requete (exemple subject alt names)
        domaines_publics = set()
        if liste_dns is not None:
            domaines_publics.update(liste_dns)
        try:
            subject_alt_names = csr.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            domaines_publics.update([d.value for d in subject_alt_names.value])
        except x509.extensions.ExtensionNotFound:
            pass

        generateur = self.__generateurs_par_role[role]
        generateur_instance = generateur(
            self.__idmg, role, node_name, self.__dict_ca, self.__clecert_intermediaire,
            domaines_publics=list(domaines_publics)
        )

        certificat = generateur_instance.signer(csr, role, duree=duree, traiter_alternames=False)
        chaine = generateur_instance.aligner_chaine(certificat)

        clecert = EnveloppeCleCert(cert=certificat)
        clecert.chaine = chaine

        return clecert

    def signer_noeud(self, csr_bytes: bytes, domaines: list = None, role_in: str = None, duree: datetime.timedelta = None):
        csr = x509.load_pem_x509_csr(csr_bytes, backend=default_backend())
        if not csr.is_signature_valid:
            raise ValueError("Signature invalide")

        if domaines is not None:
            generateur = GenerateurCertificateNoeud(self.__idmg, domaines, self.__dict_ca, self.__clecert_intermediaire)
            certificat = generateur.signer(csr)
            chaine = generateur.aligner_chaine(certificat)
            clecert = EnveloppeCleCert(cert=certificat)
            clecert.chaine = chaine
        else:
            # Verifier si on peut trouver un generateur de certificat
            sujet = csr.subject
            sujet_dict = dict()
            for elem in sujet:
                sujet_dict[elem.oid._name] = elem.value
            role = role_in or sujet_dict['organizationalUnitName']
            common_name = sujet_dict['commonName']
            clecert = self.renouveller_avec_csr(role, common_name, csr_bytes, duree=duree)

        return clecert

    def renouveller_par_role(self, role, common_name, liste_dns: list = None, duree=0, duree_heures=3):
        generateur = self.__generateurs_par_role[role]
        if issubclass(generateur, GenerateurNoeud):
            generateur_instance = generateur(
                self.__idmg, role, common_name, self.__dict_ca, self.__clecert_intermediaire,
                domaines_publics=liste_dns, generer_password=self.__generer_password,
                duree=duree, duree_heures=duree_heures)
        else:
            generateur_instance = generateur(
                self.__idmg, role, common_name, self.__dict_ca, self.__clecert_intermediaire,
                domaines_publics=liste_dns)

        cert_dict = generateur_instance.generer()
        return cert_dict

    def preparer_csr_par_role(self, role, common_name, liste_dns: list = None) -> EnveloppeCleCert:
        generateur = self.__generateurs_par_role[role]
        if issubclass(generateur, GenerateurNoeud):
            generateur_instance = generateur(
                self.__idmg, role, common_name, self.__dict_ca, self.__clecert_intermediaire,
                domaines_publics=liste_dns, generer_password=self.__generer_password,
                duree=3, duree_heures=0)
        else:
            generateur_instance = generateur(
                self.__idmg, role, common_name, self.__dict_ca, self.__clecert_intermediaire,
                domaines_publics=liste_dns)

        clecert_csr = generateur_instance.preparer_request(common_name, None, liste_dns)
        return clecert_csr

    def signer_usager(self, csr_pem: bytes, nom_usager: str, user_id: str, **kwargs):
        """
        Signe un certificat d'usager
        :param csr_pem:
        :param nom_usager:
        :param user_id:
        :param kwargs: Optionnels : delegation_globale:str, delegations_domaines:list, compte_prive:bool,
        :return:
        """
        generateur = GenerateurCertificateNavigateur(self.__idmg, self.__dict_ca, self.__clecert_intermediaire)

        csr = x509.load_pem_x509_csr(csr_pem, backend=default_backend())
        if not csr.is_signature_valid:
            raise ValueError("Signature invalide")

        certificat = generateur.signer(csr, role='Usager', nom_usager=nom_usager, user_id=user_id, **kwargs)
        chaine = generateur.aligner_chaine(certificat)

        clecert = EnveloppeCleCert(cert=certificat)
        clecert.chaine = chaine

        return clecert

    def get_securite_role(self, role: str):
        try:
            return self.__niveau_securite_par_role[role]
        except KeyError:
            return Constantes.SECURITE_PROTEGE


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
        unpadder = padding.PKCS7(ConstantesSecurityPki.SYMETRIC_PADDING).unpadder()
        decryptor = cipher.decryptor()

        contenu_decrypte = decryptor.update(contenu_crypte) + decryptor.finalize()
        contenu_unpadde = unpadder.update(contenu_decrypte) + unpadder.finalize()

        return contenu_unpadde[16:]  # Enleve 16 premiers bytes, c'est l'IV


class PemHelpers:

    def __init__(self):
        pass

    @staticmethod
    def wrap_public_key(public_key_str: str):
        wrapped_public_key = ''
        while len(public_key_str) > 0:
            wrapped_public_key = wrapped_public_key + '\n' + public_key_str[0:64]
            public_key_str = public_key_str[64:]

        wrapped_public_key = '-----BEGIN PUBLIC KEY-----' + wrapped_public_key + '\n-----END PUBLIC KEY-----'
        return wrapped_public_key

    @staticmethod
    def split_certificats(certs: str):
        END_CERT_VALUE = '-----END CERTIFICATE-----'
        liste_certs = list()
        for cert in certs.split(END_CERT_VALUE):
            if cert and cert.replace('\n', '') != '' and not END_CERT_VALUE in cert:
                liste_certs.append(cert + END_CERT_VALUE + '\n')
        return liste_certs
