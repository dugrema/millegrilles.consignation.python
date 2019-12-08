import json
import logging
from cryptography import x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from millegrilles.util.X509Certificate import RenouvelleurCertificat, EnveloppeCleCert, PemHelpers


class EnvCert:

    def __init__(self):
        self._logger = logging.getLogger('%s.%s' % (__name__, self.__class__.__name__))

        self.dict_ca = dict()
        self.cle_millegrille = EnveloppeCleCert()   # EnveloppeCleCert
        self.ca_autorite = EnveloppeCleCert()       # EnveloppeCleCert
        self.renouvelleur = None

    def charger(self):
        with open('/home/mathieu/mgdev/certs/pki.ca.root.cert', 'rb') as f:
            ca_cert = f.read()
            self.ca_autorite.cert_from_pem_bytes(ca_cert)

        with open('/home/mathieu/mgdev/certs/pki.ca.passwords', 'r') as f:
            passwords = json.load(f)

        with open('/home/mathieu/mgdev/certs/pki.ca.millegrille.cert', 'rb') as f:
            mg_cert = f.read()
        with open('/home/mathieu/mgdev/certs/pki.ca.millegrille.key', 'rb') as f:
            mg_key = f.read()

        self.cle_millegrille.from_pem_bytes(mg_key, mg_cert, passwords['pki.ca.millegrille'].encode('utf-8'))

        self.charger_ca_chaine()
        self.renouvelleur = RenouvelleurCertificat('testMG', self.dict_ca, self.cle_millegrille, self.ca_autorite)

    def charger_ca_chaine(self):
        self.dict_ca = dict()

        ca_chain_file = '/home/mathieu/mgdev/certs/pki.ca.millegrille.fullchain'
        with open(ca_chain_file, 'r') as fichier:
            chaine = fichier.read()
            certs = chaine.split('-----END CERTIFICATE-----')
            for cert in certs[0:-1]:
                cert = '%s-----END CERTIFICATE-----\n' % cert
                self._logger.warning("Loading CA cert :\n%s" % cert)
                cert = cert.encode('utf-8')
                x509_cert = x509.load_pem_x509_certificate(cert, backend=default_backend())
                skid = EnveloppeCleCert.get_subject_identifier(x509_cert)
                self.dict_ca[skid] = x509_cert


class TestSignerCertNavigateur:

    def __init__(self):
        pass

    def generer_cert_navigateur(self):
        nouvelle_cle = EnveloppeCleCert()
        nouvelle_cle.generer_private_key()

        private_key = nouvelle_cle.private_key
        public_key = private_key.public_key()
        public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        public_key_str = public_key.decode('utf-8')

        print('Public key:\n%s' % public_key_str)
        certificat = envcert.renouvelleur.signer_navigateur(public_key_str, 'testNavigateur')

        cert_output = certificat.cert_bytes.decode('utf-8')

        print("Certificat:")
        print(cert_output)

        with open('/home/mathieu/mgdev/output/generer_cert_navigateur.pem', 'wb') as f:
            f.write(certificat.cert_bytes)

    def utiliser_publickey_navigateur(self):

        # Cle generee par le crypto subtle dans le navigateur
        public_key_str = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYE8pRzlFVwAgc2uB3ot6Ffd8pPpG4Sb8btFdjArvYcbuWvsRntBUgm/w6c831GpEoOrDr/EoEPRgTjJ81zxa1tkFprsmw9t8HJ0IOV9WF6p1X8gvf4FZaeLW6wTcA6LGhk1lRoN0jIr0VhNBejX4Xl7m7B1hR+pgmafG9Qm9acAZx2+opi9cYkG0lcl33R/106x8nnaF3jwjhBjFEazH5roHN9W253Y1subRXYC0Uq6SIlzN2HDPLn0oHLujAmf0NP6PrqHmDxfrnWc+KKuSJD2Dyf8w07AjJwJgpmWa9JrcqvYjR/BViI06/CqrtJpSAHpCguSQB3QbidSzbFF3wIDAQAB'

        wrapped_public_key = PemHelpers.wrap_public_key(public_key_str)

        print('utiliser_publickey_navigateur:\n%s' % wrapped_public_key)
        certificat = envcert.renouvelleur.signer_navigateur(wrapped_public_key, 'testNavigateur')

        cert_output = certificat.cert_bytes.decode('utf-8')
        fingerprint = certificat.fingerprint
        date_expiration = certificat.not_valid_after

        print("Certificat: fingerprint: %s, date expiration: %s" % (fingerprint, date_expiration))
        print(cert_output)

        with open('/home/mathieu/mgdev/output/utiliser_publickey_navigateur.pem', 'wb') as f:
            f.write(certificat.cert_bytes)


# ----
logging.basicConfig(level=logging.INFO)

envcert = EnvCert()
envcert.charger()

test = TestSignerCertNavigateur()
# test.generer_cert_navigateur()
test.utiliser_publickey_navigateur()
