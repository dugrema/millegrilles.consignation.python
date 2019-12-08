import json
from cryptography.hazmat.primitives import serialization

from millegrilles.util.X509Certificate import RenouvelleurCertificat, EnveloppeCleCert


class EnvCert:

    def __init__(self):
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

        self.renouvelleur = RenouvelleurCertificat('testMG', self.dict_ca, self.cle_millegrille, self.ca_autorite)


class TestSignerCertNavigateur:

    def __init__(self):
        pass

    def generer_cert_navigateur(self):
        nouvelle_cle = EnveloppeCleCert()
        nouvelle_cle.generer_private_key()

        private_key = nouvelle_cle.private_key
        public_key = private_key.public_key()
        public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

        public_key_str = str(public_key, 'utf-8')

        print('Public key:\n%s' % public_key_str)
        envcert.renouvelleur.generer_certificat_navigateur('nav_test', public_key)

    def utiliser_publickey_navigateur(self):

        # Cle generee par le crypto subtle dans le navigateur
        cle = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqYE8pRzlFVwAgc2uB3ot6Ffd8pPpG4Sb8btFdjArvYcbuWvsRntBUgm/w6c831GpEoOrDr/EoEPRgTjJ81zxa1tkFprsmw9t8HJ0IOV9WF6p1X8gvf4FZaeLW6wTcA6LGhk1lRoN0jIr0VhNBejX4Xl7m7B1hR+pgmafG9Qm9acAZx2+opi9cYkG0lcl33R/106x8nnaF3jwjhBjFEazH5roHN9W253Y1subRXYC0Uq6SIlzN2HDPLn0oHLujAmf0NP6PrqHmDxfrnWc+KKuSJD2Dyf8w07AjJwJgpmWa9JrcqvYjR/BViI06/CqrtJpSAHpCguSQB3QbidSzbFF3wIDAQAB'


# ----
envcert = EnvCert()
envcert.charger()

test = TestSignerCertNavigateur()
test.generer_cert_navigateur()
