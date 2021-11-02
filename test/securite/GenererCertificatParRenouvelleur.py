import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.name import NameOID
from cryptography.hazmat.primitives.asymmetric import rsa

from millegrilles.util.X509Certificate import RenouvelleurCertificat, EnveloppeCleCert


def charger_certificat(path_certificat: str, path_cle: str = None, path_password: str = None) -> EnveloppeCleCert:
    with open(path_certificat, 'rb') as fichier:
        bytes_cert = fichier.read()

    if path_password is not None:
        with open(path_password, 'rb') as fichier:
            password = fichier.read()
            # password = base64.b64decode(password_b64)
    else:
        password = None

    clecert = EnveloppeCleCert()
    if path_cle is not None:
        with open(path_cle, 'rb') as fichier:
            bytes_cle = fichier.read()
        clecert.from_pem_bytes(bytes_cle, bytes_cert, password)
    else:
        clecert.cert_from_pem_bytes(bytes_cert)

    return clecert

clecert_millegrille = charger_certificat('/home/mathieu/mgdev/certs/pki.millegrille')
idmg = clecert_millegrille.idmg
clecert_intermediaire = charger_certificat(
    '/home/mathieu/mgdev/certs/pki.intermediaire.cert',
    '/home/mathieu/mgdev/certs/pki.intermediaire.key',
    '/home/mathieu/mgdev/certs/pki.intermediaire.passwd'
)

dict_ca = {
    clecert_intermediaire.skid: clecert_intermediaire.cert,
    clecert_millegrille.skid: clecert_millegrille.cert,
}

renouvelleur = RenouvelleurCertificat(idmg, dict_ca, clecert_intermediaire, generer_password=False)


def generer_csr(user_name):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, user_name),
    ]))

    request = builder.sign(
        private_key, hashes.SHA256(), default_backend()
    )

    return request, private_key


def generer():

    user_name = u'usager_1'

    request, private_key = generer_csr(user_name)
    csr = request.public_bytes(serialization.Encoding.PEM)
    nouveau_clecert = renouvelleur.signer_usager(csr, '2.prive', user_name, 'mABCD1235')

    pem_cert = nouveau_clecert.public_bytes
    with open('/tmp/cert.pem', 'wb') as fichier:
        fichier.write(pem_cert)

    pem_key = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with open('/tmp/key.pem', 'wb') as fichier:
        fichier.write(pem_key)

    print("Nouveau certificat et cle generer")


if __name__ == '__main__':
    generer()

