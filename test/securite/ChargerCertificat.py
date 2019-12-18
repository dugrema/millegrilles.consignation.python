from millegrilles.SecuritePKI import EnveloppeCertificat
from millegrilles.util.X509Certificate import EnveloppeCleCert

import binascii
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509 import NameAttribute


class CertificatSubjectTest:

    def __init__(self):
        self.cert_pem = None
        self.enveloppe = None
        self.clecert = None

    def charger(self, cert_path):
        with open(cert_path, 'rb') as fichier:
            pem_file = fichier.read()

        enveloppe = EnveloppeCertificat(certificat_pem=pem_file)
        self.enveloppe = enveloppe

        self.clecert = EnveloppeCleCert()
        self.clecert.cert_from_pem_bytes(pem_file)

    def afficher_info(self):
        print(self.enveloppe.fingerprint_ascii)
        est_valide = self.enveloppe.date_valide()
        print("Certificat %s, date valide: %s" % (self.enveloppe.subject_rfc4514_string(), est_valide))

        date_formattee = self.enveloppe.date_valide_concat()
        print(date_formattee)

    def verifier_typenoeud(self):
        ou = self.enveloppe.subject_organizational_unit_name
        print("Type noeud: %s" % ou)

    def subject_mq(self):
        subject = self.enveloppe.subject_rfc4514_string_mq()
        print(subject)

    def idmg(self):
        print("sha1b58\n" + self.clecert.fingerprint_base58)
        print("sha2 256\n" + self.clecert.fingerprint_sha256_base58)
        print("sha2 512\n" + self.clecert.fingerprint_sha512_base58)
        print("sha2 512/224:\n" + self.clecert.idmg)


test = CertificatSubjectTest()
test.charger('/home/mathieu/mgdev/certs/pki.racine.cert')
test.afficher_info()
test.verifier_typenoeud()
test.subject_mq()
test.idmg()