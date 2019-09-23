from millegrilles.SecuritePKI import EnveloppeCertificat

import binascii
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.x509 import NameAttribute


class CertificatSubjectTest:

    def __init__(self):
        self.cert_pem = None
        self.enveloppe = None

    def charger(self, cert_path):
        with open(cert_path, 'rb') as fichier:
            pem_file = fichier.read()

        enveloppe = EnveloppeCertificat(certificat_pem=pem_file)
        self.enveloppe = enveloppe

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


test = CertificatSubjectTest()
test.charger('/opt/millegrilles/test1/pki/certs/test1_middleware.cert.pem')
test.afficher_info()
test.verifier_typenoeud()
test.subject_mq()