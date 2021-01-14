# Helper pour les certificats de test
# Executer ce module directement pour generer un nouveau certificat/cle de millegrille
import logging

from cryptography import x509

from millegrilles.util.X509Certificate import EnveloppeCleCert, RenouvelleurCertificat, GenerateurInitial, \
    GenerateurCertificateParRequest
from millegrilles.Constantes import ConstantesGenerateurCertificat


class GenerateurCertificatIntermediaireTest(GenerateurCertificateParRequest):

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
            unit_name=u'Intermediaire',
            common_name=self._idmg,
            generer_password=False
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


class PreparateurCertificats:

    def __init__(self, clecert_millegrille: EnveloppeCleCert):
        """

        :param clecert_millegrille: Clecert de la millegrille de test (utiliser clecert_1 ou autre
        cle/cert genere via generer_certificat_millegrille()
        """
        self.clecert_millegrille = clecert_millegrille
        self.dict_ca = {
            EnveloppeCleCert.get_subject_identifier(clecert_millegrille.cert): clecert_millegrille.cert
        }
        self.idmg = self.clecert_millegrille.idmg

        self.clecert_intermediaire = self.__generer_clecert_intermediaire()
        self.dict_ca[EnveloppeCleCert.get_subject_identifier(self.clecert_intermediaire.cert)] = \
            self.clecert_intermediaire.cert

        self.__renouvelleur = RenouvelleurCertificat(self.idmg, self.dict_ca, self.clecert_intermediaire, self.clecert_millegrille)

    def __generer_clecert_intermediaire(self) -> EnveloppeCleCert:
        generateur_intermediaire = GenerateurCertificatIntermediaireTest(
            self.idmg, dict_ca=self.dict_ca, autorite=self.clecert_millegrille)
        return generateur_intermediaire.generer()

    def generer_role(self, role: str) -> EnveloppeCleCert:
        return self.__renouvelleur.renouveller_par_role(role, 'unit_test')


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


def generer_certificat_millegrille():
    logger = logging.getLogger('__main__')
    logger.info("Generer un nouveau certificat de millegrille")
    generateur = GenerateurInitial(None)

    autorite = generateur._generer_self_signed()

    idmg = autorite.idmg
    cert_bytes = autorite.cert_bytes

    # Ne pas utiliser de password pour ce certificat de test
    autorite.password = None
    key_bytes = autorite.private_key_bytes

    logger.info("Certificat de millegrille %s\n%s\nCle\n%s" % (idmg, cert_bytes.decode('utf-8'), key_bytes.decode('utf-8')))


def test_generer_roles():
    logger = logging.getLogger('__main__')
    logger.info("Generer un nouveau certificat de domaines")
    preparateur = PreparateurCertificats(clecert_1)
    clecert_domaines = preparateur.generer_role(ConstantesGenerateurCertificat.ROLE_DOMAINES)
    logger.debug("Certificat domaines\n%s\nCle\n%s" % (
        clecert_domaines.cert_bytes.decode('utf-8'), clecert_domaines.private_key_bytes.decode('utf-8')))


# Clecert - IDMG Qxteu6fWWfmhaZMm1UmoSxF1ozBXvLkh4xPic2RbK9rP
clecert_1 = EnveloppeCleCert()
clecert_1.from_pem_bytes(
    """
-----BEGIN PRIVATE KEY-----
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
vnv/TKIahlC3D5n00nNKpVzbTNta9t74
-----END PRIVATE KEY-----
    """.encode('utf-8'),
    """
-----BEGIN CERTIFICATE-----
MIIFMjCCAxqgAwIBAgIUZt8j6LG+nsSb1wsrxjmWmSn5lzUwDQYJKoZIhvcNAQEN
BQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y
MTAxMTQxODU3NTZaFw0zMTAxMTcxODU5NTZaMCcxFDASBgNVBAoMC01pbGxlR3Jp
bGxlMQ8wDQYDVQQDDAZSYWNpbmUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
AoICAQDu4dTDbd9Wz3elIVisJdBedhmhtxdmgxefKEg5uu415TfICVI4c8ay7Qav
n22S1C6LyVgB0aK1VD5NS+0fPp2sFmDQ7kP+s7QIjHkNCT6CL/n3SdLRN5gexyc1
tDd52sDAmVuXqBReQ6xDaHWc94QTbMC3eqrAhtMUjG9XMcoyW0u9LT9d7w3AElYT
zlkAcTSMmshqg893PQPzbOxjnSiLzsAUWuBrYYXx83jmMKaj6WPJ7tTFRZgZnfId
uso7rl3UpnjoFBLN9AdhKWFPmt7jnVxxaN0JwG+7elxhR007lJD2RylLtHhcPSCx
WiMZlFLTG+U+tFZgXRh5DeO1v5/vEj97JU6GX7tZG+0K0UdUa8MDvsToooFq33DV
G5Al6odx+KLATGhBm/l1HIr9LVrj+5tVklXZpaB0P8SAlic8sEF+YpLjRQLueND3
si+TpKCg6S83fMJRdp0bTXNe3oeukB8DQxaH7OqksHzMvYZnLpqjSrTrg2kmtS3z
wm6KOLXxHzE7r85m5o60SOO++C5gDxAAzwKFABZ0UhhzycMekEMTcqB+h23OQYJK
FVtdhK95A0nMQGeQqthOyIeAAmEzmCZX2SrDhF3mK1N5PDaHdv6bGPJNHzm5wMQc
nJcVTJCK9+jmFAVnEZfzphjOHcWtd95XqOYb6kkUAWxca6zGOwIDAQABo1YwVDAd
BgNVHQ4EFgQUTjgktIH9u9iCWOGwTARIqJC1ircwEgYDVR0TAQH/BAgwBgEB/wIB
BTAfBgNVHSMEGDAWgBROOCS0gf272IJY4bBMBEiokLWKtzANBgkqhkiG9w0BAQ0F
AAOCAgEAd/8X18Yt8p6L+ox7Hm23BokcVY6AfZOJajDECuVPlVqUvqu6puP2u+uk
yg1NPPmPTA981L9EQXGmW8fuwcvlJqiUueIszPqk1Zo2Zg6EvcSHJ93d3SPcDo+W
zTxrfNFDhVxnlp6RdiaYuhJzAZKICA4EJFi7rogKMdcxrzDk7yNAguoU9pkRM3oP
nKyCqe34madILHHYTir25wcaV3WsSrY+BmjSTgJkoAUWnuSWKa6fvbcocYmELSIu
nNcpavckTMPEYwLBA7xxVUppSKdXN4vOCRJVAh6NOx+NW4XhN/rb+ltSFFO87oIG
3+YihVbIith5Xj0GzUswyOX3gn2SJlXjk+B5UIiOh8cd3U4HarquArnn3cf4P5Ev
3d6J8i6oq0RQzguu6ER6JcwWkWI9psDag0GTxYUG1oQ99hSsxYavdlonJAao/hS8
i6vDK150gjFv4+mxanmuGxxgr3f5Kzu+NxwSsCVJGZ3ckyRK/SQlnGHe7K6YncTW
uEeeBOTeRYnf25D+2lr/MpCtkz5i3DHc3eI9FfeAbmDUI6O5NxYz5pBytb4zQ8Sz
eIdNRGmLNchR/uWo9Wnenvz7DAmqteUWm9Lo+5EStaYesIyHeuirUsKDSJVyS+s6
ZE4ROy5y+dG0q3rgtYWkRh5Jseo1fwtVE2IQ/WhPpi9jdFX4DRw=
-----END CERTIFICATE-----
    """.encode('utf-8')
)
if not clecert_1.cle_correspondent():
    raise ValueError("Erreur de chargement clecert_1, cle et cert ne correspondent pas")


if __name__ == '__main__':
    logging.basicConfig()
    logging.getLogger('__main__').setLevel(logging.DEBUG)
    logging.getLogger('millegrilles.util').setLevel(logging.INFO)
    # generer_certificat_millegrille()
    test_generer_roles()
