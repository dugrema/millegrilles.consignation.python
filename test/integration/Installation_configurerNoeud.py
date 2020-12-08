# Tests de configuration d'un noeud
import requests
import os

from millegrilles.util.X509Certificate import GenerateurInitial, GenererNoeudPrive, EnveloppeCleCert, RenouvelleurCertificat

serveur = "192.168.2.131"


def generer_cert_millegrille():
    generateur = GenerateurInitial(None)
    clecert = generateur.generer()

    chaine = clecert.chaine
    clecert.password = None
    privee = clecert.private_key_bytes
    idmg = clecert.idmg

    print("IDMG : %s" % idmg)
    print("Chaine certificats :\n%s" % chaine)
    print("Cle privee PEM:\n%s" % privee)


def get_csr():
    resultat = requests.get("https://%s/installation/api/csr" % serveur, verify=False)
    contenu = resultat.text
    return contenu


class SignatureCert:

    def __init__(self):
        self.idmg = 'JPtGcNcFSkfSdw49YsDpQHKxqTHMitpbPZW17a2JC54T'

        self.chaine_pem = [
            """
-----BEGIN CERTIFICATE-----
MIIDfTCCAmWgAwIBAgIJYGYjdUZ4mWUAMA0GCSqGSIb3DQEBDQUAMCcxDzANBgNV
BAMTBlJhY2luZTEUMBIGA1UEChMLTWlsbGVHcmlsbGUwHhcNMjAwODE0MTMzNTAw
WhcNMjMwODE3MTMzNTAwWjB9MS0wKwYDVQQDEyRmMDNhYTQyNi04Mjc5LTQyMDYt
YWYyYy0wNjA5N2IyMmY2MTYxFTATBgNVBAsTDE5vZXVkUHJvdGVnZTE1MDMGA1UE
ChMsSlB0R2NOY0ZTa2ZTZHc0OVlzRHBRSEt4cVRITWl0cGJQWlcxN2EySkM1NFQw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDbi6hszfap+SF2vPoJx/1t
1k4AZNUWpxpD7zTVw9gjl8re2hHjDne99w4r3bPOyDUjh6A4hWC77bQ/yTa/UQPO
LVHdU3DcbjshxCYv/TebwikEct4EoYjxQZgt6ov4rhhyyEqPK1UFvHsNkjZWH1qM
ocoHA2IeeDZqhi9mRGeKsZ7vPOYI/9RN3lQMEYUqIQI0Tx+rVEXIGT7g6WSuKwN2
O9Q1Ktqb7z6w491UkPTxukM2DkZCglSRXEnfw8Psc2c6yN1TKHgsGzf299d3zkF2
c0ZtI8rqQ9tebX1zZCyYOLZrZXWP73kr89Qnp0b3d78vB2uEHW1ioPhNstRcIQPf
AgMBAAGjVjBUMBIGA1UdEwEB/wQIMAYBAf8CAQQwHQYDVR0OBBYEFAAvK7SYudlb
e3wdxyjBcEQz/6uFMB8GA1UdIwQYMBaAFLBXLIVvPd0v2/PRpsXEhxv3SitkMA0G
CSqGSIb3DQEBDQUAA4IBAQBNR6bWpOLfEL/ERZsuCzX04YchFy7gNuCSphzhFpGx
V3gApShKPKja94V2FmcvbHqmiCnU2SK5/q7YB9X7RElYJRktl50DIUw3puKfaYS0
965K4ZIyuhA452G+OdgrvJzE29E6op19z1SAKvzqhk3e/SFrEmrsKisGAA2HGL8Q
E+cGvtDYc/b4YE0YmK4b6+PyGSF+2HDr9D9lEsavn5tJaWLjBiGp2BTKagShOpNX
VPk6OgYoAWz9RULV/jMSVrC/fm8cogmWT0TJ2NFR305iI9bv7zHKtQ7p/MjxNQN2
wh0FLaiqSb+Dd+LZiMlWm7tF2Z5vuqC1EMdbjTYVBU23
-----END CERTIFICATE-----
            """,
            """
-----BEGIN CERTIFICATE-----
MIIDKDCCAhCgAwIBAgIKAol2BgZkgwIwADANBgkqhkiG9w0BAQ0FADAnMQ8wDQYD
VQQDEwZSYWNpbmUxFDASBgNVBAoTC01pbGxlR3JpbGxlMB4XDTIwMDgwNTE3MTky
NVoXDTIxMDgwNTE3MTkyNVowJzEPMA0GA1UEAxMGUmFjaW5lMRQwEgYDVQQKEwtN
aWxsZUdyaWxsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKHD5H6t
svTC1rkQ0jDq51/5ht72LroSubFIM6SGd4PeofKGk2LCLce8IGC9zz08lXa8WMkr
I9yAxf3P0WK2UEZFXsvGJ0EvBXyewZDEX+Lfp12zyBuKGRK5rjUYFCdbEiO+qVCq
Pvqb4VU4ffbAFvuWRulSfvD5udC2PY1xRxNQytAnbs3jRJSzcFiGDk50bwG5JD/i
TZwtnm6OQYcxnckNZgzz8G34wZEAwz1f5a941nV+Tnnod+7t6kdkLFenMUtVPrd8
hVwHzitBUkBP8OsTvS/AGvyMrz/1XT1+MxwShq8o8S2fp7YGdR8eeb1uUfJLzLu8
rGB5vMOoiiGOkNkCAwEAAaNWMFQwEgYDVR0TAQH/BAgwBgEB/wIBBTAdBgNVHQ4E
FgQUsFcshW893S/b89GmxcSHG/dKK2QwHwYDVR0jBBgwFoAUsFcshW893S/b89Gm
xcSHG/dKK2QwDQYJKoZIhvcNAQENBQADggEBAKD7W6UKrnPpIXzrFVXs0EOYZi1u
IUEOBA0yoJyUQuLcyb+nNCUf9FPjyh1xGrtHLgMwNuIj3EqB3AvzZs+t9kyJ+aun
RaGxOSd6ytQzRW4LcpUNeBs0oCkTftlXGZRBU/ZgaMNQvk7b1R5MaBOtBnUkDsRA
/+bdPl2gpOCUFdNK53805Z8cgV0QXQKNPgM06EVT1URWsy9Z3O6BA57Xq3kEZOtJ
oJMuyy7g7/iRiAfXsys7ZoDgPET8SL3R0UbvUTXXI5jM2+jchBqucI6YSEjJmgBQ
TNQc8kgLqRI+hI8Ri62/ZsEeUmyn5VOrq+oPOsFc1wBS8ErdxXLln77cEEk=
-----END CERTIFICATE-----
            """]
        self.cle_pem = """
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA24uobM32qfkhdrz6Ccf9bdZOAGTVFqcaQ+801cPYI5fK3toR
4w53vfcOK92zzsg1I4egOIVgu+20P8k2v1EDzi1R3VNw3G47IcQmL/03m8IpBHLe
BKGI8UGYLeqL+K4YcshKjytVBbx7DZI2Vh9ajKHKBwNiHng2aoYvZkRnirGe7zzm
CP/UTd5UDBGFKiECNE8fq1RFyBk+4OlkrisDdjvUNSram+8+sOPdVJD08bpDNg5G
QoJUkVxJ38PD7HNnOsjdUyh4LBs39vfXd85BdnNGbSPK6kPbXm19c2QsmDi2a2V1
j+95K/PUJ6dG93e/LwdrhB1tYqD4TbLUXCED3wIDAQABAoIBAQCPCvN10MxB+rw+
7OnMra0Ff3fa8deUptOKJ7S5Ap00s5XOlS7KTYbfErT9B7o7pF5bA+b0bJKWX03t
sWAmTta34vdPySnjtT55xZ9L7SPqLBslduIJCmZ7Kk3IvOTt5iCvyKgrmAQRdLiI
IxecDVml/1PuNdocGB78UOlZLIB58AM9m3zHE0I4UDBL1Uo7q+GagklisDKkYjzU
Blxr8lkvisJniPHkOJj4DRGpXG9bJAoTTwya6tISpMNQRtOPu4lN7CzkK9CXvM/a
l8Eu9rYVzg7m3Q0jdvwiNZWEIFMLuDEi0ijWcEPurH/wV0LMIVQFe1LA7swg8BjC
PjiRExDhAoGBAPrXchrGJUAt1mx2nb9a4OJ2YRlpBkN0pPB0rsBg1AUf4raTTcwb
5S2sDqkn0zwVA3aWhWFkzTJgBlC6Ykn1xsa2VSGP1JchxAl6EgKiWxSHNkaiiBM2
Fo8jjRscMb8T0sjgDEjlmvrERDGSrJtmEPQjGTcDlsOZDlFphls3eQZ1AoGBAOAP
dE2hxX3G8zSD+/90a7bbhfhqfOJta7a6Sv6NwshR9bnI1kLqjJbg32jY15HSvdGL
Em1U5duI/oy+lZCQBBSaGSnPmhFRPqa1o8nPYh5Zz2aLroTWIjiIweGx4hJQ8F3a
wSjG3HQNLZ3y0ppH+FvH2gLuZh1CPsd95lXMjR6DAoGAKh8VhRNy2+UWlZ4RfTmI
e96/DWJKb/ddXxdo5Nsdn0KsclYoATdJ87Jpv9P1L6ijrT03ZpRjtKrVRKcXrC2+
VE3326voWfyMi77Y2WJkAv11isTuLrOtdBnXLw8790cf5SViSrdrn+JnRR/JJkss
W6KtMETFA1FnSxp6OkUFaKUCf37oQfe2qSWUiiw0lYcbaecob7lEl3eogln9Kn0D
zk+oHIYeOz2rm/XZaLD6IR93PgxxuP40F/1Amu0dBZnb+HOy1I3aCGnGmrXSK/Mi
g3CtbcunUjHrF3bt/uLW3jWBoqOGQ+HUwQj6bdwIrUC1gvZ5PAJtBWmNHAHiTZRL
R6MCgYEA6Tr6PMVlKw60m05y1S5zv6FGuUjZrepdKc1gw1U+LG3YztoykF6g+cK4
a3CFRrd9Rbz08P9l2kXM8YWaZVxH38MbOcoVhP7Al3N4ntV+y+dKW3y8IdGYcFRv
PZgCLivK4AyUNpjfeOyrmio+GqiRKt6aVCA4Ht5Az8c5j1atiZM=
-----END RSA PRIVATE KEY-----
        """

        clecert_millegrille = EnveloppeCleCert()
        clecert_millegrille.cert_from_pem_bytes(self.chaine_pem[1].encode('utf-8'))

        clecert_inter = EnveloppeCleCert()
        clecert_inter.from_pem_bytes(self.cle_pem.encode('utf-8'), self.chaine_pem[0].encode('utf-8'))

        dict_ca = {
            clecert_millegrille.fingerprint: clecert_millegrille,
            clecert_inter.fingerprint: clecert_inter
        }

        self.renouvelleur = RenouvelleurCertificat(self.idmg, dict_ca, clecert_inter, clecert_millegrille)

    def configurer_noeud_prive(self, csr):
        clecert = self.renouvelleur.renouveller_avec_csr('prive', 'AAAA', csr.encode('utf-8'))
        certificat = clecert.cert_bytes.decode('utf-8')
        chaine = list(clecert.chaine)

        message = {
            'chainePem': chaine,
            'certificatPem': certificat
        }

        resultat = requests.post(
            'https://%s/installation/api/initialisation' % serveur,
            json=message,
            verify=False
        )
        print("Inscription noeud prive : %s" % str(resultat))

    def test_reconfigurer_idmg(self, csr):
        message = {
            'chainePem': 'dummy',
            'certificatPem': 'dummy'
        }

        resultat = requests.post(
            'https://%s/installation/api/configurerIdmg' % serveur,
            json=message,
            verify=False
        )
        print("Inscription noeud prive %d : %s" % (resultat.status_code, str(resultat.json())))
        if resultat.status_code != 403:
            raise Exception('Attendu : error 403')

    def configurer_domaine(self, domaine: str = 'mg-dev4.maple.maceroc.com'):
        info_configuration = {
            'domaine': domaine,
            'modeTest': True,
            'modeCreation': 'webroot',

            # 'modeCreation': 'dns_cloudns',
            # 'dnssleep': '240',
            # 'cloudnsSubid': '1409',
            # 'cloudnsPassword': os.env['CLOUDNS_PASSWORD'],
        }

        resultat = requests.post(
            'https://%s/installation/api/configurerDomaine' % serveur,
            json=info_configuration,
            verify=False
        )
        print("Configuration domaine %s" % domaine)
        resultat.raise_for_status()

    def configurer_mq(self, host: str = 'mg-dev4.maple.maceroc.com', port: str = '5673'):
        info_configuration = {
            # 'host': host,
            # 'port': port,
            'supprimer_params_mq': True,
        }

        resultat = requests.post(
            'https://%s/installation/api/configurerMQ' % serveur,
            json=info_configuration,
            verify=False
        )
        print("Configuration MQ host:port : %s:%s" % (host, port))
        resultat.raise_for_status()

    def executer(self):
        # csr = get_csr()
        # self.configurer_noeud_prive(csr)
        # self.test_reconfigurer_idmg('')
        # self.configurer_domaine()
        self.configurer_mq()


# ------- MAIN --------
def main():
    # generer_cert_millegrille()
    SignatureCert().executer()


if __name__ == '__main__':
    main()
