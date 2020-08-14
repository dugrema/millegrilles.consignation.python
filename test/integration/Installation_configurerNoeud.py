# Tests de configuration d'un noeud
import requests

from millegrilles.util.X509Certificate import GenerateurInitial, GenererNoeudPrive, EnveloppeCleCert, RenouvelleurCertificat

serveur = "mg-dev4.maple.maceroc.com"


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
        self.idmg = 'QFyDsZPcVPQQVzG5LtfqkH172VN47izposXWusKdej6o'

        self.chaine_pem = [
            '-----BEGIN CERTIFICATE-----\nMIIEnTCCAoWgAwIBAgIUeRRgmQyx1Z5RljkbqNpZQJT8onMwDQYJKoZIhvcNAQEL\nBQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y\nMDA4MTMxOTI3MjlaFw0yMTA4MTUxOTI3MjlaMIGEMTUwMwYDVQQKDCxTcnduTXBD\nZ1NzUlpvbXlzY0d4VFhxb3l5bURDcEJoZFZjV0NFdW9qSDVjYjEUMBIGA1UECwwL\nTWlsbGVHcmlsbGUxNTAzBgNVBAMMLFNyd25NcENnU3NSWm9teXNjR3hUWHFveXlt\nRENwQmhkVmNXQ0V1b2pINWNiMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAuaNlw1/CfD+EKPkZF0rGZO2HsNSQcoMumwifjU0rfdZIs/UJUGhtq9fmLDsK\n936cZ0GKMUSLuOBthIvvzGqoA9qqwxp2yKZlUpfkLeuCXoGJGmkN/6A/Zhy1pK5z\nijLerppjMryCNuhaHjhWOqa1na9BcDTY/+oQtfK9y5sMxHoNSphOeEhYYYg0gslw\nqnCVH0vxQ3+QEUYfuPXWO/V6TGGgLKMKlREk61sVcDINl8qBhKE05n5Sq1wiQK2P\nWaOQoemnp0hfwJiTzc5doHcIOKklIX8gvam2ZV/vgA3Dgqd5OlfkiiM0dC/voEVu\nRKBdO585oLrXnfcSi4NxUqoORwIDAQABo2MwYTAdBgNVHQ4EFgQUl5ahso9hSoh/\nd1mWhq+x6w9KffgwHwYDVR0jBBgwFoAUIXcnpJkVfwCqhHvaxwoBxvzdjMkwEgYD\nVR0TAQH/BAgwBgEB/wIBBDALBgNVHQ8EBAMCAvwwDQYJKoZIhvcNAQELBQADggIB\nAK3Fb5WUrDCekjRJ5weE+HORBsG10tnBp2uOITIX+60hfqPxFV3xFUIjR1fJ9D47\nhTRYur/GD17XwdWKWtAK4dJZKoIvnQnxhjR9IxLeI9vVZlELptdHzZPOqMBJnCc8\nc6jN4epHI52dcvOj1OB4RH0GVrPKm54MUsOFhO4KOlRCDjAqa/4/JoumXy1TI+RK\nQ3gbLnmHrCN8O3Ce+WIqafxYo/UbZn0IQzI44aoUQvg4DnlFW4VNxs7oHHqZhYXt\n2tINYy1hYAPq5MuPs+DEMDIR3wFWOarHs/lkWNTVHXj/rOyqpbEwH80oJLrsbv1A\nszsIIOZvqb9S+v2jTXQM/ulCyDF+2Pkf09Q2E4LImGmtsE8CL7SH+RIJKWi5cqFw\n7E40PgeBPRJW4JAucs3PPMW89ws+5aZSUNJLKCkzfGNTAgQE/4IUWGItnXGbyHnk\npa4C6czL10Ng6/bfCBxCtHTL1uITm9pZSao2RAvF0ZkFs3K+lAZp7uSbfyrFTf+B\nJ3ZNQohIFTiPVbeXNJH6bxT8wOnsKbdpIDasLdNyfeWCGJTlv7Lydcs5iIrhYIQC\nizYwGao0MauxL2jv+WjHkZee3EnvXcZ6dygTsxetu6wxyC4IcwV341BeFY/BQqNU\nzHgzHNstSM6ebORlJFXuZ4kA7tMmzzf+Okqx0lYZ4tWN\n-----END CERTIFICATE-----\n',
            '-----BEGIN CERTIFICATE-----\nMIIFMjCCAxqgAwIBAgIUM2/usyiiLadDY+pzdUgHaxhwPk8wDQYJKoZIhvcNAQEN\nBQAwJzEUMBIGA1UECgwLTWlsbGVHcmlsbGUxDzANBgNVBAMMBlJhY2luZTAeFw0y\nMDA4MTMxOTI3MjhaFw0zMDA4MTcxOTI3MjhaMCcxFDASBgNVBAoMC01pbGxlR3Jp\nbGxlMQ8wDQYDVQQDDAZSYWNpbmUwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\nAoICAQDF9kWElV5ZDqiVLodMb9z2FyAyfhd4Jvh+oAhyXw+Ve/Xx613gp5f1Nilj\n4oLnyLIY5GcYxrGVU+7SiwyqjsrHi0HRPVpU3X2CoBZJX1vv45wy6eL/ob/TmlYb\niUa07CrprGkyc0UpCjGMfH9Dlyleb9UwWUl3iHiu4w0UScF/hlJlGZQ+lf+3ji/l\nvlpf1FCBJ58DjqgsJEH3lkmFaqIyIBNb+mnfepBFcVQERYcUCZvH//83LbnWW1l+\nkXsc3itVfMcI47BIDt2AYF4SGNOuq/MuvQIN477qvyJ+De4BG4Ujwx9oAKIZLFHr\n92EJ1vXRYrxr+PeKJzBPCs8/sabUXidTGhdam7uXaO46mN0nS2EgV+mP49a5xJBo\ns/DWOykRrkU5Q/JOuxNoCssDD6vY80AQ8EzWL4y4bYyTNcAnfDCenbBQfjKdSEur\nuiILiB7xx+m8kZGnUjIAZHAocrb8YnZ1BKyL/DdyKUUri8otDC048iNRHwh+ZZVv\npwwiOAVgg7+ckmxrfKId+/Rrd5nPkb8mXk8G918aUWmRmhIZJN34o0QWoLzLACJT\nNvSRkJHs01lErR90A2fu0F7AXBFvVdD1xfP1lIlmKbVRC6wQYQVx8E8h0dWJMhMH\nJ86ULEv9FqbtiNg8urZXz+WJASb20pa2cZoPgN3XPjoLYDImfwIDAQABo1YwVDAd\nBgNVHQ4EFgQUIXcnpJkVfwCqhHvaxwoBxvzdjMkwEgYDVR0TAQH/BAgwBgEB/wIB\nBTAfBgNVHSMEGDAWgBQhdyekmRV/AKqEe9rHCgHG/N2MyTANBgkqhkiG9w0BAQ0F\nAAOCAgEAKfg+8UL3AYzT7vOApgaieDESbOvU9X9j8uwXmWjwteRZJiETE7XsBPys\nDVMxeXWGpCmCxJZKXT11jD3hglMl2f3RiSNt0JX7MpGlTHXV9tf6W032oV31vck9\noO+Hozl3i7W9obVlFagPBQIPnemqKNkbj3NVo86Hc3XwShCZnPVvuAMGbvMq5IsH\n4f0bERP2o0RNII/JK2zY6hD/FGAQEGL0YSXrCaEDPTm3mu8LM9MzXND3NKOJiMkf\nzJfPP0xTzmmte/TTYlu2DiwrP8GCCx7WVfDJrocexEHmTKpkylkzcS+W2NOmXARZ\n0+FJthH9m/gWN+HX9j1EZnadxQHBvtimrd55X0nq3JJyib9ZEPvs8kmUQt/Qy9WX\nwAnLqFyWUHiO2YtnkH6Vje2myCZEJQHeXEBLxuGcBKDa0Whl0zq38eZSgpPlFwK1\nRelO13Vh6tIKXeCKgTc5aG9uWKyzCFlVC40nRrWyKl4eSqyDuVE21lSFKmrGKl0P\npI5mlj9/VqqBMIDi+OV/teGUvctjTxtR+Lr73K0xOQ6DU+MDEzcJj5yLDi6AtSHd\nyBU/DD7LH70+0OaEUIRUAMkYtR9MdK4uurscTA72Mdh9YsRUB0/cYdTeOCvVBgR4\n92AGM+e38GTMLYqIzvzATeosOHkkr4iV380fAH1LUFcOG6QkIA4=\n-----END CERTIFICATE-----\n']
        self.cle_pem = '-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC5o2XDX8J8P4Qo\n+RkXSsZk7Yew1JBygy6bCJ+NTSt91kiz9QlQaG2r1+YsOwr3fpxnQYoxRIu44G2E\ni+/MaqgD2qrDGnbIpmVSl+Qt64JegYkaaQ3/oD9mHLWkrnOKMt6ummMyvII26Foe\nOFY6prWdr0FwNNj/6hC18r3LmwzEeg1KmE54SFhhiDSCyXCqcJUfS/FDf5ARRh+4\n9dY79XpMYaAsowqVESTrWxVwMg2XyoGEoTTmflKrXCJArY9Zo5Ch6aenSF/AmJPN\nzl2gdwg4qSUhfyC9qbZlX++ADcOCp3k6V+SKIzR0L++gRW5EoF07nzmguted9xKL\ng3FSqg5HAgMBAAECggEAIitYTNjwdGxAiEYpfycNU4CBLGRD3kAVMQYqUBj3O2dY\n5H7i4wEFxs6rmFKZ1ypf4YWnyR/D1BjDL9WOIwMyv9rc+aKCYLZ4CfbZUjZ6Paj8\nMndJ01aMtN/t800FCVgJsvvJ7InUMgUcqVlXTd5nqYmbsuqXUqujvcnbc4GrnPJF\nlSTzRgofbUdLFe9rqkOfVU+I4V0w6mGmAr3bjkHo9aKkqqWOjVtdYKHUzScrhlFm\nVLHokp+/rh9FFUKdFMSJDYe6qmCgzFqY88GuvUgUOKXIY6rds0I8znHoA6fFXI5H\nxKoKK+xcc2bvp3/hMWgVfuyz7BVbQ6WKNfkQCeAUUQKBgQDyAYbCJ8FrozK0bxDB\nVelztkzWInXThVIXk3clxS8dPIxoIk6yxze97jqgVmQieU+oVHm/sjvgUWuiVuWa\nqnpMG3SSOw6dK5WB1gINEMFHiGTcJsjA3OXaVcBW+Bl6e06qEhDC1chPvqF9ROMb\nY/q4y0lnwk6l7aKe9Ou0xTH66QKBgQDEX3JEzAJMkrqYArDR7bkIIuHQz+JHbpdj\ny6+/ggM5L2tmZ3JN2lRYtNyaDGn4VHhUl2+mLEtlWFPgpxZHVeOD2ZwFkVYmuouQ\nJV6LXjlsjKgBjttxAF2nSfKFdj0OC8o2VugPml49D6Kgp2kvWJDz+nbodBhL5dWh\n4jNbSzuhrwKBgBjvwVQGRq7xrQrcmuxhDuImebpi6KM4DKJzRoa0z8sCbzFXv6Y6\nUusWPiJBZKYMvAGLWtQ+6F6P5ThgHd6XDG0FMzjSLwpQ8GHljGaOQGw/iK0Krgr5\neBHMXjpX7EArroplvCZnYvGcogVHcONkpPQftlujsPj2CJi6ggMpgqHpAoGAKbHG\nVlsmpdGFst7nYjtiTRry7V4mQlp15GeMElJtksfBuwV93I/d1tPX/xFhsqtkvTlG\nKHdBLux5KrrvXQgcfZNHsFryetii52E32MmR0b1vspz9dNnKCMoHp1S6k+/m6HC9\nZwq0taxLMGc7SyU36cWlV6fGvN645F1d4CVyLNsCgYAFdnNrsM1cQmB28TA1JPxh\n7AnctCRegg59Au3xkgKuGS/0+LpIHUowEWbW+5Swr4YoD546hhxsgk/1QXIP+jhT\nbJ4cdK9///+RjHogDwfVThnYattPz7akr1uPMmkOSQH0j3S2wSbVeaeJH0tj8RTN\nWi4L+HaLu60n4z8L7ob9bg==\n-----END PRIVATE KEY-----\n'

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
            'https://mg-dev4.maple.maceroc.com/installation/api/initialisation',
            json=message,
            verify=False
        )
        print("Inscription noeud prive : %s" % str(resultat))


# ------- MAIN --------
def main():
    # generer_cert_millegrille()
    csr = get_csr()
    signateur = SignatureCert()
    signateur.configurer_noeud_prive(csr)



if __name__ == '__main__':
    main()
