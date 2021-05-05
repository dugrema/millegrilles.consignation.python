from millegrilles.SecuritePKI import GenerateurRsa


def generer_cle_rsa():
    generateur = GenerateurRsa()
    cle_openssh = generateur.generer_private_openssh()
    print("Cle RSA openssh\n%s" % cle_openssh.decode('utf-8'))


if __name__ == '__main__':
    generer_cle_rsa()
