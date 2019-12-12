from millegrilles.util.X509Certificate import GenerateurInitial, EnveloppeCleCert, RenouvelleurCertificat, ConstantesGenerateurCertificat
from millegrilles import Constantes


class RunnerCertMilleGrille:

    def __init__(self):
        self.folder_output = '/home/mathieu/tmp/certs'
        self.idmg = 'test1'
        self.generateur_mg_initial = GenerateurInitial(self.idmg)

        self.self_signed = None
        self.millegrille = None

        self.renouvelleur = None


    def generer_initiale(self):
        millegrille_clecert = self.generateur_mg_initial.generer()
        print('generer_initiale()')

        self.self_signed = self.generateur_mg_initial.autorite
        self.millegrille = millegrille_clecert

        self.sauvegarder('ss', self.self_signed)
        self.sauvegarder('millegrille', self.millegrille)

        dict_ca = {
            self.self_signed.skid: self.self_signed.cert,
            self.millegrille.skid: self.millegrille.cert,
        }
        self.renouvelleur = RenouvelleurCertificat(self.idmg, dict_ca, self.millegrille, self.self_signed)

    def generer_certs_noeuds(self):
        cn = 'mg-test1'
        roles = [
            ConstantesGenerateurCertificat.ROLE_DEPLOYEUR,
            ConstantesGenerateurCertificat.ROLE_MQ,
            ConstantesGenerateurCertificat.ROLE_MONGO,
        ]
        for role in roles:
            self.sauvegarder(role, self.renouvelleur.renouveller_par_role(role, cn))

    def sauvegarder(self, nom, clecert: EnveloppeCleCert):

        with open('%s/%s.key.pem' % (self.folder_output, nom), 'wb') as fichier:
            fichier.write(clecert.private_key_bytes)

        with open('%s/%s.cert.pem' % (self.folder_output, nom), 'wb') as fichier:
            fichier.write(clecert.cert_bytes)

        if clecert.chaine is not None:
            chaine = ''.join(clecert.chaine)
            with open('%s/%s.fullchain.pem' % (self.folder_output, nom), 'w') as fichier:
                fichier.write(chaine)

        if clecert.password is not None:
            with open('%s/%s.password.txt' % (self.folder_output, nom), 'wb') as fichier:
                fichier.write(clecert.password)

    def charger_cle_cert(self):
        clecert = EnveloppeCleCert()

        with open('%s/%s.key.pem' % (self.folder_output, ConstantesGenerateurCertificat.ROLE_DEPLOYEUR), 'rb') as fichier:
            key_bytes = fichier.read()
            clecert.key_from_pem_bytes(key_bytes)

        with open('%s/%s.cert.pem' % (self.folder_output, ConstantesGenerateurCertificat.ROLE_DEPLOYEUR), 'rb') as fichier:
            cert_bytes = fichier.read()
            clecert.cert_from_pem_bytes(cert_bytes)

        # Verifier que les cles correspondent
        corresp = clecert.cle_correspondent()
        print("Cle et cert deployeur correspondent: %s" % corresp)

        with open('%s/%s.cert.pem' % (self.folder_output, ConstantesGenerateurCertificat.ROLE_MQ), 'rb') as fichier:
            cert_bytes = fichier.read()
            clecert.cert_from_pem_bytes(cert_bytes)

        # Verifier que les cles ne correspondent pas
        corresp = clecert.cle_correspondent()
        print("Cle deployeur et cert mq correspondent: %s" % corresp)


# ******** MAIN *********
runner = RunnerCertMilleGrille()
runner.generer_initiale()
runner.generer_certs_noeuds()

runner.charger_cle_cert()