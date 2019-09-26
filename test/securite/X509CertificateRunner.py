from millegrilles.util.X509Certificate import GenerateurCertificatMilleGrille


class RunnerCertMilleGrille:

    def __init__(self):
        self.generateur_mg = GenerateurCertificatMilleGrille('test1')

    def generer_initiale(self):
        resultat = self.generateur_mg.generer_certs_initial()
        print(str(resultat))


# ******** MAIN *********
runner = RunnerCertMilleGrille()
runner.generer_initiale()
