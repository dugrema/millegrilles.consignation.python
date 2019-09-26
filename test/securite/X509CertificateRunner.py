from millegrilles.util.X509Certificate import GenerateurInitial, GenerateurCertificatMilleGrille


class RunnerCertMilleGrille:

    def __init__(self):
        self.generateur_mg_initial = GenerateurInitial('test1')

    def generer_initiale(self):
        resultat = self.generateur_mg_initial.generer()
        print(str(resultat))

    def generer_deployeur(self):
        pass

# ******** MAIN *********
runner = RunnerCertMilleGrille()
runner.generer_initiale()
