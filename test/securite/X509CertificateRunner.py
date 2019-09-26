from millegrilles.util.X509Certificate import GenerateurInitial, GenerateurNoeud, GenerateurCertificat


class RunnerCertMilleGrille:

    def __init__(self):
        self.folder_output = '/home/mathieu/tmp/certs'
        self.nom_millegrille = 'test1'
        self.generateur_mg_initial = GenerateurInitial(self.nom_millegrille)

        self.self_signed = None
        self.millegrille = None


    def generer_initiale(self):
        resultat = self.generateur_mg_initial.generer()
        print('generer_initiale()')
        print(str(resultat))

        self.self_signed = resultat['self_signed']
        self.millegrille = resultat['millegrille']

        self.sauvegarder('ss', self.self_signed)
        self.sauvegarder('millegrille', self.millegrille)

    def generer_deployeur(self):
        dict_ca = {
            GenerateurCertificat.get_subject_identifier(self.self_signed['cert']): self.self_signed['cert'],
            GenerateurCertificat.get_subject_identifier(self.millegrille['cert']): self.millegrille['cert'],
        }

        generateur_mg_noeud = GenerateurNoeud(self.nom_millegrille, 'Deployeur', 'mg-test1', dict_ca, self.millegrille)
        resultat = generateur_mg_noeud.generer()

        print('generer_deployeur()')
        print(str(resultat))

        self.sauvegarder('deployeur', resultat)

    def sauvegarder(self, nom, dict_cert: dict):

        with open('%s/%s.key.pem' % (self.folder_output, nom), 'wb') as fichier:
            fichier.write(dict_cert['cle_bytes'])

        with open('%s/%s.cert.pem' % (self.folder_output, nom), 'wb') as fichier:
            fichier.write(dict_cert['cert_bytes'])

        if dict_cert.get('password') is not None:
            with open('%s/%s.password.txt' % (self.folder_output, nom), 'wb') as fichier:
                fichier.write(dict_cert['password'])




# ******** MAIN *********
runner = RunnerCertMilleGrille()
runner.generer_initiale()
runner.generer_deployeur()
