param = '   mgdomaines.appareils.SenseursPassifs:GestionnaireSenseursPassifs    '
gestionnaires = param.split(',')

for gestionnaire in gestionnaires:
    noms_module_class = gestionnaire.strip().split(':')
    nom_module = noms_module_class[0]
    nom_classe = noms_module_class[1]

    print("Nom package: %s, Classe: %s" % (nom_module, nom_classe))

    classe_processus = __import__(nom_module, fromlist=[nom_classe])
    classe = getattr(classe_processus, nom_classe)

    instance = classe()