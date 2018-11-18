import sys

# **** MAIN ****

if len(sys.argv) == 3:

    nom_module = sys.argv[1]
    nom_classe = sys.argv[2]

    # Executer la methode

    print("Demarrage du gestionnaire ")

    classe_processus = __import__(nom_module, fromlist=nom_classe)
    classe = getattr(classe_processus, nom_classe)
    instance = classe()
    instance.executer_gestionnaire()

else:
    print("Il faut fournir le nom du module et le nom de la classe a executer. Exemple script_demarrergestionnaire.py nom.module classe")
    print("Arguments fournis: %s" % sys.argv)


