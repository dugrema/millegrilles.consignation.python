import traceback
import argparse

parser = argparse.ArgumentParser(description="Demarrer un gestionnaire de domaine MilleGrilles")

def parse():
    parser.add_argument('-m', type=str, nargs=1, required=True, help="Nom du module Python")
    parser.add_argument('-c', type=str, nargs=1, required=True, help="Nom de la classe Python")

    return parser.parse_args()

def run(args):
    nom_module = args.m[0]
    nom_classe = args.c[0]

    # Executer la methode

    print("Demarrage du gestionnaire %s %s" % (nom_module, nom_classe))

    classe_processus = __import__(nom_module, fromlist=nom_classe)
    classe = getattr(classe_processus, nom_classe)
    instance = classe()
    instance.executer_gestionnaire()

# **** MAIN ****
try:
    args = parse()
    run(args)
except Exception as e:
    print("Erreur %s" % e)
    traceback.print_stack()

    parser.print_help()