import tempfile
import os

tmp1 = tempfile.mkstemp()

with open(tmp1[1], 'w+') as fichier:
    fichier.write('Allo tout le monde')
    fichier.flush()

# with open(tmp1[1], 'r') as fichier:

    fichier.seek(0)  # Retour au debut du fichier pour lire
    print(fichier.read())

print(tmp1)

os.remove(tmp1[1])

