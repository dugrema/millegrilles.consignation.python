import os

folder = '/home/mathieu/mgdev/certs'

print("Working directory : " + str(os.getcwd()))

liste_fichiers = os.listdir(folder)
liste_fichiers = sorted(liste_fichiers)

for file in liste_fichiers:
    name_split = file.split('.')
    name_short = '.'.join(name_split[0:-1])

    path_dest = os.fspath(name_short)
    try:
        print(str(path_dest))
        os.symlink(file, path_dest)
    except FileExistsError:
        os.remove(path_dest)
        os.symlink(file, path_dest)
    except Exception as e:
        print("Exception " + str(e))
