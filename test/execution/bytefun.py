

with open('/tmp/tmp-8824201640r4moLVx.jpg', 'rb') as fichier:
    # Enlever les 16 premier bytes et re-ecrire
    contenu = fichier.read()

contenu = contenu[16:]
with open('/home/mathieu/Videos/test.jpg', 'wb') as output:
    output.write(contenu)
