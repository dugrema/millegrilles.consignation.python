from base64 import b64encode

from millegrilles.util.Hachage import hacher

VALEUR1 = b'Ceci est un contenu que je vais encoder en base64 pour dautres raisons'

resultat = b64encode(VALEUR1)
print("Base64 resultat : %s " % resultat)
print("Hachage SHA2-512 %s\nSHA2-256 %s" % (hacher(VALEUR1), hacher(VALEUR1, 'sha2-256')))

