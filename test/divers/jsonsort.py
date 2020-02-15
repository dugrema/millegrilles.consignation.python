import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


valeur = {
    "cle": {
        "0nombre": 3, "_cle2": "valeur", "aCle":"a", "zCle": "z"
    }
}
print(json.dumps(valeur, sort_keys=True, separators=(',', ':')))

valeur2 = {
    "cle": "étendre",
    "pasrien": None,
    "batterie": [
        {
            "millivolt_avg": 3796.025404157044,
            "millivolt_max": 4167,
            "millivolt_min": 3359,
            "reserve_avg": 98.37875288683603,
            "reserve_max": 100,
            "reserve_min": 97,
            "timestamp": 1580169600
        }
    ]
}

valeur2_utf8 = json.dumps(valeur2, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf8')

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(valeur2_utf8)
resultat_digest = digest.finalize()
digest_base64 = str(base64.b64encode(resultat_digest), 'utf-8')

print(valeur2_utf8)
print("Digest " + digest_base64)

with open('/home/mathieu/tmp/test.json', 'r') as fichier:
    contenu = json.load(fichier)

contenu_filtre = dict()
for key, value in contenu.items():
    if not key.startswith('_') and key != 'en-tete':
        contenu_filtre[key] = value

contenu_utf8 = bytes(json.dumps(contenu_filtre, ensure_ascii=False, sort_keys=True, separators=(',', ':')), 'utf8')
print(contenu_utf8)

digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
digest.update(contenu_utf8)
resultat_digest = digest.finalize()
digest_base64 = str(base64.b64encode(resultat_digest), 'utf-8')

print("Digest fichier test.json " + digest_base64)
