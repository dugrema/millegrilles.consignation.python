import json

valeur = {
    "cle": {
        "0nombre": 3, "_cle2": "valeur", "aCle":"a", "zCle": "z"
    }
}
print(json.dumps(valeur, sort_keys=True, separators=(',', ':')))
