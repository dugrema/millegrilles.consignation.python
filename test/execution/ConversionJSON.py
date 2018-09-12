from millegrilles.transaction.Configuration import TransactionConfiguration
from millegrilles.transaction.MessageDAO import JSONHelper

json_helper = JSONHelper()

dict_test = {"contenu": "valeur était à alisée", "nombre": 22}

message_utf8 = json_helper.dict_vers_json(dict_test).encode("utf-8")

print("Message en utf8: %s" % message_utf8)

# Convertir de UTF8 vers un nouveau dictionnaire

dict_2 = json_helper.bin_utf8_json_vers_dict(message_utf8)

print("Contenu = %s, valeur = %d " % (dict_2["contenu"], dict_2["nombre"]))
