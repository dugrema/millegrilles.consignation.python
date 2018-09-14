from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO

configuration = TransactionConfiguration()

messageDao = PikaDAO(configuration)
mongoDao = MongoDAO(configuration)

mongoDao.connecter()

print("Connecte a Mongo")

message_dummy = {"contenu": "valeur"}
enveloppe = messageDao.preparer_enveloppe(message_dummy)

mongo_id = mongoDao.sauvegarder_nouvelle_transaction(enveloppe)
print("Document Mongo id=%s a ete cree" % mongo_id)

mongoDao.deconnecter()

print("Deconnecte de Mongo")