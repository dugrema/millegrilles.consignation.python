from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.MessageDAO import PikaDAO

configuration = TransactionConfiguration()

messageDao = PikaDAO(configuration)
mongoDao = MongoDAO(configuration)

mongoDao.connecter()

transaction_helper = mongoDao.transaction_helper()

print("Connecte a Mongo")

message_dummy = {"contenu": "valeur"}
enveloppe = message_dummy

mongo_id = transaction_helper.sauvegarder_nouvelle_transaction(mongoDao._collection_transactions, enveloppe)
print("Document Mongo id=%s a ete cree" % mongo_id)

mongoDao.deconnecter()

print("Deconnecte de Mongo")