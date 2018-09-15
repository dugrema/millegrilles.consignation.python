from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration

configuration = TransactionConfiguration()
configuration.loadEnvironment()

document_dao = MongoDAO(configuration)
document_dao.connecter()

document = document_dao.charger_transaction_par_id('5b9bb87ab1284a00018bbfae')

print('Document trouve: %s' % document)

document_dao.deconnecter()