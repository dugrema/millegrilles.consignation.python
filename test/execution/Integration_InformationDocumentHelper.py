from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.InformationDocumentHelper import InformationDocumentHelper

configuration = TransactionConfiguration()
configuration.loadEnvironment()

documentDao = MongoDAO(configuration)

documentDao.connecter()

informationHelper = documentDao.information_document_helper()



documentDao.deconnecter()

