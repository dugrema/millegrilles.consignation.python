from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from mgdomaine.appareils.SenseurLecture import AppareilInformationDocumentHelper

lecture_modele = {
    'millivolt': 2811,
    'version': 6,
    'temps_lecture': 1537463710,
    'humidite': 76.9,
    'location': '14',
    'pression': 101.5,
    'senseur': 15,
    'noeud': 1,
    'temperature': 19.66
}


class AppareilInformationDocumentHelper_Integration():

    def __init__(self):
        self._informationHelper = AppareilInformationDocumentHelper(documentDao.collection_information_documents())

    def sauvegarder_lecture(self):
        lecture = lecture_modele.copy()
        nouveau_id = self._informationHelper.sauvegarder_senseur_lecture(lecture)
        print("Nouvelle lecture, id: %s" % str(nouveau_id))

# Wiring initial
configuration = TransactionConfiguration()
configuration.loadEnvironment()
documentDao = MongoDAO(configuration)
documentDao.connecter()

test = AppareilInformationDocumentHelper_Integration()

try:
    test.sauvegarder_lecture()

finally:
    # Fin / deconnecter
    documentDao.deconnecter()


