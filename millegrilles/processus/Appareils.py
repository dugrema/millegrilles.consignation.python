from millegrilles.processus.MGProcessus import MGProcessusTransaction
from millegrilles import Constantes
from mgdomaine.appareils.SenseurLecture import AppareilInformationDocumentHelper

'''
Processus pour importer une lecture dans MilleGrilles.
'''
class ProcessusSenseurConserverLecture(MGProcessusTransaction):

    def __init__(self, controleur, evenement):
        super().__init__(controleur, evenement)

    def dao_helper(self):
        helper = AppareilInformationDocumentHelper(self._controleur.document_dao(), self._controleur.message_dao())
        return helper

    def initiale(self):
        helper = self.dao_helper()
        transaction = self.charger_transaction()

        lecture = transaction['charge-utile']

        # Verifier que le noeud est fourni - sinon on utilie le nom de domaine d'origine de la transaction
        if lecture.get('noeud') is None:
            # On va utiliser l'information de source du message pour donner un nom implicite au noeud.
            # Normalement ca va etre le nom de domaine: mathieu@cuisine.maple.mdugre,info, on garde cuisine.maple.mdugre.info
            source = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION][Constantes.TRANSACTION_MESSAGE_LIBELLE_SOURCE_SYSTEME]
            source = source.split('@')[1]
            lecture['noeud'] = source

        helper.sauvegarder_senseur_lecture(lecture)

        # Terminer
        self.set_etape_suivante()
