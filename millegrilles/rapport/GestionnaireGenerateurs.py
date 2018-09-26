# Module pour le gestionnaire de generateurs de rapports.
import signal
import traceback

from millegrilles.dao.MessageDAO import BaseCallback, JSONHelper, PikaDAO
from millegrilles import Constantes
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles.dao.DocumentDAO import MongoDAO
from mgdomaine.appareils.SenseurLecture import GenerateurPagesNoeudsSenseurs, GenerateurPagesNoeudsStatistiques

class GestionnaireGenerateurs(BaseCallback):

    def __init__(self):
        self._generateur = set()
        self._json_helper = JSONHelper()
        self._configuration = TransactionConfiguration()

        self._message_dao = None
        self._document_dao = None

    def initialiser(self):
        self._configuration.loadEnvironment()
        self._document_dao = MongoDAO(self._configuration)
        self._message_dao = PikaDAO(self._configuration)

        # Connecter les DAOs
        self._document_dao.connecter()
        self._message_dao.connecter()

        # Executer la configuration pour RabbitMQ
        self._message_dao.configurer_rabbitmq()

        # Preparer les generateurs
        self.preparer_generateurs()

    def preparer_generateurs(self):
        self.ajouter_generateur(GenerateurPagesNoeudsSenseurs(self._document_dao))
        self.ajouter_generateur(GenerateurPagesNoeudsStatistiques(self._document_dao))

    def executer(self):
        self._message_dao.demarrer_lecture_generateur_documents(self.callbackAvecAck)

    def deconnecter(self):
        self._document_dao.deconnecter()
        self._message_dao.deconnecter()
        print("Deconnexion completee")

    def ajouter_generateur(self, generateur):
        self._generateur.add(generateur)

    def retirer_generateur(self, generateur):
        self._generateur.remove(generateur)

    def traiter_message(self, ch, method, properties, body):
        message = self._json_helper.bin_utf8_json_vers_dict(body)
        print("Traitement message: %s" % message)

        # Passer le message a chaque generateur. On va passer un seul message a la fois et laisser
        # les generateurs faire le travail avec cette thread avant de marquer le message comme complete (ACK).
        for generateur in self._generateur:
            try:
                doit_traiter_evenement = generateur.traiter_evenement(message)
                if doit_traiter_evenement:
                    print("Traiter evenement %s pour generateur %s" % (message, generateur.__class__.__name__))
                    generateur.generer(message)
            except Exception as e:
                print("ERREUR NON GEREE: Traitement message generateur: %s" % str(e))
                traceback.print_exception(etype=type(e), value=e, tb=e.__traceback__)

# --- MAIN ---


gestionnaire = GestionnaireGenerateurs()

def exit_gracefully(signum, frame):
    print("Arret de GestionnaireGenerateurs")
    gestionnaire.deconnecter()

def main():

    print("Demarrage de GestionnaireGenerateurs")

    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    gestionnaire.initialiser()

    try:
        print("GestionnaireGenerateurs est pret")
        gestionnaire.executer()
    finally:
        exit_gracefully(None, None)

    print("GestionnaireGenerateurs est arrete")

if __name__=="__main__":
    main()
