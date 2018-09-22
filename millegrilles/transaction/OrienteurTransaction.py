#!/usr/bin/python3

'''
    L'orienteur de transaction est le processus qui prend le relai de toutes les transactions
    apres la persistance initiale.
'''

import signal

from millegrilles.dao.MessageDAO import BaseCallback, JSONHelper, PikaDAO
from millegrilles.dao.DocumentDAO import MongoDAO
from millegrilles.dao.Configuration import TransactionConfiguration
from millegrilles import Constantes

class OrienteurTransaction(BaseCallback):

    def __init__(self):

        super().__init__()

        self._processus_helper = None

        self.dict_libelle = {}
        self._message_dao = None
        self._document_dao = None
        self._json_helper = JSONHelper()
        self._configuration = TransactionConfiguration()

    def initialiser(self):
        self._configuration.loadEnvironment()
        self._message_dao = PikaDAO(self._configuration)
        self._document_dao = MongoDAO(self._configuration)

        # Connecter les DAOs
        self._document_dao.connecter()
        self._message_dao.connecter()

        # Executer la configuration pour RabbitMQ
        self._message_dao.configurer_rabbitmq()

        # Configurer le comportement de l'orienteur
        self.charger_liste_processus()

        self._processus_helper = self._document_dao.processus_helper()

        print("Configuration et connection completee")

    def executer(self):
        # Note: la methode demarrer_... est blocking
        self._message_dao.demarrer_lecture_entree_processus(self.callbackAvecAck)

    def deconnecter(self):
        self._document_dao.deconnecter()
        self._message_dao.deconnecter()
        print("Deconnexion completee")

    '''
    Traitement des nouvelles transactions. Le message est decode et le processus est declenche.
    En cas d'erreur, un message est mis sur la Q d'erreur. Dans tous les cas, le message va etre consomme.
    '''
    def callbackAvecAck(self, ch, method, properties, body):
        # Decoder l'evenement qui contient l'information sur la transaction a traiter
        evenement_dict = self.extraire_evenement(body)

        # Traiter la transaction: cette methode complete toujours avec succes. Les erreurs
        # sont mises sur une Q a cet effet.
        self.traiter_transaction(evenement_dict)

        # Transmettre le ACK pour indiquer que le message a ete traite
        super(OrienteurTransaction, self).callbackAvecAck(ch, method, properties, body)

    def extraire_evenement(self, message_body):
        # Extraire le message qui devrait etre un document JSON
        message_dict = self._json_helper.bin_utf8_json_vers_dict(message_body)
        return message_dict

    def charger_liste_processus(self):

        # Charger le dictionnaire des libelles. Permet une correspondance directe
        # vers un processus.

        # Liste des processus
        # MGPProcessus: MilleGrille Python Processus. C'est un processus qui va correspondre directement
        # a un "module.classe" du package millegrilles.processus.
        self.dict_libelle = {
            "MGPProcessus.ProcessusTest.TestOrienteur": "ProcessusTest.TestOrienteur",
            "MGPProcessus.Senseur.ConsignerLecture": "Senseur.ConsignerLecture"
        }

    def traiter_transaction(self, dictionnaire_evenement):

        id_document = dictionnaire_evenement.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO)
        #transaction_uuid = dictionnaire_evenement.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_UUID)

        try:
            moteur, processus_a_declencher = self.orienter_message(dictionnaire_evenement)

            if processus_a_declencher is not None:
                # On va declencher un nouveau processus
                id_doc_processus = self._processus_helper.sauvegarder_initialisation_processus(
                    moteur, processus_a_declencher, dictionnaire_evenement)

                self._message_dao.transmettre_evenement_mgpprocessus(
                    id_doc_processus,
                    nom_processus=processus_a_declencher
                )
            else:
                raise Exception("Transaction ne correspond pas a un processus. ERREUR LOGIQUE: une exception aurait du etre lancee au prealable")

        except ErreurInitialisationProcessus as erreur:
            # Une erreur fatale est survenue - l'erreur est liee au contenu du message (ne peut pas etre ressaye)
            transaction_id = dictionnaire_evenement.get("id-tramsaction")
            self._message_dao.transmettre_erreur_transaction(id_document, transaction_id, detail=erreur)
        except Exception as erreur:
            # Erreur inconnue. On va assumer qu'elle est fatale.
            self._message_dao.transmettre_erreur_transaction(id_document=id_document, detail=erreur)

    '''
    :param message: Evenement d'initialisation de processus recu de la Q (format dictionnaire).
    
    :raises ErreurInitialisationProcessus: le processus est inconnu
    '''
    def orienter_message(self, dictionnaire_evenement):

        # L'evenement recu dans la Q ne contient que les identifiants.
        # Charger la transaction a partir de Mongo pour identifier le type de processus a declencher.
        mongo_id = dictionnaire_evenement.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_ID_MONGO)
        if mongo_id is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement, "L'identifiant _id-transaction est vide ou absent du message: %s" % str(dictionnaire_evenement))

        transaction = self._document_dao.charger_transaction_par_id(mongo_id)
        if transaction is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement, "Aucune transaction ne correspond a _id:%s" % mongo_id)

        # Tenter d'orienter la transaction
        moteur = None
        processus_correspondant = None

        # Le message d'evenement doit avoir un element "libelle", c'est la cle pour MGPProcessus.
        indice = None
        info_transaction = transaction.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_INFO_TRANSACTION)
        if info_transaction is not None:
            indice = info_transaction.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_INDICE_PROCESSUS)

        if indice is None:
            charge_utile = transaction[Constantes.TRANSACTION_MESSAGE_LIBELLE_CHARGE_UTILE]
            if charge_utile is not None:
                indice = charge_utile.get(Constantes.TRANSACTION_MESSAGE_LIBELLE_INDICE_PROCESSUS)

        print("Indice est: %s " % indice)

        if indice is not None:
            # Determiner le moteur qui va gerer le processus
            moteur = indice.split('.')[0]
            if moteur == 'MGPProcessus':
                processus_correspondant = self.orienter_message_mgpprocessus(dictionnaire_evenement, indice)
                if processus_correspondant is None:
                    raise ErreurInitialisationProcessus(dictionnaire_evenement,
                                                        "Le document _id: %s n'est pas une transaction MGPProcessus reconnue" % mongo_id)
            else:
                raise ErreurInitialisationProcessus(dictionnaire_evenement,
                                                    "Le document _id: %s est associe a un type de processus inconnu, libelle: %s" % (mongo_id, indice))

        if processus_correspondant is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement,
                                                "Le document _id: %s n'est pas une transaction reconnue" % mongo_id)

        return moteur, processus_correspondant

    def orienter_message_mgpprocessus(self, dictionnaire_evenement, libelle):
        # On utilise le dictionanire de processus pour trouver le nom du module et de la classe
        #processus_correspondant = self.dict_libelle.get(libelle)
        return libelle.replace('MGPProcessus.', '')

        #return processus_correspondant

'''
Exception lancee lorsque le processus ne peut pas etre initialise (erreur fatale).
'''


class ErreurInitialisationProcessus(Exception):

    def __init__(self, evenement, message=None):
        super().__init__(self, message)
        self._evenement = evenement

    @property
    def evenement(self):
        return self._evenement

orienteur = OrienteurTransaction()

def exit_gracefully(signum, frame):
    print("Arret de OrienteurTransaction")
    orienteur.deconnecter()

def main():

    print("Demarrage de OrienteurTransaction")

    signal.signal(signal.SIGINT, exit_gracefully)
    signal.signal(signal.SIGTERM, exit_gracefully)

    orienteur.initialiser()

    try:
        print("OrienteurTransaction est pret")
        orienteur.executer()
    finally:
        exit_gracefully(None, None)

    print("OrienteurTransaction est arrete")

if __name__=="__main__":
    main()
