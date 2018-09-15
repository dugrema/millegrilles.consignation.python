#!/usr/bin/python3

'''
    L'orienteur de transaction est le processus qui prend le relai de toutes les transactions
    apres la persistance initiale.
'''

from millegrilles.dao.MessageDAO import BaseCallback

class OrienteurTransaction(BaseCallback):

    def __init__(self):

        self.dict_libelle = {}
        self._message_dao = None
        self._document_dao = None

    def initialiser(self):
        self._message_dao = None
        self._document_dao = None

    # Methode de callback avec ACK pour ecouter sur la Q des transactions persistees.
    def callbackAvecAck(self, ch, method, properties, body):
        # Effectuer travail ici, le ACK doit etre la derniere operation
        super(OrienteurTransaction, self).callbackAvecAck(ch, method, properties, body)

    def charger_liste_processus(self):

        # Charger le dictionnaire des libelles. Permet une correspondance directe
        # vers un processus.

        # Liste des processus
        # MGPProcessus: MilleGrille Python Processus. C'est un processus qui va correspondre directement
        # a un "module.classe" du package millegrilles.processus.
        self.dict_libelle = {
            "senseur.lecture": "MGPProcessus.Senseur.ConsignerLecture"
        }

    '''
    :param message: Evenement d'initialisation de processus recu de la Q (format dictionnaire).
    
    :raises ErreurInitialisationProcessus: le processus est inconnu
    '''
    def orienter_message(self, dictionnaire_evenement):

        # L'evenement recu dans la Q ne contient que les identifiants.
        # Charger la transaction a partir de Mongo pour identifier le type de processus a declencher.
        mongo_id = dictionnaire_evenement.get("_id")
        if mongo_id is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement, "L'identifiant _id est vide ou absent")

        transaction = self._document_dao.charger_document_par_id(mongo_id)
        if transaction is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement, "Aucune transaction ne correspond a _id:%s" % mongo_id)

        # Tenter d'orienter la transaction
        processus_correspondant = None

        # Le message d'evenement doit avoir un element "libelle", c'est la cle pour MGPProcessus.
        charge_utile = transaction.get('charge-utile')
        if charge_utile is not None:

            libelle = charge_utile.get('libelle-transaction')

            #if libelle is None:
            #    raise ErreurInitialisationProcessus(dictionnaire_evenement, "La transaction %s ne contient pas de libelle pour l'orientation" % mongo_id)

            processus_correspondant = self.orienter_message_mgpprocessus(dictionnaire_evenement, libelle)

        if processus_correspondant is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement,
                                                "Le document _id: %s n'est pas une transaction reconnue" % mongo_id)

        return processus_correspondant

    def orienter_message_mgpprocessus(self, dictionnaire_evenement, libelle):
        # On utilise le dictionanire de processus pour trouver le nom du module et de la classe
        processus_correspondant = self.dict_libelle.get(libelle)

        return processus_correspondant

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

