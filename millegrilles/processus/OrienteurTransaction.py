#!/usr/bin/python3

'''
    L'orienteur de transaction est le processus qui prend le relai de toutes les transactions
    apres la persistance initiale.
'''

from millegrilles.dao.MessageDAO import BaseCallback

class OrienteurTransaction(BaseCallback):

    def __init__(self):

        self.dict_libelle = {}
        self.message_dao = None
        self.document_dao = None

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

        # Le message d'evenement doit avoir un element "libelle", c'est la cle pour MGPProcessus.
        libelle = dictionnaire_evenement.get('libelle')

        if libelle is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement)

        # On utilise le dictionanire de processus pour trouver le nom du module et de la classe
        processus_correspondant = self.dict_libelle.get(libelle)
        if processus_correspondant is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement)

        # Char

        return processus_correspondant

    def orienter_message_mgpprocessus(self, dictionnaire_message, libelle):
        pass

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

