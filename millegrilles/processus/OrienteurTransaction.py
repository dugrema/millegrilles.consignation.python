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
        libelle = dictionnaire_evenement.get('libelle')

        if libelle is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement)

        processus_correspondant = self.dict_libelle.get(libelle)
        if processus_correspondant is None:
            raise ErreurInitialisationProcessus(dictionnaire_evenement)

        return processus_correspondant

'''
Exception lancee lorsque le processus ne peut pas etre initialise (erreur fatale).
'''


class ErreurInitialisationProcessus(Exception):

    def __init__(self, evenement):
        super().__init__(self)
        self._evenement = evenement

    @property
    def evenement(self):
        return self._evenement

