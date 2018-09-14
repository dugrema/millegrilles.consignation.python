#!/usr/bin/python3

'''
    L'orienteur de transaction est le processus qui prend le relai de toutes les transactions
    apres la persistance initiale.
'''

from millegrilles.dao.MessageDAO import BaseCallback

class OrienteurTransaction(BaseCallback):

    def __init__(self):

        self.dict_libelle = {}

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
            "senseur.lecture": "MGPProcessus.senseur."
        }

        None